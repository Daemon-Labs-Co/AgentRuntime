package workerport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var workerAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

var workerJobPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func validWorkerJobID(v string) bool { return workerJobPattern.MatchString(v) }

// remoteWorkerEndpoint admits only the explicitly configured worker alias.
// SSH transports a constrained worker protocol, never arbitrary model commands.
// Disabling remote transport never restores direct host execution.
func remoteWorkerEndpoint(endpoint, configured, enabled string) (string, string, error) {
	if endpoint == "ssh://commonroom-server" || endpoint == "ssh://commonroom-server/claude" {
		if os.Getenv("COMMONROOM_SERVER_WORKER") != "true" {
			return "", "", errors.New("The worker on this CommonRoom server is disabled; enable COMMONROOM_SERVER_WORKER after configuring its isolated runtime")
		}
		return serverWorkerBinding(endpoint)
	}
	if enabled != "true" {
		return "", "", errors.New("Remote worker transport is disabled; direct SSH execution is forbidden")
	}
	if !workerAliasPattern.MatchString(configured) {
		return "", "", errors.New("Configure COMMONROOM_REMOTE_WORKER_ALIAS")
	}
	provider := "codex"
	alias := strings.TrimPrefix(endpoint, "ssh://")
	if strings.HasSuffix(alias, "/claude") {
		provider = "claude"
		alias = strings.TrimSuffix(alias, "/claude")
	}
	if !strings.HasPrefix(endpoint, "ssh://") || alias != configured {
		return "", "", errors.New("Connection does not target the approved isolated worker")
	}
	return alias, provider, nil
}

type workerRunRequest struct {
	Version        int       `json:"version"`
	IssuedAt       time.Time `json:"issuedAt"`
	Deadline       time.Time `json:"deadline"`
	JobID          string    `json:"jobId"`
	Provider       string    `json:"provider"`
	Key            string    `json:"key"`
	Args           []string  `json:"args"`
	Repository     string    `json:"repository,omitempty"`
	ToolSeparation bool      `json:"toolSeparation,omitempty"`
}

func decodeWorkerRequest(encoded string) (workerRunRequest, error) {
	var v workerRunRequest
	if len(encoded) > 16384 {
		return v, errors.New("Worker request too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return v, errors.New("Invalid worker request")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&v); err != nil {
		return v, errors.New("Invalid worker request")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return v, errors.New("Trailing worker request data")
	}
	return v, validateWorkerRun(v)
}

// validateWorkerRun forbids arbitrary CLI options, mounts, environment and shell
// commands. Provider arguments must match the exact chat policy or the explicit
// development policy bound to an approved snapshot. The worker independently
// verifies its administrator-owned room registry before any launch.
func validateWorkerRun(v workerRunRequest) error {
	if err := requireCredentialSeparatedDevelopment(v.Repository); err != nil {
		return err
	}
	if v.Version != workerLifecycleVersion || !validWorkerJobID(v.JobID) || strings.TrimSpace(v.Key) == "" || len(v.Key) > 1024 {
		return errors.New("Invalid worker identity")
	}
	now := time.Now().UTC()
	if v.IssuedAt.IsZero() || !v.Deadline.After(v.IssuedAt) || v.Deadline.Sub(v.IssuedAt) > 3*time.Minute || v.IssuedAt.After(now.Add(5*time.Second)) || !v.Deadline.After(now) {
		return errors.New("Worker request deadline is expired or invalid")
	}
	if _, _, _, _, err := workerMembership(v.Key); err != nil {
		return err
	}
	base := []string{}
	suffix := []string{}
	threadFlag := ""
	if v.Repository != "" && !repositoryDigestPattern.MatchString(v.Repository) {
		return errors.New("Invalid development repository digest")
	}
	if v.Provider != "codex" && v.Provider != "claude" {
		return errors.New("Unsupported worker provider")
	}
	if v.ToolSeparation && v.Repository == "" {
		return errors.New("Tool separation requires an approved development workspace")
	}
	base = providerTurnArgs(v.Provider, v.Repository != "", v.ToolSeparation)
	if v.Provider == "codex" {
		suffix = []string{"-"}
		threadFlag = "resume"
	} else {
		threadFlag = "--resume"
	}

	n := len(base) + len(suffix)
	if len(v.Args) != n && len(v.Args) != n+2 {
		return errors.New("Forbidden worker arguments")
	}
	for i, arg := range base {
		if v.Args[i] != arg {
			return errors.New("Forbidden worker arguments")
		}
	}
	for i, arg := range suffix {
		if v.Args[len(v.Args)-len(suffix)+i] != arg {
			return errors.New("Forbidden worker arguments")
		}
	}
	if len(v.Args) == n+2 {
		thread := v.Args[len(base)+1]
		if v.Args[len(base)] != threadFlag || len(thread) > 128 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`).MatchString(thread) {
			return errors.New("Invalid worker session")
		}
	}
	return nil
}

type workerConfiguration struct {
	Image                   string                           `json:"image"`
	AuthDir                 string                           `json:"authDir"`
	DevelopmentEnabled      bool                             `json:"developmentEnabled,omitempty"`
	DevelopmentRepositories map[string]developmentRepository `json:"developmentRepositories,omitempty"`
}

type workerJobRecord struct {
	IdleShutdownRequestedAt time.Time         `json:"idleShutdownRequestedAt,omitempty"`
	IdleTimeoutMinutes      int               `json:"idleTimeoutMinutes,omitempty"`
	Pair                    *workerPairRecord `json:"pair,omitempty"`
	Execution               string            `json:"execution,omitempty"`
	Version                 int               `json:"version,omitempty"`
	RoomID                  string            `json:"roomId,omitempty"`
	ParticipantID           string            `json:"participantId,omitempty"`
	ConnectionID            string            `json:"connectionId,omitempty"`
	Scope                   string            `json:"scope,omitempty"`
	StartedAt               time.Time         `json:"startedAt,omitempty"`
	UpdatedAt               time.Time         `json:"updatedAt,omitempty"`
	Deadline                time.Time         `json:"deadline,omitempty"`
	ShutdownConfirmed       bool              `json:"shutdownConfirmed"`
	DiagnosticCode          string            `json:"diagnosticCode,omitempty"`
	JobID                   string            `json:"jobId"`
	Status                  string            `json:"status"`
	Provider                string            `json:"provider"`
}

func workerStateDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".local/state/commonroom-worker/jobs")
	err = os.MkdirAll(dir, 0700)
	return dir, err
}

func writeWorkerRecord(dir string, v workerJobRecord, exclusive bool) error {
	if (v.Pair != nil || v.Execution != "") && !validWorkerRecord(v) {
		return errors.New("invalid paired worker record")
	}
	raw, _ := json.Marshal(v)
	path := filepath.Join(dir, v.JobID+".json")
	if exclusive {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err = f.Write(raw); err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			return err
		}
		return syncWorkerDirectory(dir)
	}
	f, err := os.CreateTemp(dir, ".outcome-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncWorkerDirectory(dir)
}

func readWorkerRecord(dir, job string) (workerJobRecord, error) {
	var v workerJobRecord
	path := filepath.Join(dir, job+".json")
	raw, err := readPrivateBounded(path, 8192)
	if err != nil || json.Unmarshal(raw, &v) != nil || v.JobID != job {
		return v, errors.New("Invalid or unsafe worker record")
	}
	if v.Version != 0 && v.Version != 2 && !pairedLifecycleVersion(v.Version) {
		return v, errors.New("Unsupported worker record")
	}
	if v.Version != 0 && !validWorkerRecord(v) {
		return v, errors.New("Invalid worker binding or lifecycle")
	}

	return v, nil
}

func workerTerminal(status string) bool {
	return status == "finished" || status == "failed" || status == "cancelled"
}

// workerStreamWriter bounds remote output independently of the controller.
type workerStreamWriter struct {
	writer    io.Writer
	remaining int
	cancel    context.CancelFunc
}

func (w *workerStreamWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		w.cancel()
		return 0, errors.New("Worker output exceeded limit")
	}
	n, err := w.writer.Write(p)
	w.remaining -= n
	if err != nil {
		w.cancel()
	}
	return n, err
}

func configureWorker() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".config/commonroom-worker/config.json")
	raw, err := readPrivateBounded(path, 8192)
	if err != nil {
		return errors.New("Worker requires owner-only, bounded ~/.config/commonroom-worker/config.json")
	}
	var c workerConfiguration
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF || !validAgentImage(c.Image) || !filepath.IsAbs(c.AuthDir) {
		return errors.New("Worker requires a digest-pinned image and absolute authDir")
	}
	if err := validateDevelopmentRegistry(c.DevelopmentRepositories); err != nil {
		return err
	}
	registry, _ := json.Marshal(c.DevelopmentRepositories)
	os.Setenv("COMMONROOM_WORKER_DEVELOPMENT_REPOSITORIES", string(registry))
	os.Setenv("COMMONROOM_WORKER_DEVELOPMENT", fmt.Sprint(c.DevelopmentEnabled))
	os.Setenv("COMMONROOM_AGENT_IMAGE", c.Image)
	os.Setenv("COMMONROOM_AGENT_AUTH_DIR", c.AuthDir)
	return nil
}

// agentWorkerMain is a database-free entry point, invoked only by the installed
// worker wrapper over authenticated SSH. Provider secrets remain on this host.
// A fork CAN bypass isolation, BUT removes the documented containment boundary.
func agentWorkerMain(args []string, in io.Reader, out, diagnostics io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(diagnostics, err); return 1 }
	if len(args) == 0 {
		return fail(errors.New("Worker action required"))
	}
	if args[0] == "auth-login-v1" || args[0] == "auth-status-v1" || args[0] == "auth-logout-v1" || args[0] == "verify-v1" {
		return workerProviderAuth(args, in, out, diagnostics)
	}
	if args[0] == "idle-v1" && len(args) == 1 {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		idle, err := workerIdleProbe(ctx)
		if err != nil {
			return fail(err)
		}
		json.NewEncoder(out).Encode(map[string]any{"version": 1, "lifecycleVersion": 2, "idle": idle})
		return 0
	}
	if args[0] == "jobs-v2" && len(args) == 1 {
		if err := configureWorker(); err != nil {
			return fail(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := workerRuntimeReady(ctx); err != nil {
			return fail(err)
		}
		containers, err := managedWorkerContainers(ctx)
		if err != nil {
			return fail(err)
		}
		dir, err := workerStateDirectory()
		if err != nil {
			return fail(err)
		}
		snapshot, err := workerSnapshot(dir, containers)
		if err != nil {
			return fail(err)
		}
		if json.NewEncoder(out).Encode(snapshot) != nil {
			return 1
		}
		return 0
	}
	if args[0] == "ready-v1" && len(args) == 1 {
		if err := configureWorker(); err != nil {
			return fail(err)
		}
		if err := isolationAvailable("codex"); err != nil {
			return fail(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		info, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .}}").Output()
		if err != nil || !dockerSecurityReady(info) {
			return fail(errors.New("Rootless Docker or required limits unavailable"))
		}
		if exec.CommandContext(ctx, "docker", "image", "inspect", os.Getenv("COMMONROOM_AGENT_IMAGE")).Run() != nil {
			return fail(errors.New("Configured agent image is unavailable"))
		}
		credentials := map[string]bool{}
		for provider, filename := range map[string]string{"codex": "auth.json", "claude": ".credentials.json"} {
			fi, err := os.Lstat(filepath.Join(os.Getenv("COMMONROOM_AGENT_AUTH_DIR"), provider, filename))
			credentials[provider] = err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0077 == 0 && fi.Size() <= 65536
		}
		json.NewEncoder(out).Encode(map[string]any{"version": 1, "lifecycleVersion": 2, "configured": true, "runtimeReady": true, "credentials": credentials})
		return 0
	}
	if len(args) != 2 {
		return fail(errors.New("Invalid worker request"))
	}

	if args[0] == "audit-link-v1" {
		scope, err := decodeWorkerAuditScope(args[1])
		if err != nil {
			return fail(errors.New("Audit link refused"))
		}
		if err = configureWorker(); err != nil {
			return fail(errors.New("Audit link unavailable"))
		}
		dir, err := workerStateDirectory()
		if err != nil {
			return fail(errors.New("Audit link unavailable"))
		}
		ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
		defer cancel()
		if workerAttachAudit(ctx, dir, scope, in, out) != nil {
			return fail(errors.New("Audit link failed"))
		}
		return 0
	}
	if args[0] == "status-v1" && validWorkerJobID(args[1]) {
		dir, err := workerStateDirectory()
		if err != nil {
			return fail(err)
		}
		v, err := readWorkerRecord(dir, args[1])
		if err != nil {
			return fail(err)
		}
		json.NewEncoder(out).Encode(v)
		return 0
	}
	if args[0] == "cancel-v2" || args[0] == "cancel-pair-v1" || args[0] == "cancel-pair-workspace-v1" {
		request, err := decodeFenceRequest(args[1])
		if err == nil && ((args[0] == "cancel-v2" && request.Version != 2) || (args[0] == "cancel-pair-v1" && request.Version != 3) || (args[0] == "cancel-pair-workspace-v1" && request.Version != workerWorkspaceLifecycleVersion)) {
			err = errors.New("cancellation protocol mismatch")
		}
		if err != nil {
			return fail(err)
		}
		if err = configureWorker(); err != nil {
			return fail(err)
		}
		dir, err := workerStateDirectory()
		if err != nil {
			return fail(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
		defer cancel()
		if err := workerRuntimeReady(ctx); err != nil {
			return fail(err)
		}
		record, err := fenceWorkerJob(ctx, dir, request, stopWorkerContainer)
		if err != nil {
			return fail(err)
		}
		json.NewEncoder(out).Encode(workerFenceAcknowledgement(request, record))
		return 0
	}

	if args[0] != "run-v2" {
		return fail(errors.New("Unsupported worker action"))
	}
	request, err := decodeWorkerRequest(args[1])
	if err != nil {
		return fail(err)
	}
	if err = configureWorker(); err != nil {
		return fail(err)
	}
	dir, err := workerStateDirectory()
	if err != nil {
		return fail(err)
	}
	admissionCtx, admissionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err = workerRuntimeReady(admissionCtx); err != nil {
		admissionCancel()
		return fail(err)
	}
	containers, err := managedWorkerContainers(admissionCtx)
	if err != nil {
		admissionCancel()
		return fail(err)
	}
	record, leases, err := admitWorkerJob(admissionCtx, dir, request, containers)
	admissionCancel()
	if err != nil {
		return fail(err)
	}
	defer leases.Close()

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()
	deadline := request.Deadline
	if ceiling := time.Now().Add(3 * time.Minute); deadline.After(ceiling) {
		deadline = ceiling
	}
	ctx, cancel := context.WithDeadline(signalCtx, deadline)
	defer cancel()
	latch := filepath.Join(dir, request.JobID+".cancel")
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := os.Stat(latch); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	type promptResult struct {
		data []byte
		err  error
	}
	promptCh := make(chan promptResult, 1)
	go func() { data, err := io.ReadAll(io.LimitReader(in, 1024*1024+1)); promptCh <- promptResult{data, err} }()
	var prompt []byte
	select {
	case result := <-promptCh:
		prompt, err = result.data, result.err
	case <-ctx.Done():
		err = ctx.Err()
	}

	if err != nil || len(prompt) > 1024*1024 {
		record.Status = "failed"
		record.UpdatedAt = time.Now().UTC()
		record.DiagnosticCode = "preparation_failed"
		record.ShutdownConfirmed = true
		writeWorkerRecord(dir, record, false)
		return fail(errors.New("Worker prompt exceeded limit"))
	}
	cmd, cleanup, err := localIsolatedDevelopmentCommand(ctx, request.Provider, request.Key, request.JobID, request.Repository, request.ToolSeparation, request.Args...)
	if err != nil {
		record.Status = "failed"
		record.UpdatedAt = time.Now().UTC()
		record.DiagnosticCode = "preparation_failed"
		record.ShutdownConfirmed = true
		writeWorkerRecord(dir, record, false)
		return fail(err)
	}
	if ctx.Err() != nil {
		cleanup()
		record.Status = "cancelled"
		record.UpdatedAt = time.Now().UTC()
		record.DiagnosticCode = "cancelled_before_launch"
		record.ShutdownConfirmed = true
		writeWorkerRecord(dir, record, false)
		return fail(errors.New("Worker job cancelled before launch"))
	}
	record.Status = "running"
	record.UpdatedAt = time.Now().UTC()
	record.DiagnosticCode = "running"
	if err = writeWorkerRecord(dir, record, false); err != nil {
		cleanup()
		return fail(err)
	}
	cmd.Stdin = strings.NewReader(string(prompt))
	cmd.Stdout = &workerStreamWriter{writer: out, remaining: 4 * 1024 * 1024, cancel: cancel}
	cmd.Stderr = &workerStreamWriter{writer: diagnostics, remaining: 4 * 1024 * 1024, cancel: cancel}
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	cleanup()
	record.Status = "finished"
	if err != nil {
		record.Status = "failed"
	}
	if ctx.Err() != nil {
		record.Status = "cancelled"
	}
	proofCtx, proofCancel := context.WithTimeout(context.Background(), 5*time.Second)
	proofErr := stopWorkerContainer(proofCtx, request.JobID)
	proofCancel()
	record.UpdatedAt = time.Now().UTC()
	record.ShutdownConfirmed = proofErr == nil
	record.DiagnosticCode = "completed"
	if ctx.Err() != nil {
		record.DiagnosticCode = "cancelled_or_deadline"
	} else if err != nil {
		record.DiagnosticCode = "provider_failed"
	}
	if proofErr != nil {
		record.Status = "shutdown_unconfirmed"
		record.DiagnosticCode = "container_shutdown_unverified"
		err = errors.New("Worker shutdown unconfirmed")
	}
	if writeWorkerRecord(dir, record, false) != nil {
		return fail(errors.New("Worker outcome could not be recorded"))
	}
	if err != nil {
		return fail(errors.New("Isolated worker turn failed"))
	}
	return 0
}
