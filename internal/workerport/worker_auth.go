package workerport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Connection credentials are isolated from other connections. Agent execution
// remains disposable and separately scoped; no host CLI is used for sign-in.
type workerAuthRequest struct {
	Version    int    `json:"version"`
	Connection string `json:"connection"`
	Provider   string `json:"provider"`
}

func connectionAuthKey(connection string) string {
	digest := sha256.Sum256([]byte(connection))
	return hex.EncodeToString(digest[:])
}

func executionConnectionID(key string) (string, error) {
	parts := strings.SplitN(key, "/", 4)
	if len(parts) != 4 || !workerAliasPattern.MatchString(parts[2]) {
		return "", errors.New("Execution requires a valid connection identity")
	}
	return parts[2], nil
}

func encodeWorkerAuth(v workerAuthRequest) (string, error) {
	if v.Version != 1 || !workerAliasPattern.MatchString(v.Connection) || (v.Provider != "codex" && v.Provider != "claude") {
		return "", errors.New("Invalid authentication request")
	}
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeWorkerAuth(encoded string) (workerAuthRequest, error) {
	var v workerAuthRequest
	if len(encoded) > 1024 {
		return v, errors.New("Authentication request too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return v, err
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return v, errors.New("Invalid authentication request")
	}
	_, err = encodeWorkerAuth(v)
	return v, err
}

func providerCredentialName(provider string) string {
	if provider == "claude" {
		return ".credentials.json"
	}
	return "auth.json"
}

// Forget only this connection/provider's stored credential; provider-wide revocation is separate.
func clearWorkerCredential(root, provider string) error {
	return clearWorkerCredentialDurably(root, provider, syncParentDirectory)
}

// clearWorkerCredentialDurably acknowledges local revocation only after the
// directory entry is synced. Missing-file retries must sync too: a previous
// unlink may have succeeded while its durability acknowledgement failed.
func clearWorkerCredentialDurably(root, provider string, syncDirectory func(string) error) error {
	if provider != "codex" && provider != "claude" {
		return errors.New("Unsupported credential provider")
	}
	path := filepath.Join(root, providerCredentialName(provider))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDirectory(path)
}

func lockWorkerCredential(root string) (func(), error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	f, err := openPrivateRegular(filepath.Join(root, ".auth.lock"), os.O_CREATE|os.O_RDWR, 8192)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("Connection authentication is busy; finish the current sign-in first")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func credentialPresent(path string) bool {
	if !workerCredentialReady(filepath.Dir(path)) {
		return false
	}
	raw, err := readPrivateBounded(path, 65536)
	return err == nil && len(raw) > 2 && json.Valid(raw)
}

// workerProviderAuth permits only provider login/status in a constrained image.
// Login is a human administrative operation, bounded to fifteen minutes, with
// the same network gateway and resource limits as agent turns. There is no
// credential upload endpoint or arbitrary command/mount option.
func workerProviderAuth(args []string, in io.Reader, out, diagnostics io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(diagnostics, err); return 1 }
	if len(args) != 2 {
		return fail(errors.New("Invalid authentication request"))
	}
	v, err := decodeWorkerAuth(args[1])
	if err != nil {
		return fail(err)
	}
	if err = configureWorker(); err != nil {
		return fail(err)
	}
	root := filepath.Join(os.Getenv("COMMONROOM_AGENT_AUTH_DIR"), connectionAuthKey(v.Connection), v.Provider)
	credential := filepath.Join(root, providerCredentialName(v.Provider))
	if args[0] == "auth-status-v1" {
		json.NewEncoder(out).Encode(map[string]bool{"credentialPresent": credentialPresent(credential), "recoveryRequired": !workerCredentialReady(root)})
		return 0
	}
	if args[0] == "verify-v1" {
		return workerVerifyConnection(v, out, diagnostics)
	}
	if args[0] != "auth-login-v1" && args[0] != "auth-logout-v1" {
		return fail(errors.New("Unsupported authentication action"))
	}
	unlock, err := lockWorkerCredential(root)
	if err != nil {
		return fail(err)
	}
	defer unlock()
	journal, journalErr := workerStateDirectory()
	if journalErr != nil || !workerCredentialConnectionQuiescent(journal, v.Connection, v.Provider) {
		return fail(errors.New("Connection execution must be fenced before changing authentication"))
	}
	if args[0] == "auth-logout-v1" {
		if err = clearWorkerCredential(root, v.Provider); err != nil {
			return fail(errors.New("Unable to clear connection credentials"))
		}
		if err = clearWorkerCredentialRecovery(root, syncParentDirectory); err != nil {
			return fail(err)
		}
		json.NewEncoder(out).Encode(map[string]bool{"signedOut": true})
		return 0
	}
	if err = isolationAvailable(v.Provider); err != nil {
		return fail(err)
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, 15*time.Minute)
	defer cancel()
	info, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .}}").Output()
	if err != nil || !dockerSecurityReady(info) {
		return fail(errors.New("Rootless Docker limits unavailable"))
	}
	host, err := exec.CommandContext(ctx, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").Output()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(host)), "unix://") || os.Getenv("DOCKER_HOST") != "" || os.Getenv("DOCKER_CONTEXT") != "" {
		return fail(errors.New("Local rootless Docker context required"))
	}
	dir, err := os.MkdirTemp("", "commonroom-login-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)
	gateway, err := newProviderGateway(ctx, filepath.Join(dir, "provider.sock"), v.Provider)
	if err != nil {
		return fail(err)
	}
	defer gateway.Close()
	name := "commonroom-login-" + connectionAuthKey(v.Connection)[:32]
	// Container-name collision serializes login for this connection. A competing
	// launch never removes the other login container.
	volume := name + "-" + id()
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		exec.CommandContext(cleanup, "docker", "volume", "rm", volume, volume+"-work").Run()
	}()
	launch := isolatedRunArgs(os.Getenv("COMMONROOM_AGENT_IMAGE"), name, volume, gateway.socket, "/unused", v.Provider, []string{"auth-login"})
	filtered := workerLoginContainerArgs(launch, v.Provider)

	var result cappedStatusOutput
	create := exec.CommandContext(ctx, "docker", filtered...)
	create.Stdout = &result
	create.Stderr = diagnostics
	if err = create.Run(); err != nil {
		return fail(errors.New("Sign-in container unavailable; another login may be active"))
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if exec.CommandContext(cleanup, "docker", "rm", "--force", name).Run() != nil {
			fmt.Fprintln(diagnostics, "Sign-in container cleanup unconfirmed:", name)
		}
	}()
	attach := "-ai"
	if v.Provider == "codex" {
		attach = "-a"
	}
	run := exec.CommandContext(ctx, "docker", "start", attach, name)
	if v.Provider != "codex" {
		run.Stdin = in
	}
	run.Stdout = out
	run.Stderr = diagnostics
	// Login can rotate/invalidate existing subscription tokens before returning.
	// Keep failed/interrupted recovery blocked rather than trust the old file.
	if err = markWorkerCredentialUncertain(root); err != nil {
		return fail(err)
	}
	if run.Run() != nil {
		return fail(errors.New("Provider sign-in did not complete; complete connection sign-in again before use"))
	}
	exportArgs, err := workerCredentialExportArgs(os.Getenv("COMMONROOM_AGENT_IMAGE"), volume, v.Provider)
	if err != nil {
		return fail(err)
	}
	var exported credentialExportOutput
	export := exec.CommandContext(ctx, "docker", exportArgs...)
	export.Stdout = &exported
	// Export output contains credentials. Never forward either stream to logs.
	if export.Run() != nil {
		return fail(errors.New("Provider credential export failed; existing credentials were preserved"))
	}
	target := filepath.Join(dir, "credential.json")
	if err = os.WriteFile(target, exported.Bytes(), 0600); err != nil {
		return fail(errors.New("Unable to stage private provider credential"))
	}
	if err = persistWorkerCredential(root, v.Provider, target); err != nil {
		return fail(err)
	}
	fmt.Fprintln(out, "Connection sign-in saved. Return to CommonRoom and choose Check sign-in.")
	return 0
}

// credentialExportOutput bounds sensitive output in memory; callers must never
// forward it to diagnostics. Overflow fails the export instead of truncating it.
type credentialExportOutput struct{ bytes.Buffer }

func (b *credentialExportOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}

// workerCredentialExportArgs reads one known credential from the connection's
// login volume in a non-root, network-disabled container. The volume is read-only;
// there are no host paths, provider invocation, gateway, or Docker socket mounts.
// Source forks CAN weaken these limits, BUT risk exposing every host credential.
func workerCredentialExportArgs(image, volume, provider string) ([]string, error) {
	path := "/home/agent/.codex/auth.json"
	if provider == "claude" {
		path = "/home/agent/.claude/.credentials.json"
	} else if provider != "codex" {
		return nil, errors.New("Unsupported credential provider")
	}
	// O_NOFOLLOW also rejects symlink substitution between stat and open. Read
	// at most the limit plus one byte, even if the file grows after inspection.
	script := `const fs=require("node:fs");try{const fd=fs.openSync(process.argv[1],fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const st=fs.fstatSync(fd);if(!st.isFile()||st.size<=2||st.size>65536)process.exit(78);const b=Buffer.alloc(65537);const n=fs.readSync(fd,b,0,b.length,0);fs.closeSync(fd);if(n<=2||n>65536)process.exit(78);JSON.parse(b.subarray(0,n).toString());process.stdout.write(b.subarray(0,n));}catch{process.exit(78);}`
	return []string{"run", "--rm", "--pull=never", "--network=none", "--read-only", "--user", "1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=32", "--memory=128m", "--memory-swap=128m", "--cpus=1", "--log-driver=none", "--workdir", "/", "--mount", "type=volume,src=" + volume + ",dst=/home/agent,readonly", "--entrypoint", "node", image, "-e", script, path}, nil
}

// persistWorkerCredential validates only the exported provider file and replaces
// the connection's private credential atomically and syncs its parent. Invalid
// exports leave the prior login untouched; post-rename sync failure is ambiguous
// and must not be acknowledged as saved. No credential bytes enter diagnostics.
func persistWorkerCredential(root, provider, source string) error {
	return persistWorkerCredentialDurably(root, provider, source, syncParentDirectory)
}

func persistWorkerCredentialDurably(root, provider, source string, syncDirectory func(string) error) error {
	if provider != "codex" && provider != "claude" {
		return errors.New("Unsupported credential provider")
	}
	raw, err := readPrivateBounded(source, 65536)
	if err != nil || len(raw) <= 2 || !json.Valid(raw) {
		return errors.New("Invalid private provider credential JSON")
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err := replacePrivateDurably(filepath.Join(root, providerCredentialName(provider)), raw, syncDirectory); err != nil {
		return errors.New("Private provider credential persistence unconfirmed")
	}
	return clearWorkerCredentialRecovery(root, syncDirectory)
}

// workerVerifyConnection rejects the legacy unjournalled verification launcher.
// Controllers must use registered run-v2 jobs with verified cancellation instead.
func workerVerifyConnection(v workerAuthRequest, out, diagnostics io.Writer) int {
	fmt.Fprintln(diagnostics, "Legacy verification is disabled; use controller-managed protocol-v2 verification")
	return 1
}

// Codex device authorization has no stdin exchange. Interactive Docker TTY/stdin
// attachment must not hide or stall its headless verification instructions.
func workerLoginContainerArgs(launch []string, provider string) []string {
	filtered := []string{}
	for i := 0; i < len(launch); i++ {
		if launch[i] == "--rm" || (provider == "codex" && launch[i] == "-i") {
			continue
		}
		if launch[i] == "--mount" && i+1 < len(launch) && strings.Contains(launch[i+1], "dst=/run/provider-auth.json") {
			i++
			continue
		}
		filtered = append(filtered, launch[i])
	}
	filtered[0] = "create"
	if provider != "codex" {
		filtered = append([]string{filtered[0], "-i", "-t"}, filtered[1:]...)
	}
	return filtered
}
