package workerport

import (
	"commonroom-runtime/internal/toolbroker"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

const workerLifecycleVersion = 2

// Reserve physical container slots before creation, including unresolved jobs.
// This worker-local ceiling cannot replace account-wide multi-worker admission.
const workerContainerLimit = managedContainerLimit

func workerContainerSlots(record workerJobRecord) int {
	if record.Pair != nil {
		return 2
	}
	return 1
}

var membershipPartPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type workerLease struct{ file *os.File }

func (l *workerLease) Close() {
	if l != nil && l.file != nil {
		syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		l.file.Close()
		l.file = nil
	}
}

// workerTryLease uses a persistent private inode; never delete lock files while
// running. Kernel ownership disappears on supervisor crash. A source fork CAN
// skip fencing, BUT allows delayed launches after cancellation and overlapping jobs.
func workerTryLease(dir, name string) (*workerLease, bool, error) {
	path := filepath.Join(dir, name)
	f, err := openPrivateRegular(path, os.O_RDWR|os.O_CREATE, 8192)
	if err != nil {
		return nil, false, err
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		f.Close()
		return nil, false, nil
	}
	if err != nil {
		f.Close()
		return nil, false, err
	}
	return &workerLease{file: f}, true, nil
}

func workerWaitLease(ctx context.Context, dir, name string) (*workerLease, error) {
	for {
		lease, free, err := workerTryLease(dir, name)
		if err != nil {
			return nil, err
		}
		if free {
			return lease, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func syncWorkerDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func workerMembership(key string) (string, string, string, string, error) {
	parts := strings.SplitN(key, "/", 4)
	if len(parts) != 4 {
		return "", "", "", "", errors.New("invalid membership binding")
	}
	for _, part := range parts[:3] {
		if !membershipPartPattern.MatchString(part) {
			return "", "", "", "", errors.New("invalid membership binding")
		}
	}
	sum := sha256.Sum256([]byte(parts[0] + "/" + parts[1]))
	return parts[0], parts[1], parts[2], hex.EncodeToString(sum[:]), nil
}

func newWorkerJobRecord(request workerRunRequest) (workerJobRecord, error) {
	room, participant, connection, scope, err := workerMembership(request.Key)
	if err != nil {
		return workerJobRecord{}, err
	}
	now := time.Now().UTC()
	record := workerJobRecord{Version: 2, JobID: request.JobID, Provider: request.Provider, RoomID: room, ParticipantID: participant, ConnectionID: connection, Scope: scope, Status: "starting", StartedAt: now, UpdatedAt: now, Deadline: now.Add(3 * time.Minute), DiagnosticCode: "preparing"}
	if !request.Deadline.IsZero() {
		if !request.Deadline.After(now) {
			return workerJobRecord{}, errors.New("worker request expired before admission")
		}
		record.Deadline = request.Deadline
	}
	return record, nil
}

func boundedWorkerRecords(dir string) ([]workerJobRecord, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(16385)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 16384 {
		return nil, errors.New("worker file scan limit exceeded")
	}
	records := []workerJobRecord{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		job := strings.TrimSuffix(entry.Name(), ".json")
		if !validWorkerJobID(job) {
			return nil, errors.New("invalid worker record identity")
		}
		record, err := readWorkerRecord(dir, job)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
		if len(records) > 4096 {
			return nil, errors.New("worker record scan limit exceeded")
		}
	}
	return records, nil
}

func workerJobSettled(v workerJobRecord) bool {
	// A terminal label from a legacy supervisor is not shutdown proof. Never
	// silently upgrade that label into permission to resume managed execution.
	return workerTerminal(v.Status) && (v.Version == workerLifecycleVersion || pairedLifecycleVersion(v.Version)) && v.ShutdownConfirmed && validWorkerPair(v)
}

// workerAdmission checks durable records and live containers under the shared
// admission lock. Scope locks serialize a membership across connections/providers.
func workerAdmission(records []workerJobRecord, containers []string, next workerJobRecord) error {
	count, roomCount, containerSlots := 0, 0, 0
	byJob := map[string]workerJobRecord{}
	for _, record := range records {
		byJob[record.JobID] = record
		if !validWorkerPair(record) {
			return errors.New("invalid pair lifecycle evidence")
		}
		if workerJobSettled(record) {
			continue
		}
		if record.Version != 2 && !pairedLifecycleVersion(record.Version) {
			return errors.New("legacy unresolved worker job requires administrator review")
		}
		if record.Scope == next.Scope {
			return errors.New("membership has unresolved worker work")
		}
		count++
		containerSlots += workerContainerSlots(record)
		if record.RoomID == next.RoomID {
			roomCount++
		}
	}
	for _, name := range containers {
		job := strings.TrimPrefix(name, "commonroom-turn-")
		paired := false
		for _, role := range []string{"engine", "tool"} {
			if strings.HasPrefix(name, "commonroom-"+role+"-") {
				job = strings.TrimPrefix(name, "commonroom-"+role+"-")
				paired = true
				break
			}
		}
		record, ok := byJob[job]
		if (!paired && !strings.HasPrefix(name, "commonroom-turn-")) || !validWorkerJobID(job) || !ok || (record.Version != 2 && !pairedLifecycleVersion(record.Version)) || workerJobSettled(record) || paired != (record.Pair != nil) {
			return errors.New("unreconciled managed container blocks dispatch")
		}
		if record.Scope == next.Scope {
			return errors.New("membership container still exists")
		}
	}
	if containerSlots+workerContainerSlots(next) > workerContainerLimit {
		return errors.New("worker container capacity reached")
	}
	if count >= 8 || roomCount >= 4 {
		return errors.New("worker concurrency capacity reached")
	}
	return nil
}

type workerJobLeases struct{ scope, job *workerLease }

func (l *workerJobLeases) Close() {
	if l != nil {
		l.job.Close()
		l.scope.Close()
	}
}

func admitWorkerJob(ctx context.Context, dir string, request workerRunRequest, containers []string) (workerJobRecord, *workerJobLeases, error) {
	record, err := newWorkerJobRecord(request)
	if err != nil {
		return record, nil, err
	}
	return admitWorkerRecord(ctx, dir, record, containers)
}

func admitWorkerRecord(ctx context.Context, dir string, record workerJobRecord, containers []string) (workerJobRecord, *workerJobLeases, error) {
	if !validWorkerRecord(record) {
		return record, nil, errors.New("invalid worker admission record")
	}
	admission, err := workerWaitLease(ctx, dir, ".admission.lease")
	if err != nil {
		return record, nil, err
	}
	defer admission.Close()
	scope, free, err := workerTryLease(dir, ".scope-"+record.Scope+".lease")
	if err != nil || !free {
		return record, nil, errors.New("membership supervisor is already active")
	}
	job, free, err := workerTryLease(dir, ".job-"+record.JobID+".lease")
	if err != nil || !free {
		scope.Close()
		return record, nil, errors.New("job supervisor is already active")
	}
	leases := &workerJobLeases{scope: scope, job: job}
	if _, err := os.Lstat(filepath.Join(dir, record.JobID+".cancel")); !os.IsNotExist(err) {
		leases.Close()
		return record, nil, errors.New("worker identity cancelled or unverified")
	}
	records, err := boundedWorkerRecords(dir)
	if err == nil {
		err = workerProbeCapacity(dir, records, workerContainerSlots(record))
	}
	if err == nil {
		err = workerAdmission(records, containers, record)
	}
	if err == nil {
		err = writeWorkerRecord(dir, record, true)
	}
	if err != nil {
		leases.Close()
		return record, nil, err
	}
	return record, leases, nil
}

func managedWorkerContainers(ctx context.Context) ([]string, error) {
	var output limitedAgentOutput
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "label=commonroom.managed=true", "--format", "{{.Names}}")
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("managed container state unavailable")
	}
	names := strings.Fields(output.String())
	if len(names) > 4096 {
		return nil, errors.New("managed container scan limit exceeded")
	}
	return names, nil
}

// stopWorkerContainer checks the exact name and managed label, removes only that
// container and confirms absence. Output/errors never contain provider data.
func stopWorkerContainer(ctx context.Context, job string) error {
	name := "commonroom-turn-" + job
	for attempts := 0; attempts < 2; attempts++ {
		var output limitedAgentOutput
		cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.Names}}|{{.Label \"commonroom.managed\"}}")
		cmd.Stdout = &output
		cmd.Stderr = io.Discard
		if cmd.Run() != nil {
			return errors.New("container absence unverified")
		}
		label := strings.TrimSpace(output.String())
		if label == "" {
			return nil
		}
		if label != name+"|true" {
			return errors.New("refusing unmanaged container removal")
		}
		cmd = exec.CommandContext(ctx, "docker", "rm", "--force", name)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if cmd.Run() != nil {
			return errors.New("container removal unverified")
		}
	}
	return errors.New("container shutdown unverified")
}

// DiscardWorkspace is not human approval. Destructive callers must first obtain
// exact current human authorization, then bind the complete observed identity.
// The owner review endpoint requires a durable one-shot approval first.
// Ordinary reconciliation never sets these.
type workerFenceRequest struct {
	ExpectedWorkspace *toolbroker.WorkspaceVolumeIdentity `json:"expectedWorkspace,omitempty"`
	Repository        string                              `json:"repository,omitempty"`
	DiscardWorkspace  bool                                `json:"discardWorkspace,omitempty"`
	Version           int                                 `json:"version"`
	JobID             string                              `json:"jobId"`
	Provider          string                              `json:"provider"`
	Key               string                              `json:"key"`
}

func (v workerFenceRequest) record() (workerJobRecord, error) {
	if v.DiscardWorkspace {
		if v.Version != workerWorkspaceLifecycleVersion || v.ExpectedWorkspace == nil || !toolbroker.ValidWorkspaceVolume(v.JobID, *v.ExpectedWorkspace, true) {
			return workerJobRecord{}, errors.New("exact workspace disposal binding required")
		}
	} else if v.ExpectedWorkspace != nil {
		return workerJobRecord{}, errors.New("unexpected workspace disposal binding")
	}

	if (v.DiscardWorkspace && v.Version != workerWorkspaceLifecycleVersion) || (v.Version != 2 && !pairedLifecycleVersion(v.Version)) || !validWorkerJobID(v.JobID) || (v.Provider != "codex" && v.Provider != "claude") || (v.Version == 2 && v.Repository != "") || (pairedLifecycleVersion(v.Version) && !repositoryDigestPattern.MatchString(v.Repository)) {
		return workerJobRecord{}, errors.New("invalid cancellation binding")
	}
	record, err := newWorkerJobRecord(workerRunRequest{JobID: v.JobID, Provider: v.Provider, Key: v.Key})
	if err == nil && pairedLifecycleVersion(v.Version) {
		record.Version = v.Version
		record.Execution = pairExecution(v.Version)
		record.Pair = &workerPairRecord{Version: workerPairVersion, Repository: v.Repository}
	}
	return record, err
}

// fenceWorkerJob tombstones before launch and proves the supervisor lease is
// released before acknowledging shutdown. No automatic task replay is permitted.
func fenceWorkerJob(ctx context.Context, dir string, request workerFenceRequest, stopContainer func(context.Context, string) error) (workerJobRecord, error) {
	return fenceWorkerJobContainers(ctx, dir, request, func(ctx context.Context, v workerJobRecord) (workerJobRecord, error) {
		if v.Pair != nil {
			return stopWorkerPair(ctx, v, dockerCLIRunner{})
		}
		return v, stopContainer(ctx, v.JobID)
	})
}

func fenceWorkerJobContainers(ctx context.Context, dir string, request workerFenceRequest, stopContainers func(context.Context, workerJobRecord) (workerJobRecord, error)) (workerJobRecord, error) {
	if ctx == nil || ctx.Err() != nil || stopContainers == nil {
		return workerJobRecord{}, errors.New("worker cancellation context unavailable")
	}
	// Snapshot pointer input before asynchronous lease waiting. The caller must
	// not mutate inputs during this invocation.
	if request.ExpectedWorkspace != nil {
		copy := *request.ExpectedWorkspace
		request.ExpectedWorkspace = &copy
	}
	expected, err := request.record()
	if err != nil {
		return expected, err
	}
	existing, err := readWorkerRecord(dir, request.JobID)
	if err == nil && (!sameWorkerFenceBinding(existing, expected) || !matchesWorkspaceDisposal(request, existing)) {
		return expected, errors.New("worker cancellation binding mismatch")
	}
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, request.JobID+".json")); !os.IsNotExist(statErr) {
			return expected, errors.New("worker record is unverified")
		}
	}
	if err != nil && request.DiscardWorkspace {
		return expected, errors.New("workspace disposal journal unavailable")
	}
	latch := filepath.Join(dir, request.JobID+".cancel")
	file, err := os.OpenFile(latch, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, err = file.WriteString("cancel")
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	} else if os.IsExist(err) {
		info, e := os.Lstat(latch)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return expected, errors.New("invalid cancellation latch")
		}
		err = nil
	}
	if err != nil || syncWorkerDirectory(dir) != nil {
		return expected, errors.New("cancellation could not be persisted")
	}
	for {
		lease, free, err := workerTryLease(dir, ".job-"+request.JobID+".lease")
		if err != nil {
			return expected, err
		}
		if free {
			defer lease.Close()
			record, readErr := readWorkerRecord(dir, request.JobID)
			missing := false
			if readErr != nil {
				if _, e := os.Lstat(filepath.Join(dir, request.JobID+".json")); !os.IsNotExist(e) {
					return expected, errors.New("worker record is unverified")
				}
				record = expected
				missing = true
			}
			if !sameWorkerFenceBinding(record, expected) || !matchesWorkspaceDisposal(request, record) {
				return expected, errors.New("worker cancellation binding mismatch")
			}
			if missing {
				if err = writeWorkerRecord(dir, record, true); err != nil {
					return expected, err
				}
			}
			cleanupCtx := context.WithValue(ctx, workerCleanupOwnershipKey{}, true)
			cleanupCtx = context.WithValue(cleanupCtx, workerWorkspaceDiscardKey{}, request.ExpectedWorkspace)
			stopped, stopErr := stopContainers(cleanupCtx, record)
			if !sameWorkerFenceBinding(stopped, expected) || !sameWorkspaceEvidence(record, stopped) || !matchesWorkspaceDisposal(request, stopped) {
				return record, errors.New("shutdown changed worker binding")
			}
			record = stopped
			err = stopErr
			if err == nil {
				candidate := record
				candidate.Status = "cancelled"
				candidate.ShutdownConfirmed = true
				if !validWorkerRecord(candidate) || ctx.Err() != nil {
					err = errors.New("shutdown proof incomplete")
				}
			}
			if err != nil {
				record.Status = "shutdown_unconfirmed"
				record.DiagnosticCode = "container_shutdown_unverified"
				record.UpdatedAt = time.Now().UTC()
				record.ShutdownConfirmed = false
				_ = writeWorkerRecord(dir, record, false)
				return record, err
			}
			if !workerTerminal(record.Status) {
				record.Status = "cancelled"
				record.DiagnosticCode = "abandoned_supervisor_reconciled"
			}
			if missing {
				record.DiagnosticCode = "cancelled_before_launch"
			}
			record.ShutdownConfirmed = true
			record.UpdatedAt = time.Now().UTC()
			if err = writeWorkerRecord(dir, record, false); err != nil {
				return record, err
			}
			return record, nil
		}
		// Removal can interrupt a still-held supervisor, but a missing container alone
		// never counts as stopped: keep waiting for the lease to be released.
		active, readErr := readWorkerRecord(dir, request.JobID)
		if readErr != nil || !sameWorkerFenceBinding(active, expected) || !matchesWorkspaceDisposal(request, active) {
			return expected, errors.New("active worker binding unverified")
		}
		if _, err = stopContainers(ctx, active); err != nil {
			return expected, err
		}
		select {
		case <-ctx.Done():
			return expected, errors.New("supervisor shutdown unverified")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type workerJobView struct {
	workerJobRecord
	LeaseState string `json:"leaseState"`
}

type workerJobsSnapshot struct {
	Version           int             `json:"version"`
	Jobs              []workerJobView `json:"jobs"`
	ManagedContainers int             `json:"managedContainers"`
	Unresolved        int             `json:"unresolved"`
	Truncated         bool            `json:"truncated"`
}

func workerSnapshot(dir string, containers []string) (workerJobsSnapshot, error) {
	result := workerJobsSnapshot{Version: 2, Jobs: []workerJobView{}, ManagedContainers: len(containers)}
	records, err := boundedWorkerRecords(dir)
	if err != nil {
		return result, err
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := !workerJobSettled(records[i]), !workerJobSettled(records[j])
		if a != b {
			return a
		}
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})
	for _, record := range records {
		view := workerJobView{workerJobRecord: record, LeaseState: "legacy"}
		if record.Version == 2 || pairedLifecycleVersion(record.Version) {
			lease, free, err := workerTryLease(dir, ".job-"+record.JobID+".lease")
			if err != nil {
				return result, err
			}
			if free {
				view.LeaseState = "free"
				lease.Close()
			} else {
				view.LeaseState = "held"
			}
		}
		if !workerJobSettled(record) || view.LeaseState == "held" {
			result.Unresolved++
		}
		if len(result.Jobs) < 128 {
			result.Jobs = append(result.Jobs, view)
		} else {
			result.Truncated = true
		}
	}
	return result, nil
}

func decodeFenceRequest(encoded string) (workerFenceRequest, error) {
	var request workerFenceRequest
	if len(encoded) > 4096 {
		return request, errors.New("oversized cancellation request")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || !validFenceWire(raw, false) {
		return request, errors.New("invalid cancellation request")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return request, errors.New("invalid cancellation request")
	}
	_, err = request.record()
	return request, err
}

func workerRuntimeReady(ctx context.Context) error {
	if runtime.GOOS != "linux" || os.Getenv("DOCKER_HOST") != "" || os.Getenv("DOCKER_CONTEXT") != "" {
		return errors.New("worker runtime selection is unsupported")
	}
	var info limitedAgentOutput
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .}}")
	cmd.Stdout = &info
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || !dockerSecurityReady(info.Bytes()) {
		return errors.New("rootless worker runtime unverified")
	}
	var host limitedAgentOutput
	cmd = exec.CommandContext(ctx, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	cmd.Stdout = &host
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || !strings.HasPrefix(strings.TrimSpace(host.String()), "unix://") {
		return errors.New("worker Docker context unverified")
	}
	return nil
}

func validV2WorkerRecord(v workerJobRecord) bool {
	if v.IdleShutdownRequestedAt.IsZero() {
		if v.IdleTimeoutMinutes != 0 || v.DiagnosticCode == "idle_shutdown_requested" {
			return false
		}
	} else if v.IdleTimeoutMinutes < 1 || v.IdleTimeoutMinutes > 60 || v.IdleShutdownRequestedAt.Before(v.StartedAt) {
		return false
	}
	if !validWorkerPair(v) {
		return false
	}
	if v.Version != 2 || !validWorkerJobID(v.JobID) || (v.Provider != "codex" && v.Provider != "claude") || v.StartedAt.IsZero() || v.UpdatedAt.IsZero() || !v.Deadline.After(v.StartedAt) {
		return false
	}
	_, _, _, scope, err := workerMembership(v.RoomID + "/" + v.ParticipantID + "/" + v.ConnectionID + "/worker")
	if err != nil || scope != v.Scope {
		return false
	}
	switch v.Status {
	case "starting", "running", "shutdown_unconfirmed":
		if v.ShutdownConfirmed {
			return false
		}
	case "finished", "failed", "cancelled":
	default:
		return false
	}
	switch v.DiagnosticCode {
	case "idle_shutdown_requested", "preparing", "preparation_failed", "running", "completed", "cancelled_or_deadline", "provider_failed", "container_shutdown_unverified", "abandoned_supervisor_reconciled", "cancelled_before_launch":
		return true
	}
	return false
}

// Pair cancellation is a separate versioned contract. Legacy requests may not
// reinterpret a pair as one container, including across mixed worker binaries.
func sameWorkerFenceBinding(record, expected workerJobRecord) bool {
	if record.Version != expected.Version || record.JobID != expected.JobID || record.Scope != expected.Scope || record.ConnectionID != expected.ConnectionID || record.Provider != expected.Provider || record.Execution != expected.Execution {
		return false
	}
	if expected.Pair == nil {
		return record.Pair == nil
	}
	return record.Pair != nil && record.Pair.Version == expected.Pair.Version && record.Pair.Repository == expected.Pair.Repository
}

// Validate both before the cancellation tombstone and again under the creator
// lease. A stale identity may not cancel/delete a different retained workspace.
func matchesWorkspaceDisposal(request workerFenceRequest, record workerJobRecord) bool {
	if !request.DiscardWorkspace {
		return true
	}
	return request.ExpectedWorkspace != nil && record.Pair != nil && record.Pair.Workspace != nil && *request.ExpectedWorkspace == record.Pair.Workspace.Identity
}
