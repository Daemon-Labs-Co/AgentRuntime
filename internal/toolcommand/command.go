// Package toolcommand defines fixed build/check policy for the credential-free
// container. It is not a host execution API. Only the audited, verified isolated
// tool launcher may supply Runner. A source fork CAN inject a host runner, BUT
// then violates mandatory isolation. There is no default runner or shell fallback.
package toolcommand

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

const MaxOutputBytes = 8 * 1024
const Timeout = 120 * time.Second

var ErrRefused = errors.New("isolated command refused")
var ErrExecution = errors.New("isolated command failed or exceeded its bound")

// ErrOutputLimit distinguishes capture overflow without weakening the existing
// execution-failure contract. No partial receipt is safe to release.
var ErrOutputLimit = fmt.Errorf("%w: output limit exceeded", ErrExecution)

// Valid permits only reviewed profiles; argv never selects a shell, executable
// path, environment, working directory, timeout or image.
func Valid(argv []string) bool {
	return slices.Equal(argv, []string{"go", "test", "./..."}) || slices.Equal(argv, []string{"go", "build", "./..."})
}

type Spec struct {
	Program   string
	Args, Env []string
	Dir       string
}
type Runner interface {
	Run(context.Context, Spec, io.Writer) (int, error)
}
type Receipt struct {
	Operation     string `json:"operation"`
	Bytes         int    `json:"bytes"`
	SHA256        string `json:"sha256"`
	Encoding      string `json:"encoding"`
	Data          string `json:"data"`
	ExitCode      int    `json:"clientExitCode"`
	Completion    string `json:"completion"`
	CommandDigest string `json:"commandDigest"`
}

func Digest(argv []string) string {
	raw, _ := json.Marshal(argv)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Run captures a combined bounded stdout/stderr receipt. ExitCode is the observed
// Docker CLI status. Nonzero remains unconfirmed: a daemon failure can look like
// a compiler failure, so it must not be certified as a completed test result.
// Success here is NOT descendant absence; the outer worker MUST remove/verify
// the tool container before releasing the receipt or executing more model work.
func Run(ctx context.Context, argv []string, runner Runner) (Receipt, error) {
	if ctx == nil || ctx.Err() != nil || runner == nil || !Valid(argv) {
		return Receipt{}, ErrRefused
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	spec := Spec{Program: "/usr/local/go/bin/go", Args: append([]string(nil), argv[1:]...), Dir: "/workspace/repository", Env: []string{
		"PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/tmp/tool-home",
		"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOWORK=off", "GOFLAGS=", "CGO_ENABLED=0",
		"GOCACHE=/workspace/.commonroom-command/cache", "GOTMPDIR=/workspace/.commonroom-command/tmp",
		"GOMODCACHE=/workspace/.commonroom-command/modules", "TMPDIR=/tmp",
	}}
	out := &boundedWriter{cancel: cancel}
	code, err := runner.Run(ctx, spec, out)
	out.mu.Lock()
	defer out.mu.Unlock()
	out.closed = true
	if out.overflow {
		return Receipt{}, ErrOutputLimit
	}
	if err != nil || ctx.Err() != nil || code < 0 || code > 255 {
		return Receipt{}, ErrExecution
	}
	sum := sha256.Sum256(out.data)
	completion := "unconfirmed"
	if code == 0 {
		completion = "succeeded"
	}
	return Receipt{"command", len(out.data), hex.EncodeToString(sum[:]), "base64", base64.StdEncoding.EncodeToString(out.data), code, completion, Digest(argv)}, nil
}

type boundedWriter struct {
	mu               sync.Mutex
	data             []byte
	overflow, closed bool
	cancel           context.CancelFunc
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.overflow || len(p) > MaxOutputBytes-len(w.data) {
		w.overflow = true
		w.cancel()
		return 0, ErrOutputLimit
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
