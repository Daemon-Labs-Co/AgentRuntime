// Package worker is the container runtime's protocol entry point.
//
// This build implements ready-v1 only. Every other action is refused with
// "Unsupported worker action"; actions move here one at a time from the
// controller without behavior changes. Containment is mandatory: there is no
// host-execution fallback and no option to disable the Docker checks. A source
// fork can remove these checks, which invalidates the containment contract.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"commonroom-runtime/protocol"
)

// Deps are the host facts the worker depends on. Tests supply fakes; main
// supplies the real values.
type Deps struct {
	Home   string // account home directory
	GOOS   string // operating system name
	Docker string // docker executable (name or path)
	Euid   int    // effective user ID that must own private files
}

// Run executes one worker invocation and returns the process exit code.
// Diagnostics are bounded, human-readable and never include credentials.
func Run(d Deps, args []string, in io.Reader, out, diag io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(diag, err); return 1 }
	if len(args) == 0 {
		return fail(errors.New("Worker action required"))
	}
	if args[0] == protocol.ActionReady && len(args) == 1 {
		return ready(d, out, fail)
	}
	return fail(errors.New("Unsupported worker action"))
}

type developmentRepository struct {
	Bundle string `json:"bundle"`
	SHA256 string `json:"sha256"`
}

type configuration struct {
	Image                   string                           `json:"image"`
	AuthDir                 string                           `json:"authDir"`
	DevelopmentEnabled      bool                             `json:"developmentEnabled,omitempty"`
	DevelopmentRepositories map[string]developmentRepository `json:"developmentRepositories,omitempty"`
}

var (
	roomPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// validateDevelopmentRegistry bounds the private registry and disallows paths
// whose spelling could change Docker mount-option interpretation. This build
// validates the registry exactly as the controller's worker does but never
// uses it: development workspaces are not launched by this build.
func validateDevelopmentRegistry(repositories map[string]developmentRepository) error {
	if len(repositories) > 64 {
		return errors.New("Too many development repositories")
	}
	for room, repository := range repositories {
		if !roomPattern.MatchString(room) || !digestPattern.MatchString(repository.SHA256) || !filepath.IsAbs(repository.Bundle) || strings.ContainsAny(repository.Bundle, ",\r\n") {
			return errors.New("Invalid approved development bundle configuration")
		}
	}
	return nil
}

// loadConfiguration reads the private ~/.config/commonroom-worker/config.json.
func loadConfiguration(d Deps) (configuration, error) {
	var c configuration
	path := filepath.Join(d.Home, ".config/commonroom-worker/config.json")
	raw, err := readPrivateBounded(path, protocol.MaxConfigFileBytes, d.Euid)
	if err != nil {
		return c, errors.New("Worker requires owner-only, bounded ~/.config/commonroom-worker/config.json")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF || !protocol.ValidImage(c.Image) || !filepath.IsAbs(c.AuthDir) {
		return c, errors.New("Worker requires a digest-pinned image and absolute authDir")
	}
	if err := validateDevelopmentRegistry(c.DevelopmentRepositories); err != nil {
		return c, err
	}
	return c, nil
}

func ready(d Deps, out io.Writer, fail func(error) int) int {
	c, err := loadConfiguration(d)
	if err != nil {
		return fail(err)
	}
	if d.GOOS != "linux" {
		return fail(errors.New("Isolated agent execution currently requires a Linux worker with rootless Docker"))
	}
	if _, err := exec.LookPath(d.Docker); err != nil {
		return fail(errors.New("Rootless Docker is required; direct agent execution is disabled"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), protocol.ReadyTimeoutSeconds*time.Second)
	defer cancel()
	info, err := exec.CommandContext(ctx, d.Docker, "info", "--format", "{{json .}}").Output()
	if err != nil || !dockerSecurityReady(info) {
		return fail(errors.New("Rootless Docker or required limits unavailable"))
	}
	if exec.CommandContext(ctx, d.Docker, "image", "inspect", c.Image).Run() != nil {
		return fail(errors.New("Configured agent image is unavailable"))
	}
	credentials := map[string]bool{}
	for provider, filename := range protocol.CredentialFiles {
		fi, err := os.Lstat(filepath.Join(c.AuthDir, provider, filename))
		credentials[provider] = err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0077 == 0 && fi.Size() <= protocol.MaxCredentialFileBytes
	}
	result := protocol.Ready{
		Version:          protocol.ReadyVersion,
		LifecycleVersion: protocol.LifecycleVersion,
		Configured:       true,
		RuntimeReady:     true,
		Credentials:      credentials,
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 1
	}
	return 0
}

// dockerSecurityReady fails closed when the daemon cannot enforce required limits.
func dockerSecurityReady(raw []byte) bool {
	var info struct {
		SecurityOptions                                []string
		MemoryLimit, SwapLimit, PidsLimit, CpuCfsQuota bool
	}
	if json.Unmarshal(raw, &info) != nil {
		return false
	}
	security := strings.Join(info.SecurityOptions, " ")
	return strings.Contains(security, "name=rootless") && strings.Contains(security, "name=seccomp") &&
		info.MemoryLimit && info.SwapLimit && info.PidsLimit && info.CpuCfsQuota
}
