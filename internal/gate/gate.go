// Package gate is the forced-command gatekeeper for SSH access to the worker
// account. The controller reaches the worker by running
//
//	exec ~/.local/bin/commonroom-worker ACTION ['VALUE']
//
// over SSH. With the authorized key restricted to this gate, sshd passes that
// text in SSH_ORIGINAL_COMMAND. The gate accepts only that exact shape, a known
// action and a value drawn from the base64url/hex alphabet, then executes the
// installed worker directly. No shell ever sees the text, so quoting tricks,
// command chaining and interactive sessions cannot reach the account.
package gate

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"commonroom-runtime/protocol"
)

const commandPrefix = "exec ~/.local/bin/commonroom-worker "

// ExecFunc replaces the current process (syscall.Exec); tests substitute a fake.
type ExecFunc func(path string, argv []string, env []string) error

var errForbidden = errors.New("Forbidden worker command")

// Parse validates the original SSH command and returns the action and value.
func Parse(original string) (action, value string, err error) {
	if original == "" {
		return "", "", errors.New("Interactive sessions are not permitted")
	}
	if !strings.HasPrefix(original, commandPrefix) {
		return "", "", errForbidden
	}
	rest := original[len(commandPrefix):]
	action, quoted, hasValue := strings.Cut(rest, " ")
	if !knownAction(action) {
		return "", "", errForbidden
	}
	if !hasValue {
		return action, "", nil
	}
	if len(quoted) < 3 || quoted[0] != '\'' || quoted[len(quoted)-1] != '\'' {
		return "", "", errForbidden
	}
	value = quoted[1 : len(quoted)-1]
	if len(value) > protocol.MaxRunRequestChars || !safeValue(value) {
		return "", "", errForbidden
	}
	return action, value, nil
}

func knownAction(action string) bool {
	for _, a := range protocol.Actions {
		if a == action {
			return true
		}
	}
	return false
}

// safeValue admits only base64url and hex characters, which covers every value
// the controller sends (encoded requests and job identifiers). It rejects
// quotes, whitespace, shell metacharacters, control characters and non-ASCII.
func safeValue(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Environment returns the only variables the worker receives. Everything else,
// including SSH and Docker variables, is dropped; PATH is fixed.
func Environment(parent []string) []string {
	out := []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	for _, kv := range parent {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case "HOME", "USER", "LOGNAME", "LANG":
			out = append(out, kv)
		}
	}
	return out
}

// Run is the program body: args are the gate's own arguments (--worker PATH),
// env is the process environment. On success it does not return (exec).
func Run(args []string, env []string, execve ExecFunc, stderr io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(stderr, err); return 126 }
	if len(args) != 2 || args[0] != "--worker" {
		return fail(errors.New("usage: commonroom-ssh-gate --worker ABSOLUTE_PATH"))
	}
	worker := args[1]
	if !filepath.IsAbs(worker) || filepath.Clean(worker) != worker || strings.ContainsAny(worker, " \t\r\n'\"") {
		return fail(errors.New("worker path must be absolute and canonical"))
	}
	var original string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "SSH_ORIGINAL_COMMAND="); ok {
			original = v
		}
	}
	action, value, err := Parse(original)
	if err != nil {
		return fail(err)
	}
	argv := []string{"commonroom-worker", action}
	if value != "" {
		argv = append(argv, value)
	}
	if err := execve(worker, argv, Environment(env)); err != nil {
		return fail(errors.New("Worker could not be started"))
	}
	return 0
}
