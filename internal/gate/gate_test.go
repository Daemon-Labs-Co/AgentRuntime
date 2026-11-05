package gate

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"commonroom-runtime/protocol"
)

func command(action, value string) string {
	c := "exec ~/.local/bin/commonroom-worker " + action
	if value != "" {
		c += " '" + value + "'"
	}
	return c
}

func TestParseAcceptsEveryActionWithAndWithoutValue(t *testing.T) {
	t.Parallel()
	for _, action := range protocol.Actions {
		for _, value := range []string{"", "0123456789abcdef0123456789abcdef", "eyJ2ZXJzaW9uIjoyfQ", "A-b_C9"} {
			got, v, err := Parse(command(action, value))
			if err != nil || got != action || v != value {
				t.Errorf("%s %q: got %q %q %v", action, value, got, v, err)
			}
		}
	}
}

func TestParseAcceptsTheLargestPermittedValue(t *testing.T) {
	t.Parallel()
	_, v, err := Parse(command(protocol.ActionRun, strings.Repeat("a", protocol.MaxRunRequestChars)))
	if err != nil || len(v) != protocol.MaxRunRequestChars {
		t.Fatalf("rejected maximum value: %v", err)
	}
}

func TestParseRefusesEverythingElse(t *testing.T) {
	t.Parallel()
	ok := "0123abcd"
	bad := map[string]string{
		"interactive":            "",
		"plain shell":            "bash",
		"wrong program":          "exec ~/.local/bin/other " + protocol.ActionReady,
		"absolute path":          "exec /opt/commonroom-space/bin/commonroom-worker ready-v1",
		"no exec":                "~/.local/bin/commonroom-worker ready-v1",
		"unknown action":         "exec ~/.local/bin/commonroom-worker ready-v9",
		"action prefix only":     "exec ~/.local/bin/commonroom-worker ready",
		"no action":              "exec ~/.local/bin/commonroom-worker ",
		"chained command":        command(protocol.ActionReady, "") + "; id",
		"chained with and":       command(protocol.ActionReady, "") + " && id",
		"pipe":                   command(protocol.ActionReady, "") + " | cat",
		"backgrounded":           command(protocol.ActionReady, "") + " &",
		"redirect":               command(protocol.ActionReady, "") + " > /tmp/x",
		"newline injection":      command(protocol.ActionReady, "") + "\nid",
		"carriage return":        command(protocol.ActionReady, "") + "\rid",
		"trailing space":         command(protocol.ActionReady, "") + " ",
		"double space":           "exec ~/.local/bin/commonroom-worker  ready-v1",
		"tab separator":          "exec ~/.local/bin/commonroom-worker\tready-v1",
		"unquoted value":         "exec ~/.local/bin/commonroom-worker status-v1 " + ok,
		"double quoted value":    `exec ~/.local/bin/commonroom-worker status-v1 "` + ok + `"`,
		"empty value":            "exec ~/.local/bin/commonroom-worker status-v1 ''",
		"unterminated quote":     "exec ~/.local/bin/commonroom-worker status-v1 '" + ok,
		"two values":             "exec ~/.local/bin/commonroom-worker status-v1 '" + ok + "' '" + ok + "'",
		"quote break out":        "exec ~/.local/bin/commonroom-worker status-v1 '" + ok + "'; id; '",
		"escaped quote":          "exec ~/.local/bin/commonroom-worker status-v1 '" + ok + `'\''id`,
		"command substitution":   "exec ~/.local/bin/commonroom-worker status-v1 '$(id)'",
		"backtick":               "exec ~/.local/bin/commonroom-worker status-v1 '`id`'",
		"variable":               "exec ~/.local/bin/commonroom-worker status-v1 '$HOME'",
		"glob":                   "exec ~/.local/bin/commonroom-worker status-v1 '*'",
		"space in value":         "exec ~/.local/bin/commonroom-worker status-v1 'a b'",
		"path in value":          "exec ~/.local/bin/commonroom-worker status-v1 '../x'",
		"padding character":      "exec ~/.local/bin/commonroom-worker status-v1 'abc='",
		"option-like value":      "exec ~/.local/bin/commonroom-worker status-v1 '-x' ; ",
		"non-ascii value":        "exec ~/.local/bin/commonroom-worker status-v1 'café'",
		"nul byte":               "exec ~/.local/bin/commonroom-worker status-v1 'a\x00b'",
		"oversized value":        command(protocol.ActionRun, strings.Repeat("a", protocol.MaxRunRequestChars+1)),
		"upper-case action":      "exec ~/.local/bin/commonroom-worker READY-V1",
		"action with value flag": "exec ~/.local/bin/commonroom-worker ready-v1 --help",
	}
	for name, original := range bad {
		if a, v, err := Parse(original); err == nil {
			t.Errorf("%s: accepted %q as %q %q", name, original, a, v)
		}
	}
}

func TestEnvironmentKeepsOnlyAllowlistedVariables(t *testing.T) {
	t.Parallel()
	got := Environment([]string{
		"HOME=/home/commonroom-worker", "USER=commonroom-worker", "LOGNAME=commonroom-worker", "LANG=C.UTF-8",
		"SSH_ORIGINAL_COMMAND=x", "SSH_AUTH_SOCK=/tmp/a", "DOCKER_HOST=unix:///x", "DOCKER_CONTEXT=x",
		"PATH=/evil", "LD_PRELOAD=/evil.so", "DATABASE_URL=postgres://x", "XDG_RUNTIME_DIR=/run/user/1",
	})
	want := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/commonroom-worker", "USER=commonroom-worker", "LOGNAME=commonroom-worker", "LANG=C.UTF-8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment %v", got)
	}
}

type recorder struct {
	path string
	argv []string
	env  []string
	err  error
	n    int
}

func (r *recorder) exec(path string, argv, env []string) error {
	r.path, r.argv, r.env, r.n = path, argv, env, r.n+1
	return r.err
}

func TestRunExecutesTheWorkerDirectlyWithParsedArguments(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	var stderr bytes.Buffer
	env := []string{"HOME=/h", "SSH_ORIGINAL_COMMAND=" + command(protocol.ActionStatus, "0123456789abcdef0123456789abcdef"), "DOCKER_HOST=unix:///x"}
	code := Run([]string{"--worker", "/opt/commonroom-space/bin/commonroom-worker"}, env, r.exec, &stderr)
	if code != 0 || r.n != 1 || r.path != "/opt/commonroom-space/bin/commonroom-worker" {
		t.Fatalf("code=%d n=%d path=%q stderr=%q", code, r.n, r.path, stderr.String())
	}
	if !reflect.DeepEqual(r.argv, []string{"commonroom-worker", "status-v1", "0123456789abcdef0123456789abcdef"}) {
		t.Fatalf("argv %v", r.argv)
	}
	for _, kv := range r.env {
		if strings.HasPrefix(kv, "DOCKER_HOST") || strings.HasPrefix(kv, "SSH_") {
			t.Fatalf("leaked %q", kv)
		}
	}
}

func TestRunOmitsValueWhenNoneWasSent(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	Run([]string{"--worker", "/w"}, []string{"SSH_ORIGINAL_COMMAND=" + command(protocol.ActionReady, "")}, r.exec, &bytes.Buffer{})
	if !reflect.DeepEqual(r.argv, []string{"commonroom-worker", "ready-v1"}) {
		t.Fatalf("argv %v", r.argv)
	}
}

func TestRunRefusesWithoutExecutingAnything(t *testing.T) {
	t.Parallel()
	cases := map[string][]string{
		"no original command": {"HOME=/h"},
		"shell command":       {"SSH_ORIGINAL_COMMAND=/bin/sh"},
		"chained":             {"SSH_ORIGINAL_COMMAND=" + command(protocol.ActionReady, "") + "; id"},
	}
	for name, env := range cases {
		r := &recorder{}
		var stderr bytes.Buffer
		if code := Run([]string{"--worker", "/w"}, env, r.exec, &stderr); code != 126 || r.n != 0 {
			t.Errorf("%s: code=%d executed=%d", name, code, r.n)
		}
		if strings.Contains(stderr.String(), "id") && strings.Contains(stderr.String(), ";") {
			t.Errorf("%s: refusal echoed the command: %q", name, stderr.String())
		}
	}
}

func TestRunRejectsBadGateArguments(t *testing.T) {
	t.Parallel()
	good := []string{"SSH_ORIGINAL_COMMAND=" + command(protocol.ActionReady, "")}
	for _, args := range [][]string{
		nil, {"--worker"}, {"--worker", "relative/path"}, {"--worker", "/a/../b"}, {"--worker", "/a b"},
		{"--worker", "/a'b"}, {"--other", "/w"}, {"--worker", "/w", "extra"}, {"/w"},
	} {
		r := &recorder{}
		if code := Run(args, good, r.exec, &bytes.Buffer{}); code != 126 || r.n != 0 {
			t.Errorf("%v: code=%d executed=%d", args, code, r.n)
		}
	}
}

func TestRunReportsAFailedStartWithoutDetail(t *testing.T) {
	t.Parallel()
	r := &recorder{err: errors.New("exec /secret/path: permission denied")}
	var stderr bytes.Buffer
	code := Run([]string{"--worker", "/w"}, []string{"SSH_ORIGINAL_COMMAND=" + command(protocol.ActionReady, "")}, r.exec, &stderr)
	if code != 126 || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}
