package workerport

import (
	"slices"
	"testing"
)

func TestChatCommandToolsCannotBeEnabledByWorkerRequest(t *testing.T) {
	t.Parallel()
	v := sampleWorkerRequest()
	index := slices.Index(v.Args, "features.shell_tool=false")
	if index < 1 || v.Args[index-1] != "-c" {
		t.Fatal("chat shell tool disabling missing")
	}
	if err := validateWorkerRun(v); err != nil {
		t.Fatal("tool-free chat policy refused", err)
	}
	for _, enabled := range []string{"features.shell_tool=true", "features.shell_tool=1"} {
		altered := v
		altered.Args = slices.Clone(v.Args)
		altered.Args[index] = enabled
		if err := validateWorkerRun(altered); err == nil {
			t.Fatal("worker accepted command tool override")
		}
	}
	removed := v
	removed.Args = append(slices.Clone(v.Args[:index-1]), v.Args[index+1:]...)
	if err := validateWorkerRun(removed); err == nil {
		t.Fatal("worker accepted old command-enabled chat policy")
	}
	override := v
	override.Args = append(slices.Clone(v.Args), "-c", "features.shell_tool=true")
	if err := validateWorkerRun(override); err == nil {
		t.Fatal("worker accepted trailing tool override")
	}
}

func TestChatPolicyAppliesToFreshAndResumedTurns(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"codex", "claude"} {
		for _, resumed := range []bool{false, true} {
			v := sampleWorkerRequest()
			v.Provider = provider
			v.Args = providerTurnArgs(provider, false, false)
			if resumed {
				flag := "resume"
				if provider == "claude" {
					flag = "--resume"
				}
				v.Args = append(v.Args, flag, "synthetic-thread")
			}
			if provider == "codex" {
				v.Args = append(v.Args, "-")
			}
			if err := validateWorkerRun(v); err != nil {
				t.Fatal(provider, resumed, err)
			}
		}
	}
	if slices.Contains(providerTurnArgs("codex", true, false), "features.shell_tool=false") {
		t.Fatal("development policy accidentally changed; its credential boundary remains separately open")
	}
	if !slices.Contains(providerTurnArgs("codex", true, true), "features.shell_tool=false") {
		t.Fatal("tool-separated development policy must keep the native shell tool disabled")
	}
}

func TestWorkerAcceptsOnlyOneSafeModelOption(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"codex", "claude"} {
		flag, suffix := "--model", []string{}
		if provider == "codex" {
			flag, suffix = "-m", []string{"-"}
		}
		v := sampleWorkerRequest()
		v.Provider = provider
		base := providerTurnArgs(provider, v.Repository != "", v.ToolSeparation)
		build := func(extra ...string) workerRunRequest {
			c := v
			c.Args = append(append(slices.Clone(base), extra...), suffix...)
			return c
		}
		if err := validateWorkerRun(build()); err != nil {
			t.Fatal(provider, "default turn refused", err)
		}
		if err := validateWorkerRun(build(flag, "model-1")); err != nil {
			t.Fatal(provider, "model refused", err)
		}
		threadFlag := "--resume"
		if provider == "codex" {
			threadFlag = "resume"
		}
		if err := validateWorkerRun(build(flag, "model-1", threadFlag, "thread-1")); err != nil {
			t.Fatal(provider, "model with resume refused", err)
		}
		for _, bad := range [][]string{{flag, "--dangerously-skip-permissions"}, {flag, "a b"}, {flag, "-x"}, {flag}, {flag, "m", flag, "m"}, {threadFlag, "t", flag, "m"}, {"--config", "x"}} {
			if err := validateWorkerRun(build(bad...)); err == nil {
				t.Fatal(provider, "accepted forbidden options", bad)
			}
		}
	}
}
