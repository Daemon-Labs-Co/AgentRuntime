package workerport

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLegacyDevelopmentCannotReadCredentialsOrLaunch(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"codex", "claude"} {
		for _, separated := range []bool{false, true} {
			cmd, cleanup, err := localIsolatedDevelopmentCommand(context.Background(), provider, "synthetic", strings.Repeat("a", 32), strings.Repeat("b", 64), separated, providerTurnArgs(provider, true, separated)...)
			if !errors.Is(err, errCredentialBoundary) || cmd != nil || cleanup != nil {
				t.Fatal("development preparation reached credential/runtime setup before verified paired integration")
			}
		}
	}
}

func TestWorkerRefusesLegacyDevelopmentBeforeAdmission(t *testing.T) {
	t.Parallel()
	v := sampleWorkerRequest()
	v.Repository = strings.Repeat("b", 64)
	v.Args = append(providerTurnArgs("codex", true, false), "-")
	if !errors.Is(validateWorkerRun(v), errCredentialBoundary) {
		t.Fatal("legacy development worker request accepted")
	}
	v.Repository = ""
	v.Args = append(providerTurnArgs("codex", false, false), "-")
	if err := validateWorkerRun(v); err != nil {
		t.Fatal("chat request unexpectedly refused", err)
	}
}
