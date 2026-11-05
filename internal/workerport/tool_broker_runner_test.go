package workerport

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// dockerCLIRunner shells out to the real "docker" CLI, so these tests cover
// only its precondition checks (which must fail before any subprocess runs),
// not live Docker behavior. Per this repo's established convention for every
// other Docker-touching path (isolation.go), live verification stays a
// documented manual step, not a mocked exec.Command in the automated suite.
func TestDockerCLIRunnerRejectsMissingPreconditions(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	cases := []struct {
		name string
		ctx  context.Context
		args []string
		out  *bytes.Buffer
	}{
		{"nil context", nil, []string{"info"}, &out},
		{"cancelled context", canceledContext(t), []string{"info"}, &out},
		{"no arguments", t.Context(), nil, &out},
		{"nil output sink", t.Context(), []string{"info"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var writer io.Writer
			if tc.out != nil {
				writer = tc.out
			}
			if err := (dockerCLIRunner{}).Run(tc.ctx, tc.args, nil, writer); err == nil {
				t.Fatal("expected a precondition rejection")
			}
			if err := (dockerCLIRunner{}).RunInput(tc.ctx, tc.args, nil, writer); err == nil {
				t.Fatal("expected streaming precondition rejection")
			}

		})
	}
}

func canceledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}
