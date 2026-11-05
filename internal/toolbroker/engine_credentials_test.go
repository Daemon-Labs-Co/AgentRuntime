package toolbroker

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

type exportEngineFake struct {
	*engineDockerFake
	exports int
	mode    string
}

func (f *exportEngineFake) Run(ctx context.Context, args []string, input []byte, out io.Writer) error {
	if args[0] != "exec" {
		return f.engineDockerFake.Run(ctx, args, input, out)
	}
	f.exports++
	expected := []string{"exec", "--user", "1000:1000", "--workdir", "/tmp", f.runtime.id, "/usr/local/bin/node", "-e", engineCredentialExportScript}
	if !slices.Equal(args, expected) || len(input) != 0 {
		return errors.New("unsafe private exporter")
	}
	switch f.mode {
	case "error":
		return errors.New("synthetic sensitive error")
	case "oversize":
		_, err := io.WriteString(out, strings.Repeat("x", 65537))
		return err
	case "empty":
		return nil
	case "drift":
		f.mutation = func(v map[string]any) { v["Image"] = "sha256:" + strings.Repeat("0", 64) }
	}
	_, err := io.WriteString(out, `{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic-only"}}`)
	return err
}
func TestEnginePrivateCredentialExportOneShotAndPolicyBound(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "error", "oversize", "empty", "drift", "cancelled", "unattached"} {
		t.Run(mode, func(t *testing.T) {
			r, streamFake, _ := streamFixture(t)
			if mode != "unattached" {
				stream, err := r.Attach(t.Context(), r.id)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
			}
			fake := &exportEngineFake{engineDockerFake: streamFake.engineDockerFake, mode: mode}
			r.runner = fake
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			raw, err := r.ExportCredential(ctx, r.id)
			if mode == "success" {
				if err != nil || !strings.Contains(string(raw), "synthetic-only") {
					t.Fatal("export refused", err)
				}
			} else if err == nil || len(raw) != 0 {
				t.Fatal("unsafe private export accepted", mode)
			}
			if _, again := r.ExportCredential(ctx, r.id); again == nil {
				t.Fatal("export replayed")
			}
			if fake.exports > 1 {
				t.Fatal("multiple credential export attempts")
			}
		})
	}
}
