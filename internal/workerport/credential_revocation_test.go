package workerport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialRevocationRequiresSyncEvenOnRetry(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := filepath.Join(root, providerCredentialName(provider))
			if err := os.WriteFile(path, []byte(`{"synthetic":"credential"}`), 0600); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("synthetic directory failure")
			calls := 0
			sync := func(got string) error {
				calls++
				if got != path {
					t.Fatal("wrong credential entry synced")
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("sync occurred before unlink")
				}
				return failure
			}
			if err := clearWorkerCredentialDurably(root, provider, sync); !errors.Is(err, failure) {
				t.Fatal("unlink sync failure acknowledged", err)
			}
			if err := clearWorkerCredentialDurably(root, provider, sync); !errors.Is(err, failure) {
				t.Fatal("missing-file retry skipped durability", err)
			}
			if calls != 2 {
				t.Fatal("retry did not repeat sync", calls)
			}
			if err := clearWorkerCredential(root, provider); err != nil {
				t.Fatal("repair/retry failed", err)
			}
		})
	}
}

func TestUnknownCredentialProviderCannotDeleteCodexCredential(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "auth.json")
	if err := os.WriteFile(path, []byte(`{"synthetic":"preserved"}`), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := clearWorkerCredentialDurably(root, "unknown", func(string) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("unknown provider reached revocation")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"synthetic":"preserved"}` {
		t.Fatal("unknown provider erased default credential", err)
	}
}
