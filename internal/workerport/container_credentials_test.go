package workerport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialStagingRefusesExistingAndAliasedTargets(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"existing", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path, target := filepath.Join(dir, "auth.json"), filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("synthetic preserved target"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "existing":
				err = os.WriteFile(path, []byte("synthetic existing file"), 0600)
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = stageContainerCredential(path, []byte(`{"synthetic":"credential"}`)); err == nil {
				t.Fatal("existing destination overwritten")
			}
			raw, err := os.ReadFile(target)
			if err != nil || string(raw) != "synthetic preserved target" {
				t.Fatal("target changed", err)
			}
			if kind == "existing" {
				raw, err = os.ReadFile(path)
				if err != nil || string(raw) != "synthetic existing file" {
					t.Fatal("existing file changed", err)
				}
			}
		})
	}
}

func TestCredentialStagingPrivacySizeAndPermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	for _, raw := range [][]byte{nil, []byte("invalid synthetic input"), []byte(`{"synthetic":"` + strings.Repeat("a", 65536) + `"}`)} {
		if err := stageContainerCredential(path, raw); err == nil {
			t.Fatal("invalid input accepted")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("invalid input created a file")
		}
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := stageContainerCredential(path, []byte(`{}`)); err == nil {
		t.Fatal("public staging directory accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := stageContainerCredential(path, []byte(`{"synthetic":"credential"}`)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0444 {
		t.Fatal("mapped container readability not normalized", err)
	}
	link := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := stageContainerCredential(filepath.Join(link, "other.json"), []byte(`{}`)); err == nil {
		t.Fatal("aliased staging directory accepted")
	}
}
