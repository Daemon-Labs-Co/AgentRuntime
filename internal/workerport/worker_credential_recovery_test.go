package workerport

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialRecoveryNeedsDurableCredentialBeforeMarkerClear(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "credential sync failure", "marker sync failure", "invalid export"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(t.TempDir(), "synthetic-export.json")
			if err := markWorkerCredentialUncertain(root); err != nil {
				t.Fatal(err)
			}
			raw := syntheticEngineCredential
			if mode == "invalid export" {
				raw = "not JSON"
			}
			if err := os.WriteFile(source, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			credentialSynced := false
			cleared := false
			sync := func(path string) error {
				if filepath.Base(path) == "auth.json" {
					if workerCredentialReady(root) {
						t.Fatal("recovery opened before credential sync")
					}
					if mode == "credential sync failure" {
						return errors.New("synthetic backend detail")
					}
					credentialSynced = true
				} else {
					if !credentialSynced {
						t.Fatal("marker clear preceded credential durability")
					}
					cleared = true
					if mode == "marker sync failure" {
						return errors.New("synthetic backend detail")
					}
				}
				return syncParentDirectory(path)
			}
			err := persistWorkerCredentialDurably(root, "codex", source, sync)
			if mode == "success" {
				if err != nil || !credentialPresent(filepath.Join(root, "auth.json")) || !cleared {
					t.Fatal("durable recovery refused", err)
				}
			} else {
				if err == nil || strings.Contains(err.Error(), "synthetic backend detail") {
					t.Fatal("failed custody acknowledged or diagnostic leaked", err)
				}
				if mode != "marker sync failure" && workerCredentialReady(root) {
					t.Fatal("failed credential persistence cleared marker")
				}
			}
		})
	}
}

func TestCredentialRecoverySyncFailureRemainsBlocked(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	synced := false
	err := markWorkerCredentialUncertainDurably(root, func(path string) error {
		synced = true
		if workerCredentialReady(root) {
			t.Fatal("marker not published before sync")
		}
		return errors.New("synthetic sensitive backend error")
	})
	if err == nil || !synced || workerCredentialReady(root) || strings.Contains(err.Error(), "synthetic sensitive") {
		t.Fatal("uncertain marker accepted or error leaked", err)
	}
}
