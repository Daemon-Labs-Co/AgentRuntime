package workerport

import (
	"os"
	"path/filepath"
)

// syncParentDirectory persists a create/rename/unlink entry on supported Unix
// filesystems. Successful file Sync alone does not make that entry durable.
// Parent directories are trusted; filesystem/hardware guarantees still apply.
func syncParentDirectory(path string) error {
	f, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// replacePrivateDurably publishes complete data then syncs its directory. An
// error after rename is ambiguous: the new file may be visible, but durability
// has not been acknowledged. Callers must fail the security operation.
func replacePrivateDurably(path string, data []byte, syncDirectory func(string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".private-state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(path)
}
