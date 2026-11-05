package workerport

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// stageContainerCredential creates only a new per-turn file in a trusted private
// directory. Explicit chmod permits the mapped container UID to read it despite
// the host umask; the private parent and read-only bind remain required. This is
// NOT credential isolation from model tools sharing the same container/UID.
func stageContainerCredential(path string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 65536 || !json.Valid(raw) {
		return errors.New("Provider credential must be bounded valid JSON")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("Credential staging directory must be private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("Credential staging directory must belong to this account")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("Private credential staging unavailable")
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(raw); err != nil {
		return errors.New("Private credential staging unavailable")
	}
	if err = f.Chmod(0444); err != nil {
		return errors.New("Private credential staging unavailable")
	}
	if err = f.Close(); err != nil {
		return errors.New("Private credential staging unavailable")
	}
	complete = true
	return nil
}
