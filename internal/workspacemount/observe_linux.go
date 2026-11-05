//go:build linux

package workspacemount

import (
	"context"
	"io"
	"os"
	"syscall"
)

// Observe reads only fixed kernel metadata and directory identity, never source
// bytes. Read-only statfs flags are checked independently from mountinfo. The
// approved container must run as UID/GID1000 with a read-only rootfs and no other
// workspace writers. No host path, fallback or mount command is accepted.
func Observe(ctx context.Context, challenge string) (Proof, error) {
	return observeFixed(ctx, challenge, "/workspace")
}

// ObserveObjects verifies only the fixed isolated read-only custody mount. The
// caller must independently bind its reviewed reader/volume; this proof does not
// authorize workspace access, exports, writer fencing or physical quota.
func ObserveObjects(ctx context.Context, challenge string) (Proof, error) {
	return observeFixed(ctx, challenge, "/objects")
}

func observeFixed(ctx context.Context, challenge, fixed string) (Proof, error) {
	if ctx == nil || ctx.Err() != nil || !ValidChallenge(challenge) || os.Geteuid() != 1000 || os.Getegid() != 1000 {
		return Proof{}, ErrRefused
	}
	info, err := os.Lstat(fixed)
	if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
		return Proof{}, ErrRefused
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 1000 {
		return Proof{}, ErrRefused
	}
	var workspace, root syscall.Statfs_t
	if syscall.Statfs(fixed, &workspace) != nil || syscall.Statfs("/", &root) != nil || workspace.Flags&1 == 0 || root.Flags&1 == 0 {
		return Proof{}, ErrRefused
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return Proof{}, ErrRefused
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxMountInfoBytes+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || ctx.Err() != nil {
		return Proof{}, ErrRefused
	}
	id, err := mountIDAt(raw, fixed)
	if err != nil {
		return Proof{}, err
	}
	return Proof{Version: 1, Challenge: challenge, MountID: id, ReadOnly: true, RootReadOnly: true}, nil
}
