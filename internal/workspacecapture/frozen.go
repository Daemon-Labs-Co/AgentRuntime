// Package workspacecapture assembles a fixed isolated read-only source view with
// live supervisor authority. It never accepts a host source path or supplies a
// permissive authority. Managed callers MUST run in the reviewed credential-free
// capture container with all other writers fenced. A source fork can replace the
// authority/kernel observer, invalidating isolation and source identity claims.
package workspacecapture

import (
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"
)

var ErrRefused = errors.New("isolated workspace capture unavailable")

const MaxLifetime = 30 * time.Second

// Authority is the authenticated supervisor, not an agent or the kernel mount
// report alone. Every call MUST bind the exact job/creator/import/volume, reviewed
// running helper and current principal/task/export policy, hold creator ownership,
// verify complete writer exclusion and existing workspace storage accounting, and
// durably authorize bounded observation before success. Proof is local kernel
// evidence, not independent remote attestation or source release permission.
// Implementations must honor cancellation and must not reenter the same source.
// No production transport or permissive default authority is provided here.
type Authority interface {
	AuthorizeFrozenSource(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error
}

// containerView is private: production always uses the fixed /workspace view and
// actual kernel checks. Tests may explicitly mock it against synthetic fixtures;
// external callers cannot choose a different root or mount observer.
type containerView interface {
	OpenRoot() (*os.Root, error)
	RootIdentity() (os.FileInfo, error)
	Observe(context.Context, string) (workspacemount.Proof, error)
}
type fixedContainerView struct{}

func (fixedContainerView) OpenRoot() (*os.Root, error)        { return os.OpenRoot("/workspace") }
func (fixedContainerView) RootIdentity() (os.FileInfo, error) { return os.Lstat("/workspace") }
func (fixedContainerView) Observe(ctx context.Context, challenge string) (workspacemount.Proof, error) {
	return workspacemount.Observe(ctx, challenge)
}

type frozenLease struct {
	mu        sync.Mutex
	lifetime  context.Context
	root      *os.Root
	view      containerView
	binding   workspacesnapshot.Binding
	challenge string
	authority Authority
	proof     workspacemount.Proof
}

func missingAuthority(a Authority) bool { return a == nil || isNilDependency(a) }
func isNilDependency(value any) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Func, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// VerifyFrozen combines live supervisor fencing with actual fixed kernel mount
// evidence and pinned root identity on EVERY source verification/read. A stopped
// probe report cannot construct this lease or substitute for its running view.
func (l *frozenLease) VerifyFrozen(ctx context.Context, root *os.Root, b workspacesnapshot.Binding) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || l.lifetime.Err() != nil || root != l.root || b != l.binding {
		return ErrRefused
	}
	deadline, _ := l.lifetime.Deadline()
	child, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	before, err := l.root.Lstat(".")
	if err != nil {
		return ErrRefused
	}
	fixed, err := l.view.RootIdentity()
	if err != nil || !fixed.IsDir() || fixed.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, fixed) {
		return ErrRefused
	}
	proof, err := l.view.Observe(child, l.challenge)
	if err != nil || !workspacemount.ValidProof(proof, l.challenge) || l.proof.Version != 0 && proof != l.proof {
		return ErrRefused
	}
	if l.authority.AuthorizeFrozenSource(child, l.binding, proof) != nil || child.Err() != nil || l.lifetime.Err() != nil {
		return ErrRefused
	}
	// Recheck local identity and kernel mount after the supervisor's potentially
	// remote checks, so a changed local view is not silently adopted as the source.
	after, err := l.root.Lstat(".")
	if err != nil || !os.SameFile(before, after) {
		return ErrRefused
	}
	fixed, err = l.view.RootIdentity()
	if err != nil || fixed.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, fixed) {
		return ErrRefused
	}
	again, err := l.view.Observe(child, l.challenge)
	if err != nil || again != proof || child.Err() != nil || l.lifetime.Err() != nil {
		return ErrRefused
	}
	l.proof = proof
	return nil
}

// WithFrozenSource opens only the fixed isolated /workspace root, captures actual
// finite source bytes and lends the Source synchronously. No host path, mounting,
// provider invocation or fallback exists. Each lazy read still requires live
// authority; custody MUST reserve and enforce physical quota before consuming it.
// The lease expires at callback exit, error, cancellation or the lifetime ceiling.
// A retained Source cannot revive with a fresh context. No file is persisted here.
func WithFrozenSource(ctx context.Context, b workspacesnapshot.Binding, members []workspacesnapshot.Member, challenge string, authority Authority, use func(*workspacesnapshot.Source) error) error {
	return withFrozenSource(ctx, fixedContainerView{}, b, members, challenge, authority, use)
}
func withFrozenSource(ctx context.Context, view containerView, b workspacesnapshot.Binding, members []workspacesnapshot.Member, challenge string, authority Authority, use func(*workspacesnapshot.Source) error) error {
	if ctx == nil || ctx.Err() != nil || view == nil || !workspacemount.ValidChallenge(challenge) || missingAuthority(authority) || use == nil {
		return ErrRefused
	}
	members = append([]workspacesnapshot.Member(nil), members...)
	lifetime, cancel := context.WithTimeout(ctx, MaxLifetime)
	root, err := view.OpenRoot()
	if err != nil {
		cancel()
		return ErrRefused
	}
	// Expire before closing the root on every exit, including panic unwinding.
	defer root.Close()
	defer cancel()
	lease := &frozenLease{lifetime: lifetime, root: root, view: view, binding: b, challenge: challenge, authority: authority}
	source, err := workspacesnapshot.Capture(lifetime, root, b, members, lease)
	if err != nil {
		return ErrRefused
	}
	if err = use(source); err != nil {
		return err
	}
	if source.Current(lifetime) != nil {
		return ErrRefused
	}
	return nil
}

var _ workspacesnapshot.FrozenLease = (*frozenLease)(nil)
