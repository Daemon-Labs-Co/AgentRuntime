// Package objectread runs only in the reviewed credential-free isolated reader.
// Its fixed /objects root and kernel observation cannot be replaced by callers.
// A source fork CAN substitute views/journals or run on a host, invalidating the
// mandatory isolation/physical-quota contract; there is no supported host fallback.
package objectread

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacemount"
	"context"
	"io"
	"os"
	"reflect"
	"time"
)

type Request struct {
	Receipt   objectcustody.Receipt `json:"receipt"`
	Challenge string                `json:"challenge"`
}

func ValidRequest(r Request) bool {
	return objectcustody.ValidReceipt(r.Receipt) && workspacemount.ValidChallenge(r.Challenge)
}

type containerView interface {
	OpenRoot() (*os.Root, error)
	Identity() (os.FileInfo, error)
	Observe(context.Context, string) (workspacemount.Proof, error)
}
type fixedView struct{}

func (fixedView) OpenRoot() (*os.Root, error)    { return os.OpenRoot("/objects") }
func (fixedView) Identity() (os.FileInfo, error) { return os.Lstat("/objects") }
func (fixedView) Observe(ctx context.Context, c string) (workspacemount.Proof, error) {
	return workspacemount.ObserveObjects(ctx, c)
}

type readLease struct {
	ctx       context.Context
	view      containerView
	root      *os.Root
	challenge string
	proof     workspacemount.Proof
	journal   *objectcustody.ReadJournalChannel
}

func (l *readLease) verify(ctx context.Context) error {
	if ctx.Err() != nil || l.ctx.Err() != nil {
		return objectcustody.ErrRefused
	}
	before, err := l.root.Lstat(".")
	if err != nil {
		return objectcustody.ErrRefused
	}
	fixed, err := l.view.Identity()
	if err != nil || !fixed.IsDir() || fixed.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, fixed) {
		return objectcustody.ErrRefused
	}
	proof, err := l.view.Observe(ctx, l.challenge)
	if err != nil || !workspacemount.ValidProof(proof, l.challenge) || l.proof.Version != 0 && proof != l.proof {
		return objectcustody.ErrRefused
	}
	after, err := l.root.Lstat(".")
	if err != nil || !os.SameFile(before, after) {
		return objectcustody.ErrRefused
	}
	fixed, err = l.view.Identity()
	if err != nil || fixed.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, fixed) {
		return objectcustody.ErrRefused
	}
	again, err := l.view.Observe(ctx, l.challenge)
	if err != nil || again != proof || ctx.Err() != nil || l.ctx.Err() != nil {
		return objectcustody.ErrRefused
	}
	l.proof = proof
	return nil
}
func (l *readLease) AuthorizeRead(ctx context.Context, s objectcustody.Scope, r objectcustody.Receipt) error {
	if l.verify(ctx) != nil || l.journal.AuthorizeRead(ctx, s, r) != nil || l.verify(ctx) != nil {
		return objectcustody.ErrRefused
	}
	return nil
}
func (l *readLease) AcknowledgeRead(ctx context.Context, r objectcustody.Receipt) error {
	if l.verify(ctx) != nil || l.journal.AcknowledgeRead(ctx, r) != nil || l.verify(ctx) != nil {
		return objectcustody.ErrRefused
	}
	return nil
}
func (*readLease) Reserve(context.Context, objectcustody.Intent) error {
	return objectcustody.ErrRefused
}
func (*readLease) Seal(context.Context, objectcustody.Receipt) error { return objectcustody.ErrRefused }

type leasedReader struct {
	lease *readLease
	store *objectcustody.Store
}

func (r leasedReader) Get(ctx context.Context, s objectcustody.Scope, receipt objectcustody.Receipt) ([]byte, error) {
	if r.lease.verify(ctx) != nil {
		return nil, objectcustody.ErrRefused
	}
	raw, err := r.store.Get(ctx, s, receipt)
	if err != nil || r.lease.verify(ctx) != nil {
		return nil, objectcustody.ErrRefused
	}
	return raw, nil
}

// Serve reads one exact sealed receipt through current supervisor authorization and
// durable source acknowledgment. The supervisor MUST bind the actual reviewed
// running reader/volume, fence writers and enforce real quota/account/export policy.
// Local kernel reports are not independent authentication. No paths or credentials
// are accepted, and no bytes are returned on mount, policy or audit uncertainty.
func Serve(ctx context.Context, q Request, stream io.ReadWriteCloser) error {
	return serve(ctx, q, stream, fixedView{})
}
func serve(ctx context.Context, q Request, stream io.ReadWriteCloser, view containerView) error {
	if ctx == nil || ctx.Err() != nil || !ValidRequest(q) || missing(stream) || missing(view) {
		return objectcustody.ErrRefused
	}
	defer stream.Close()
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	journal, err := objectcustody.NewReadJournalChannel(child, stream, q.Receipt, cancel)
	if err != nil {
		return err
	}
	defer journal.Close()
	root, err := view.OpenRoot()
	if err != nil || root == nil {
		return objectcustody.ErrRefused
	}
	defer root.Close()
	lease := &readLease{ctx: child, view: view, root: root, challenge: q.Challenge, journal: journal}
	if lease.verify(child) != nil {
		return objectcustody.ErrRefused
	}
	store, err := objectcustody.New(root, lease)
	if err != nil {
		return err
	}
	return objectcustody.ServeReadChannel(child, stream, q.Receipt.Intent.Scope, q.Receipt, leasedReader{lease, store})
}

func missing(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Chan, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}
