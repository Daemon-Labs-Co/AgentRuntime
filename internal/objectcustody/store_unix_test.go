//go:build linux || darwin

package objectcustody

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type custodyJournal struct {
	mu                                       sync.Mutex
	capacity, total                          int64
	reserved                                 map[string]Intent
	sealed                                   map[string]Receipt
	events                                   []string
	allowed                                  bool
	failReserve, failSeal, failRead, failAck bool
	afterReserve                             func()
	afterAuthorize                           func()
}

func (j *custodyJournal) Reserve(_ context.Context, intent Intent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, "reserve")
	if !j.allowed || j.failReserve || intent.MaxBytes > j.capacity-j.total {
		return errors.New("synthetic reserve refusal")
	}
	if _, exists := j.reserved[intent.ObjectID]; exists {
		return errors.New("duplicate object")
	}
	j.reserved[intent.ObjectID] = intent
	j.total += intent.MaxBytes
	if j.afterReserve != nil {
		j.afterReserve()
	}
	return nil
}
func (j *custodyJournal) Seal(_ context.Context, receipt Receipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, "seal")
	if !j.allowed || j.failSeal || j.reserved[receipt.Intent.ObjectID] != receipt.Intent {
		return errors.New("synthetic seal refusal")
	}
	j.sealed[receipt.Intent.ObjectID] = receipt
	return nil
}
func (j *custodyJournal) AuthorizeRead(_ context.Context, scope Scope, receipt Receipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, "authorize-read")
	if !j.allowed || j.failRead || scope != receipt.Intent.Scope || j.sealed[receipt.Intent.ObjectID] != receipt {
		return errors.New("synthetic read refusal")
	}
	if j.afterAuthorize != nil {
		j.afterAuthorize()
	}
	return nil
}
func (j *custodyJournal) AcknowledgeRead(_ context.Context, receipt Receipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, "acknowledge-read")
	if !j.allowed || j.failAck || j.sealed[receipt.Intent.ObjectID] != receipt {
		return errors.New("synthetic release refusal")
	}
	return nil
}
func syntheticScope() Scope {
	return Scope{ExecutionScope: ExecutionScope{CompanyID: "synthetic-company", RoomID: "synthetic-room", TaskID: "synthetic-task", ExecutionID: strings.Repeat("a", 32), JobID: strings.Repeat("b", 32), RepositoryDigest: strings.Repeat("c", 64), RevisionDigest: strings.Repeat("d", 64), DefinitionDigest: strings.Repeat("e", 64)}, OutputName: "report", MemberName: "docs/report.txt"}
}
func custodyFixture(t *testing.T) (*Store, *custodyJournal, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	j := &custodyJournal{capacity: MaxObjectBytes * 64, reserved: map[string]Intent{}, sealed: map[string]Receipt{}, allowed: true}
	store, err := New(root, j)
	if err != nil {
		t.Fatal(err)
	}
	return store, j, dir
}
func TestCustodyActualBytesRequireAccountingSealAndReleaseAcknowledgment(t *testing.T) {
	t.Parallel()
	store, j, dir := custodyFixture(t)
	scope := syntheticScope()
	source := []byte("<synthetic immutable bytes>")
	receipt, err := store.Put(t.Context(), scope, 128, bytes.NewReader(source))
	if err != nil || receipt.Bytes != int64(len(source)) || !validReceipt(receipt) {
		t.Fatal(receipt, err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, objectName(receipt.Intent.ObjectID)))
	if err != nil || !bytes.Equal(stored, source) {
		t.Fatal("actual bytes not retained", err)
	}
	returned, err := store.Get(t.Context(), scope, receipt)
	if err != nil || !bytes.Equal(returned, source) {
		t.Fatal(err)
	}
	returned[0] = 'x'
	again, err := store.Get(t.Context(), scope, receipt)
	if err != nil || !bytes.Equal(again, source) {
		t.Fatal("caller modified immutable stored bytes", err)
	}
	if j.total != 128 || strings.Join(j.events, ",") != "reserve,seal,authorize-read,acknowledge-read,authorize-read,acknowledge-read" {
		t.Fatal("accounting/audit order incorrect", j.total, j.events)
	}
}

type readCounter struct{ calls int }

func (r *readCounter) Read(p []byte) (int, error) { r.calls++; return 0, io.EOF }
func TestCustodyRefusesBeforeReadingOrAllocatingWithoutAdmission(t *testing.T) {
	for _, scenario := range []string{"quota", "reserve failure", "authority", "scope", "size", "canceled", "nil context"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			store, j, dir := custodyFixture(t)
			scope := syntheticScope()
			limit := int64(128)
			ctx := t.Context()
			source := &readCounter{}
			switch scenario {
			case "quota":
				j.capacity = 1
			case "reserve failure":
				j.failReserve = true
			case "authority":
				j.allowed = false
			case "scope":
				scope.TaskID = "../escape"
			case "size":
				limit = MaxObjectBytes + 1
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil context":
				ctx = nil
			}
			receipt, err := store.Put(ctx, scope, limit, source)
			entries, _ := os.ReadDir(dir)
			if !errors.Is(err, ErrRefused) || receipt != (Receipt{}) || source.calls != 0 || len(entries) != 0 {
				t.Fatal("refused custody consumed bytes or allocated", receipt, err, source.calls, len(entries))
			}
		})
	}
}
func TestCustodyMaximumReservationRemainsChargedAtExactBoundary(t *testing.T) {
	t.Parallel()
	store, j, _ := custodyFixture(t)
	j.capacity = 10
	for _, raw := range []string{"abc", "de"} {
		if _, err := store.Put(t.Context(), syntheticScope(), 5, strings.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	source := &readCounter{}
	if _, err := store.Put(t.Context(), syntheticScope(), 1, source); !errors.Is(err, ErrRefused) || source.calls != 0 || j.total != 10 {
		t.Fatal("account exceeded quota or refunded unused capacity", err, j.total)
	}
}
func TestCustodyUncertainWritesRetainBytesAndChargeWithoutReceipt(t *testing.T) {
	for _, scenario := range []string{"oversize", "reader failure", "file sync", "directory sync", "seal failure", "authority changed", "root closed", "canceled after reserve"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			store, j, dir := custodyFixture(t)
			ctx := t.Context()
			var reader io.Reader = strings.NewReader("synthetic bytes")
			limit := int64(64)
			switch scenario {
			case "oversize":
				limit = 3
			case "reader failure":
				reader = errorReader{}
			case "file sync":
				store.syncFile = func(*os.File) error { return errors.New("synthetic fsync failure") }
			case "directory sync":
				store.syncDirectory = func(*os.File) error { return errors.New("synthetic directory failure") }
			case "seal failure":
				j.failSeal = true
			case "authority changed":
				reader = &changingReader{source: strings.NewReader("synthetic bytes"), change: func() { j.allowed = false }}
			case "root closed":
				j.afterReserve = func() { store.root.Close() }
			case "canceled after reserve":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				j.afterReserve = cancel
			}
			receipt, err := store.Put(ctx, syntheticScope(), limit, reader)
			if receipt != (Receipt{}) || err == nil || j.total != limit || len(j.reserved) != 1 || len(j.sealed) != 0 {
				t.Fatal("uncertain write claimed success/refunded capacity", receipt, err, j.total)
			}
			if scenario != "root closed" && scenario != "canceled after reserve" {
				entries, _ := os.ReadDir(dir)
				if len(entries) != 1 {
					t.Fatal("uncertain bytes were silently deleted", len(entries))
				}
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read(p []byte) (int, error) {
	return copy(p, "partial"), errors.New("synthetic stream failure")
}

type changingReader struct {
	source *strings.Reader
	change func()
}

func (r *changingReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if r.change != nil {
		r.change()
		r.change = nil
	}
	return n, err
}
func TestCustodyUnsealedOrForeignClaimsCannotReleaseBytes(t *testing.T) {
	t.Parallel()
	store, j, _ := custodyFixture(t)
	scope := syntheticScope()
	receipt, err := store.Put(t.Context(), scope, 32, strings.NewReader("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"foreign scope", "forged digest", "forged size", "forged object", "unsealed", "revoked", "audit failure", "authority changed after authorize"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := receipt
			requested := scope
			j.allowed = true
			j.failAck = false
			j.afterAuthorize = nil
			switch scenario {
			case "foreign scope":
				requested.RoomID = "foreign"
			case "forged digest":
				candidate.Digest = strings.Repeat("f", 64)
			case "forged size":
				candidate.Bytes++
			case "forged object":
				candidate.Intent.ObjectID = strings.Repeat("0", 32)
			case "unsealed":
				delete(j.sealed, receipt.Intent.ObjectID)
			case "revoked":
				j.allowed = false
			case "audit failure":
				j.failAck = true
			case "authority changed after authorize":
				j.afterAuthorize = func() { j.allowed = false }
			}
			raw, e := store.Get(t.Context(), requested, candidate)
			if e == nil || raw != nil {
				t.Fatal("unconfirmed/foreign bytes released", scenario, e)
			}
			j.sealed[receipt.Intent.ObjectID] = receipt
		})
	}
	if j.total != 32 {
		t.Fatal("read failure refunded retained storage")
	}
}
func TestCustodyRefusesSymlinkHardlinkPermissionsAndTamperedActualBytes(t *testing.T) {
	for _, scenario := range []string{"symlink", "hardlink", "permissions", "tamper", "size"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			store, j, dir := custodyFixture(t)
			receipt, err := store.Put(t.Context(), syntheticScope(), 64, strings.NewReader("synthetic"))
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, objectName(receipt.Intent.ObjectID))
			outside := filepath.Join(t.TempDir(), "synthetic-outside")
			if err = os.WriteFile(outside, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "symlink":
				if err = os.Remove(name); err == nil {
					err = os.Symlink(outside, name)
				}
			case "hardlink":
				if err = os.Remove(name); err == nil {
					err = os.Link(outside, name)
				}
			case "permissions":
				err = os.Chmod(name, 0644)
			case "tamper":
				err = os.WriteFile(name, []byte("different"), 0600)
			case "size":
				err = os.WriteFile(name, []byte("different length"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if raw, e := store.Get(t.Context(), syntheticScope(), receipt); e == nil || raw != nil {
				t.Fatal("unsafe/tampered file released")
			}
			for _, event := range j.events {
				if event == "acknowledge-read" {
					t.Fatal("unsafe bytes acknowledged for release")
				}
			}
			raw, err := os.ReadFile(outside)
			if err != nil || string(raw) != "outside" {
				t.Fatal("outside fixture changed", err)
			}
		})
	}
}

type emptyReader struct{ reads int }

func (r *emptyReader) Read([]byte) (int, error) { r.reads++; return 0, nil }
func TestCustodyEmptyContentAndNonProgressingStreamsAreBounded(t *testing.T) {
	t.Parallel()
	store, _, _ := custodyFixture(t)
	receipt, err := store.Put(t.Context(), syntheticScope(), 1, strings.NewReader(""))
	if err != nil || receipt.Bytes != 0 {
		t.Fatal(receipt, err)
	}
	raw, err := store.Get(t.Context(), syntheticScope(), receipt)
	if err != nil || len(raw) != 0 {
		t.Fatal(err)
	}
	reader := &emptyReader{}
	if _, err = store.Put(t.Context(), syntheticScope(), 1, reader); !errors.Is(err, ErrUnconfirmed) || reader.reads != 16 {
		t.Fatal("non-progressing stream was not bounded", err, reader.reads)
	}
}
func TestCustodyParallelObjectsNeverOverwriteOrLoseCharges(t *testing.T) {
	t.Parallel()
	store, j, _ := custodyFixture(t)
	var wg sync.WaitGroup
	receipts := make(chan Receipt, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			receipt, err := store.Put(t.Context(), syntheticScope(), 32, strings.NewReader("synthetic concurrent bytes"))
			if err != nil {
				t.Error(err)
				return
			}
			receipts <- receipt
		}()
	}
	wg.Wait()
	close(receipts)
	seen := map[string]bool{}
	for receipt := range receipts {
		if seen[receipt.Intent.ObjectID] {
			t.Fatal("object identity overwritten")
		}
		seen[receipt.Intent.ObjectID] = true
		raw, err := store.Get(t.Context(), syntheticScope(), receipt)
		if err != nil || string(raw) != "synthetic concurrent bytes" {
			t.Fatal(err)
		}
	}
	if len(seen) != 24 || j.total != 24*32 {
		t.Fatal("concurrent accounting lost objects", len(seen), j.total)
	}
}
func TestCustodyRequiresPrivateOwnedRootAndJournal(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, nil); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
	store, j, dir := custodyFixture(t)
	if _, err := New(store.root, nil); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(store.root, j); !errors.Is(err, ErrRefused) {
		t.Fatal("nonprivate root admitted", err)
	}
}

func TestCustodyTypedNilDependenciesAndPreexistingObjectsRefuseSafely(t *testing.T) {
	t.Parallel()
	store, j, dir := custodyFixture(t)
	var journal *custodyJournal
	if _, err := New(store.root, journal); !errors.Is(err, ErrRefused) {
		t.Fatal("typed nil journal admitted", err)
	}
	var source *strings.Reader
	if _, err := store.Put(t.Context(), syntheticScope(), 32, source); !errors.Is(err, ErrRefused) || j.total != 0 {
		t.Fatal("typed nil source consumed reservation", err)
	}
	j.afterReserve = func() {
		for id := range j.reserved {
			if err := os.WriteFile(filepath.Join(dir, objectName(id)), []byte("preexisting fixture"), 0600); err != nil {
				t.Error(err)
			}
		}
	}
	counter := &readCounter{}
	if _, err := store.Put(t.Context(), syntheticScope(), 32, counter); !errors.Is(err, ErrUnconfirmed) || counter.calls != 0 {
		t.Fatal("preexisting object was overwritten/adopted", err, counter.calls)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil || string(raw) != "preexisting fixture" || j.total != 32 || len(j.sealed) != 0 {
		t.Fatal("existing object lost or unconfirmed capacity refunded", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func TestCustodyExactMaximumActualBytesAndOverBoundStream(t *testing.T) {
	t.Parallel()
	store, j, dir := custodyFixture(t)
	receipt, err := store.Put(t.Context(), syntheticScope(), MaxObjectBytes, io.LimitReader(zeroReader{}, MaxObjectBytes))
	if err != nil || receipt.Bytes != MaxObjectBytes {
		t.Fatal(receipt, err)
	}
	raw, err := store.Get(t.Context(), syntheticScope(), receipt)
	if err != nil || int64(len(raw)) != MaxObjectBytes {
		t.Fatal("exact maximum rejected", len(raw), err)
	}
	if _, err = store.Put(t.Context(), syntheticScope(), MaxObjectBytes, io.LimitReader(zeroReader{}, MaxObjectBytes+1)); !errors.Is(err, ErrUnconfirmed) {
		t.Fatal("over-bound actual content accepted", err)
	}
	if j.total != 2*MaxObjectBytes || len(j.sealed) != 1 {
		t.Fatal("uncertain over-bound object unmetered", j.total)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("over-bound partial bytes were not retained", err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Size() > MaxObjectBytes {
			t.Fatal("storage exceeded its reserved byte bound", err)
		}
	}
}

func TestCustodySealsActualReadBackBytesRatherThanWriteBuffers(t *testing.T) {
	t.Parallel()
	store, j, _ := custodyFixture(t)
	store.syncFile = func(file *os.File) error {
		if _, err := file.WriteAt([]byte("different"), 0); err != nil {
			return err
		}
		return file.Sync()
	}
	receipt, err := store.Put(t.Context(), syntheticScope(), 64, strings.NewReader("synthetic"))
	if !errors.Is(err, ErrUnconfirmed) || receipt != (Receipt{}) || len(j.sealed) != 0 || j.total != 64 {
		t.Fatal("changed actual inode bytes were falsely sealed", receipt, err)
	}
}

func TestCustodyLogicalMemberNamesCannotSelectFilesystemPaths(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../outside", "/absolute", "a/../b", "a//b", "a\\b", "file:\\target", "a\x00b", "a\nb"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, j, _ := custodyFixture(t)
			scope := syntheticScope()
			scope.MemberName = name
			source := &readCounter{}
			if _, err := store.Put(t.Context(), scope, 128, source); err == nil || source.calls != 0 || len(j.reserved) != 0 {
				t.Fatal("unsafe member admitted", err)
			}
		})
	}
	t.Run("exact output and member binding", func(t *testing.T) {
		t.Parallel()
		store, _, _ := custodyFixture(t)
		scope := syntheticScope()
		receipt, err := store.Put(t.Context(), scope, 128, strings.NewReader("synthetic"))
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range []Scope{{ExecutionScope: scope.ExecutionScope, OutputName: "different", MemberName: scope.MemberName}, {ExecutionScope: scope.ExecutionScope, OutputName: scope.OutputName, MemberName: "different.txt"}} {
			if _, err := store.Get(t.Context(), other, receipt); err == nil {
				t.Fatal("logical member substitution accepted")
			}
		}
	})
}

func TestCustodyPutCloseUncertaintyWithholdsReceiptWithoutRetry(t *testing.T) {
	for _, mode := range []string{"object close", "directory close", "early source failure", "object close cancel", "directory close cancel"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			store, j, dir := custodyFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			objects, directories := 0, 0
			store.closeFile = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					t.Fatal("close retried after uncertainty", err)
				}
				if info.IsDir() {
					directories++
				} else {
					objects++
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(mode, "cancel") {
					if info.IsDir() && mode == "directory close cancel" || !info.IsDir() && mode == "object close cancel" {
						cancel()
					}
					return nil
				}
				if info.IsDir() && mode == "directory close" || !info.IsDir() && mode != "directory close" {
					return errors.New("synthetic close uncertainty")
				}
				return nil
			}
			var source io.Reader = strings.NewReader("synthetic bytes")
			if mode == "early source failure" {
				source = errorReader{}
			}
			receipt, err := store.Put(ctx, syntheticScope(), 128, source)
			if !errors.Is(err, ErrUnconfirmed) || receipt != (Receipt{}) || objects != 1 || directories != 1 || j.total != 128 || len(j.reserved) != 1 {
				t.Fatal("cleanup uncertainty escaped", receipt, err, objects, directories, j.total)
			}
			wantSealed := 0
			if mode == "directory close" || mode == "directory close cancel" {
				wantSealed = 1
			}
			if len(j.sealed) != wantSealed {
				t.Fatal("wrong durable seal outcome", j.events)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatal("uncertain bytes deleted/refunded", err)
			}
		})
	}
}
func TestCustodyGetCloseUncertaintyWithholdsAuthorizedBytes(t *testing.T) {
	for _, mode := range []string{"object close", "directory close", "object close cancel", "directory close cancel"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			store, j, dir := custodyFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			receipt, err := store.Put(ctx, syntheticScope(), 128, strings.NewReader("synthetic retained bytes"))
			if err != nil {
				t.Fatal(err)
			}
			objects, directories := 0, 0
			store.closeFile = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					t.Fatal("close retried", err)
				}
				if info.IsDir() {
					directories++
				} else {
					objects++
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(mode, "cancel") {
					if info.IsDir() && mode == "directory close cancel" || !info.IsDir() && mode == "object close cancel" {
						cancel()
					}
					return nil
				}
				if info.IsDir() && mode == "directory close" || !info.IsDir() && mode == "object close" {
					return errors.New("synthetic close uncertainty")
				}
				return nil
			}
			raw, err := store.Get(ctx, syntheticScope(), receipt)
			if !errors.Is(err, ErrRefused) || raw != nil || objects != 1 || directories != 1 || j.total != 128 || j.sealed[receipt.Intent.ObjectID] != receipt {
				t.Fatal("uncertain release returned bytes/credit", raw, err, objects, directories)
			}
			if j.events[len(j.events)-1] != "acknowledge-read" {
				t.Fatal("authorization history erased", j.events)
			}
			actual, err := os.ReadFile(filepath.Join(dir, objectName(receipt.Intent.ObjectID)))
			if err != nil || string(actual) != "synthetic retained bytes" {
				t.Fatal("retained object changed", err)
			}
		})
	}
}
