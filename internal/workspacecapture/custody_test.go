package workspacecapture

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type transferJournal struct {
	intents  []objectcustody.Intent
	receipts []objectcustody.Receipt
	charged  int64
	reserve  func(objectcustody.Intent) error
	seal     func(objectcustody.Receipt) error
	reads    int
}

func (j *transferJournal) Reserve(ctx context.Context, i objectcustody.Intent) error {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > MaxLifetime {
		return errors.New("unbounded transfer authority")
	}
	j.intents = append(j.intents, i)
	j.charged += i.MaxBytes
	if j.reserve != nil {
		return j.reserve(i)
	}
	return ctx.Err()
}
func (j *transferJournal) Seal(ctx context.Context, r objectcustody.Receipt) error {
	if j.seal != nil {
		if err := j.seal(r); err != nil {
			return err
		}
	}
	j.receipts = append(j.receipts, r)
	return ctx.Err()
}
func (j *transferJournal) AuthorizeRead(context.Context, objectcustody.Scope, objectcustody.Receipt) error {
	j.reads++
	return nil
}
func (j *transferJournal) AcknowledgeRead(context.Context, objectcustody.Receipt) error {
	j.reads++
	return nil
}
func transferRoot(t *testing.T) (*os.Root, string) {
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
	return root, dir
}
func TestCaptureToCustodyActualMemberAndReceipt(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	root, dir := transferRoot(t)
	j := &transferJournal{}
	j.reserve = func(i objectcustody.Intent) error {
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 0 {
			t.Fatal("object created before quota acknowledgment", err)
		}
		if i.Scope.RevisionDigest == "" || i.Scope.DefinitionDigest != b.Execution.DefinitionDigest || i.Scope.MemberName != m[0].Name || i.MaxBytes != 128 {
			t.Fatal("source binding changed", i)
		}
		return nil
	}
	result, err := captureToCustody(t.Context(), v, Request{b, m, v.proof.Challenge}, &fixtureAuthority{}, root, j)
	if err != nil || len(result.Receipts) != 1 || len(j.receipts) != 1 || j.charged != 128 || j.reads != 0 {
		t.Fatal("capture transfer failed", err, result, j.charged)
	}
	receipt := result.Receipts[0]
	raw, err := os.ReadFile(filepath.Join(dir, "object-"+receipt.Intent.ObjectID+".blob"))
	if err != nil || string(raw) != "synthetic captured result\n" {
		t.Fatal("wrong persisted bytes", err)
	}
	sum := sha256.Sum256(raw)
	if receipt.Digest != hex.EncodeToString(sum[:]) || receipt.Bytes != int64(len(raw)) || receipt.Intent.Scope.ExecutionScope != result.Snapshot.Scope {
		t.Fatal("receipt not actual captured source", receipt)
	}
	if result.Receipts[0] != j.receipts[0] {
		t.Fatal("sealed receipt changed")
	}
}
func TestCaptureToCustodyFailureRetainsChargesAndWithholdsResult(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"quota failure", "quota revocation", "source changed", "seal failure", "after seal revocation", "second member failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			v, b, m := captureFixture(t)
			root, dir := transferRoot(t)
			deny := false
			authority := &fixtureAuthority{check: func(context.Context, workspacesnapshot.Binding, workspacemount.Proof) error {
				if deny {
					return errors.New("revoked")
				}
				return nil
			}}
			j := &transferJournal{}
			j.reserve = func(i objectcustody.Intent) error {
				switch mode {
				case "quota failure":
					return errors.New("synthetic physical quota unavailable")
				case "quota revocation":
					deny = true
				case "source changed":
					return os.WriteFile(filepath.Join(v.dir, "result.txt"), []byte("changed"), 0600)
				case "second member failure":
					if len(j.intents) == 2 {
						return errors.New("synthetic quota failure")
					}
				}
				return nil
			}
			j.seal = func(objectcustody.Receipt) error {
				if mode == "seal failure" {
					return errors.New("synthetic durable seal failure")
				}
				if mode == "after seal revocation" {
					deny = true
				}
				return nil
			}
			if mode == "second member failure" {
				if err := os.WriteFile(filepath.Join(v.dir, "z.txt"), []byte("second synthetic output"), 0600); err != nil {
					t.Fatal(err)
				}
				m = append(m, workspacesnapshot.Member{OutputName: "second", Name: "z.txt", MaxBytes: 128})
			}
			result, err := captureToCustody(t.Context(), v, Request{b, m, v.proof.Challenge}, authority, root, j)
			if !errors.Is(err, objectcustody.ErrUnconfirmed) || result.Snapshot.Version != 0 || len(result.Receipts) != 0 {
				t.Fatal("failure released partial result", err, result)
			}
			if j.charged < 128 || j.reads != 0 {
				t.Fatal("lost charge or released bytes", j.charged, j.reads)
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "quota failure", "quota revocation", "source changed":
				if len(files) != 0 || len(j.receipts) != 0 {
					t.Fatal("wrote before quota/current source", files, j.receipts)
				}
			case "seal failure":
				if len(files) != 1 || len(j.receipts) != 0 {
					t.Fatal("uncertain inode not retained")
				}
			case "after seal revocation":
				if len(files) != 1 || len(j.receipts) != 1 {
					t.Fatal("individually sealed object lost")
				}
			case "second member failure":
				if len(files) != 1 || len(j.receipts) != 1 || j.charged != 256 {
					t.Fatal("partial batch accounting lost", len(files), len(j.receipts), j.charged)
				}
			}
		})
	}
}
func TestCapturedSourceJournalCannotExpandScopeOrReleaseBytes(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	underlying := &transferJournal{}
	err := withFrozenSource(t.Context(), v, b, m, v.proof.Challenge, &fixtureAuthority{}, func(source *workspacesnapshot.Source) error {
		j := &capturedSourceJournal{source: source, journal: underlying}
		scope := capturedScope(source)
		scope.MemberName = "undeclared.txt"
		if j.Reserve(t.Context(), objectcustody.Intent{ObjectID: strings.Repeat("a", 32), Scope: scope, MaxBytes: 128}) == nil || len(underlying.intents) != 0 {
			t.Fatal("undeclared output reserved")
		}
		scope = capturedScope(source)
		fabricated := objectcustody.Receipt{Intent: objectcustody.Intent{ObjectID: strings.Repeat("a", 32), Scope: scope, MaxBytes: 128}, Bytes: 3, Digest: strings.Repeat("b", 64)}
		if j.Seal(t.Context(), fabricated) == nil || len(underlying.receipts) != 0 {
			t.Fatal("fabricated receipt sealed")
		}
		if j.AuthorizeRead(t.Context(), scope, fabricated) == nil || j.AcknowledgeRead(t.Context(), fabricated) == nil || underlying.reads != 0 {
			t.Fatal("capture adapter granted release")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestCaptureToCustodyMissingJournalRefusesBeforeSource(t *testing.T) {
	t.Parallel()
	v, b, m := captureFixture(t)
	root, _ := transferRoot(t)
	var j *transferJournal
	if _, err := captureToCustody(t.Context(), v, Request{b, m, v.proof.Challenge}, &fixtureAuthority{}, root, j); err == nil || v.opened {
		t.Fatal("source opened without custody admission")
	}
}
