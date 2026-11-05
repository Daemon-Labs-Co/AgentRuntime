//go:build linux || darwin

package artifactmanifest

import (
	"bytes"
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/taskcontract"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type journal struct {
	sealed   map[string]objectcustody.Receipt
	reserved map[string]objectcustody.Intent
	allowed  bool
	reads    int
	failAck  bool
}

func (j *journal) Reserve(_ context.Context, i objectcustody.Intent) error {
	if !j.allowed {
		return ErrRefused
	}
	j.reserved[i.ObjectID] = i
	return nil
}
func (j *journal) Seal(_ context.Context, r objectcustody.Receipt) error {
	if !j.allowed || j.reserved[r.Intent.ObjectID] != r.Intent {
		return ErrRefused
	}
	j.sealed[r.Intent.ObjectID] = r
	return nil
}
func (j *journal) AuthorizeRead(_ context.Context, s objectcustody.Scope, r objectcustody.Receipt) error {
	j.reads++
	if !j.allowed || s != r.Intent.Scope || j.sealed[r.Intent.ObjectID] != r {
		return ErrRefused
	}
	return nil
}
func (j *journal) AcknowledgeRead(_ context.Context, r objectcustody.Receipt) error {
	if !j.allowed || j.failAck || j.sealed[r.Intent.ObjectID] != r {
		return ErrRefused
	}
	return nil
}
func definition(bundle bool) taskcontract.Definition {
	out := taskcontract.DataContract{Name: "report", Type: "file", Required: true, FileName: "docs/report.txt", MediaType: "text/plain", MaxBytes: 128}
	if bundle {
		out = taskcontract.DataContract{Name: "report", Type: "bundle", Required: true, MediaType: "application/vnd.commonroom.bundle+json", MaxBytes: 256, Members: []taskcontract.BundleMember{{Name: "docs/report.txt", MediaType: "text/plain", MaxBytes: 128}, {Name: "data.json", MediaType: "application/json", MaxBytes: 128}}}
	}
	return taskcontract.Definition{SchemaVersion: 1, Revision: 1, Task: "Produce synthetic report", ExpectedInputs: []taskcontract.DataContract{{Name: "source", Type: "value", Required: true, SchemaID: "text.v1", MaxBytes: 128}}, Process: taskcontract.Process{Mode: "objective", Instructions: "Summarize synthetic input", Constraints: []string{"Use synthetic input only"}}, DesiredOutputs: []taskcontract.DataContract{out}, AcceptanceCriteria: []taskcontract.Criterion{{ID: "correct", Description: "Matches input", Method: "human", Output: "report"}}, ExecutionConstraints: taskcontract.Limits{AllowedOperations: []string{"read"}, MaxDurationSeconds: 60, MaxResponseBytes: 1024, MaxToolCalls: 3, CompletionAuthority: "owner", ResourceScope: "assigned-task-workspace"}, FailureContract: taskcontract.Failure{MissingInput: "block", ExecutionFailure: "record-and-stop", Retry: "human-only"}}
}
func fixture(t *testing.T, d taskcontract.Definition, contents ...string) (*objectcustody.Store, *journal, objectcustody.ExecutionScope, []Claim, string) {
	t.Helper()
	if err := taskcontract.Validate(d); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	j := &journal{sealed: map[string]objectcustody.Receipt{}, reserved: map[string]objectcustody.Intent{}, allowed: true}
	store, err := objectcustody.New(root, j)
	if err != nil {
		t.Fatal(err)
	}
	scope := objectcustody.ExecutionScope{CompanyID: "synthetic-company", RoomID: "synthetic-room", TaskID: "synthetic-task", ExecutionID: strings.Repeat("a", 32), JobID: strings.Repeat("b", 32), RepositoryDigest: strings.Repeat("c", 64), RevisionDigest: strings.Repeat("d", 64), DefinitionDigest: taskcontract.Digest(d)}
	members := d.DesiredOutputs[0].Members
	if d.DesiredOutputs[0].Type == "file" {
		members = []taskcontract.BundleMember{{Name: d.DesiredOutputs[0].FileName, MaxBytes: d.DesiredOutputs[0].MaxBytes}}
	}
	claims := []Claim{}
	for i, m := range members {
		r, err := store.Put(t.Context(), objectcustody.Scope{ExecutionScope: scope, OutputName: "report", MemberName: m.Name}, m.MaxBytes, bytes.NewBufferString(contents[i]))
		if err != nil {
			t.Fatal(err)
		}
		claims = append(claims, Claim{Name: m.Name, Receipt: r})
	}
	return store, j, scope, claims, dir
}
func TestManifestCanonicalBundleAndActualRevalidation(t *testing.T) {
	t.Parallel()
	d := definition(true)
	store, j, s, c, _ := fixture(t, d, "synthetic report", `{"count":1}`)
	got, err := Resolve(t.Context(), d, s, "report", c, store)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []Claim{c[1], c[0]}
	again, err := Resolve(t.Context(), d, s, "report", reversed, store)
	if err != nil || !reflect.DeepEqual(got, again) || got.TotalBytes != int64(len("synthetic report")+len(`{"count":1}`)) {
		t.Fatal(got, again, err)
	}
	if err := Revalidate(t.Context(), d, s, "report", got, store); err != nil {
		t.Fatal(err)
	}
	got.TotalBytes++
	got.Digest = manifestDigest(got)
	if Revalidate(t.Context(), d, s, "report", got, store) == nil {
		t.Fatal("forged metadata accepted")
	}
	j.allowed = false
	if _, err := Resolve(t.Context(), d, s, "report", c, store); err == nil {
		t.Fatal("revoked authority accepted")
	}
}
func TestManifestPreflightRefusesEntireSetBeforeReads(t *testing.T) {
	for _, name := range []string{"missing", "extra", "duplicate name", "duplicate object", "member substitution", "output substitution", "foreign room", "foreign revision", "wrong limit", "negative bytes", "oversize", "unsupported format", "unsupported charset", "wrong definition", "unknown output", "canceled"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := definition(true)
			store, j, s, c, _ := fixture(t, d, "report", `{}`)
			output := "report"
			ctx := t.Context()
			switch name {
			case "missing":
				c = c[:1]
			case "extra":
				c = append(c, c[0])
			case "duplicate name":
				c[1].Name = c[0].Name
			case "duplicate object":
				c[1].Receipt.Intent.ObjectID = c[0].Receipt.Intent.ObjectID
			case "member substitution":
				c[0].Receipt.Intent.Scope.MemberName = "other.txt"
			case "output substitution":
				c[0].Receipt.Intent.Scope.OutputName = "other"
			case "foreign room":
				s.RoomID = "foreign"
			case "foreign revision":
				s.RevisionDigest = strings.Repeat("f", 64)
			case "wrong limit":
				c[0].Receipt.Intent.MaxBytes++
			case "negative bytes":
				c[0].Receipt.Bytes = -1
			case "oversize":
				c[0].Receipt.Bytes = 129
			case "unsupported format":
				d.DesiredOutputs[0].Members[1].MediaType = "image/png"
				s.DefinitionDigest = taskcontract.Digest(d)
			case "unsupported charset":
				d.DesiredOutputs[0].Members[1].MediaType = "application/json; charset=latin1"
				s.DefinitionDigest = taskcontract.Digest(d)
			case "wrong definition":
				s.DefinitionDigest = strings.Repeat("f", 64)
			case "unknown output":
				output = "missing"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := Resolve(ctx, d, s, output, c, store)
			if !errors.Is(err, ErrRefused) || !reflect.DeepEqual(got, Manifest{}) || j.reads != 0 {
				t.Fatal("preflight returned bytes/partial manifest", got, err, j.reads)
			}
		})
	}
}
func TestRegisteredFormatsCheckActualSealedBytes(t *testing.T) {
	for _, tc := range []struct {
		media, raw string
		ok         bool
	}{{"text/plain", "", true}, {"text/markdown; charset=UTF-8", "# Report\n", true}, {"application/octet-stream", string([]byte{0, 255}), true}, {"text/plain", string([]byte{255}), false}, {"text/plain", "bad\x00text", false}, {"application/json", `{"n":9007199254740993}`, true}, {"application/json", `{"n":1,"n":2}`, false}, {"application/json", `"\ud800"`, false}, {"application/json", "", false}, {"application/json", "{} trailing", false}} {
		t.Run(tc.media+tc.raw, func(t *testing.T) {
			t.Parallel()
			d := definition(false)
			d.DesiredOutputs[0].MediaType = tc.media
			store, j, s, c, _ := fixture(t, d, tc.raw)
			got, err := Resolve(t.Context(), d, s, "report", c, store)
			if (err == nil) != tc.ok {
				t.Fatal(got, err)
			}
			if len(j.reserved) != 1 || len(j.sealed) != 1 {
				t.Fatal("format rejection discarded custody")
			}
		})
	}
}
func TestManifestIntegrityAndReleaseAcknowledgment(t *testing.T) {
	for _, name := range []string{"tampered bytes", "unsealed", "audit failure"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := definition(false)
			store, j, s, c, dir := fixture(t, d, "report")
			m, err := Resolve(t.Context(), d, s, "report", c, store)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "tampered bytes":
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 1 {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("tamper"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsealed":
				delete(j.sealed, c[0].Receipt.Intent.ObjectID)
			case "audit failure":
				j.failAck = true
			}
			if Revalidate(t.Context(), d, s, "report", m, store) == nil {
				t.Fatal("unusable bytes accepted")
			}
			if len(j.reserved) != 1 {
				t.Fatal("uncertainty refunded")
			}
		})
	}
}

func TestManifestMetadataIsCanonicalShapeNotByteAuthority(t *testing.T) {
	t.Parallel()
	d := definition(true)
	store, j, scope, claims, _ := fixture(t, d, "report", "{}")
	manifest, err := Resolve(t.Context(), d, scope, "report", claims, store)
	if err != nil {
		t.Fatal(err)
	}
	reads := j.reads
	j.allowed = false
	if ValidateMetadata(d, scope, "report", manifest) != nil || j.reads != reads {
		t.Fatal("metadata replay performed I/O/authority")
	}
	for _, mode := range []string{"digest", "format", "total", "order", "receipt", "scope"} {
		t.Run(mode, func(t *testing.T) {
			m := manifest
			m.Files = append([]File(nil), m.Files...)
			switch mode {
			case "digest":
				m.Digest = strings.Repeat("0", 64)
			case "format":
				m.Files[0].StructuralCheck = "invented"
				m.Digest = manifestDigest(m)
			case "total":
				m.TotalBytes++
				m.Digest = manifestDigest(m)
			case "order":
				m.Files[0], m.Files[1] = m.Files[1], m.Files[0]
				m.Digest = manifestDigest(m)
			case "receipt":
				m.Files[0].Receipt.Digest = "bad"
				m.Digest = manifestDigest(m)
			case "scope":
				m.Scope.CompanyID = "foreign"
				m.Digest = manifestDigest(m)
			}
			if ValidateMetadata(d, scope, "report", m) == nil || j.reads != reads {
				t.Fatal("noncanonical metadata accepted/read bytes")
			}
		})
	}
}
func TestManifestMalformedLaterReceiptRefusesBeforeAnyRead(t *testing.T) {
	t.Parallel()
	d := definition(true)
	store, j, scope, claims, _ := fixture(t, d, "report", "{}")
	claims[1].Receipt.Digest = "not-a-sealed-digest"
	if _, err := Resolve(t.Context(), d, scope, "report", claims, store); err == nil || j.reads != 0 {
		t.Fatal("malformed complete set caused partial reads", err, j.reads)
	}
}
