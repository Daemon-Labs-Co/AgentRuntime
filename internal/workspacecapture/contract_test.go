package workspacecapture

import (
	"commonroom-runtime/internal/artifactmanifest"
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/taskcontract"
	"commonroom-runtime/internal/workspacesnapshot"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func captureDefinition() taskcontract.Definition {
	return taskcontract.Definition{SchemaVersion: 1, Revision: 1, Task: "Produce synthetic result", ExpectedInputs: []taskcontract.DataContract{{Name: "input", Type: "value", Required: true, SchemaID: "text.v1", MaxBytes: 128}}, Process: taskcontract.Process{Mode: "objective", Instructions: "Use synthetic input", Constraints: []string{"No real services"}}, DesiredOutputs: []taskcontract.DataContract{{Name: "result", Type: "file", Required: true, FileName: "result.txt", MediaType: "text/plain", MaxBytes: 128}, {Name: "extra", Type: "file", Required: false, FileName: "extra.txt", MediaType: "text/markdown", MaxBytes: 128}}, AcceptanceCriteria: []taskcontract.Criterion{{ID: "correct", Description: "Matches synthetic input", Method: "human", Output: "result"}}, ExecutionConstraints: taskcontract.Limits{AllowedOperations: []string{"read"}, MaxDurationSeconds: 60, MaxResponseBytes: 1024, MaxToolCalls: 3, CompletionAuthority: "owner", ResourceScope: "assigned-task-workspace"}, FailureContract: taskcontract.Failure{MissingInput: "block", ExecutionFailure: "record-and-stop", Retry: "human-only"}}
}
func TestContractRequestRequiredOptionalAndCanonical(t *testing.T) {
	t.Parallel()
	_, b, _ := captureFixture(t)
	d := captureDefinition()
	b.Execution.DefinitionDigest = taskcontract.Digest(d)
	required, err := ContractRequest(d, b, strings.Repeat("1", 32), nil)
	if err != nil || len(required.Members) != 1 || required.Members[0].OutputName != "result" {
		t.Fatal("required selection", err)
	}
	all, err := ContractRequest(d, b, required.Challenge, []string{"extra"})
	if err != nil || len(all.Members) != 2 || all.Members[0].OutputName != "extra" {
		t.Fatal("optional selection", err)
	}
	if ValidateContractRequest(d, required) != nil || ValidateContractRequest(d, all) != nil {
		t.Fatal("canonical request refused")
	}
	all.Members[0].Name = "mutated"
	if required.Members[0].Name != "result.txt" || d.DesiredOutputs[1].FileName != "extra.txt" {
		t.Fatal("selection aliases contract")
	}
}
func TestContractRequestRejectsOmissionsAndSubstitutions(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"missing required", "changed limit", "wrong output", "wrong path", "wrong definition", "noncanonical", "duplicate", "unknown optional", "required as optional", "unsafe Git path", "excess quota", "value selected"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			_, b, _ := captureFixture(t)
			d := captureDefinition()
			b.Execution.DefinitionDigest = taskcontract.Digest(d)
			q, err := ContractRequest(d, b, strings.Repeat("1", 32), []string{"extra"})
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing required":
				q.Members = q.Members[:1]
			case "changed limit":
				q.Members[0].MaxBytes++
			case "wrong output":
				q.Members[0].OutputName = "foreign"
			case "wrong path":
				q.Members[0].Name = "other.txt"
			case "wrong definition":
				q.Binding.Execution.DefinitionDigest = strings.Repeat("9", 64)
			case "noncanonical":
				q.Members[0], q.Members[1] = q.Members[1], q.Members[0]
			case "duplicate":
				q.Members = append(q.Members, q.Members[0])
			case "unknown optional", "required as optional":
				name := "unknown"
				if mode == "required as optional" {
					name = "result"
				}
				if _, e := ContractRequest(d, b, q.Challenge, []string{name}); e == nil {
					t.Fatal("invalid optional admitted")
				}
				return
			case "unsafe Git path":
				d.DesiredOutputs[0].FileName = ".git/config"
				b.Execution.DefinitionDigest = taskcontract.Digest(d)
				if _, e := ContractRequest(d, b, q.Challenge, nil); e == nil {
					t.Fatal("Git metadata admitted")
				}
				return
			case "excess quota":
				d.DesiredOutputs[0].MaxBytes = workspacesnapshot.MaxSelectedBytes
				d.DesiredOutputs[1].MaxBytes = workspacesnapshot.MaxSelectedBytes
				b.Execution.DefinitionDigest = taskcontract.Digest(d)
				if _, e := ContractRequest(d, b, q.Challenge, []string{"extra"}); e == nil {
					t.Fatal("aggregate overflow admitted")
				}
				return
			case "value selected":
				d.DesiredOutputs[1] = taskcontract.DataContract{Name: "extra", Type: "value", Required: false, SchemaID: "text.v1", MaxBytes: 128}
				b.Execution.DefinitionDigest = taskcontract.Digest(d)
				if _, e := ContractRequest(d, b, q.Challenge, []string{"extra"}); e == nil {
					t.Fatal("value admitted as file")
				}
				return
			}
			if ValidateContractRequest(d, q) == nil {
				t.Fatal("substituted contract admitted")
			}
		})
	}
}
func TestContractRequestBundleMembersAndDuplicatePaths(t *testing.T) {
	t.Parallel()
	_, b, _ := captureFixture(t)
	d := captureDefinition()
	d.DesiredOutputs = d.DesiredOutputs[:1]
	d.DesiredOutputs[0] = taskcontract.DataContract{Name: "result", Type: "bundle", Required: true, MediaType: "application/vnd.commonroom.bundle+json", MaxBytes: 256, Members: []taskcontract.BundleMember{{Name: "z.txt", MediaType: "text/plain", MaxBytes: 128}, {Name: "a.json", MediaType: "application/json", MaxBytes: 128}}}
	b.Execution.DefinitionDigest = taskcontract.Digest(d)
	q, e := ContractRequest(d, b, strings.Repeat("1", 32), nil)
	if e != nil || len(q.Members) != 2 || q.Members[0].Name != "a.json" {
		t.Fatal("bundle", e)
	}
	d.DesiredOutputs = append(d.DesiredOutputs, taskcontract.DataContract{Name: "other", Type: "file", Required: true, FileName: "a.json", MediaType: "application/json", MaxBytes: 128})
	b.Execution.DefinitionDigest = taskcontract.Digest(d)
	if _, e = ContractRequest(d, b, q.Challenge, nil); e == nil {
		t.Fatal("aliased path admitted")
	}
}
func TestContractCaptureToActualFormatManifest(t *testing.T) {
	t.Parallel()
	view, b, _ := captureFixture(t)
	d := captureDefinition()
	b.Execution.DefinitionDigest = taskcontract.Digest(d)
	q, err := ContractRequest(d, b, view.proof.Challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, dir := transferRoot(t)
	journal := &transferJournal{}
	captured, err := captureToCustody(t.Context(), view, q, &fixtureAuthority{}, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	store, err := objectcustody.New(root, journal)
	if err != nil {
		t.Fatal(err)
	}
	claims := []artifactmanifest.Claim{{Name: "result.txt", Receipt: captured.Receipts[0]}}
	manifest, err := artifactmanifest.Resolve(t.Context(), d, captured.Snapshot.Scope, "result", claims, store)
	if err != nil || manifest.Files[0].StructuralCheck != "utf8-text-v1" {
		t.Fatal("actual content validation", err)
	}
	if artifactmanifest.Revalidate(t.Context(), d, captured.Snapshot.Scope, "result", manifest, store) != nil {
		t.Fatal("revalidation failed")
	}
	// Corrupt retained bytes: matching metadata must not authorize a forged manifest.
	before := append([]objectcustody.Receipt(nil), journal.receipts...)
	files, e := os.ReadDir(dir)
	if e != nil || len(files) != 1 {
		t.Fatal("custody fixture", e)
	}
	if e = os.WriteFile(filepath.Join(dir, files[0].Name()), []byte("synthetic tampering"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = artifactmanifest.Resolve(t.Context(), d, captured.Snapshot.Scope, "result", claims, store); e == nil {
		t.Fatal("corrupted object validated")
	}
	if !reflect.DeepEqual(before, journal.receipts) || journal.charged != 128 {
		t.Fatal("validation failure discarded custody")
	}
}

func TestContractCapturedInvalidFormatRetainsCustody(t *testing.T) {
	t.Parallel()
	view, b, _ := captureFixture(t)
	d := captureDefinition()
	d.DesiredOutputs[0].MediaType = "application/json"
	b.Execution.DefinitionDigest = taskcontract.Digest(d)
	q, err := ContractRequest(d, b, view.proof.Challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, dir := transferRoot(t)
	j := &transferJournal{}
	captured, err := captureToCustody(t.Context(), view, q, &fixtureAuthority{}, root, j)
	if err != nil {
		t.Fatal(err)
	}
	store, err := objectcustody.New(root, j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = artifactmanifest.Resolve(t.Context(), d, captured.Snapshot.Scope, "result", []artifactmanifest.Claim{{Name: "result.txt", Receipt: captured.Receipts[0]}}, store); err == nil {
		t.Fatal("non-JSON source accepted as JSON")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || j.charged != 128 || len(j.receipts) != 1 {
		t.Fatal("format denial discarded retained state", err)
	}
}
