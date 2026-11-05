package taskcontract

import (
	"encoding/json"
	"strings"
	"testing"
)

func sample() Definition {
	return Definition{SchemaVersion: 1, Revision: 1, Task: "Produce a synthetic summary", ExpectedInputs: []DataContract{{Name: "source", Type: "value", Required: true, SchemaID: "text.v1", MaxBytes: 512}}, Process: Process{Mode: "objective", Instructions: "Summarize the supplied synthetic source", Constraints: []string{"Do not invent facts"}}, DesiredOutputs: []DataContract{{Name: "summary", Type: "value", Required: true, SchemaID: "text.v1", MaxBytes: 1024}}, AcceptanceCriteria: []Criterion{{ID: "summaryCorrect", Description: "Matches the supplied source", Method: "human", Output: "summary"}}, ExecutionConstraints: Limits{AllowedOperations: []string{"read"}, MaxDurationSeconds: 60, MaxResponseBytes: 2048, MaxToolCalls: 3, CompletionAuthority: "owner", ResourceScope: "assigned-task-workspace"}, FailureContract: Failure{MissingInput: "block", ExecutionFailure: "record-and-stop", Retry: "human-only"}}
}
func TestFiniteContractsAndCanonicalBindings(t *testing.T) {
	t.Parallel()
	d := sample()
	raw, _ := json.Marshal(d)
	decoded, err := Decode(raw)
	if err != nil || Digest(d) != Digest(decoded) {
		t.Fatal(err)
	}
	bound, err := Bind(d, []Binding{{Name: "source", Value: json.RawMessage(`"<source>"`), SourceVersion: "synthetic-v1"}})
	if err != nil || len(bound) != 1 || bound[0].ValueJSON != `"\u003csource\u003e"` {
		t.Fatal(bound, err)
	}
	outputs, err := ReturnedValues(d, []byte(`{ "summary" : "<answer>" }`), "attempt-v1")
	if err != nil || outputs[0].ValueJSON != `"\u003canswer\u003e"` {
		t.Fatal(outputs, err)
	}
	marshaled, _ := json.Marshal(outputs)
	var restored []BoundValue
	_ = json.Unmarshal(marshaled, &restored)
	if restored[0].Digest != outputs[0].Digest || string(restored[0].Value) != string(outputs[0].Value) {
		t.Fatal("JSON round-trip changed immutable value")
	}
	if !Allows(d, "read") || Allows(d, "write") {
		t.Fatal("operation constraint expanded")
	}
}
func TestDefinitionValidationAdversaries(t *testing.T) {
	for _, name := range []string{"version", "missing task", "missing inputs", "missing process", "no outputs", "unregistered schema", "unknown type", "duplicate input", "missing criteria", "unknown output", "schema file", "permission", "duration", "response", "calls", "authority", "failure"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := sample()
			switch name {
			case "version":
				d.SchemaVersion = 2
			case "missing task":
				d.Task = " "
			case "missing inputs":
				d.ExpectedInputs = nil
			case "missing process":
				d.Process.Instructions = ""
			case "no outputs":
				d.DesiredOutputs = nil
			case "unregistered schema":
				d.DesiredOutputs[0].SchemaID = "custom-unreviewed"
			case "unknown type":
				d.DesiredOutputs[0].Type = "remote-service"
			case "duplicate input":
				d.ExpectedInputs = append(d.ExpectedInputs, d.ExpectedInputs[0])
			case "missing criteria":
				d.AcceptanceCriteria = nil
			case "unknown output":
				d.AcceptanceCriteria[0].Output = "foreign"
			case "schema file":
				d.DesiredOutputs[0] = DataContract{Name: "summary", Type: "file", Required: true, FileName: "result.md", MediaType: "text/markdown", MaxBytes: 1024}
				d.AcceptanceCriteria[0].Method = "schema"
			case "permission":
				d.ExecutionConstraints.AllowedOperations = []string{"host-shell"}
			case "duration":
				d.ExecutionConstraints.MaxDurationSeconds = 181
			case "response":
				d.ExecutionConstraints.MaxResponseBytes = 16385
			case "calls":
				d.ExecutionConstraints.MaxToolCalls = 65
			case "authority":
				d.ExecutionConstraints.CompletionAuthority = "model"
			case "failure":
				d.FailureContract.Retry = "automatic"
			}
			if Validate(d) == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
	raw, _ := json.Marshal(sample())
	for _, malformed := range []string{strings.Replace(string(raw), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1), strings.Replace(string(raw), `"schemaVersion":1`, `"unknown":true,"schemaVersion":1`, 1), string(raw) + `{}`, strings.Replace(string(raw), `"Produce a synthetic summary"`, `"\ud800"`, 1)} {
		if _, err := Decode([]byte(malformed)); err == nil {
			t.Fatal("malformed definition accepted")
		}
	}
}
func TestInputAndOutputRefusals(t *testing.T) {
	t.Parallel()
	d := sample()
	for _, bindings := range [][]Binding{nil, {{Name: "foreign", Value: json.RawMessage(`"x"`), SourceVersion: "v1"}}, {{Name: "source", Value: json.RawMessage(`42`), SourceVersion: "v1"}}, {{Name: "source", Value: json.RawMessage(`"x"`)}}, {{Name: "source", Value: json.RawMessage(`"x"`), SourceVersion: "v1"}, {Name: "source", Value: json.RawMessage(`"x"`), SourceVersion: "v1"}}} {
		if _, err := Bind(d, bindings); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	for _, raw := range []string{`{"summary":4}`, `{"summary":"x","extra":"x"}`, `{}`, `{"summary":"a","summary":"b"}`, "```json\n{\"summary\":\"x\"}\n```"} {
		if _, err := ReturnedValues(d, []byte(raw), "attempt"); err == nil {
			t.Fatal("invalid return accepted", raw)
		}
	}
	d.ExpectedInputs[0] = DataContract{Name: "source", Type: "file", Required: true, FileName: "source.md", MediaType: "text/markdown", MaxBytes: 1024}
	if _, err := Bind(d, []Binding{{Name: "source", Value: json.RawMessage(`"host-path"`), SourceVersion: "v1"}}); err == nil {
		t.Fatal("unverified file claim accepted")
	}
}
func TestFileAndBundleContracts(t *testing.T) {
	t.Parallel()
	valid := DataContract{Name: "guide", Type: "file", FileName: "guide.md", Required: true, MediaType: "text/markdown", MaxBytes: 1024}
	if ValidData(valid) != nil {
		t.Fatal("valid file refused")
	}
	valid.Type = "bundle"
	valid.FileName = ""
	valid.MediaType = "application/vnd.commonroom.bundle+json"
	valid.Members = []BundleMember{{Name: "docs/guide.md", MediaType: "text/markdown", MaxBytes: 512}}
	if ValidData(valid) != nil {
		t.Fatal("valid bundle refused")
	}
	for _, path := range []string{"..", "../escape", "/absolute", "a/../b", "a\\b", "C:drive"} {
		bad := valid
		bad.Members = []BundleMember{{Name: path, MediaType: "text/plain", MaxBytes: 512}}
		if ValidData(bad) == nil {
			t.Fatal("unsafe manifest accepted", path)
		}
	}
	d := sample()
	d.DesiredOutputs = []DataContract{valid}
	d.AcceptanceCriteria[0].Output = "guide"
	if Validate(d) != nil || Executable(d) == nil {
		t.Fatal("file declaration/execution capability conflated")
	}
}
func TestRegisteredValueSchemas(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		id, raw string
		valid   bool
	}{{"text.v1", `"text"`, true}, {"integer.v1", `9223372036854775807`, true}, {"integer.v1", `9223372036854775808`, false}, {"integer.v1", `1.5`, false}, {"number.v1", `1e500`, false}, {"boolean.v1", `false`, true}, {"object.v1", `{"a":1}`, true}, {"object.v1", `{"a":1,"a":2}`, false}, {"array.v1", `[1,"x"]`, true}, {"array.v1", `null`, false}} {
		if ValidValue(v.id, []byte(v.raw)) != v.valid {
			t.Fatal(v)
		}
	}
}

func TestConcreteObjectAndArrayContracts(t *testing.T) {
	t.Parallel()
	object := DataContract{Name: "result", Type: "value", Required: true, SchemaID: "object.v1", MaxBytes: 1024, Properties: []ValueProperty{{Name: "count", SchemaID: "integer.v1", Required: true}, {Name: "label", SchemaID: "text.v1"}}}
	for _, test := range []struct {
		raw   string
		valid bool
	}{{`{"count":2}`, true}, {`{"count":2,"label":"x"}`, true}, {`{"count":"two"}`, false}, {`{"label":"x"}`, false}, {`{"count":2,"unexpected":true}`, false}} {
		if ValidContractValue(object, []byte(test.raw)) != test.valid {
			t.Fatal(test)
		}
	}
	object.Properties = nil
	if ValidData(object) == nil {
		t.Fatal("undefined object shape accepted")
	}
	array := DataContract{Name: "items", Type: "value", SchemaID: "array.v1", MaxBytes: 1024, ItemSchemaID: "integer.v1", MaxItems: 2}
	if !ValidContractValue(array, []byte(`[1,2]`)) || ValidContractValue(array, []byte(`[1,"2"]`)) || ValidContractValue(array, []byte(`[1,2,3]`)) {
		t.Fatal("array item contract bypassed")
	}
	d := sample()
	d.ExpectedInputs[0] = DataContract{Name: "source", Type: "value", Required: true, SchemaID: "integer.v1", MaxBytes: 64}
	bound, err := Bind(d, []Binding{{Name: "source", ValueJSON: `9223372036854775807`, SourceVersion: "exact-v1"}})
	if err != nil || bound[0].ValueJSON != `9223372036854775807` {
		t.Fatal("exact numeric input lost precision", bound, err)
	}
}

func TestUnresolvedReturnedValueReferenceIsNeverAManualBinding(t *testing.T) {
	t.Parallel()
	for _, input := range []Binding{
		{Name: "source", Source: &ValueReference{ExecutionID: "attempt", OutputName: "summary"}},
		{Name: "source", Value: json.RawMessage(`"spoof"`), SourceVersion: "attempt/summary", Source: &ValueReference{ExecutionID: "attempt", OutputName: "summary"}},
	} {
		if _, err := Bind(sample(), []Binding{input}); err == nil {
			t.Fatal("unverified reference accepted by pure value binder")
		}
	}
}
