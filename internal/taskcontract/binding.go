package taskcontract

import (
	"bytes"
	"commonroom-runtime/internal/strictjson"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
)

// Binding belongs to an execution, never to its reusable definition. File and
// bundle references require independently verified immutable storage; this
// initial value-input resolver deliberately refuses unresolved object claims.
// ValueReference names an immutable returned value. Only the controller may
// resolve it and attach accepted-source provenance; labels are not proof.
type ValueReference struct {
	ExecutionID string `json:"executionId"`
	OutputName  string `json:"outputName"`
}
type ValueProvenance struct {
	TaskID           string `json:"taskId"`
	ExecutionID      string `json:"executionId"`
	OutputName       string `json:"outputName"`
	TaskRevision     int    `json:"taskRevision"`
	DefinitionDigest string `json:"definitionDigest"`
	OutputDigest     string `json:"outputDigest"`
}
type Binding struct {
	Source        *ValueReference `json:"source,omitempty"`
	ValueJSON     string          `json:"valueJson,omitempty"`
	Name          string          `json:"name"`
	Value         json.RawMessage `json:"value,omitempty"`
	SourceVersion string          `json:"sourceVersion"`
}
type BoundValue struct {
	Provenance    *ValueProvenance `json:"provenance,omitempty"`
	ValueJSON     string           `json:"valueJson"`
	Name          string           `json:"name"`
	Value         json.RawMessage  `json:"value"`
	SourceVersion string           `json:"sourceVersion"`
	Digest        string           `json:"digest"`
}

func ValidValue(schemaID string, raw []byte) bool {
	if len(raw) > MaxValueBytes || !strictjson.ValidEncoding(raw) || scanJSON(raw) != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return false
	}
	switch schemaID {
	case "text.v1":
		_, ok := value.(string)
		return ok
	case "boolean.v1":
		_, ok := value.(bool)
		return ok
	case "object.v1":
		_, ok := value.(map[string]any)
		return ok
	case "array.v1":
		_, ok := value.([]any)
		return ok
	case "integer.v1":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := strconv.ParseInt(n.String(), 10, 64)
		return err == nil
	case "number.v1":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	}
	return false
}
func Bind(d Definition, inputs []Binding) ([]BoundValue, error) {
	if err := Validate(d); err != nil {
		return nil, err
	}
	if len(inputs) > len(d.ExpectedInputs) {
		return nil, errors.New("unexpected input binding")
	}
	declared := map[string]DataContract{}
	for _, c := range d.ExpectedInputs {
		declared[c.Name] = c
	}
	bound := []BoundValue{}
	seen := map[string]bool{}
	total := 0
	for _, input := range inputs {
		if input.Source != nil {
			return nil, errors.New("returned-value reference requires controller verification")
		}
		if input.ValueJSON != "" {
			if len(input.Value) != 0 {
				return nil, errors.New("input value and valueJson are mutually exclusive")
			}
			input.Value = json.RawMessage(input.ValueJSON)
		}
		c, ok := declared[input.Name]
		if !ok || seen[input.Name] || !bounded(input.SourceVersion, 120) {
			return nil, errors.New("input name/version missing, undeclared or duplicate")
		}
		seen[input.Name] = true
		if c.Type != "value" {
			return nil, errors.New("file/bundle input requires verified immutable object storage; execution blocked")
		}
		if int64(len(input.Value)) > c.MaxBytes || !ValidContractValue(c, input.Value) {
			return nil, errors.New("input value does not match its declared schema/limit")
		}
		canonical := canonicalValue(input.Value)
		if int64(len(canonical)) > c.MaxBytes {
			return nil, errors.New("canonical input value exceeds its byte limit")
		}
		total += len(canonical)
		if total > 32*1024 {
			return nil, errors.New("bound input set exceeds 32 KiB")
		}
		bound = append(bound, BoundValue{Name: input.Name, Value: canonical, ValueJSON: string(canonical), SourceVersion: input.SourceVersion, Digest: bytesDigest(canonical)})
	}
	for _, c := range d.ExpectedInputs {
		if c.Required && !seen[c.Name] {
			return nil, errors.New("required input missing; execution blocked")
		}
	}
	return bound, nil
}

func bytesDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// ReturnedValues validates actual returned JSON, not a model claim that an
// artifact exists. Immutable file/bundle custody belongs to the artifact path.
func ReturnedValues(d Definition, raw []byte, version string) ([]BoundValue, error) {
	if len(raw) > d.ExecutionConstraints.MaxResponseBytes || !strictjson.ValidEncoding(raw) || scanJSON(raw) != nil {
		return nil, errors.New("response is not bounded strict JSON")
	}
	var outputs map[string]json.RawMessage
	if json.Unmarshal(raw, &outputs) != nil || outputs == nil {
		return nil, errors.New("return one JSON object keyed by desired output name")
	}
	declared := map[string]DataContract{}
	for _, c := range d.DesiredOutputs {
		declared[c.Name] = c
	}
	result := []BoundValue{}
	for name, value := range outputs {
		c, ok := declared[name]
		if !ok || c.Type != "value" || int64(len(value)) > c.MaxBytes || !ValidContractValue(c, value) {
			return nil, errors.New("returned output fails its declared type/schema/size contract")
		}
		canonical := canonicalValue(value)
		if int64(len(canonical)) > c.MaxBytes {
			return nil, errors.New("canonical returned value exceeds its byte limit")
		}
		result = append(result, BoundValue{Name: name, Value: canonical, ValueJSON: string(canonical), SourceVersion: version, Digest: bytesDigest(canonical)})
	}
	for _, c := range d.DesiredOutputs {
		if c.Required {
			if _, ok := outputs[c.Name]; !ok {
				return nil, errors.New("required desired output missing")
			}
		}
	}
	canonicalSet := map[string]json.RawMessage{}
	for _, value := range result {
		canonicalSet[value.Name] = value.Value
	}
	encoded, _ := json.Marshal(canonicalSet)
	if len(encoded) > d.ExecutionConstraints.MaxResponseBytes {
		return nil, errors.New("canonical returned JSON exceeds response limit")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
func Executable(d Definition) error {
	for _, c := range d.DesiredOutputs {
		if c.Required && c.Type != "value" {
			return errors.New("file/bundle delivery needs verified artifact storage; this task cannot dispatch yet")
		}
	}
	return nil
}

func canonicalValue(raw []byte) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	_ = dec.Decode(&value)
	result, _ := json.Marshal(value)
	return result
}

func ValidContractValue(c DataContract, raw []byte) bool {
	if ValidData(c) != nil || !ValidValue(c.SchemaID, raw) {
		return false
	}
	if c.SchemaID == "object.v1" {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return false
		}
		declared := map[string]ValueProperty{}
		for _, p := range c.Properties {
			declared[p.Name] = p
			if p.Required {
				if _, ok := object[p.Name]; !ok {
					return false
				}
			}
		}
		for name, value := range object {
			p, ok := declared[name]
			if !ok || !ValidValue(p.SchemaID, value) {
				return false
			}
		}
	}
	if c.SchemaID == "array.v1" {
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || len(values) > c.MaxItems {
			return false
		}
		for _, value := range values {
			if !ValidValue(c.ItemSchemaID, value) {
				return false
			}
		}
	}
	return true
}
