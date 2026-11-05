// Package taskcontract defines finite task contracts. Descriptive instructions
// never grant resource/tool authority; callers must intersect limits with their
// existing authenticated execution policies and keep attempts separate.
package taskcontract

import (
	"bytes"
	"commonroom-runtime/internal/strictjson"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxDefinitionBytes = 48 * 1024
const MaxValueBytes = 16 * 1024

var namePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,47}$`)

type Definition struct {
	SchemaVersion        int            `json:"schemaVersion"`
	Revision             int            `json:"revision"`
	Task                 string         `json:"task"`
	ExpectedInputs       []DataContract `json:"expectedInput"`
	Process              Process        `json:"process"`
	DesiredOutputs       []DataContract `json:"desiredOutput"`
	AcceptanceCriteria   []Criterion    `json:"acceptanceCriteria"`
	ExecutionConstraints Limits         `json:"executionConstraints"`
	FailureContract      Failure        `json:"failureContract"`
}
type Process struct {
	Mode         string   `json:"mode"`
	Instructions string   `json:"instructions"`
	Constraints  []string `json:"constraints"`
}
type DataContract struct {
	Name         string          `json:"name"`
	Type         string          `json:"type"` // file, bundle, value; no arbitrary provider type.
	Required     bool            `json:"required"`
	MediaType    string          `json:"mediaType,omitempty"`
	SchemaID     string          `json:"schemaId,omitempty"`
	MaxBytes     int64           `json:"maxBytes"`
	FileName     string          `json:"fileName,omitempty"`
	Members      []BundleMember  `json:"members,omitempty"`
	Properties   []ValueProperty `json:"properties,omitempty"`
	ItemSchemaID string          `json:"itemSchemaId,omitempty"`
	MaxItems     int             `json:"maxItems,omitempty"`
}
type ValueProperty struct {
	Name     string `json:"name"`
	SchemaID string `json:"schemaId"`
	Required bool   `json:"required"`
}
type BundleMember struct {
	Name      string `json:"name"`
	MediaType string `json:"mediaType"`
	MaxBytes  int64  `json:"maxBytes"`
}
type Criterion struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Method      string `json:"method"`
	Output      string `json:"output"`
}
type Limits struct {
	ResourceScope       string   `json:"resourceScope"`
	AllowedOperations   []string `json:"allowedOperations"`
	MaxDurationSeconds  int      `json:"maxDurationSeconds"`
	MaxResponseBytes    int      `json:"maxResponseBytes"`
	MaxToolCalls        int      `json:"maxToolCalls"`
	CompletionAuthority string   `json:"completionAuthority"`
}
type Failure struct {
	MissingInput     string `json:"missingInput"`
	ExecutionFailure string `json:"executionFailure"`
	Retry            string `json:"retry"`
}

func bounded(s string, max int) bool {
	return utf8.ValidString(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= max && !strings.ContainsRune(s, 0)
}
func media(s string) bool {
	_, _, e := mime.ParseMediaType(s)
	return e == nil && len(s) <= 120 && !strings.ContainsAny(s, "\r\n")
}
func relative(s string) bool {
	return bounded(s, 200) && s != "." && s != ".." && !strings.ContainsAny(s, "\\\r\n:") && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "../") && path.Clean(s) == s
}
func schema(s string) bool {
	switch s {
	case "text.v1", "integer.v1", "number.v1", "boolean.v1", "object.v1", "array.v1":
		return true
	}
	return false
}
func ValidData(c DataContract) error {
	if !namePattern.MatchString(c.Name) || c.MaxBytes < 1 || c.MaxBytes > 16*1024*1024 {
		return errors.New("named data contract needs a bounded positive byte limit")
	}
	switch c.Type {
	case "value":
		if !schema(c.SchemaID) || c.MaxBytes > MaxValueBytes || c.MediaType != "" || c.FileName != "" || len(c.Members) != 0 {
			return errors.New("value needs a registered schema and at most 16384 bytes")
		}
		if c.SchemaID == "object.v1" {
			if len(c.Properties) < 1 || len(c.Properties) > 32 || c.ItemSchemaID != "" || c.MaxItems != 0 {
				return errors.New("object schema requires one to thirty-two named properties")
			}
			seen := map[string]bool{}
			for _, p := range c.Properties {
				if !namePattern.MatchString(p.Name) || seen[p.Name] || !primitive(p.SchemaID) {
					return errors.New("invalid object property schema")
				}
				seen[p.Name] = true
			}
		}
		if c.SchemaID == "array.v1" {
			if !primitive(c.ItemSchemaID) || c.MaxItems < 1 || c.MaxItems > 256 || len(c.Properties) != 0 {
				return errors.New("array schema needs a primitive item schema and maximum item count")
			}
		}
		if primitive(c.SchemaID) && (len(c.Properties) != 0 || c.ItemSchemaID != "" || c.MaxItems != 0) {
			return errors.New("primitive values cannot contain object/array schema fields")
		}
	case "file":
		if len(c.Properties) != 0 || c.ItemSchemaID != "" || c.MaxItems != 0 {
			return errors.New("file cannot contain value schema fields")
		}
		if !media(c.MediaType) || !relative(c.FileName) || c.SchemaID != "" || len(c.Members) != 0 {
			return errors.New("file needs a safe file name and media type")
		}
	case "bundle":
		if len(c.Properties) != 0 || c.ItemSchemaID != "" || c.MaxItems != 0 {
			return errors.New("bundle cannot contain value schema fields")
		}
		if c.MediaType != "application/vnd.commonroom.bundle+json" || c.SchemaID != "" || c.FileName != "" || len(c.Members) < 1 || len(c.Members) > 32 {
			return errors.New("bundle needs a bounded explicit member manifest")
		}
		seen := map[string]bool{}
		var total int64
		for _, m := range c.Members {
			if !relative(m.Name) || !media(m.MediaType) || m.MaxBytes < 1 || m.MaxBytes > c.MaxBytes || seen[m.Name] {
				return errors.New("invalid or duplicate bundle member")
			}
			for previous := range seen {
				if strings.HasPrefix(previous, m.Name+"/") || strings.HasPrefix(m.Name, previous+"/") {
					return errors.New("bundle members overlap as file and directory")
				}
			}
			seen[m.Name] = true
			total += m.MaxBytes
		}
		if total > c.MaxBytes {
			return errors.New("bundle member limits exceed bundle limit")
		}
	default:
		return errors.New("data type must be file, bundle or value")
	}
	return nil
}
func Validate(d Definition) error {
	if d.SchemaVersion != 1 || d.Revision < 1 || !bounded(d.Task, 2000) {
		return errors.New("task definition needs schema version 1, revision and task description")
	}
	if d.ExpectedInputs == nil || len(d.ExpectedInputs) > 16 || len(d.DesiredOutputs) < 1 || len(d.DesiredOutputs) > 8 {
		return errors.New("declare expected inputs (possibly empty) and one to eight outputs")
	}
	for _, list := range [][]DataContract{d.ExpectedInputs, d.DesiredOutputs} {
		seen := map[string]bool{}
		for _, c := range list {
			if err := ValidData(c); err != nil {
				return err
			}
			if seen[c.Name] {
				return errors.New("duplicate data contract name")
			}
			seen[c.Name] = true
		}
	}
	required := false
	outputs := map[string]bool{}
	for _, c := range d.DesiredOutputs {
		required = required || c.Required
		outputs[c.Name] = true
	}
	if !required {
		return errors.New("at least one desired output must be required")
	}
	if (d.Process.Mode != "prescribed" && d.Process.Mode != "objective") || !bounded(d.Process.Instructions, 8000) || d.Process.Constraints == nil || len(d.Process.Constraints) > 16 {
		return errors.New("process requires prescribed/objective instructions and bounded constraints")
	}
	for _, c := range d.Process.Constraints {
		if !bounded(c, 1000) {
			return errors.New("invalid process constraint")
		}
	}
	if len(d.AcceptanceCriteria) < 1 || len(d.AcceptanceCriteria) > 32 {
		return errors.New("declare one to thirty-two acceptance criteria")
	}
	criteria := map[string]bool{}
	for _, c := range d.AcceptanceCriteria {
		if !namePattern.MatchString(c.ID) || criteria[c.ID] || !bounded(c.Description, 2000) || (c.Method != "human" && c.Method != "schema") || !outputs[c.Output] {
			return errors.New("criterion requires unique identity, description, output and human/schema method")
		}
		criteria[c.ID] = true
		if c.Method == "schema" {
			found := false
			for _, o := range d.DesiredOutputs {
				if o.Name == c.Output && o.Type == "value" {
					found = true
				}
			}
			if !found {
				return errors.New("schema criterion requires a value output")
			}
		}
	}
	l := d.ExecutionConstraints
	if len(l.AllowedOperations) > 4 || l.AllowedOperations == nil || l.MaxDurationSeconds < 1 || l.MaxDurationSeconds > 180 || l.MaxResponseBytes < 1 || l.MaxResponseBytes > 16*1024 || l.MaxToolCalls < 1 || l.MaxToolCalls > 64 || l.CompletionAuthority != "owner" || l.ResourceScope != "assigned-task-workspace" {
		return errors.New("invalid bounded execution constraints; completion authority must be owner")
	}
	seen := map[string]bool{}
	for _, op := range l.AllowedOperations {
		if (op != "read" && op != "write" && op != "patch" && op != "command") || seen[op] {
			return errors.New("invalid or duplicate allowed operation")
		}
		seen[op] = true
	}
	if d.FailureContract.MissingInput != "block" || d.FailureContract.ExecutionFailure != "record-and-stop" || d.FailureContract.Retry != "human-only" {
		return errors.New("failure contract must block missing input, record/stop failure and require human retry")
	}
	raw, _ := json.Marshal(d)
	if len(raw) > MaxDefinitionBytes {
		return errors.New("task definition exceeds 48 KiB")
	}
	return nil
}
func Digest(d Definition) string {
	raw, _ := json.Marshal(d)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func Same(a, b Definition) bool { a.Revision = 1; b.Revision = 1; return Digest(a) == Digest(b) }
func Allows(d Definition, operation string) bool {
	for _, op := range d.ExecutionConstraints.AllowedOperations {
		if op == operation {
			return true
		}
	}
	return false
}

// Decode rejects unknown/duplicate object keys, excessive nesting, malformed
// Unicode and trailing JSON. Size limits apply before any decoding allocations.
func Decode(raw []byte) (Definition, error) {
	var d Definition
	if len(raw) > MaxDefinitionBytes || !strictjson.ValidEncoding(raw) {
		return d, errors.New("invalid bounded definition encoding")
	}
	if err := scanJSON(raw); err != nil {
		return d, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	return d, Validate(d)
}
func CriteriaText(d Definition) string {
	parts := make([]string, 0, len(d.AcceptanceCriteria))
	for _, c := range d.AcceptanceCriteria {
		parts = append(parts, fmt.Sprintf("%s [%s]: %s", c.ID, c.Output, c.Description))
	}
	return strings.Join(parts, "\n")
}

func scanJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 12 {
			return errors.New("definition nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				k, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate definition field")
				}
				seen[key] = true
				if err = scan(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON structure")
		}
		_, err = decoder.Token()
		return err
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing definition data")
	}

	return nil
}

func primitive(id string) bool {
	return id == "text.v1" || id == "integer.v1" || id == "number.v1" || id == "boolean.v1"
}

// ValidJSON checks bounded grammar, Unicode, duplicates and depth before typed decoding.
func ValidJSON(raw []byte, maxBytes int) bool {
	return len(raw) <= maxBytes && strictjson.ValidEncoding(raw) && scanJSON(raw) == nil
}
