package toolbroker

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"commonroom-runtime/internal/strictjson"
)

const MaxAuditFrameBytes = 4096

// ValidAuditScope validates trusted admission metadata against a trusted clock.
func ValidAuditScope(scope Scope, now time.Time) bool { return validScope(scope, now) }

// AuditFrame belongs to the authenticated supervisor/controller channel, never
// the model's callback channel. It contains hashes and bounded lifecycle metadata,
// never actions or capabilities.
type AuditFrame struct {
	Delegation *DelegationRequest `json:"delegation,omitempty"`
	IdleStop   *IdleStop          `json:"idleStop,omitempty"`
	Version    int                `json:"version"`
	Sequence   int                `json:"sequence"`
	Session    string             `json:"session"`
	Stage      string             `json:"stage"`
	Intent     Intent             `json:"intent"`
	Outcome    *Outcome           `json:"outcome,omitempty"`
}

type auditAck struct {
	Version  int    `json:"version"`
	Digest   string `json:"digest"`
	Accepted bool   `json:"accepted"`
}

// ValidAuditIntent checks bounded metadata. now is a trusted admission clock;
// outcome persistence may instead use the original intent's admission instant.
func ValidAuditIntent(intent Intent, now time.Time) bool {
	return validScope(intent.Scope, now) && identifier(intent.CallID) && operation(intent.Operation) && digest(intent.PayloadDigest, 32)
}

// ValidAuditOutcome bounds evidence metadata; hashes are not filesystem attestation.
func ValidAuditOutcome(outcome Outcome) bool {
	if outcome.OutputBytes < 0 || outcome.OutputBytes > MaxOutputBytes || !digest(outcome.OutputDigest, 32) {
		return false
	}
	switch outcome.Status {
	case "succeeded", "failed", "output_limit", "not_executed":
		return true
	}
	return false
}

func auditFrameDigest(frame AuditFrame) (string, error) {
	raw, err := json.Marshal(frame)
	if err != nil || len(raw) > MaxAuditFrameBytes {
		return "", ErrAudit
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

// auditDecode rejects duplicate/unknown/case-folded/missing members and explicit
// nulls before typed decoding. All wire fields are mandatory except outcome and
// the version-2 idleStop extension. Stage validation forbids mixed payloads.
func auditDecode(raw []byte, target any) error {
	if len(raw) > MaxAuditFrameBytes || !strictjson.ValidEncoding(raw) {
		return ErrAudit
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if auditUniqueValue(decoder, 0) != nil {
		return ErrAudit
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrAudit
	}
	var fields any
	if json.Unmarshal(raw, &fields) != nil || !auditShape(fields, reflect.TypeOf(target).Elem()) {
		return ErrAudit
	}
	if json.Unmarshal(raw, target) != nil {
		return ErrAudit
	}
	return nil
}

func auditShape(value any, schema reflect.Type) bool {
	if schema.Kind() == reflect.Pointer {
		return auditShape(value, schema.Elem())
	}
	if schema == reflect.TypeOf(time.Time{}) {
		_, ok := value.(string)
		return ok
	}
	if schema.Kind() != reflect.Struct {
		return true // typed decoding enforces primitive types/ranges
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return false
	}
	known := 0
	for index := 0; index < schema.NumField(); index++ {
		field := schema.Field(index)
		tag := field.Tag.Get("json")
		name := tag
		optional := false
		if comma := bytes.IndexByte([]byte(tag), ','); comma >= 0 {
			name, optional = tag[:comma], tag[comma+1:] == "omitempty"
		}
		child, present := fields[name]
		if !present {
			if !optional {
				return false
			}
			continue
		}
		known++
		if !auditShape(child, field.Type) {
			return false
		}
	}
	return known == len(fields)
}

func auditUniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrAudit
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return ErrAudit
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delim != '{' {
		return ErrAudit
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return ErrAudit
		}
		seen[key] = true
		if auditUniqueValue(decoder, depth+1) != nil {
			return ErrAudit
		}
	}
	_, err = decoder.Token()
	return err
}

func auditRead(reader *bufio.Reader, target any) error {
	raw, err := reader.ReadSlice('\n')
	if err != nil || len(raw) > MaxAuditFrameBytes {
		return ErrAudit
	}
	return auditDecode(raw, target)
}

func auditWrite(writer io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > MaxAuditFrameBytes {
		return ErrAudit
	}
	raw = append(raw, '\n')
	n, err := writer.Write(raw)
	if err != nil || n != len(raw) {
		return ErrAudit
	}
	return nil
}
