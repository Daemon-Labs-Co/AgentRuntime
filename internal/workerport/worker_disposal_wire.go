package workerport

import (
	"bytes"
	"commonroom-runtime/internal/strictjson"
	"encoding/json"
	"errors"
	"io"
)

// Destructive request/receipt objects require exact keys and unique fields.
// encoding/json alone accepts aliases, duplicate keys and null scalar values.
// The wire bound is intentionally shared with existing cancellation transport.
func fenceObjectFields(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 4096 || !strictjson.ValidEncoding(raw) {
		return nil, errors.New("invalid fence object")
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("invalid fence object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || fields[name] != nil {
			return nil, errors.New("invalid fence field")
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("invalid fence value")
		}
		fields[name] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("invalid fence object")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing fence data")
	}
	return fields, nil
}

func validFenceWire(raw []byte, ack bool) bool {
	keys := []string{"repository", "discardWorkspace", "expectedWorkspace", "version", "jobId", "provider", "key"}
	identity := "expectedWorkspace"
	if ack {
		keys = []string{"version", "jobId", "scope", "stopped", "cancellationRequested", "execution", "repository", "workspaceRemoved", "discardedWorkspace"}
		identity = "discardedWorkspace"
	}
	fields, err := fenceObjectFields(raw, keys...)
	if err != nil {
		return false
	}
	if nested, ok := fields[identity]; ok {
		if _, err = fenceObjectFields(nested, "version", "name", "nonce", "createdAt"); err != nil {
			return false
		}
	}
	return true
}
