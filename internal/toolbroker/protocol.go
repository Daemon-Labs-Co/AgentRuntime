// Package toolbroker defines admission for the planned credential-free tool bridge.
// The injected dispatcher requires audit acknowledgement but provides no real
// executor, filesystem access or transport. A reservation is NOT permission to
// perform a side effect. Production runtime separation remains unwired.
package toolbroker

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"commonroom-runtime/internal/strictjson"
)

const MaxRequestBytes = 64 * 1024
const MaxCalls = 100

var ErrRejected = errors.New("tool request rejected")

// Scope is supplied by trusted supervisor state, never inferred from a model.
// Version is the bridge protocol version, independent of worker lifecycle versions.
type Scope struct {
	Version          int       `json:"version"`
	JobID            string    `json:"jobId"`
	Room             string    `json:"room"`
	Participant      string    `json:"participant"`
	Connection       string    `json:"connection"`
	Provider         string    `json:"provider"`
	RepositoryDigest string    `json:"repositoryDigest"`
	Deadline         time.Time `json:"deadline"`
}

// Request accepts only typed workspace operations, never container launch options.
// Path validation here is lexical; execution MUST separately prevent symlink,
// mount and special-file escapes using trusted workspace descriptors.
type Request struct {
	Scope      Scope    `json:"scope"`
	Capability string   `json:"capability"`
	CallID     string   `json:"callId"`
	Operation  string   `json:"operation"`
	Path       string   `json:"path,omitempty"`
	Content    string   `json:"content,omitempty"`
	Command    []string `json:"command,omitempty"`
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func digest(s string, size int) bool {
	if size <= 0 || len(s) != size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func operation(s string) bool { return s == "read" || s == "write" || s == "patch" || s == "command" }
func validRequest(r Request) bool {
	if !identifier(r.CallID) || !operation(r.Operation) || !digest(r.Capability, 32) {
		return false
	}
	return validAction(Action{r.Operation, r.Path, r.Content, r.Command})
}

func validAction(a Action) bool {
	if !operation(a.Operation) || !actionTextBudget(a) {
		return false
	}
	if !utf8.ValidString(a.Path) || !utf8.ValidString(a.Content) {
		return false
	}
	for _, arg := range a.Command {
		if !utf8.ValidString(arg) {
			return false
		}
	}
	r := Request{Operation: a.Operation, Path: a.Path, Content: a.Content, Command: a.Command}
	if r.Operation == "command" {
		if r.Path != "" || r.Content != "" || len(r.Command) == 0 || len(r.Command) > 128 {
			return false
		}
		for _, arg := range r.Command {
			if len(arg) > 8192 || strings.ContainsRune(arg, 0) {
				return false
			}
		}
		return r.Command[0] != ""
	}
	if len(r.Command) != 0 || r.Path == "" || len(r.Path) > 4096 || strings.ContainsAny(r.Path, "\\\x00") || path.IsAbs(r.Path) || path.Clean(r.Path) != r.Path || r.Path == "." || r.Path == ".." || strings.HasPrefix(r.Path, "../") {
		return false
	}
	return r.Operation != "read" || r.Content == ""
}

// Decode bounds the whole message and rejects ambiguous, unknown or trailing JSON.
// It never includes the request or capability in diagnostics.
func Decode(reader io.Reader) (Request, error) {
	var r Request
	raw, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil || len(raw) > MaxRequestBytes || !strictjson.ValidEncoding(raw) {
		return r, ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err = uniqueValue(d, 0); err != nil {
		return r, ErrRejected
	}
	if _, err = d.Token(); err != io.EOF {
		return r, ErrRejected
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil || !validRequest(r) {
		return Request{}, ErrRejected
	}
	return r, nil
}

// uniqueValue detects duplicate members at every nesting level before decoding.
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrRejected
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		if token == nil {
			return ErrRejected
		}
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || !knownKey(s) || seen[s] {
				return ErrRejected
			}
			seen[s] = true
			if err = uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrRejected
	}
	_, err = d.Token()
	return err
}

// Authority owns immutable policy and a capability hash. Do not serialize it.
// The bridge transport must authenticate its expected peer independently.
type Authority struct {
	mu      sync.Mutex
	scope   Scope
	issued  time.Time
	hash    [32]byte
	allowed map[string]bool
	calls   map[string]bool
	revoked bool
	done    chan struct{}
	slot    chan struct{}
}

// New mints authority for at most three minutes using a trusted clock. The raw
// token is returned once for protected delivery; never log or persist it in chat.
func New(scope Scope, allowed []string, now time.Time) (*Authority, string, error) {
	if !validScope(scope, now) {
		return nil, "", ErrRejected
	}
	scope.Deadline = scope.Deadline.UTC().Round(0)
	a := &Authority{scope: scope, issued: now, allowed: map[string]bool{}, calls: map[string]bool{}, done: make(chan struct{}), slot: make(chan struct{}, 1)}
	for _, op := range allowed {
		if !operation(op) {
			return nil, "", ErrRejected
		}
		a.allowed[op] = true
	}
	if len(a.allowed) == 0 {
		return nil, "", ErrRejected
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, "", err
	}
	token := hex.EncodeToString(secret[:])
	a.hash = sha256.Sum256([]byte(token))
	return a, token, nil
}

// Reserve atomically consumes a call ID, including failed future executions.
// Replays are refused, not retried. Future dispatch still requires durable audit
// intent, cancellation checks and credential-free execution. Caller time is trusted.
func (a *Authority) Reserve(r Request, now time.Time) error {
	if !validRequest(r) {
		return ErrRejected
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r.Scope.Deadline = r.Scope.Deadline.UTC().Round(0)
	hash := sha256.Sum256([]byte(r.Capability))
	if a.revoked || now.Before(a.issued) || !now.Before(a.scope.Deadline) || r.Scope != a.scope || subtle.ConstantTimeCompare(hash[:], a.hash[:]) != 1 || !a.allowed[r.Operation] || len(a.calls) >= MaxCalls || a.calls[r.CallID] {
		return ErrRejected
	}
	// Enforce the same wire-size budget for in-process callers.
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRequestBytes {
		return ErrRejected
	}
	a.calls[r.CallID] = true
	return nil
}

// Revoke fences all future reservations. It does not stop already running tools;
// the future supervisor must cancel and verify both container lifecycles.
func (a *Authority) Revoke() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.revoked {
		a.revoked = true
		close(a.done)
	}
}

func knownKey(s string) bool {
	switch s {
	case "scope", "capability", "callId", "operation", "path", "content", "command", "version", "jobId", "room", "participant", "connection", "provider", "repositoryDigest", "deadline":
		return true
	}
	return false
}

func validScope(scope Scope, now time.Time) bool {
	return !(scope.Version != 1 || !digest(scope.JobID, 16) || !digest(scope.RepositoryDigest, 32) || !identifier(scope.Room) || !identifier(scope.Participant) || !identifier(scope.Connection) || (scope.Provider != "codex" && scope.Provider != "claude") || !scope.Deadline.After(now) || scope.Deadline.Sub(now) > 3*time.Minute)
}

// actionTextBudget refuses typed oversized input before hashing/copying/encoding.
// JSON encoding may expand escaped characters; the serialized cap is still
// checked afterwards, but its worst-case allocation is now bounded.
func actionTextBudget(a Action) bool {
	if len(a.Command) > 128 || len(a.Content) > MaxRequestBytes || len(a.Path) > 4096 {
		return false
	}
	total := len(a.Operation) + len(a.Path) + len(a.Content)
	if total > MaxRequestBytes {
		return false
	}
	for _, arg := range a.Command {
		if len(arg) > 8192 || len(arg) > MaxRequestBytes-total {
			return false
		}
		total += len(arg)
	}
	return true
}

// permitsAction is a defense-in-depth executor gate, not an audit acknowledgement
// or capability-bearing admission. It never expands or consumes the copied job
// policy. External requests must still pass the authenticated audited dispatcher.
func (a *Authority) permitsAction(scope Scope, action Action, now time.Time) bool {
	if !validAction(action) {
		return false
	}
	scope.Deadline = scope.Deadline.UTC().Round(0)
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.revoked && !now.Before(a.issued) && now.Before(a.scope.Deadline) && scope == a.scope && a.allowed[action.Operation]
}
