//go:build linux || darwin

// Package workspacesnapshot captures finite source bytes under a mandatory
// trusted frozen-volume lease. It is internal infrastructure, not a host file
// API, production exporter or proof that a model produced useful work. Managed
// use MUST borrow the verified credential-free isolated tool root after writers
// are fenced. A source fork CAN supply a host root or dishonest lease, BUT then
// source/isolation claims are invalid. No default lease or host fallback exists.
package workspacesnapshot

import (
	"commonroom-runtime/internal/objectcustody"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxEntries             = 10000
	MaxDepth               = 32
	MaxPathBytes           = 2048
	MaxTreeBytes     int64 = 256 * 1024 * 1024
	MaxFileBytes     int64 = objectcustody.MaxObjectBytes
	MaxSelectedBytes int64 = objectcustody.MaxObjectBytes
	MaxMembers             = 32
)

var ErrRefused = errors.New("isolated source snapshot refused")

// Binding is trusted creator/import metadata, not model claims or authority.
// Execution.RevisionDigest MUST be empty on input: capture computes it from
// actual bounded source entries. BaseCommit identifies the imported revision;
// it does not claim that the workspace is clean or that Git HEAD is unchanged.
type Binding struct {
	Execution       objectcustody.ExecutionScope `json:"execution"`
	BaseCommit      string                       `json:"baseCommit"`
	VolumeName      string                       `json:"volumeName"`
	VolumeNonce     string                       `json:"volumeNonce"`
	VolumeCreatedAt string                       `json:"volumeCreatedAt"`
}

// FrozenLease is TRUSTED worker/controller infrastructure, never a model/plugin.
// VerifyFrozen must authenticate exact job/creator/volume/root identity, establish
// an actual read-only isolated view, prove all other writers fenced under the
// creator lease, and check current principal/revision/export policy plus durable authorization
// for bounded source observation. Existing workspace bytes must already be
// accounted; capture creates no custody object or on-disk copy. Read-only
// access in this process alone does not freeze other mounts. Calls must respect
// context. No production lease implementation is supplied by this package.
// Tests use explicit synthetic leases; those cannot admit real source work.
type FrozenLease interface {
	VerifyFrozen(context.Context, *os.Root, Binding) error
}

type Member struct {
	OutputName string `json:"outputName"`
	Name       string `json:"name"`
	MaxBytes   int64  `json:"maxBytes"`
}

// Entry describes observed source content; it is not an independently observed
// build/test check. Git's root metadata directory is excluded and never executed.
type Entry struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest,omitempty"`
}
type Snapshot struct {
	Version    int                          `json:"version"`
	Binding    Binding                      `json:"binding"`
	Scope      objectcustody.ExecutionScope `json:"scope"`
	Entries    []Entry                      `json:"entries"`
	Members    []Member                     `json:"members"`
	TotalBytes int64                        `json:"totalBytes"`
	Digest     string                       `json:"digest"`
}

// Source borrows a pinned root and live trusted lease; caller keeps both valid
// until all reads finish. It never owns/deletes source or creates storage files.
// No constructor accepts a precomputed snapshot or model-provided bytes.
type Source struct {
	root     *os.Root
	lease    FrozenLease
	snapshot Snapshot
	selected map[string][]byte
}

func absent(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func active(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }
func validHexDigest(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func validBinding(b Binding) bool {
	e := b.Execution
	if e.RevisionDigest != "" {
		return false
	}
	e.RevisionDigest = strings.Repeat("0", 64)
	t, err := time.Parse(time.RFC3339Nano, b.VolumeCreatedAt)
	return objectcustody.ValidExecutionScope(e) && (validHexDigest(b.BaseCommit, 20) || validHexDigest(b.BaseCommit, 32)) && b.VolumeName == "commonroom-tool-work-"+e.JobID && validHexDigest(b.VolumeNonce, 16) && err == nil && !t.IsZero() && len(b.VolumeCreatedAt) <= 64
}
func safeName(name string) bool {
	if name == "" || len(name) > MaxPathBytes || !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name || name == "." || name == ".." || strings.ContainsAny(name, "\\\x00:") || strings.HasPrefix(name, "../") {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if strings.EqualFold(part, ".git") {
			return false
		}
	}
	return true
}
func safeInfo(info os.FileInfo, directory bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
		return false
	}
	if directory {
		return info.IsDir()
	}
	return info.Mode().IsRegular() && st.Nlink == 1
}
func validateMembers(b Binding, members []Member) bool {
	if len(members) < 1 || len(members) > MaxMembers {
		return false
	}
	names := map[string]bool{}
	var total int64
	for _, m := range members {
		if !safeName(m.Name) || names[m.Name] || m.MaxBytes < 1 || m.MaxBytes > MaxFileBytes || m.MaxBytes > MaxSelectedBytes-total {
			return false
		}
		scope := objectcustody.Scope{ExecutionScope: b.Execution, OutputName: m.OutputName, MemberName: m.Name}
		scope.RevisionDigest = strings.Repeat("0", 64)
		if !objectcustody.ValidIntent(objectcustody.Intent{ObjectID: strings.Repeat("0", 32), Scope: scope, MaxBytes: m.MaxBytes}) {
			return false
		}
		names[m.Name] = true
		total += m.MaxBytes
	}
	return true
}

// ValidSelection validates finite metadata only, without opening a root or
// granting source authority. Capture still requires a live trusted frozen lease.
func ValidSelection(b Binding, members []Member) bool {
	return validBinding(b) && validateMembers(b, members)
}

func verify(ctx context.Context, root *os.Root, lease FrozenLease, b Binding) error {
	if !active(ctx) || root == nil || absent(lease) || !validBinding(b) {
		return ErrRefused
	}
	if err := lease.VerifyFrozen(ctx, root, b); err != nil || !active(ctx) {
		return ErrRefused
	}
	info, err := root.Lstat(".")
	if err != nil || !safeInfo(info, true) {
		return ErrRefused
	}
	return nil
}

// Capture enumerates/hashes the actual finite tree twice under the frozen lease,
// buffers only approved members, and computes the revision identity itself.
// It never shells out, follows Git configuration, reads .git or fetches URLs.
// Double observation detects mutations but is NOT a replacement for real fencing.
func Capture(ctx context.Context, root *os.Root, b Binding, members []Member, lease FrozenLease) (*Source, error) {
	if !validateMembers(b, members) || verify(ctx, root, lease, b) != nil {
		return nil, ErrRefused
	}
	selected := map[string]Member{}
	for _, m := range members {
		selected[m.Name] = m
	}
	entries, contents, total, err := scan(ctx, root, selected)
	if err != nil || verify(ctx, root, lease, b) != nil {
		return nil, ErrRefused
	}
	again, _, secondTotal, err := scan(ctx, root, nil)
	if err != nil || total != secondTotal || !sameEntries(entries, again) || verify(ctx, root, lease, b) != nil {
		return nil, ErrRefused
	}
	for _, m := range members {
		if _, ok := contents[m.Name]; !ok {
			return nil, ErrRefused
		}
	}
	copyMembers := append([]Member(nil), members...)
	sort.Slice(copyMembers, func(i, j int) bool { return copyMembers[i].Name < copyMembers[j].Name })
	snapshot := Snapshot{Version: 1, Binding: b, Entries: entries, Members: copyMembers, TotalBytes: total}
	revision, err := json.Marshal(struct {
		Version    int
		Binding    Binding
		Entries    []Entry
		TotalBytes int64
	}{1, b, entries, total})
	if err != nil {
		return nil, ErrRefused
	}
	sum := sha256.Sum256(revision)
	snapshot.Scope = b.Execution
	snapshot.Scope.RevisionDigest = hex.EncodeToString(sum[:])
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, ErrRefused
	}
	sum = sha256.Sum256(raw)
	snapshot.Digest = hex.EncodeToString(sum[:])
	return &Source{root: root, lease: lease, snapshot: snapshot, selected: contents}, nil
}
func sameEntries(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (s *Source) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	result := s.snapshot
	result.Entries = append([]Entry(nil), s.snapshot.Entries...)
	result.Members = append([]Member(nil), s.snapshot.Members...)
	return result
}

// Current re-observes the complete tree, not only the selected artifact. It
// refuses a changed unrelated source file and never edits/adopts the snapshot.
func (s *Source) Current(ctx context.Context) error {
	if s == nil || verify(ctx, s.root, s.lease, s.snapshot.Binding) != nil {
		return ErrRefused
	}
	entries, _, total, err := scan(ctx, s.root, nil)
	if err != nil || total != s.snapshot.TotalBytes || !sameEntries(entries, s.snapshot.Entries) || verify(ctx, s.root, s.lease, s.snapshot.Binding) != nil {
		return ErrRefused
	}
	return nil
}
func (s *Source) member(scope objectcustody.Scope, max int64) ([]byte, bool) {
	if s == nil || scope.ExecutionScope != s.snapshot.Scope {
		return nil, false
	}
	for _, m := range s.snapshot.Members {
		if m.OutputName == scope.OutputName && m.Name == scope.MemberName && max == m.MaxBytes {
			b, ok := s.selected[m.Name]
			return b, ok
		}
	}
	return nil, false
}

// Open prepares a lazy bounded reader; its first Read revalidates current source
// authority and the complete revision before returning an independent byte copy. Intended caller is the trusted
// custody store, not an HTTP/model endpoint. Custody must still reserve/account
// and establish its physical quota BEFORE reading this stream. Capture itself is
// a separately authorized bounded source-observation operation under FrozenLease.
func (s *Source) Open(ctx context.Context, scope objectcustody.Scope, max int64) (io.ReadCloser, error) {
	raw, ok := s.member(scope, max)
	if !ok || !active(ctx) {
		return nil, ErrRefused
	}
	return &sourceReader{ctx: ctx, source: s, raw: raw}, nil
}

// VerifyReceipt ties stored bytes to the observed source member, not a supplied
// digest string alone. Physical custody quota and root proof remain separate.
func (s *Source) VerifyReceipt(ctx context.Context, receipt objectcustody.Receipt) error {
	if !objectcustody.ValidReceipt(receipt) {
		return ErrRefused
	}
	raw, ok := s.member(receipt.Intent.Scope, receipt.Intent.MaxBytes)
	if !ok || int64(len(raw)) != receipt.Bytes || s.Current(ctx) != nil {
		return ErrRefused
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != receipt.Digest {
		return ErrRefused
	}
	return nil
}

type sourceReader struct {
	mu              sync.Mutex
	ctx             context.Context
	data, raw       []byte
	offset          int
	closed, started bool
	source          *Source
}

func (r *sourceReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !active(r.ctx) {
		return 0, ErrRefused
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !r.started {
		if r.source.Current(r.ctx) != nil {
			return 0, ErrRefused
		}
		r.data = append([]byte(nil), r.raw...)
		r.raw = nil
		r.started = true
	}
	if r.offset == len(r.data) {
		return 0, io.EOF
	}
	if verify(r.ctx, r.source.root, r.source.lease, r.source.snapshot.Binding) != nil {
		return 0, ErrRefused
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
func (r *sourceReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	clear(r.data)
	r.data = nil
	r.raw = nil
	return nil
}

func scan(ctx context.Context, root *os.Root, selected map[string]Member) ([]Entry, map[string][]byte, int64, error) {
	rootInfo, err := root.Lstat(".")
	if err != nil || !safeInfo(rootInfo, true) {
		return nil, nil, 0, ErrRefused
	}
	entries := []Entry{{Name: ".", Kind: "directory", Mode: uint32(rootInfo.Mode().Perm())}}
	contents := map[string][]byte{}
	var total int64
	var walk func(*os.Root, string, int) error
	walk = func(dir *os.Root, prefix string, depth int) error {
		if !active(ctx) || depth > MaxDepth {
			return ErrRefused
		}
		handle, err := dir.Open(".")
		if err != nil {
			return ErrRefused
		}
		children, err := handle.ReadDir(MaxEntries + 1)
		closeErr := handle.Close()
		if err != nil && err != io.EOF || closeErr != nil || len(children) > MaxEntries {
			return ErrRefused
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			if !active(ctx) {
				return ErrRefused
			}
			name := child.Name()
			full := name
			if prefix != "" {
				full = prefix + "/" + name
			}
			info, err := dir.Lstat(name)
			if err != nil {
				return ErrRefused
			}
			if prefix == "" && name == ".git" {
				if !safeInfo(info, true) {
					return ErrRefused
				}
				continue
			}
			if !safeName(full) || len(entries) >= MaxEntries {
				return ErrRefused
			}
			if info.IsDir() {
				if !safeInfo(info, true) {
					return ErrRefused
				}
				nested, err := dir.OpenRoot(name)
				if err != nil {
					return ErrRefused
				}
				pinned, err := nested.Lstat(".")
				if err != nil || !os.SameFile(info, pinned) {
					nested.Close()
					return ErrRefused
				}
				entries = append(entries, Entry{Name: full, Kind: "directory", Mode: uint32(info.Mode().Perm())})
				err = walk(nested, full, depth+1)
				closeErr := nested.Close()
				if err != nil || closeErr != nil {
					return ErrRefused
				}
				after, err := dir.Lstat(name)
				if err != nil || !os.SameFile(info, after) || !safeInfo(after, true) {
					return ErrRefused
				}
			} else {
				if !safeInfo(info, false) || info.Size() < 0 || info.Size() > MaxFileBytes || info.Size() > MaxTreeBytes-total {
					return ErrRefused
				}
				f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
				if err != nil {
					return ErrRefused
				}
				pinned, err := f.Stat()
				if err != nil || !os.SameFile(info, pinned) || !safeInfo(pinned, false) {
					f.Close()
					return ErrRefused
				}
				h := sha256.New()
				var data []byte
				buffer := make([]byte, 32*1024)
				var count int64
				member, wanted := selected[full]
				for {
					if !active(ctx) {
						f.Close()
						return ErrRefused
					}
					n, e := f.Read(buffer)
					if n > 0 {
						if int64(n) > MaxFileBytes-count || int64(n) > MaxTreeBytes-total-count || (wanted && int64(n) > member.MaxBytes-count) {
							f.Close()
							return ErrRefused
						}
						count += int64(n)
						h.Write(buffer[:n])
						if wanted {
							data = append(data, buffer[:n]...)
						}
					}
					if e == io.EOF {
						break
					}
					if e != nil || n == 0 {
						f.Close()
						return ErrRefused
					}
				}
				after, e := f.Stat()
				closeErr := f.Close()
				current, e2 := dir.Lstat(name)
				if e != nil || e2 != nil || closeErr != nil || count != info.Size() || after.Size() != count || !os.SameFile(info, after) || !os.SameFile(info, current) || !safeInfo(after, false) || !safeInfo(current, false) || after.Mode() != info.Mode() || current.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) || !current.ModTime().Equal(info.ModTime()) {
					return ErrRefused
				}
				total += count
				entries = append(entries, Entry{Name: full, Kind: "file", Mode: uint32(info.Mode().Perm()), Bytes: count, Digest: hex.EncodeToString(h.Sum(nil))})
				if wanted {
					if data == nil {
						data = []byte{}
					}
					contents[full] = data
				}
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return nil, nil, 0, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, contents, total, nil
}
