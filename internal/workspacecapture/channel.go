package workspacecapture

import (
	"bytes"
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacemount"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

const MaxControlFrameBytes = 128 * 1024
const MaxControlMessages = 4096

type Report struct {
	Version        int                          `json:"version"`
	Scope          objectcustody.ExecutionScope `json:"scope"`
	SnapshotDigest string                       `json:"snapshotDigest"`
	Receipts       []objectcustody.Receipt      `json:"receipts"`
}
type captureFrame struct {
	Version       int                    `json:"version"`
	Sequence      uint64                 `json:"sequence"`
	BindingDigest string                 `json:"bindingDigest"`
	Operation     string                 `json:"operation"`
	Proof         *workspacemount.Proof  `json:"proof,omitempty"`
	Intent        *objectcustody.Intent  `json:"intent,omitempty"`
	Receipt       *objectcustody.Receipt `json:"receipt,omitempty"`
	Report        *Report                `json:"report,omitempty"`
}
type captureAck struct {
	Version  int    `json:"version"`
	Sequence uint64 `json:"sequence"`
	Accepted bool   `json:"accepted"`
}

// RequestDigest validates finite metadata only. Authentication and reviewed helper,
// creator, source and physical quota proof remain mandatory trusted setup duties.
func RequestDigest(request Request) (string, error) {
	if !workspacemount.ValidChallenge(request.Challenge) || !workspacesnapshot.ValidSelection(request.Binding, request.Members) {
		return "", ErrRefused
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > MaxControlFrameBytes {
		return "", ErrRefused
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func controlWrite(w io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxControlFrameBytes {
		return ErrRefused
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	for _, part := range [][]byte{header[:], raw} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil || n <= 0 || n > len(part) {
				return ErrRefused
			}
			part = part[n:]
		}
	}
	return nil
}
func controlRead(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return ErrRefused
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxControlFrameBytes {
		return ErrRefused
	}
	raw := make([]byte, int(size))
	if _, err := io.ReadFull(r, raw); err != nil {
		return ErrRefused
	}
	if json.Unmarshal(raw, value) != nil {
		return ErrRefused
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrRefused
	}
	return nil
}
func memberIntent(request Request, i objectcustody.Intent) bool {
	if !objectcustody.ValidIntent(i) {
		return false
	}
	scope := i.Scope.ExecutionScope
	scope.RevisionDigest = ""
	if scope != request.Binding.Execution {
		return false
	}
	for _, m := range request.Members {
		if m.OutputName == i.Scope.OutputName && m.Name == i.Scope.MemberName && m.MaxBytes == i.MaxBytes {
			return true
		}
	}
	return false
}
func memberKey(i objectcustody.Intent) string {
	return i.Scope.OutputName + "\x00" + i.Scope.MemberName
}
func digest32(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func validReport(request Request, r Report) bool {
	scope := r.Scope
	scope.RevisionDigest = ""
	if r.Version != 1 || !objectcustody.ValidExecutionScope(r.Scope) || scope != request.Binding.Execution || !digest32(r.SnapshotDigest) || len(r.Receipts) != len(request.Members) {
		return false
	}
	ids, members := map[string]bool{}, map[string]bool{}
	for _, receipt := range r.Receipts {
		id, key := receipt.Intent.ObjectID, memberKey(receipt.Intent)
		if !objectcustody.ValidReceipt(receipt) || !memberIntent(request, receipt.Intent) || receipt.Intent.Scope.ExecutionScope != r.Scope || ids[id] || members[key] {
			return false
		}
		ids[id] = true
		members[key] = true
	}
	return true
}

// CaptureChannel uses ONLY an authenticated supervisor-owned stream connected to
// the reviewed helper, never model stdin/stdout. Both peers pin the same Request
// before I/O. No reconnect, retry, read/release operation or source bytes exist in
// this protocol. Kernel/worker/volume/quota proof comes from trusted authorities,
// not successful frame decoding. A fork exposing/substituting this stream loses
// those guarantees; mandatory managed isolation has no host fallback.
type CaptureChannel struct {
	mu               sync.Mutex
	stream           io.ReadWriteCloser
	lifetime         context.Context
	cancel           context.CancelFunc
	request          Request
	digest           string
	sequence         uint64
	failed, finished bool
	stop             func()
	stopOnce         sync.Once
}

func NewCaptureChannel(ctx context.Context, stream io.ReadWriteCloser, request Request, stop func()) (*CaptureChannel, error) {
	digest, err := RequestDigest(request)
	if ctx == nil || ctx.Err() != nil || stream == nil || isNilDependency(stream) || err != nil || stop == nil {
		return nil, ErrRefused
	}
	request.Members = append([]workspacesnapshot.Member(nil), request.Members...)
	lifetime, cancel := context.WithTimeout(ctx, MaxLifetime)
	return &CaptureChannel{stream: stream, lifetime: lifetime, cancel: cancel, request: request, digest: digest, stop: stop}, nil
}
func (c *CaptureChannel) fail() {
	c.failed = true
	c.stopOnce.Do(func() { c.stream.Close(); c.cancel(); c.stop() })
}
func (c *CaptureChannel) Close() error { c.cancel(); return c.stream.Close() }
func (c *CaptureChannel) exchange(ctx context.Context, frame captureFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || c.finished {
		return ErrRefused
	}
	if c.sequence >= MaxControlMessages || ctx == nil || ctx.Err() != nil || c.lifetime.Err() != nil {
		c.fail()
		return ErrRefused
	}
	deadline, _ := c.lifetime.Deadline()
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	call, shortCancel := context.WithTimeout(call, 5*time.Second)
	defer shortCancel()
	parentStop := context.AfterFunc(c.lifetime, cancel)
	defer parentStop()
	closeIO := context.AfterFunc(call, func() { c.stream.Close() })
	defer closeIO()
	c.sequence++
	frame.Version = 1
	frame.Sequence = c.sequence
	frame.BindingDigest = c.digest
	var ack captureAck
	if controlWrite(c.stream, frame) != nil || controlRead(c.stream, &ack) != nil || ack.Version != 1 || ack.Sequence != c.sequence || !ack.Accepted || call.Err() != nil || c.lifetime.Err() != nil {
		c.fail()
		return ErrRefused
	}
	if frame.Operation == "finish" {
		c.finished = true
	}
	return nil
}
func (c *CaptureChannel) AuthorizeFrozenSource(ctx context.Context, b workspacesnapshot.Binding, p workspacemount.Proof) error {
	if c == nil || b != c.request.Binding || !workspacemount.ValidProof(p, c.request.Challenge) {
		return ErrRefused
	}
	return c.exchange(ctx, captureFrame{Operation: "observe", Proof: &p})
}
func (c *CaptureChannel) Reserve(ctx context.Context, i objectcustody.Intent) error {
	if c == nil || !memberIntent(c.request, i) {
		return ErrRefused
	}
	return c.exchange(ctx, captureFrame{Operation: "reserve", Intent: &i})
}
func (c *CaptureChannel) Seal(ctx context.Context, r objectcustody.Receipt) error {
	if c == nil || !objectcustody.ValidReceipt(r) || !memberIntent(c.request, r.Intent) {
		return ErrRefused
	}
	return c.exchange(ctx, captureFrame{Operation: "seal", Receipt: &r})
}
func (*CaptureChannel) AuthorizeRead(context.Context, objectcustody.Scope, objectcustody.Receipt) error {
	return ErrRefused
}
func (*CaptureChannel) AcknowledgeRead(context.Context, objectcustody.Receipt) error {
	return ErrRefused
}
func (c *CaptureChannel) Finish(ctx context.Context, result CapturedObjects) error {
	if c == nil || len(result.Receipts) != len(c.request.Members) {
		return ErrRefused
	}
	r := Report{Version: 1, Scope: result.Snapshot.Scope, SnapshotDigest: result.Snapshot.Digest, Receipts: append([]objectcustody.Receipt(nil), result.Receipts...)}
	if c == nil || !validReport(c.request, r) {
		return ErrRefused
	}
	return c.exchange(ctx, captureFrame{Operation: "finish", Report: &r})
}

// ServeCaptureChannel acknowledges only after current authority and durable journal
// callbacks succeed. Its result is private metadata, not public delivery: callers
// must still verify helper exit/cleanup and policy before publishing it. Callbacks
// must not reenter this same stream. Partial writes/seals survive transport errors.
func ServeCaptureChannel(ctx context.Context, stream io.ReadWriteCloser, request Request, authority Authority, journal objectcustody.Journal) (Report, error) {
	return serveCaptureChannel(ctx, stream, request, authority, journal, true)
}

// ServeSupervisedCaptureChannel borrows the supervisor's attached process stream.
// On protocol success it leaves that stream open: the caller MUST wait for actual
// successful process exit, verify exited-container policy, and finally close/join
// the process before owned cleanup/report release. Error/cancellation still closes
// the stream promptly. Authentication, custody and mandatory isolation are unchanged;
// this does not permit model pipes, a host launch or an unsupervised fallback.
func ServeSupervisedCaptureChannel(ctx context.Context, stream io.ReadWriteCloser, request Request, authority Authority, journal objectcustody.Journal) (Report, error) {
	return serveCaptureChannel(ctx, stream, request, authority, journal, false)
}

func serveCaptureChannel(ctx context.Context, stream io.ReadWriteCloser, request Request, authority Authority, journal objectcustody.Journal, closeOnSuccess bool) (report Report, err error) {
	attempted := false
	defer func() {
		if err != nil && attempted {
			err = errors.Join(objectcustody.ErrUnconfirmed, err)
		}
	}()
	digest, err := RequestDigest(request)
	if ctx == nil || ctx.Err() != nil || stream == nil || isNilDependency(stream) || err != nil || missingAuthority(authority) || missingJournal(journal) {
		return Report{}, ErrRefused
	}
	request.Members = append([]workspacesnapshot.Member(nil), request.Members...)
	ctx, cancel := context.WithTimeout(ctx, MaxLifetime)
	defer cancel()
	defer func() {
		if closeOnSuccess || err != nil {
			_ = stream.Close()
		}
	}()
	closeIO := context.AfterFunc(ctx, func() { stream.Close() })
	defer closeIO()
	reserved := map[string]objectcustody.Intent{}
	sealed := map[string]objectcustody.Receipt{}
	members := map[string]bool{}
	var proof workspacemount.Proof
	revision := ""
	for sequence := uint64(1); sequence <= MaxControlMessages; sequence++ {
		var f captureFrame
		if controlRead(stream, &f) != nil || f.Version != 1 || f.Sequence != sequence || f.BindingDigest != digest || ctx.Err() != nil {
			return Report{}, ErrRefused
		}
		payloads := 0
		for _, present := range []bool{f.Proof != nil, f.Intent != nil, f.Receipt != nil, f.Report != nil} {
			if present {
				payloads++
			}
		}
		if payloads != 1 {
			return Report{}, ErrRefused
		}
		switch f.Operation {
		case "observe":
			if f.Proof == nil || !workspacemount.ValidProof(*f.Proof, request.Challenge) || proof.Version != 0 && *f.Proof != proof {
				return Report{}, ErrRefused
			}
			if authority.AuthorizeFrozenSource(ctx, request.Binding, *f.Proof) != nil {
				return Report{}, ErrRefused
			}
			proof = *f.Proof
		case "reserve":
			if f.Intent == nil || proof.Version == 0 || !memberIntent(request, *f.Intent) || members[memberKey(*f.Intent)] || reserved[f.Intent.ObjectID].ObjectID != "" || revision != "" && f.Intent.Scope.RevisionDigest != revision {
				return Report{}, ErrRefused
			}
			if authority.AuthorizeFrozenSource(ctx, request.Binding, proof) != nil {
				return Report{}, ErrRefused
			}
			attempted = true
			if journal.Reserve(ctx, *f.Intent) != nil {
				return Report{}, ErrRefused
			}
			reserved[f.Intent.ObjectID] = *f.Intent
			members[memberKey(*f.Intent)] = true
			revision = f.Intent.Scope.RevisionDigest
		case "seal":
			if f.Receipt == nil || !objectcustody.ValidReceipt(*f.Receipt) || reserved[f.Receipt.Intent.ObjectID] != f.Receipt.Intent || sealed[f.Receipt.Intent.ObjectID].Intent.ObjectID != "" {
				return Report{}, ErrRefused
			}
			if authority.AuthorizeFrozenSource(ctx, request.Binding, proof) != nil || journal.Seal(ctx, *f.Receipt) != nil {
				return Report{}, ErrRefused
			}
			sealed[f.Receipt.Intent.ObjectID] = *f.Receipt
		case "finish":
			if f.Report == nil || !validReport(request, *f.Report) || f.Report.Scope.RevisionDigest != revision || len(sealed) != len(request.Members) {
				return Report{}, ErrRefused
			}
			for _, r := range f.Report.Receipts {
				if sealed[r.Intent.ObjectID] != r {
					return Report{}, ErrRefused
				}
			}
			if authority.AuthorizeFrozenSource(ctx, request.Binding, proof) != nil {
				return Report{}, ErrRefused
			}
		default:
			return Report{}, ErrRefused
		}
		if ctx.Err() != nil || controlWrite(stream, captureAck{1, sequence, true}) != nil {
			return Report{}, ErrRefused
		}
		if f.Operation == "finish" {
			return *f.Report, nil
		}
	}
	return Report{}, ErrRefused
}

var _ Authority = (*CaptureChannel)(nil)
var _ objectcustody.Journal = (*CaptureChannel)(nil)
