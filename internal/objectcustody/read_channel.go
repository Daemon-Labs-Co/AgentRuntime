package objectcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"time"
)

// ReadReleaseGuard is trusted receiving-side authority, not a model callback.
// It must pin the authenticated principal/session and recheck current room,
// receipt/revision/export policy. AcknowledgeRead must durably authorize release
// before bytes leave ReadChannel. StopReadAuthority must be local/nonblocking.
// A missing/no-op guard cannot admit production delivery. No isolation bypass exists.
type ReadReleaseGuard interface {
	AuthorizeRead(context.Context, Scope, Receipt) error
	AcknowledgeRead(context.Context, Receipt) error
	StopReadAuthority()
}

// SealedReader must be a trusted isolated custody reader: Get verifies actual bytes
// and current authority, durably acknowledges release and returns no bytes on failure.
// Production setup must bind it to the actual quota-backed private object root; never
// supply a model path, host fallback or fake reader as evidence of stored bytes.
type SealedReader interface {
	Get(context.Context, Scope, Receipt) ([]byte, error)
}

const readChannelFrameLimit = 4096

type readChannelHeader struct {
	Version   int     `json:"version"`
	Operation string  `json:"operation"`
	Receipt   Receipt `json:"receipt"`
}

func readChannelAbsent(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}
func writeReadChannelBytes(w io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil || n <= 0 || n > len(raw) {
			return ErrRefused
		}
		raw = raw[n:]
	}
	return nil
}
func writeReadChannelHeader(w io.Writer, h readChannelHeader) error {
	raw, err := json.Marshal(h)
	if err != nil || len(raw) > readChannelFrameLimit {
		return ErrRefused
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(raw)))
	if writeReadChannelBytes(w, length[:]) != nil || writeReadChannelBytes(w, raw) != nil {
		return ErrRefused
	}
	return nil
}
func readReadChannelHeader(r io.Reader) (readChannelHeader, error) {
	var zero, h readChannelHeader
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return zero, ErrRefused
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > readChannelFrameLimit {
		return zero, ErrRefused
	}
	raw := make([]byte, int(n))
	if _, err := io.ReadFull(r, raw); err != nil || json.Unmarshal(raw, &h) != nil {
		return zero, ErrRefused
	}
	canonical, err := json.Marshal(h)
	if err != nil || !bytes.Equal(raw, canonical) {
		return zero, ErrRefused
	}
	return h, nil
}
func readChannelContent(raw []byte, r Receipt) bool {
	if int64(len(raw)) != r.Bytes {
		return false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == r.Digest
}

// ReadChannel owns a ONE-SHOT already authenticated supervisor stream pinned to an
// exact sealed receipt. It is never model stdio or a public download handler. Both
// peers must be bound by trusted private setup; JSON fields are not authentication.
// The raw body is finite, rehashed, and withheld until current durable release
// acknowledgment. Any uncertainty returns nil and stops receiving-side authority.
// There is no reconnect, retry, path/URI selection or host execution fallback.
func ReadChannel(ctx context.Context, stream io.ReadWriteCloser, scope Scope, receipt Receipt, guard ReadReleaseGuard) ([]byte, error) {
	return readChannel(ctx, stream, scope, receipt, guard, true)
}

// ReadSupervisedChannel borrows the private attached helper stream. On success it
// leaves the stream open so its owner can Wait for actual process exit and inspect
// exited policy before Close joins the pumps. Error/cancellation still closes it.
// Returned bytes remain private: the owner MUST confirm cleanup and current durable
// release authority before downstream delivery. Mandatory isolation has no fallback.
func ReadSupervisedChannel(ctx context.Context, stream io.ReadWriteCloser, scope Scope, receipt Receipt, guard ReadReleaseGuard) ([]byte, error) {
	return readChannel(ctx, stream, scope, receipt, guard, false)
}

func readChannel(ctx context.Context, stream io.ReadWriteCloser, scope Scope, receipt Receipt, guard ReadReleaseGuard, closeOnSuccess bool) (raw []byte, err error) {
	if ctx == nil || ctx.Err() != nil || readChannelAbsent(stream) || readChannelAbsent(guard) || !validReceipt(receipt) || scope != receipt.Intent.Scope {
		return nil, ErrRefused
	}
	defer func() {
		if closeOnSuccess || err != nil {
			_ = stream.Close()
		}
	}()
	success := false
	defer func() {
		if !success {
			guard.StopReadAuthority()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stopIO := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stopIO()
	if guard.AuthorizeRead(ctx, scope, receipt) != nil || ctx.Err() != nil {
		return nil, ErrRefused
	}
	if writeReadChannelHeader(stream, readChannelHeader{Version: 1, Operation: "read", Receipt: receipt}) != nil {
		return nil, ErrRefused
	}
	// A fixed isolated reader may relay its store journal over this same private
	// stream. Only authorize -> durable acknowledge -> object is permitted. Direct
	// readers already carrying their own trusted journal may send object immediately.
	phase := 0
	for {
		h, e := readReadChannelHeader(stream)
		if e != nil || h.Version != 1 || h.Receipt != receipt || ctx.Err() != nil {
			return nil, ErrRefused
		}
		response := ""
		switch h.Operation {
		case "object":
			if phase == 1 {
				return nil, ErrRefused
			}
		case "source-authorize":
			if phase != 0 || guard.AuthorizeRead(ctx, scope, receipt) != nil || ctx.Err() != nil {
				return nil, ErrRefused
			}
			phase = 1
			response = "source-authorized"
		case "source-acknowledge":
			if phase != 1 || guard.AcknowledgeRead(ctx, receipt) != nil || ctx.Err() != nil {
				return nil, ErrRefused
			}
			phase = 2
			response = "source-acknowledged"
		default:
			return nil, ErrRefused
		}
		if response == "" {
			break
		}
		if writeReadChannelHeader(stream, readChannelHeader{Version: 1, Operation: response, Receipt: receipt}) != nil {
			return nil, ErrRefused
		}
	}
	raw = make([]byte, int(receipt.Bytes))
	if _, e := io.ReadFull(stream, raw); e != nil || !readChannelContent(raw, receipt) || ctx.Err() != nil {
		return nil, ErrRefused
	}
	// EOF completes this one-object stream. Extra bytes, another frame, a stalled
	// connection or an unconfirmed close cannot be silently treated as completion.
	var extra [1]byte
	n, e := stream.Read(extra[:])
	if n != 0 || e != io.EOF || ctx.Err() != nil {
		return nil, ErrRefused
	}
	if guard.AcknowledgeRead(ctx, receipt) != nil || ctx.Err() != nil {
		return nil, ErrRefused
	}
	success = true
	return raw, nil
}

// ServeReadChannel releases only the receipt pinned by trusted session setup, using
// the sealed store's mandatory read/audit guards. It serves one object then closes.
// A successful write means bytes were authorized onto this stream, never that a
// user received or accepted them. Failed transfers do not refund/delete stored data.
func ServeReadChannel(ctx context.Context, stream io.ReadWriteCloser, scope Scope, receipt Receipt, reader SealedReader) error {
	if ctx == nil || ctx.Err() != nil || readChannelAbsent(stream) || readChannelAbsent(reader) || !validReceipt(receipt) || scope != receipt.Intent.Scope {
		return ErrRefused
	}
	defer stream.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stopIO := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stopIO()
	h, err := readReadChannelHeader(stream)
	if err != nil || h.Version != 1 || h.Operation != "read" || h.Receipt != receipt || ctx.Err() != nil {
		return ErrRefused
	}
	raw, err := reader.Get(ctx, scope, receipt)
	if err != nil || !readChannelContent(raw, receipt) || ctx.Err() != nil {
		return ErrRefused
	}
	if writeReadChannelHeader(stream, readChannelHeader{Version: 1, Operation: "object", Receipt: receipt}) != nil || writeReadChannelBytes(stream, raw) != nil || ctx.Err() != nil {
		return ErrRefused
	}
	return nil
}
