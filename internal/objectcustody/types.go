// Package objectcustody defines finite immutable object identities. Metadata
// validation establishes shape only, never source identity or write authority.
package objectcustody

import (
	"context"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxObjectBytes int64 = 16 * 1024 * 1024

var (
	ErrRefused     = errors.New("object custody refused")
	ErrUnconfirmed = errors.New("object custody unconfirmed; retain charge and bytes")
	identifier     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// Scope is checked against the authenticated principal and actual isolated job
// by Journal. These identifiers/hashes are evidence bindings, never authority.
type ExecutionScope struct {
	CompanyID        string `json:"companyId"`
	RoomID           string `json:"roomId"`
	TaskID           string `json:"taskId"`
	ExecutionID      string `json:"executionId"`
	JobID            string `json:"jobId"`
	RepositoryDigest string `json:"repositoryDigest"`
	RevisionDigest   string `json:"revisionDigest"`
	DefinitionDigest string `json:"definitionDigest"`
}

// Scope adds immutable output/member labels. Labels never become filesystem
// paths here; the trusted source adapter must verify their actual origin.
type Scope struct {
	ExecutionScope
	OutputName string `json:"outputName"`
	MemberName string `json:"memberName"`
}
type Intent struct {
	ObjectID string `json:"objectId"`
	Scope    Scope  `json:"scope"`
	MaxBytes int64  `json:"maxBytes"`
}
type Receipt struct {
	Intent Intent `json:"intent"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

func lowerDigest(value string, size int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size && hex.EncodeToString(raw) == value
}

// ValidExecutionScope validates metadata shape only, never admission/authority.
func ValidExecutionScope(s ExecutionScope) bool {
	return identifier.MatchString(s.CompanyID) && identifier.MatchString(s.RoomID) && identifier.MatchString(s.TaskID) && lowerDigest(s.ExecutionID, 16) && lowerDigest(s.JobID, 16) && lowerDigest(s.RepositoryDigest, 32) && lowerDigest(s.RevisionDigest, 32) && lowerDigest(s.DefinitionDigest, 32)
}
func validScope(s Scope) bool {
	name := s.MemberName
	return ValidExecutionScope(s.ExecutionScope) && identifier.MatchString(s.OutputName) && utf8.ValidString(name) && strings.TrimSpace(name) != "" && utf8.RuneCountInString(name) <= 200 && !strings.ContainsAny(name, "\\\x00\r\n:") && !path.IsAbs(name) && name != "." && name != ".." && !strings.HasPrefix(name, "../") && path.Clean(name) == name
}
func validIntent(v Intent) bool {
	return lowerDigest(v.ObjectID, 16) && validScope(v.Scope) && v.MaxBytes > 0 && v.MaxBytes <= MaxObjectBytes
}
func validReceipt(v Receipt) bool {
	return validIntent(v.Intent) && v.Bytes >= 0 && v.Bytes <= v.Intent.MaxBytes && lowerDigest(v.Digest, 32)
}

// ValidIntent validates metadata only; a trusted journal must admit capacity.
func ValidIntent(v Intent) bool { return validIntent(v) }

// ValidReceipt validates metadata only; it does not prove stored byte identity.
func ValidReceipt(v Receipt) bool { return validReceipt(v) }

// Journal is a mandatory TRUSTED controller/worker integration boundary, never
// a model/plugin callback. Reserve must durably charge maximum capacity across
// retained/staged/uncertain account data AND establish an actual physical quota
// before any bytes are read/created. Seal must revalidate current job, source
// revision, policy and authority and durably acknowledge the exact content.
// AuthorizeRead requires an exact existing sealed receipt plus current room,
// principal, revision and export policy. AcknowledgeRead must revalidate current
// authority again and durably record bytes authorized for release, not proof
// that a remote client received them.
// A missing, no-op or synthetic implementation cannot admit production work.
// There is deliberately no automatic refund, deletion, adoption or retry API.
type Journal interface {
	Reserve(context.Context, Intent) error
	Seal(context.Context, Receipt) error
	AuthorizeRead(context.Context, Scope, Receipt) error
	AcknowledgeRead(context.Context, Receipt) error
}
