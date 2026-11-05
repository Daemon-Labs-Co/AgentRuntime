package toolbroker

import (
	"context"
	"time"
)

// DelegationRequest contains no claimed agent identity, resources or permissions.
// Identity and scope come exclusively from the authenticated supervisor link.
type DelegationRequest struct {
	// Supervisor-owned snapshot, overwritten from the local Authority by
	// ToolSession.ProposeDelegation. Never copy this from model input.
	ParentOperations uint8  `json:"parentOperations"`
	RequestID        string `json:"requestId"`
	TaskID           string `json:"taskId"`
	TaskRevision     int    `json:"taskRevision"`
	DelegateID       string `json:"delegateId"`
}
type DelegationAuditor interface {
	RecordDelegation(context.Context, Scope, DelegationRequest) error
}

func ValidDelegation(r DelegationRequest) bool {
	return r.ParentOperations > 0 && r.ParentOperations < 16 && identifier(r.RequestID) && identifier(r.TaskID) && identifier(r.DelegateID) && r.TaskRevision > 0
}
func (client *AuditClient) ProposeDelegation(ctx context.Context, r DelegationRequest) error {
	if !client.mu.TryLock() {
		return ErrBusy
	}
	defer client.mu.Unlock()
	if client.terminal || client.pending != nil || !ValidDelegation(r) || !validScope(client.scope, time.Now()) {
		return client.fail()
	}
	return client.exchange(ctx, AuditFrame{Version: 3, Stage: "delegation", Intent: Intent{Scope: client.scope}, Delegation: &r})
}

// ProposeDelegation shares the supervisor's active-work slot and authenticated
// control link. It does not mint capabilities, execute work or revoke cleanup.
// Provider adapters must explicitly translate a supported typed proposal here;
// model stdout and claims of identity must never substitute for this channel.
func (s *ToolSession) ProposeDelegation(ctx context.Context, r DelegationRequest) error {
	if s == nil || s.audit == nil || s.Dispatcher == nil {
		return ErrAudit
	}
	authority := s.Dispatcher.authority
	select {
	case authority.slot <- struct{}{}:
		defer func() { <-authority.slot }()
	default:
		return ErrBusy
	}
	authority.mu.Lock()
	if authority.revoked || !time.Now().Before(authority.scope.Deadline) {
		authority.mu.Unlock()
		return ErrAudit
	}
	r.ParentOperations = 0
	for op := range authority.allowed {
		r.ParentOperations |= OperationMask(op)
	}
	authority.mu.Unlock()
	return s.audit.ProposeDelegation(ctx, r)
}

// OperationMask is a fixed policy representation, never an executable command.
func OperationMask(operation string) uint8 {
	switch operation {
	case "read":
		return 1
	case "write":
		return 2
	case "patch":
		return 4
	case "command":
		return 8
	}
	return 0
}
