package toolbroker

import (
	"context"
	"time"
)

// IdleStop is bounded lifecycle metadata on the private supervisor audit link,
// never a model tool or proof that containers/source are absent.
type IdleStop struct {
	StartedAt      time.Time `json:"startedAt"`
	RequestedAt    time.Time `json:"requestedAt"`
	Minutes        int       `json:"minutes"`
	PolicyRevision int       `json:"policyRevision"`
}

// IdleAuditor is an optional controller protocol extension. Success MUST follow
// durable persistence under registered policy. A no-op source adapter invalidates
// auditing; this interface grants no executor, disposal or host-run authority.
type IdleAuditor interface {
	RecordIdleStop(context.Context, Scope, IdleStop) error
}

func ValidAuditIdleStop(scope Scope, stop IdleStop, now time.Time) bool {
	return validScope(scope, now) && stop.Minutes >= 1 && stop.Minutes <= 60 && stop.PolicyRevision >= 0 && !stop.StartedAt.IsZero() && !stop.RequestedAt.Before(stop.StartedAt.Add(time.Duration(stop.Minutes)*time.Minute)) && stop.RequestedAt.Before(scope.Deadline) && !stop.RequestedAt.After(now.Add(5*time.Second))
}
func (client *AuditClient) RecordIdleStop(ctx context.Context, stop IdleStop) error {
	if !client.mu.TryLock() {
		return ErrBusy
	}
	defer client.mu.Unlock()
	if client.pending != nil || client.terminal || !ValidAuditIdleStop(client.scope, stop, time.Now()) {
		return client.fail()
	}
	client.terminal = true
	return client.exchange(ctx, AuditFrame{Version: 2, Stage: "idle-stop", Intent: Intent{Scope: client.scope}, IdleStop: &stop})
}

// RecordIdleStop is supervisor-only and permanently closes tool authority before
// sending the lifecycle frame. It must share the dispatch slot; active operations
// cannot be relabelled idle. No automatic retry or audit transport downgrade.
func (s *ToolSession) RecordIdleStop(ctx context.Context, stop IdleStop) error {
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
	authority.Revoke()
	return s.audit.RecordIdleStop(ctx, stop)
}
