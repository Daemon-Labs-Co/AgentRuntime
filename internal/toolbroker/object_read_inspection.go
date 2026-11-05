package toolbroker

import (
	"context"
	"strings"
	"time"
)

type objectReadInspector struct {
	plan   *ObjectReadContainerPlan
	runner DockerRunner
}

func (r *objectReadInspector) capture(ctx context.Context, args ...string) ([]byte, error) {
	return (&ContainerExecutor{runner: r.runner}).capture(ctx, args, MaxInspectionBytes)
}
func (r *objectReadInspector) owned(ctx context.Context, id string) error {
	raw, err := r.capture(ctx, "inspect", "--type", "container", "--format", "{{json .}}", id)
	var c toolInspection
	if err != nil || decodeInspection(raw, &c) != nil || c.ID != id || c.Name != "/"+r.plan.name() || c.Image != r.plan.image || c.Config.Image != r.plan.image || !sameMap(c.Config.Labels, r.plan.labels()) {
		return ErrRejected
	}
	return nil
}

// known accepts a durably recorded immutable ID only. Policy drift permits owned
// cleanup, never reads. Replacements/conflicts refuse; no ID discovery or adoption.
func (r *objectReadInspector) known(ctx context.Context, id string) (bool, error) {
	absent := false
	for pass := 0; pass < 2; pass++ {
		found := ""
		if id != "" {
			raw, err := r.capture(ctx, "ps", "-a", "--no-trunc", "--filter", "id="+id, "--format", "{{.ID}}")
			found = strings.TrimSpace(string(raw))
			if err != nil || found != "" && found != id {
				return false, ErrShutdownUnconfirmed
			}
		}
		if pass > 0 && absent != (found == "") {
			return false, ErrShutdownUnconfirmed
		}
		absent = found == ""
		if !absent && r.owned(ctx, id) != nil {
			return false, ErrShutdownUnconfirmed
		}
		for _, filter := range []string{"volume=" + r.plan.objects.Name, "label=commonroom.job=" + r.plan.request.Receipt.Intent.Scope.JobID, "name=^/" + r.plan.name() + "$"} {
			raw, err := r.capture(ctx, "ps", "-a", "--no-trunc", "--filter", filter, "--format", "{{.ID}}")
			if err != nil || strings.TrimSpace(string(raw)) != found {
				return false, ErrShutdownUnconfirmed
			}
		}
		raw, err := r.capture(ctx, "volume", "inspect", "--format", "{{json .}}", r.plan.objects.Name)
		if err != nil {
			return false, ErrShutdownUnconfirmed
		}
		if _, err = r.plan.verifyVolume(raw); err != nil {
			return false, ErrShutdownUnconfirmed
		}
		raw, err = r.capture(ctx, "volume", "ls", "--filter", "label=commonroom.job="+r.plan.request.Receipt.Intent.Scope.JobID, "--filter", "label=commonroom.execution=object-custody-v1", "--format", "{{.Name}}")
		if err != nil || strings.TrimSpace(string(raw)) != r.plan.objects.Name {
			return false, ErrShutdownUnconfirmed
		}
	}
	if ctx.Err() != nil {
		return false, ErrShutdownUnconfirmed
	}
	return absent, nil
}
func (r *objectReadInspector) absent(ctx context.Context, id string) error {
	absent, err := r.known(ctx, id)
	if err != nil || !absent {
		return ErrShutdownUnconfirmed
	}
	return nil
}

// VerifyNoReferences requires the retained exact custody volume without any job,
// helper-name or volume references. It grants neither creation nor release rights.
func (p *ObjectReadContainerPlan) VerifyNoReferences(ctx context.Context, runner DockerRunner) error {
	if p == nil || ctx == nil || ctx.Err() != nil || missingProbeDependency(runner) {
		return ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return (&objectReadInspector{p, runner}).absent(child, "")
}

// InspectRecorded checks a separately durably bound immutable reader ID. It may
// observe owned policy drift for cleanup, never authorizes reads, discovers IDs or
// performs daemon mutations. Caller must hold actual creator/cleanup authority.
func (p *ObjectReadContainerPlan) InspectRecorded(ctx context.Context, runner DockerRunner, id string) (bool, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || missingProbeDependency(runner) || !digest(id, 32) {
		return false, ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return (&objectReadInspector{p, runner}).known(child, id)
}
