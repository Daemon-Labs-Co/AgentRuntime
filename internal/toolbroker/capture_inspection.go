package toolbroker

import (
	"context"
	"strings"
	"time"
)

type captureInspector struct {
	plan   *CaptureContainerPlan
	runner DockerRunner
}

func (r *captureInspector) capture(ctx context.Context, args ...string) ([]byte, error) {
	return (&ContainerExecutor{runner: r.runner}).capture(ctx, args, MaxInspectionBytes)
}
func (r *captureInspector) owned(ctx context.Context, id string) error {
	raw, err := r.capture(ctx, "inspect", "--type", "container", "--format", "{{json .}}", id)
	var c toolInspection
	if err != nil || decodeInspection(raw, &c) != nil || c.ID != id || c.Name != "/"+r.plan.name() || c.Image != r.plan.image || c.Config.Image != r.plan.image || !sameMap(c.Config.Labels, r.plan.labels()) {
		return ErrRejected
	}
	return nil
}

// absent checks identities even after removal, and rejects any retained references.
func (r *captureInspector) absent(ctx context.Context, id string) error {
	absent, err := r.known(ctx, id)
	if err != nil || !absent {
		return ErrShutdownUnconfirmed
	}
	return nil
}

// known admits only the recorded immutable ID, never name discovery/adoption.
// A present owned container may have drifted policy and may only be stopped.
func (r *captureInspector) known(ctx context.Context, id string) (bool, error) {
	absent := false
	for pass := 0; pass < 2; pass++ {
		found := ""
		var raw []byte
		var err error
		if id != "" {
			raw, err = r.capture(ctx, "ps", "-a", "--no-trunc", "--filter", "id="+id, "--format", "{{.ID}}")
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
		for _, filter := range []string{"volume=" + r.plan.source.Name, "volume=" + r.plan.objects.Name, "label=commonroom.job=" + r.plan.request.Binding.Execution.JobID, "name=^/" + r.plan.name() + "$"} {
			raw, err = r.capture(ctx, "ps", "-a", "--no-trunc", "--filter", filter, "--format", "{{.ID}}")
			if err != nil || strings.TrimSpace(string(raw)) != found {
				return false, ErrShutdownUnconfirmed
			}
		}
		src, err := r.capture(ctx, "volume", "inspect", "--format", "{{json .}}", r.plan.source.Name)
		if err != nil {
			return false, ErrShutdownUnconfirmed
		}
		obj, err := r.capture(ctx, "volume", "inspect", "--format", "{{json .}}", r.plan.objects.Name)
		if err != nil {
			return false, ErrShutdownUnconfirmed
		}
		if _, _, err = r.plan.verifyVolumes(src, obj); err != nil {
			return false, ErrShutdownUnconfirmed
		}
		for execution, name := range map[string]string{"separated-tool-v1": r.plan.source.Name, "object-custody-v1": r.plan.objects.Name} {
			raw, err = r.capture(ctx, "volume", "ls", "--filter", "label=commonroom.job="+r.plan.request.Binding.Execution.JobID, "--filter", "label=commonroom.execution="+execution, "--format", "{{.Name}}")
			if err != nil || strings.TrimSpace(string(raw)) != name {
				return false, ErrShutdownUnconfirmed
			}
		}
	}
	if ctx.Err() != nil {
		return false, ErrShutdownUnconfirmed
	}
	return absent, nil
}

// VerifyNoReferences admits only both retained volumes with no helper/job/name/
// volume references. It never discovers/adopts an ID, starts or removes anything.
// The caller must hold creator ownership and separately authorize the operation.
func (p *CaptureContainerPlan) VerifyNoReferences(ctx context.Context, runner DockerRunner) error {
	if p == nil || ctx == nil || ctx.Err() != nil || missingProbeDependency(runner) {
		return ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return (&captureInspector{p, runner}).absent(child, "")
}

// InspectRecorded checks only a separately durably recorded immutable helper ID.
// A present owned policy-drifted helper is eligible for cleanup only, never source
// reads/execution. No deletion, release or name adoption occurs in this observer.
func (p *CaptureContainerPlan) InspectRecorded(ctx context.Context, runner DockerRunner, id string) (bool, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || missingProbeDependency(runner) || !digest(id, 32) {
		return false, ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return (&captureInspector{p, runner}).known(child, id)
}
