package workerport

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

func workerIdleProbe(ctx context.Context) (bool, error) {
	if err := configureWorker(); err != nil {
		return false, err
	}
	var info limitedAgentOutput
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .}}")
	cmd.Stdout = &info
	if cmd.Run() != nil || !dockerSecurityReady(info.Bytes()) {
		return false, errors.New("rootless Docker unavailable")
	}
	var ids limitedAgentOutput
	cmd = exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "label=commonroom.managed=true", "--format", "{{.ID}}")
	cmd.Stdout = &ids
	if cmd.Run() != nil {
		return false, errors.New("container state unavailable")
	}
	if strings.TrimSpace(ids.String()) != "" {
		return false, nil
	}
	dir, err := workerStateDirectory()
	if err != nil {
		return false, err
	}
	snapshot, err := workerSnapshot(dir, nil)
	if err != nil {
		return false, err
	}
	return snapshot.Unresolved == 0, nil

}
