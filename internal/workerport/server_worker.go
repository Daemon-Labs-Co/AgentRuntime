package workerport

import "errors"

// commonroom-server is an internal worker identity, never an SSH host. Both transports use
// the same fenced lifecycle, audit channel and mandatory container implementation.
func serverWorkerBinding(endpoint string) (string, string, error) {
	switch endpoint {
	case "ssh://commonroom-server":
		return "commonroom-server", "codex", nil
	case "ssh://commonroom-server/claude":
		return "commonroom-server", "claude", nil
	}
	return "", "", errors.New("Invalid server worker provider")
}
