// Command commonroom-ssh-gate is the SSH forced command for the worker account.
// Install it in authorized_keys as:
//
//	command="/opt/commonroom-space/bin/commonroom-ssh-gate --worker /opt/commonroom-space/bin/commonroom-worker",restrict ssh-ed25519 AAAA...
package main

import (
	"os"
	"syscall"

	"commonroom-runtime/internal/gate"
)

func main() {
	os.Exit(gate.Run(os.Args[1:], os.Environ(), syscall.Exec, os.Stderr))
}
