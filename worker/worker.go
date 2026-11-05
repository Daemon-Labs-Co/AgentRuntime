// Package worker is the container runtime's protocol entry point.
//
// All actions are served by the code extracted unchanged from the controller's
// worker (internal/workerport). Containment is mandatory: there is no
// host-execution fallback and no option to disable the Docker checks. A source
// fork can remove these checks, which invalidates the containment contract.
package worker

import (
	"io"

	"commonroom-runtime/internal/workerport"
)

// Run executes one worker invocation and returns the process exit code.
// Diagnostics are bounded, human-readable and never include credentials.
func Run(args []string, in io.Reader, out, diag io.Writer) int {
	return workerport.Main(args, in, out, diag)
}
