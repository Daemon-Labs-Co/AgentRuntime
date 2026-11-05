package workerport

import "io"

// Main is the worker protocol entry point: it runs one action with the given
// operands and returns the process exit code. It is the unmodified
// agentWorkerMain extracted from the controller's worker; behavior must not
// change except through a documented protocol version change.
func Main(args []string, in io.Reader, out, diagnostics io.Writer) int {
	return agentWorkerMain(args, in, out, diagnostics)
}
