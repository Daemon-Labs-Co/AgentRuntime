// Command commonroom-worker is the container runtime's protocol entry point.
// The controller invokes it as: commonroom-worker ACTION [VALUE]
package main

import (
	"os"

	"commonroom-runtime/worker"
)

func main() {
	os.Exit(worker.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
