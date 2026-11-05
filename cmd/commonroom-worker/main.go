// Command commonroom-worker is the container runtime's protocol entry point.
// The controller invokes it as: commonroom-worker ACTION [VALUE]
package main

import (
	"fmt"
	"os"
	"runtime"

	"commonroom-runtime/worker"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Worker requires a home directory")
		os.Exit(1)
	}
	deps := worker.Deps{Home: home, GOOS: runtime.GOOS, Docker: "docker", Euid: os.Geteuid()}
	os.Exit(worker.Run(deps, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
