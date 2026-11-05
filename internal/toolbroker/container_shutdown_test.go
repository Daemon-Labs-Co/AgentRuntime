package toolbroker

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestStopContainerProof(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"removed", "already_absent", "daemon_failure", "foreign_inventory", "ownership_failure", "removal_failure", "survives", "overflow", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			id := strings.Repeat("a", 64)
			calls, verified, removals := 0, 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			runner := mockDocker(func(_ context.Context, args []string, _ []byte, out io.Writer) error {
				calls++
				if mode == "daemon_failure" {
					return errors.New("offline")
				}
				if args[0] == "rm" {
					removals++
					if mode == "removal_failure" {
						return errors.New("failed")
					}
					return nil
				}
				raw := id
				if mode == "already_absent" || removals > 0 && mode != "survives" {
					raw = ""
				}
				if mode == "foreign_inventory" {
					raw = strings.Repeat("b", 64)
				}
				if mode == "overflow" {
					raw = strings.Repeat("x", 8193)
				}
				_, err := io.WriteString(out, raw)
				return err
			})
			err := StopContainer(ctx, runner, id, func(context.Context, string) error {
				verified++
				if mode == "ownership_failure" {
					return errors.New("foreign")
				}
				return nil
			})
			success := mode == "removed" || mode == "already_absent"
			if (err == nil) != success {
				t.Fatalf("unexpected proof: %v", err)
			}
			if mode == "removed" && (verified != 1 || removals != 1 || calls != 3) {
				t.Fatal("missing verification/removal/absence")
			}
			if (mode == "foreign_inventory" || mode == "ownership_failure" || mode == "daemon_failure" || mode == "cancelled" || mode == "overflow") && removals != 0 {
				t.Fatal("unsafe removal")
			}
		})
	}
}
