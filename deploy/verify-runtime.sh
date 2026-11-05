#!/usr/bin/env bash
# Read-only verification of the worker through the same SSH route the controller
# uses. Run as the controller account. Sends only ready-v1, idle-v1, jobs-v2 and one
# deliberately forbidden command; it starts nothing and changes no state.
# Usage: verify-runtime.sh [--alias NAME]
set -uo pipefail
ALIAS=cr-space
while (( $# )); do
  case "$1" in
    --alias) shift; ALIAS="${1:?name}" ;;
    -h|--help) echo "Usage: $0 [--alias NAME]  (read-only checks through the SSH alias)"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$ALIAS" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { echo "Invalid alias" >&2; exit 2; }
fail=0
call() { ssh -T "$ALIAS" "exec ~/.local/bin/commonroom-worker $1" </dev/null; }
check() { # name, expected jq-free substring, output
  if [[ "$3" == *"$2"* ]]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s\n        got: %s\n' "$1" "${3:0:300}"; fail=1; fi
}
echo "Worker verification via ssh alias '$ALIAS'"
out=$(call ready-v1 2>&1);  check "ready-v1 reports a ready runtime" '"runtimeReady":true' "$out"
printf '        %s\n' "${out:0:300}"
out=$(call idle-v1 2>&1);   check "idle-v1 answers" '"idle":' "$out"
printf '        %s\n' "${out:0:200}"
out=$(call jobs-v2 2>&1);   check "jobs-v2 returns a snapshot" '"managedContainers":' "$out"
printf '        %s\n' "${out:0:300}"
out=$(ssh -T "$ALIAS" id </dev/null 2>&1); check "a plain command is refused" 'Forbidden worker command' "$out"
out=$(ssh -T "$ALIAS" "exec ~/.local/bin/commonroom-worker ready-v1; id" </dev/null 2>&1); check "a chained command is refused" 'Forbidden worker command' "$out"
if (( fail )); then echo "RESULT: FAILED (see lines above)"; exit 1; fi
echo "RESULT: all checks passed. Provider credentials still need sign-in if ready-v1 shows false."
