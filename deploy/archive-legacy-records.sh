#!/usr/bin/env bash
# Move legacy-format worker job records out of the active scan so the worker can
# report idle again. Run AS THE WORKER ACCOUNT. Dry run by default; --apply moves.
#
# Follows the documented maintenance procedure: nothing is edited or deleted, only
# records in a legacy format (no lifecycle version) with a TERMINAL status are moved
# to a private timestamped archive directory, and only when no managed container
# exists and no worker run is in progress. Valid lifecycle-2 records, active-looking
# records and cancel markers are never touched.
set -euo pipefail
apply=0
case "${1:-}" in
  "") ;;
  --apply) apply=1 ;;
  -h|--help) echo "Usage: $0 [--apply]   (run as the worker account; dry run without --apply)"; exit 0 ;;
  *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac
state="$HOME/.local/state/commonroom-worker"
jobs="$state/jobs"
[[ -d "$jobs" ]] || { echo "No job directory at $jobs (are you running as the worker account?)" >&2; exit 1; }

managed=$(docker ps -a --filter label=commonroom.managed=true --format '{{.ID}}')
if [[ -n "$managed" ]]; then echo "REFUSING: managed containers exist; inspect and stop them first." >&2; exit 1; fi
if pgrep -u "$(id -u)" -f 'commonroom-worker (run-v2|auth-login-v1)' >/dev/null 2>&1; then
  echo "REFUSING: a worker run or login is in progress." >&2; exit 1
fi

stamp=$(date +%Y%m%d-%H%M%S)
python3 - "$jobs" "$state/archive/legacy-$stamp" "$apply" <<'PY'
import json, os, sys, shutil
jobs, dest, apply = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
terminal = {"finished", "failed", "cancelled"}
move, keep, odd = [], 0, []
for name in sorted(os.listdir(jobs)):
    if not name.endswith(".json"):
        continue
    path = os.path.join(jobs, name)
    try:
        with open(path) as f:
            rec = json.load(f)
    except Exception:
        odd.append((name, "unreadable")); continue
    version = rec.get("version", 0)
    if version != 0:
        keep += 1; continue
    if rec.get("status") in terminal:
        move.append((name, rec.get("status")))
    else:
        odd.append((name, "legacy but status=%r (not terminal)" % rec.get("status")))
print("legacy terminal records to archive: %d; current-format records left alone: %d" % (len(move), keep))
for name, status in move:
    print("  %s  %s" % (name, status))
for name, why in odd:
    print("  LEFT IN PLACE %s: %s" % (name, why))
if not apply:
    print("Dry run: nothing moved. Re-run with --apply to archive the records listed above.")
    sys.exit(0)
if not move:
    print("Nothing to archive."); sys.exit(0)
os.makedirs(dest, mode=0o700)
for name, _ in move:
    shutil.move(os.path.join(jobs, name), os.path.join(dest, name))
print("Moved %d record(s) to %s" % (len(move), dest))
PY
