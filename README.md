# CommonRoom container runtime

The container runtime for [Agent CommonRoom](../AgentChat): it owns the container
engine, images, volumes and cleanup, and exposes only a fixed, versioned worker
protocol to the application. The application never calls Docker, and agents
never reach the engine. Open source, GPL-3.0-only.

## Status

The worker serves every action of the existing worker protocol. Its code was
extracted mechanically, without edits, from the application's worker entry point
(the transitive closure of declarations reachable from `agentWorkerMain`,
about 2,950 lines in `internal/workerport`) together with the internal packages it
depends on (`internal/toolbroker`, `workspace*`, `objectcustody`, `objectread`,
`strictjson`, `taskcontract`, `toolcommand`, `toolworkspace`, `artifactmanifest`)
and the existing tests that exercise only that code (73 test functions). Nothing
here has been accepted against live providers: passing synthetic tests is not live
acceptance, and repository-bound development stays refused until the
credential-separated bridge is verified.

Known debt:
- The application still contains its own copy of this code. Until the application
  stops using it, fixes must be made in both places and the protocol version bumped
  together.
- `internal/taskcontract` and `internal/objectcustody` are application-domain
  contracts copied for now; they should become shared protocol types.
- The other 722 test functions in the application package were not extracted
  because they also exercise controller code. Runtime-only equivalents for any
  worker behavior they cover are still to be written.

Design and contracts live with the application:
[separation design](../AgentChat/docs/technical/runtime-separation.md) and
[worker protocol](../AgentChat/docs/technical/worker-protocol.md).

## SSH access for the controller

`commonroom-ssh-gate` is the forced command for the worker account's
`authorized_keys`. It accepts only `exec ~/.local/bin/commonroom-worker ACTION
['VALUE']` with a known action and a base64url/hex value, then runs the installed
worker directly with a fixed minimal environment. No shell is involved.

```text
command="/opt/commonroom-space/bin/commonroom-ssh-gate --worker /opt/commonroom-space/bin/commonroom-worker",restrict ssh-ed25519 AAAA... controller
```

Verified against a real sshd with a throwaway key: valid commands run, chained
commands, plain shells and interactive sessions are refused. Port-forwarding
refusal is documented by `restrict` but was not observed.

## Host setup (administrator)

Both scripts live in `deploy/`, check before they change anything, ask before
replacing a file, keep timestamped backups, and accept `--dry-run`:

- `deploy/host-space-setup.sh`: group, state and socket directories, a systemd
  unit (installed, not enabled; its `DOCKER_HOST` line must be removed before it is
  ever used, because the worker refuses that variable) and a restricted sudo rule.
- `deploy/host-ssh-setup.sh`: a controller key, the forced-command line in the
  worker account's `authorized_keys`, the pinned host key (compared with the key on
  disk, no trust-on-first-use) and the SSH alias, then a live check as the
  controller account that an allowed action works and a plain command is refused.

Run them from an administrator account. They are not run by automated tests.
`deploy/archive-legacy-records.sh` (run as the worker account; dry run unless
`--apply`) moves legacy-format terminal job records to a private archive so the
worker can report idle, following the documented maintenance procedure. It refuses
when managed containers exist and never edits or deletes records.
After the SSH setup, `deploy/verify-runtime.sh` (run as the controller account,
read-only) checks `ready-v1`, `idle-v1`, `jobs-v2` and that plain and chained
commands are refused, through the same route the controller uses.

## Use

```bash
make build        # bin/commonroom-worker
make test         # fast, parallel-safe, no real containers or database
make check        # gofmt, vet, race detector
```

The controller runs `commonroom-worker ACTION [VALUE]`. The worker reads its
owner-only `~/.config/commonroom-worker/config.json` (a digest-pinned `image` and
an absolute `authDir`), requires Linux and a rootless Docker daemon, and refuses
a missing or tag-only image. There is no host-execution fallback.

## Rules

- Work on a feature branch; the owner signs and publishes commits.
- Tests must be fast and parallel-safe, use temporary directories and fakes, and
  never launch real provider agents or real containers.
- Container isolation is mandatory: no off switch, no uncontained fallback.
