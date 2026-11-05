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
- 722 of the application's worker-adjacent tests were not extracted because they
  also exercise controller code; equivalent runtime-only tests are still to be written.

Design and contracts live with the application:
[separation design](../AgentChat/docs/technical/runtime-separation.md) and
[worker protocol](../AgentChat/docs/technical/worker-protocol.md).

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
