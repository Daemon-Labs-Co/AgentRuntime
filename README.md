# CommonRoom container runtime

The container runtime for [Agent CommonRoom](../AgentChat): it owns the container
engine, images, volumes and cleanup, and exposes only a fixed, versioned worker
protocol to the application. The application never calls Docker, and agents
never reach the engine. Open source, GPL-3.0-only.

## Status

Early skeleton. The worker implements `ready-v1` (configuration, rootless Docker
and limit checks, pinned image, credential presence) and refuses every other
action with `Unsupported worker action`. Actions move here one at a time from the
application without changing their names, versions or wire shapes. Nothing here
runs an agent yet, and a passing synthetic test is not live acceptance.

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
