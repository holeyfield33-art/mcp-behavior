# Architecture decision: Linux isolation backend (v0.2.0)

**Status:** Accepted for implementation  
**Date:** 2026-10-30  
**Decision:** One Linux **user/mount/pid/network/UTS/IPC namespace + cgroup v2** backend for subject isolation. A dedicated VM is an alternative architecture requiring equivalent acceptance evidence; it is not built in parallel.

## Context

v0.1.0 native subprocess mode cannot prove containment. Same-UID subjects can reach oracle/report storage; network and host paths are not denied; escaped descendants are not group-limited. ROADMAP §1 requires one backend with external evidence before any containment PASS.

## Decision

### Controller vs subject

| Role | Trust | Responsibility |
|------|--------|----------------|
| Controller | Trusted | Fixtures, oracle, report writer, preflight, observation, teardown |
| Subject | Untrusted | MCP server process tree only |

Expected answers, reports, controller process interfaces, and supervisor channels must be inaccessible to the subject. Runtime code/config mounts are read-only. Only declared disposable fixture/temp trees are writable.

### Namespace/cgroup backend (chosen)

Required properties (must be **observed**, not only requested):

1. **Identity** — distinct subject UID/GID (or mapped user namespace); not the controller identity for oracle-readable paths.
2. **Filesystem** — private mount namespace; host secret canaries and oracle/report paths unavailable; allowed runtime read-only.
3. **Process** — PID namespace + cgroup v2 process aggregation; no signal/inspect of controller PIDs.
4. **Capability / NNP** — no_new_privs set; capabilities dropped; verified externally.
5. **Network** — network namespace with no usable host routing (or equivalent denial).
6. **Resources** — cgroup memory/CPU/pids limits owned by controller; verified teardown of the whole group.
7. **Preflight** — if any required control is unavailable, launch is **refused** or the run is **INCOMPLETE**. No automatic native fallback.

### Explicit non-goals for this backend

- Not a claim that arbitrary hostile binaries are safe.
- Not full dependency-closure attestation.
- Not Windows/macOS isolation in v0.2.0.
- Not HTTP/auth transport isolation (deferred profiles).

## Consequences

- CLI retains `--native` for development; containment remains required UNKNOWN.
- New mode (e.g. `--isolation namespace`) may record containment PASS only when the acceptance matrix evidence for that run is complete.
- Unsupported kernels or missing privileges fail closed with a structured reason.
- Original v0.1.0 proof artifacts remain immutable under `proof/`.

### Checkpoint 1 behavior

The backend interface, feature probes, runner/report wiring and CLI selection are implemented at this checkpoint. Namespace subject launch and external acceptance observers are still unimplemented. A namespace request produces a fresh FINISHED/INCOMPLETE report with zero cases and explicit preflight reasons. It starts neither fixture-probe subprocesses nor MCP subjects, and never falls back to native execution.

Native execution retains required containment UNKNOWN and the existing behavioral checks. Requested resource limits come from the run configuration; feature-file presence is recorded as a probe observation, not as proof that a namespace/cgroup policy was enforced. Even a successful feature probe cannot authorize a namespace launch at this checkpoint.

## Alternatives considered

| Alternative | Why not now |
|-------------|-------------|
| Docker/Podman only | Useful packaging; still needs the same external observer matrix. Can wrap the namespace backend later. |
| Firecracker / full VM | Stronger boundary; higher operational cost. Deferred as alternate architecture with same gates. |
| seccomp-only on host | Insufficient for filesystem/oracle isolation and process-group limits. |

## References

- `docs/ROADMAP.md` — acceptance matrix and release gate  
- `docs/ADVERSARIAL_REVIEW.md` — G01, G31, G32 and open host-compromise risks  
- `docs/SPEC.md` §1 — trust model  
