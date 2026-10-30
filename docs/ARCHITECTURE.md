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

### Checkpoint 1 behavior — historical, merged PR #1

The backend interface, feature probes, runner/report wiring and CLI selection are implemented at this checkpoint. Namespace subject launch and external acceptance observers are still unimplemented. A namespace request produces a fresh FINISHED/INCOMPLETE report with zero cases and explicit preflight reasons. It starts neither fixture-probe subprocesses nor MCP subjects, and never falls back to native execution.

Native execution retains required containment UNKNOWN and the existing behavioral checks. Requested resource limits come from the run configuration; feature-file presence is recorded as a probe observation, not as proof that a namespace/cgroup policy was enforced. Even a successful feature probe cannot authorize a namespace launch at this checkpoint.

### Checkpoint 2 partial behavior — as merged in PR #2

Namespace preflight now collects candidate tool and synthetic filesystem-probe evidence. Only the fixed controller-owned helper is launched; arbitrary subject launch remains disabled both in `launch_subject()` and in Runner. Missing tools, failed namespace operations, invalid fixture preconditions, malformed evidence, output overflow and timeouts remain explicit failed preconditions, so the run is INCOMPLETE with zero subject cases.

A successful synthetic host-path probe cannot waive the required run-level oracle/controller, network, aggregate-resource or teardown gates. Probe limits and process-group cleanup are helper backstops, not the cgroup subject supervisor. Native behavior and its containment UNKNOWN are unchanged. See ROADMAP sections 2-5 for the acceptance matrix and remaining work.

### Checkpoint 3 supervision contract

`--cgroup-parent` is a namespace-preflight-only operational setting, included in the reported isolation policy and policy digest. It must name a canonical genuinely cgroup-v2 directory already delegated with active cpu/memory/pids controllers. The controller only creates its own leaf; it never changes parent controllers or limits.

The fixed supervisor helper joins through a narrow inherited cgroup descriptor and blocks on a release pipe. The controller checks actual membership and configured limit readback before releasing it. The trusted bootstrap closes its control descriptors before its detached-child phase. Recursive cgroup kill, populated=0, empty membership and removal are all required cleanup observations. A pidfd fallback targets only the fixed trusted helper and cannot turn failed cgroup cleanup into success. Memory/swap/PID limits and CPU bandwidth are kernel requests with readback; sampled aggregate CPU usage has its own budget. A full resource-stress acceptance is still required.

The synthetic network observer owns IPv4/IPv6 loopback TCP listeners outside the candidate view. Host positive controls and strict nonce-bound helper results are mandatory. External isolated receipts fail the candidate test even if the helper claims denial. Missing families, observer faults, unrecognized traffic, timeout and cutoff cannot pass. This finite probe does not cover all protocols, paths or an actual server namespace.

This checkpoint accepts only fixed controller-owned helper code. No configured MCP command is passed to the supervisor. Synthetic probe success does not authorize Runner or `launch_subject()`. Run-level oracle/controller protection, complete network/resource enforcement, external filesystem observation, host acceptance and actual subject transport remain open. Version 0.2.0 is unreleased.

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

- [Linux cgroup-v2 control and delegation documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Bubblewrap security model and limitations](https://github.com/containers/bubblewrap)

Checkpoint 3 is identified in package metadata and reports as `0.2.0.dev3`; this development version does not grant a stable 0.2.0 release or containment verdict.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.

Hosted verification attempt [41122595917](https://github.com/holeyfield33-art/mcp-behavior/actions/runs/41122595917), on 2026-10-30, failed before the live-helper job executed any steps and produced no job log. Its failure annotation was not retrievable in this session. No positive hosted containment evidence is recorded. [Checkpoint 3 PR #3](https://github.com/holeyfield33-art/mcp-behavior/pull/3) remains unmerged pending successful hosted verification; local validation is 108 passing tests with one explicitly skipped live cgroup test.
