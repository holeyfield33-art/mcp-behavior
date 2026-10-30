# Version 0.2.0 — isolated-runner acceptance plan

Status: checkpoint 1 done; checkpoint 2 in progress (launcher + host-canary observer). 2026-10-30.

One development slice: run the existing stdio inventory profile in an independently validated Linux isolation backend. Keep the v0.1.0 profile and reference controls working. Do not add HTTP, authentication, tool families, a model judge or commercial features in this slice.

## 1. Architecture decision before implementation

Record one backend choice and its supported kernel/runtime prerequisites. A Linux namespace/cgroup backend must provide a distinct subject identity, filesystem and process boundaries, no-new-privileges/capability policy, network denial and controller-owned limits. A dedicated VM is an alternative architecture requiring equivalent acceptance evidence, not a second backend to build simultaneously.

Separate the controller/oracle/report writer from the subject. Expected answers, reports, controller memory/process interfaces and supervisor control channels must be inaccessible to the subject. Runtime artifacts are mounted read-only; only declared disposable fixture/temp areas are writable. No inherited credentials, unintended file descriptors, host sockets or writable runtime/configuration mounts are allowed.

Startup must verify actual protections externally. A successful launcher invocation or a server's own report is not evidence that containment holds. If prerequisites or observation are unavailable, record INCOMPLETE with the reason and do not start in native mode automatically.

See `docs/ARCHITECTURE.md` for the accepted backend decision.

## 5. Progress log

| Date | Checkpoint | Notes |
|------|------------|--------|
| 2026-10-30 | 1 | Interface, preflight, fail-closed CLI. Merged PR #1. 48 tests. |
| 2026-10-30 | 2 (partial) | `namespace_runtime.py`: bwrap launcher, host-canary + oracle-dir probe. Preflight records real tool/canary evidence. Network + cgroup teardown observers still required False (fail closed). 51 tests. |

Full acceptance matrix remains in sections 2–4 of the original roadmap; network denial and teardown verification are still open gates.
