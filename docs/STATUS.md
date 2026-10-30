# Implementation and proof status

Updated 2026-10-30. Repository: https://github.com/holeyfield33-art/mcp-behavior. Development package version: **0.2.0.dev5**. Development target: **0.2.0**, not released.

Decision: **GO for reviewed local behavioral runs and trusted-helper development; NO-GO for arbitrary hostile MCP subjects, broad security certification or a containment PASS.**

## Current checkpoints

| Checkpoint | Implemented | Evidence / remaining gate |
|---|---|---|
| 1 — interface and fail-closed preflight | Merged PR #1; backend selection, full Runner, fresh reports | 48-test checkpoint baseline; namespace zero subject launches, native containment UNKNOWN |
| 2 — candidate namespace layout | Merged PR #2; bounded trusted host-path helper, private fixtures, strict nonce/schema validation | 76-test checkpoint baseline; actual subject launch intentionally disabled |
| 3 — supervision and network observations | Merged PR #3 (`d434494`); controller-owned IPv4/IPv6 TCP listeners and cgroup-v2 helper supervision | User-recorded capable-host evidence: 109 passed, zero skipped; all helper probes green in a privileged Ubuntu 24.04 Docker Desktop/WSL2 container |
| 4 — experimental subject sessions | Explicit `--namespace-subject`, policy-bound probe gate, per-session cgroup, membership-before-release, bounded MCP transport and recursive teardown | In development on a branch from `d434494`; see [design and acceptance criteria](CHECKPOINT4.md). Default remains helper-only |
| Finite actual-subject acceptance | Protected-path/artifact alias guards, external syscall/process/TCP observations, deliberately unsafe control, aggregate CPU/memory stress, crash/late writers and observer interruption | Implemented and locally exercised; see [the finite matrix](SUBJECT_ACCEPTANCE.md). This does not close the full containment matrix |
| Run-level containment | Partial session integration; no containment PASS | Full protected oracle/controller storage, egress, resource-intervention and descendant/race matrix remains required |
| External read/write/race coverage | Not implemented | Quiet canaries and final snapshots remain insufficient |
| Fixed Sentinel-Zero acceptance | Pending | Reference control cannot substitute for a fixed real-subject retest |

Checkpoint 3 validation on merged `d434494`: **109 passed, zero skipped** with explicit delegation; all helper probes passed and helper-only namespace smoke remained FINISHED/INCOMPLETE with zero cases. This evidence is specific to a privileged Ubuntu 24.04 container on Docker Desktop/WSL2, not bare-metal or a non-root delegated harness. Ordinary-file control models are not kernel proof. Evidence remains offline in a project-named bundle; no machine-specific bundle paths are committed.

## What the new evidence means

Namespace mode remains helper-only unless `--namespace-subject` is explicit. The experimental path requires green helper probes bound to the requested policy, then creates a fresh cgroup per subject session. A controller-owned bootstrap joins and blocks until sole membership and limits are verified; it then execs bubblewrap. There is no native fallback. The standalone ungated `launch_subject()` API still refuses. Full containment preflight remains incomplete even when experimental launch prerequisites pass, and containment remains UNKNOWN.

The filesystem helper validates known nonempty private secrets before testing the candidate view. The network helper requires positive controls at both controller-owned IPv4 and IPv6 TCP endpoints and uses external receipts to catch leaked traffic, including a helper that lies about its connection outcome. It does not grade UDP, arbitrary routes, Unix sockets or every possible egress path.

The cgroup self-test and experimental subject sessions require an explicitly delegated genuine cgroup-v2 directory. They set and read back limits in a fresh owned leaf and verify bootstrap membership before release. Subject transport samples aggregate usage and records recursive `cgroup.kill`, `populated=0`, empty membership and removal. CPU bandwidth and sampled total CPU usage are distinct controls. Parent limits/controllers are never changed. These observations do not complete the resource or containment matrix.

The earlier constrained host could not run bubblewrap network namespaces and exposed no cgroup filesystem. The later recorded Docker Desktop/WSL2 run closed the helper gap for its stated environment. Missing delegation and fake ordinary-file cgroup directories continue to fail closed.

## Historical v0.1.0 first proof — 2026-10-29

The original 38-test prototype and installed-wheel proof remain immutable under `proof/`. The repository was fully restored and then checkpoints 1 and 2 were merged on 2026-10-30; archived reports describe their original environment and commits.

External subject: Sentinel-Zero at reviewer-declared revision `303267e4786735b068ed544936480b2368194b01`. Its handshake version is server-reported, not a sealed artifact attestation.

| Behavioral gate | Historical observed result |
|---|---|
| Bad input needs a reason | FAIL: `Error executing tool analyze_repository` |
| Mixed-language inputs accounted for | FAIL: two planted JavaScript files absent from processed-file evidence |
| Large result bounded or explicitly refused | FAIL: frame stopped at 278,528 observed bytes versus 262,144 frame ceiling; tool-result budget 65,536 bytes |
| Relative paths follow profile contract | FAIL: relative input accepted and server-CWD decoy canary disclosed |
| Repeatability | PASS after the explicit `/plans/*/generated_at` normalization |
| Completion / scanner finding correctness | UNKNOWN: missing completion mapping and finding-level oracle |

Historical real-subject readiness/security/overall: FAIL. The independent correct reference passed readiness and remained security/overall INCOMPLETE in native mode. Four deliberately defective controls reproduced the four behavioral failures. A fixed real Sentinel-Zero revision has not been retested here.

## Evidence and next action

Archived evidence: `proof/summary.json`, `proof/reference.{json,md}`, `proof/sentinel-zero.{json,md}`, `proof/negative-controls.json`, logs and explicit source hashes. Archived configurations contain machine-specific launch paths and must be reviewed before reuse.

Next: finish checkpoint 4 acceptance on a capable explicitly delegated Linux host without waiving the matrix in [ROADMAP.md](ROADMAP.md), then complete the run-level matrix and fixed Sentinel-Zero retest. HTTP/auth, new profile families, real-model scoring and commercial features remain outside this slice.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.

Hosted run [41133686609](https://github.com/holeyfield33-art/mcp-behavior/actions/runs/41133686609) on merged `d434494` failed before either job started. Both annotations state that the account is locked due to a billing issue; artifact count was zero. This does not diagnose cgroup setup. Unlock billing before rerunning hosted checks. PR #3 is merged; local capable-host evidence is the available authority.
