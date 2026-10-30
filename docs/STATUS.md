# Implementation and proof status

Updated 2026-10-30. Repository: https://github.com/holeyfield33-art/mcp-behavior. Development package version: **0.2.0.dev3**. Development target: **0.2.0**, not released.

Decision: **GO for reviewed local behavioral runs and trusted-helper development; NO-GO for arbitrary hostile MCP subjects, broad security certification or a containment PASS.**

## Current checkpoints

| Checkpoint | Implemented | Evidence / remaining gate |
|---|---|---|
| 1 — interface and fail-closed preflight | Merged PR #1; backend selection, full Runner, fresh reports | 48-test checkpoint baseline; namespace zero subject launches, native containment UNKNOWN |
| 2 — candidate namespace layout | Merged PR #2; bounded trusted host-path helper, private fixtures, strict nonce/schema validation | 76-test checkpoint baseline; actual subject launch intentionally disabled |
| 3 — supervision and network observations | Controller-owned IPv4/IPv6 TCP listeners, required host controls, cgroup-v2 helper supervision, `--cgroup-parent`, policy digest and regression cases | Implemented for trusted helpers; positive live cgroup/namespace acceptance is pending on a capable host |
| Run-level containment | Not integrated | Actual MCP subject supervision, protected oracle/controller storage, complete network policy and descendant teardown remain required |
| External read/write/race coverage | Not implemented | Quiet canaries and final snapshots remain insufficient |
| Fixed Sentinel-Zero acceptance | Pending | Reference control cannot substitute for a fixed real-subject retest |

Checkpoint 3 validation: **109 tests discovered, 108 passed, one live cgroup integration test skipped** because no delegated cgroup path was supplied. Ordinary-file control models test contracts and failure handling; they are not kernel containment proof. Installed-wheel checks retain native readiness PASS/containment UNKNOWN and namespace zero subject cases, reject fake cgroup directories and verify the policy digest. A fresh-checkout run is required before merge.

## What the new evidence means

Namespace preflight may start only fixed controller-owned helpers. It never starts the configured MCP command, even if all synthetic probes succeed. `launch_subject()` and Runner each retain their launch refusal. Required run-level gates remain incomplete; the resulting report is FINISHED/INCOMPLETE with zero subject cases and containment UNKNOWN.

The filesystem helper validates known nonempty private secrets before testing the candidate view. The network helper requires positive controls at both controller-owned IPv4 and IPv6 TCP endpoints and uses external receipts to catch leaked traffic, including a helper that lies about its connection outcome. It does not grade UDP, arbitrary routes, Unix sockets or every possible egress path.

The cgroup self-test requires an explicitly delegated genuine cgroup-v2 directory. It sets and reads back limits in a fresh owned leaf, verifies bootstrap membership before release, observes a detached helper child, and uses `cgroup.kill` plus recursive `populated=0`, empty membership and removal as cleanup evidence. CPU bandwidth and sampled total CPU usage are distinct controls. It never changes parent limits or enables parent controllers. Resource stress acceptance and actual subject integration remain open.

On this development host, real host TCP positive controls succeed; bubblewrap 0.12.0 fails the candidate network-namespace operation with NETLINK_ROUTE `Operation not permitted`; no cgroup filesystem is exposed. Missing delegation and fake ordinary-file cgroup directories fail closed. These observations do not establish a positive containment proof.

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

Next: run the helper integration on a capable explicitly delegated Linux host, preserve its artifact/config/policy identities and negative controls, then integrate supervised subject transport without waiving the acceptance matrix in [ROADMAP.md](ROADMAP.md). HTTP/auth, new profile families, real-model scoring and commercial features remain outside this slice.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.
