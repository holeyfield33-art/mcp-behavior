# MCP Behavior — current status and maintenance authority

**Observed:** 2026-11-01, using GitHub repository contents and CI metadata.  
**Pinned `main` before this documentation change:** `0634e209d98fcf29f688f7a294ae73e5cec6b552` (PR #6, removal of unintended Studio product linking).  
**Package:** `0.2.0.dev5`; intended `0.2.0` release **not published**.  
**Disposition:** **GO for reviewed local behavioral assessments and trusted-helper development only. NO-GO for arbitrary hostile subjects, full containment/security certification, and unrestricted production release.** `containment: UNKNOWN`; overall reference security evaluation `INCOMPLETE`.

This is the **one living current-status document**. The [SDLC](SDLC.md) owns durable engineering and maintenance procedures; [SPEC](SPEC.md) and [ARCHITECTURE](ARCHITECTURE.md) own stable contracts; [ROADMAP](ROADMAP.md) owns acceptance matrix; `proof/` and dated checkpoint notes are historical. Record current status here, not in competing handoffs.

## Implemented as source-inspected at baseline

- Python 3.11+ stdlib CLI for fixture-owned, oracle-graded synchronous stdio MCP tool assessment; initial profile is read-only repository inventory.
- Distinct readiness and security verdicts; FAIL precedence over missing required evidence; UNKNOWN/INCOMPLETE rather than invented PASS.
- Native mode retains containment UNKNOWN. Namespace mode defaults to trusted helper probes and zero subject launches; explicitly opted-in experimental sessions require actual helper/preflight and cgroup supervision, and **still** cannot award full containment PASS.
- Experimental Linux namespace/cgroup-v2 runner uses bubblewrap, controller-owned storage/process/TCP observations and finite actual-subject controls. Safety evidence is scoped to the exact independent observers and available environment.
- CI workflow declares deterministic tests plus live Linux helpers. A workflow definition is not a completed run.

## Evidence ledger (do not mix historical results with new verification)

| Evidence | Classification | Source and limitation |
| --- | --- | --- |
| Exact GitHub main and package metadata | **OBSERVED** | Main `0634e209`; `pyproject.toml` `0.2.0.dev5`; source/docs inspected in this maintenance review |
| Original prototype proof | **HISTORICAL** | Immutable `proof/` and restoration ledger; not today's execution |
| Checkpoint 3 helper run | **HISTORICAL LOCAL**: 109 tests PASS | Stated privileged Ubuntu Docker Desktop/WSL2 environment; helper probes only |
| Checkpoint 4 opt-in run | **HISTORICAL LOCAL**: 122 tests PASS | `docs/CHECKPOINT4.md`; limited experimental subject path |
| Finite subject acceptance | **HISTORICAL LOCAL**: **128 tests PASS, zero skipped** | `docs/SUBJECT_ACCEPTANCE.md` recorded 2026-10-30: privileged Ubuntu 24.04 container on WSL2/Docker Desktop, Python 3.12.3, bubblewrap 0.9.0, strace 6.8. Five finite records and mount/alias test; NOT full containment, no fixed Sentinel-Zero |
| Hosted CI on `main` (`41325740177`) | **BLOCKED / NOT_RUN** | `deterministic` and `live-helpers` jobs both concluded failure with **zero executed steps**; cannot infer an application test failure or pass |
| New documentation branch: Python tests, real namespace/strace, wheel, fixed Sentinel-Zero | **NOT_RUN** | Source/CI review via GitHub only; this edit did not execute repository tests or hostile subjects |
| Full isolation and independent target acceptance | **NOT_ESTABLISHED** | Open read/write/race and egress coverage, aggregate disk quota, observer tamper/loss, full controller-crash/closure and fixed Sentinel-Zero retest; see [subject acceptance](SUBJECT_ACCEPTANCE.md) and [roadmap](ROADMAP.md) |

Never replace a missing required oracle with a target assertion. A missing kernel feature, cgroup delegation, observer, budget or required test leaves applicable evidence UNKNOWN/INCOMPLETE, not PASS. The historical 128 local tests are not fresh CI or a production certification.

## Current priorities and owners

1. **Restore executed CI evidence.** Repository operator must resolve the Actions account/runner blocker; rerun `.github/workflows/checkpoints.yml` on exact head and inspect **executed steps** and saved output, not just job conclusions. No billing or privileged-host action is authorized by this document.
2. **Finish the containment acceptance matrix**, using a disposable, explicitly delegated capable Linux host with authorized independent observation of forbidden reads, transient writes, TOCTOU, broader egress, aggregate storage, observer loss and controller recovery. Assign host operator/reviewer before running. Never weaken required proofs to reach PASS.
3. **Run fixed Sentinel-Zero subject acceptance** against pinned failing/fixed artifacts, profile and harness revision, with an independent behavioral oracle; record all inputs, missing evidence and verdicts. The reference server is only a control, never a substitute.

## Repository maintenance posture

The [project-specific maintenance section](SDLC.md#10-repository-maintenance-and-owasp-phase-coverage) covers change/release and post-change verification, dependency/toolchain drift, Linux kernel/bubblewrap/cgroup assumptions, CI, incident/advisory intake, documentation hygiene and risk-based periodic health review.

**Proposed cadence:** monthly for this actively evolving security-test harness, subject to operator approval and appropriate host availability. **No scheduled check or new periodic review has been created or performed.** Update this page only when concrete evidence, decision or owner changes; preserve immutable old proof and exact test records elsewhere.

**Separation:** MCP Behavior remains independent. Studio supplied engineering knowledge and an earlier scoped assessment; **it is neither a runtime authority nor a linked product**. Code Sentinel/Sentinel-Zero is an optional external test subject, not a harness dependency. MOTHERSHIP evidence remains separate.
