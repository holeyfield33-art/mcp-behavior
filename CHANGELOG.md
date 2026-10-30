# Changelog

## Unreleased — 0.2.0.dev5, finite subject acceptance, 2026-10-30

- Reject protected report/config/oracle mount overlaps and explicit artifact
  hardlink aliases; the CLI supplies its actual report and config destinations.
- Abort later namespace sessions after resource-observer loss, including OSError,
  while preserving resource intervention versus missing-evidence attribution.
- Add actual MCP attack controls with external syscall/process/TCP observations,
  unsafe-layout detection, CPU/memory/PID/file-limit interventions, crashed/late
  descendants and interrupted-observer acceptance. Preserve full containment
  UNKNOWN; aggregate storage quota and the wider read/write/race matrix stay open.
- Expand live CI to retain finite subject evidence; hosted execution is still
  subject to the account's known billing lock.

## Unreleased — 0.2.0.dev4, experimental checkpoint 4, 2026-10-30

- Add explicit `--namespace-subject` opt-in after policy-bound host-path, network
  endpoint and cgroup helper probes pass; helper-only mode remains the default.
- Run each configured MCP session in a fresh cgroup through a blocked trusted
  bootstrap, verify membership before release into bubblewrap, sample resource
  usage, and record recursive teardown. Never fall back to native execution.
- Mount declared artifact files read-only and preserve fixture/CWD paths; reject
  unsupported namespace UID/GID overrides and unsafe mount layouts.
- Add contract and capable-host integration tests; keep containment UNKNOWN until
  the full run-level matrix is complete. Sentinel-Zero acceptance remains pending.
- Record the user-confirmed checkpoint 3 helper evidence and confirmed hosted CI
  billing blocker without committing local evidence paths.

## Unreleased — 0.2.0.dev3, checkpoint 3, 2026-10-30

Development package/report version is now `0.2.0.dev3`; no stable 0.2.0 release or package-registry publication has occurred.
The CLI, report metadata and MCP client handshake use the same development version.

### Added

- Controller-owned IPv4/IPv6 loopback TCP observers with mandatory host positive controls, nonce-bound helper evidence, bounded frames/connections and explicit observer-shutdown failures.
- A fixed-helper cgroup-v2 supervisor self-test: genuine-filesystem/delegation checks, fresh owned leaf, memory/swap/PID/CPU readback, membership-before-release and a detached-child cleanup check using cgroup.kill plus recursive empty/removal observations.
- Namespace-only --cgroup-parent and a separate isolation-policy digest in JSON/readable reports. Parent controllers and limits are never changed.
- Negative controls for leaked network traffic, lying helpers, incomplete observations, fake cgroup files, ineffective controls, failed membership and failed cleanup. An opt-in live cgroup integration test explicitly skips without a delegated host.

### Documentation

- Updated README, specification, architecture, current/historical status, adversarial review, roadmap and SDLC with current commands, evidence scope, host limitations and remaining gates.

### Current limits

- Only fixed trusted preflight helpers run in namespace mode. Configured MCP subjects remain disabled even after successful helper probes; containment remains UNKNOWN and the assessment remains INCOMPLETE.
- This host has working TCP positive controls, blocked bubblewrap namespace creation and no exposed cgroup filesystem. Positive live namespace/cgroup acceptance and resource stress are pending.
- No 0.2.0 package release. Run-level integration, protected oracle/controller storage, complete egress enforcement and external read/write/race coverage remain open.

## Checkpoint 2 — 2026-10-30

Merged [PR #2](https://github.com/holeyfield33-art/mcp-behavior/pull/2), main commit 5c96823. Added bounded trusted host-path probes, private known fixtures, strict schema/nonce validation and preflight wiring; restored the acceptance matrix and kept subject launch disabled. 76 tests passed from a fresh checkout; installed-wheel checks retained zero namespace subject cases and native containment UNKNOWN.

## Checkpoint 1 — 2026-10-30

Merged [PR #1](https://github.com/holeyfield33-art/mcp-behavior/pull/1), main commit 71645fb. Restored the full Runner and added backend selection, fail-closed namespace preflight, report wiring and regression coverage. 48 tests passed. Native containment remained UNKNOWN.

## 0.1.0 prototype — 2026-10-29

Standalone stdlib Linux behavioral harness: bounded stdio transport, reviewer-owned profiles, independent fixtures/oracle, readiness/security lanes, deterministic recovery and atomic JSON/Markdown reports. Original 38-test proof detected four Sentinel-Zero behavior defects; correct reference readiness passed and native overall remained INCOMPLETE. Original proof artifacts are retained unchanged under proof/. A fixed real-subject retest remains pending.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.

Hosted verification attempt [41122595917](https://github.com/holeyfield33-art/mcp-behavior/actions/runs/41122595917), on 2026-10-30, failed before the live-helper job executed any steps and produced no job log. Its failure annotation was not retrievable in this session. No positive hosted containment evidence is recorded. [Checkpoint 3 PR #3](https://github.com/holeyfield33-art/mcp-behavior/pull/3) remains unmerged pending successful hosted verification; local validation is 108 passing tests with one explicitly skipped live cgroup test.
