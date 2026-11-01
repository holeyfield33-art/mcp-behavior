# Implementation and proof status

Updated 2026-11-01. Repository: https://github.com/holeyfield33-art/mcp-behavior. Development package version: **0.2.0.dev5**. Development target: **0.2.0**, not released.

Decision: **GO for reviewed local behavioral runs and trusted-helper development; NO-GO for arbitrary hostile MCP subjects, broad security certification or a containment PASS.**

## Current checkpoints

| Checkpoint | Implemented | Evidence / remaining gate |
|---|---|---|
| 1 — interface and fail-closed preflight | Merged | Backend selection; namespace zero default subject launches; native containment UNKNOWN |
| 2 — candidate namespace layout | Merged | Bounded trusted helpers; private fixtures |
| 3 — supervision and network observations | Merged PR #3 | Helper probes + cgroup supervision; live container evidence recorded offline |
| 4 — experimental subject path | In tree (dev) | Explicit flag only; full run-level matrix incomplete; containment UNKNOWN |
| Fixed Sentinel-Zero acceptance | Pending | Reference control cannot substitute |

Helper live evidence (stated disposable Ubuntu container / private cgroup namespace): 109 tests passed including live cgroup supervisor; namespace smoke exit 2 / INCOMPLETE / zero subjects when launch disabled. Hosted CI may be blocked by account billing—unrun jobs are not cgroup diagnoses.

## Next action

Finish run-level subject matrix and fixed Sentinel-Zero retest per [ROADMAP.md](ROADMAP.md). Do not claim containment PASS from helper evidence alone.
