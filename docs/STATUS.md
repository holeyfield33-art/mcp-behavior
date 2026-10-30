# Implementation and first proof

2026-10-29. Version 0.1.0. Standalone local Git repository: `mcp-behavior`. No remote repository has been created by this task.

Decision: **GO for the local behavioral prototype. NO-GO for broad security certification or execution of arbitrary hostile servers on the host.**

## Implemented and verified

- A stdlib-only Python/Linux CLI and bounded stdio MCP client.
- Reviewer-owned JSON profiles and strict response-field mappings.
- Independent randomized fixtures, content hashes, coverage/completion checks, canaries and filesystem snapshots.
- Missing/bad/relative/outside path cases; escaping/internal/dangling symlinks; directory loop; FIFO; verified mode-000 failure; mixed-language and large repositories.
- Same/fresh-session repeatability with narrow declared timestamp normalization.
- Same-session scripted repair, separate from real-model behavior.
- Separate readiness/security lanes; PASS/FAIL/UNKNOWN/N/A; no weighted score or missing-evidence pass.
- Request, case and suite deadlines; pre-decode byte caps; message/cursor/stderr bounds; process-group cleanup and minimal environment.
- External execution-identity, capability, permission and canary-readability probes.
- JSON/Markdown reports with run IDs, atomic completion markers, exact profile/config/explicit artifact hashes and fail-closed exit codes.

Validation: **38 tests passed**. Tests drive independent defective server processes as well as the oracle and reporting failure paths. The wheel built successfully; its Python sources exactly matched the tested sources. Installed-wheel CLI runs from `/tmp` produced both final proof reports, without a source-tree import path. Both full runs completed 14 cases and recorded zero harness errors.

## Live first subject

External subject: Sentinel-Zero at reviewer-declared Git revision `303267e4786735b068ed544936480b2368194b01`. The report separately records the server's own `0.1.0` handshake version and hashes explicit source files and the executable. It does not present that string as an artifact attestation or claim a sealed dependency closure.

| Acceptance case | Observed result |
|---|---|
| Bad input must carry a reason | FAIL: `Error executing tool analyze_repository` |
| Mixed-language inputs must be accounted for | FAIL: two planted JavaScript files absent from the processed-file evidence |
| Large result must fit the configured budget or explicitly refuse | FAIL: harness stopped the frame at 278,528 observed bytes, beyond the 262,144-byte frame ceiling; caller tool-result budget was 65,536 bytes |
| Relative path must follow the profile contract | FAIL: accepted relative input and disclosed the decoy server-CWD canary |
| Repeated frozen input beyond allowed timestamps | PASS after explicitly declaring `/plans/*/generated_at` as the only varying timestamp path |
| Completion truth | UNKNOWN: no completion flag mapped; the harness does not infer one |
| Scanner semantic correctness | UNKNOWN: no finding-level/content oracle; processed-file lists alone are insufficient |

Readiness FAIL; security FAIL; overall FAIL. Outside-root behavior also failed this profile's explicit root restriction. These are results against this named behavioral contract, not claims that MCP roots themselves are a normative OS access-control mechanism.

The original roughly 196k-token observation was not adopted as a new measurement. This proof measures wire bytes and records the interception as FAIL.

## Controls and the incomplete gate

The independent reference inventory implementation passed readiness. It correctly reported failed work, refused unsupported paths/entries with reasons, preserved watched files, returned correct hashes, and explicitly refused the oversized result. Security and overall remained INCOMPLETE because native execution containment is unproven.

Four separate injected controls reproduced generic errors, silent mixed-language omissions, oversized output and CWD-relative path resolution. All four were detected. Additional regression tests cover lies about completion, false hashes/counts, contradictory results, silent truncation, duplicate paths, writes, instability, framing/ID/JSON faults, flooding, cursor loops, timeout/deadline handling, unsupported features, broken setup/observation and stale PASS reports.

This establishes the failing-subject and honest-INCOMPLETE parts of the first proof, plus a correct implementation as a harness control. **A fixed Sentinel-Zero version has not been implemented or retested here.** The reference implementation is not substituted for that acceptance gate.

## Next required work

1. Implement and externally validate isolated execution: protected oracle/report storage, host/network boundaries, process/cgroup limits and complete descendant teardown.
2. Add external read/write observation and synchronized race cases before claiming absence of unauthorized reads or transient effects.
3. Retest a fixed real subject against the same four behavioral gates. Add independently reviewed finding-level fixtures before claiming scanner accuracy.

HTTP, authentication, additional tool types, real-model evaluations and commercial features remain outside this version.

## Evidence

`proof/summary.json` provides the compact machine-readable result. `proof/reference.{json,md}` and `proof/sentinel-zero.{json,md}` contain the final installed-wheel assessments. `proof/sentinel-zero-config.json` records the exact local launch/profile configuration and must be edited for a different machine. `proof/negative-controls.json`, `proof/tests.log`, build/install logs and `proof/source-sha256.json` preserve the validation record.

The downloadable bundle includes the source tree, built wheel, all proof files, a Git bundle preserving the independent repository, and SHA256SUMS. Native execution, observational limits and incomplete dependency identity remain visible in the reports.
