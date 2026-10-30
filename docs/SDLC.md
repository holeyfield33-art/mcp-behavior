# MCP Behavior — reviewed SDLC and handoff

Review date: 2026-10-30. Current development package version: **0.2.0.dev4** (original prototype: 0.1.0). Next development target: **0.2.0, one validated Linux isolation backend**. Checkpoint 3 helper live evidence is recorded for its stated container environment. Checkpoint 4 adds experimental, explicitly opted-in supervised subject sessions. Version 0.2.0 is not released and containment remains UNKNOWN.

Repository: https://github.com/holeyfield33-art/mcp-behavior

Decision: **GO for the local behavioral prototype; NO-GO for broad security certification or executing arbitrary hostile servers on the host.** Isolation, observer coverage and the fixed real-subject acceptance run remain open.

## 1. Product and scope

Drive one explicitly selected synchronous MCP tool over stdio and check its behavior against reviewer-owned fixtures and an external oracle. The target never supplies the answer key. The current profile is a read-only repository inventory contract.

This is a standalone project. Sentinel-Zero is an external test subject. Its implementation is not imported by the harness. A real model is not involved in grading; scripted recovery does not establish a model's ability to recover.

## 2. Review findings and corrections

| Priority | Issue in the supplied handoff | Corrected rule |
|---|---|---|
| P1 | “Any required UNKNOWN means overall INCOMPLETE” conflicts with the existing failing-subject report | Required FAIL takes precedence. Otherwise missing required evidence means INCOMPLETE. UNKNOWN never upgrades anything to PASS. |
| P1 | “Every harness intervention is server FAIL” also covers broken observers and exhausted suite budgets | An observed violation of an agreed server limit is FAIL, even when intercepted. Harness/setup/observer failures, unsupported features and unrun work are UNKNOWN. |
| P1 | “Separate UID/namespace or VM” is insufficient acceptance criteria | Validate protected storage, host/network boundaries, aggregate resource limits, descendant teardown and external observation; do not infer containment from a launcher flag. |
| P2 | “First proof: done” overstates the acceptance result | Failing real subject and honest INCOMPLETE are demonstrated. The reference is a positive control. A fixed Sentinel-Zero retest remains pending. |
| P2 | Force-pushing the bundle is unnecessary and its new origin has no fetched lease | Restore exact file content as a fast-forward commit with an expected-head check. Do not replace history to repair file content. |
| P2 | Auditing a few filenames can accept approximate or truncated files | Verify every baseline path, mode and Git blob ID, or the whole tree hash. |
| P2 | Bare unittest discovery does not put a src-layout package on the import path | Use `PYTHONPATH=src`, or first install the package into the test environment. |
| P2 | Archived proof and absolute launch paths can be mistaken for a current rerun | Keep historical proof unchanged; name current run ID, environment, commit and validation result separately. |

These corrections govern the handoff. They do not change the restored v0.1.0 implementation or rewrite its original proof.

## 3. Source of truth and restoration record

The repository is now the development source of truth. The ZIP remains an immutable v0.1.0 reference, not the place to make future edits.

| Artifact | Identity |
|---|---|
| ZIP | `MCP_Behavior_Prototype_v0.1.0.zip` |
| ZIP SHA-256 | `b5e0ade7414cd7253aa7cb33e050566e56a551673cfaec1d764c4cf4242d190f` |
| Bundled prototype commit | `db9b50be5b4ba0fcaa1d42e17a836dafe8faacde` |
| Exact 32-file prototype tree | `6cf3a245aeb338769b078bb95924b6008a75d7a3` |
| Partial remote before repair | `14f90a4526eb715c72e77f377d4fb5cc064b75a7` |
| Complete restoration commit | `15b8dbef8bc3501628a394ad2e45e0e89b3b113e` |

The audit found 16 missing files and 11 differing files; five files already matched. No remote-only files existed. One commit restored the exact prototype tree while retaining the previous remote commit as its parent. At the restoration/handoff commit all original 32 files were unchanged. Later checkpoint code and documentation changes are recorded in Git history and CHANGELOG.md.

`proof/` preserves the original 2026-10-29 prototype run. `STATUS.md` now records current checkpoints and labels the original proof as historical. This document records the 2026-10-30 repository repair and current handoff.

## 4. Non-negotiable verdict rules

1. The server never grades itself. Declarative mappings locate evidence; they cannot invent it, import target code or supply executable scoring logic.
2. If the target exceeds the agreed byte, request-time, case-time or other server limit, record FAIL even if the harness prevents the consequences.
3. A failed oracle, setup, unsupported capability, unusable precondition, suite-budget exhaustion or unrun scenario gives required UNKNOWN evidence. Do not attribute those failures to the target without evidence.
4. Aggregate required checks in this order: any FAIL → FAIL; otherwise any UNKNOWN or required N/A, or no required checks → INCOMPLETE; otherwise PASS. Optional exclusions cannot satisfy a required check.
5. Compute readiness and security separately. Native execution always retains required containment UNKNOWN. A native run can still be FAIL if another required property was disproved.
6. No LLM in the scoring path. Real-model runs are separately reported and cannot override fixture results.
7. A quiet canary does not prove no unauthorized read; final snapshots do not prove no transient write. Claim only the named observed property.
8. A protocol handshake identity is server-reported. Explicit file hashes are not a sealed runtime dependency closure.

## 5. Current status

| Area | State |
|---|---|
| Complete source, examples, documentation and original proof on GitHub | Restored, exact baseline tree |
| Linux stdlib CLI, bounded stdio client and one inventory profile | Implemented |
| Fixtures, content hashes, canaries, coverage/completion, paths, repeatability, snapshots and scripted repair | Implemented within the stated profile |
| Automated tests | Original baseline 38; checkpoint 1: 48; checkpoint 2: 76; checkpoint 3 capable-host run: 109 passed, zero skipped. Checkpoint 4 adds contract and explicitly enabled live subject tests |
| Fresh-clone reference run | Exit 2; readiness PASS; security INCOMPLETE; overall INCOMPLETE; 14 cases; no harness errors |
| Isolation helpers | Namespace host-path and finite TCP observers; delegated cgroup helper supervision, limit readback and detached-child cleanup contract implemented |
| Isolated MCP execution and verified run-level containment | Experimental supervised sessions integrated behind opt-in; full run-level containment matrix remains incomplete |
| Complete external read/write and race observation | Not implemented |
| Fixed Sentinel-Zero acceptance run | Pending |
| Finding-level scanner accuracy | Not established by inventory evidence |
| HTTP, authentication, more tool types and real-model runs | Outside this development slice |

The 38-test count is the historical prototype baseline, not a permanent quota. A skipped live integration test supplies no acceptance evidence. The opt-in cgroup test requires MCP_BEHAVIOR_CGROUP_PARENT on a genuinely delegated host. New behavior needs meaningful new regression and negative-control cases. Subprocess/wire tests are part of this suite; calling all of them unit tests hides their scope.

## 6. Start from a clean checkout

Run these commands in Linux or WSL Bash, with Python 3.11 or newer:

```bash
git clone https://github.com/holeyfield33-art/mcp-behavior.git
cd mcp-behavior
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Use this smoke check to validate the expected nonzero exit, finished report and matching run ID together:

```bash
PYTHONPATH=src python3 - <<'PY'
import json, subprocess, sys
from pathlib import Path

run = subprocess.run(
    [sys.executable, "-m", "mcp_behavior", "run",
     "--config", "examples/reference.json", "--output", "out/reference.json", "--native"],
    capture_output=True, text=True,
)
summary = json.loads(run.stdout)
report = json.loads(Path("out/reference.json").read_text())
assert run.returncode == 2, (run.returncode, run.stdout, run.stderr)
assert report["state"] == "FINISHED"
assert report["run_id"] == summary["run_id"]
assert report["verdict"] == "INCOMPLETE"
assert report["lanes"] == {"readiness": "PASS", "security": "INCOMPLETE"}
assert not report["harness_errors"]
print(summary)
PY
```

An unavailable kernel feature or unsuitable test host is an environmental gate, not permission to remove containment UNKNOWN or waive tests. Capture the precise failure and use an appropriate Linux environment.

## 7. Development order and change discipline

1. Preserve the restored v0.1.0 tree and original proof as the baseline.
2. Validate the implemented namespace/TCP/cgroup helpers on a capable explicitly delegated Linux host, then integrate one supervised subject backend against [ROADMAP.md](ROADMAP.md). --cgroup-parent only selects an existing delegated path; never auto-enable parent controllers or change parent limits. Unsupported prerequisites must fail closed; no automatic native fallback.
3. Add independent observation and synchronized race cases before expanding claims about reads/writes.
4. Retest an actual fixed Sentinel-Zero release against the same four behavioral gates. Preserve both failing and fixed artifact/config/profile identities. The reference server cannot substitute for this gate.
5. Decide on finding-level fixtures separately before claiming scanner correctness. HTTP/authentication and real-model experiments remain deferred.

Use a branch for each bounded implementation change. A review identifies the property, independent oracle, deliberate failure control, test result and limitations. Do not change grading policy or weaken a check just to make a target pass. A profile/normalization change needs an explicit version/digest change and a reviewed reason.

Keep original proof immutable. New runs go to `out/` or a distinct versioned proof directory and record the commit, interpreter, environment, profile/config hashes and final exit state. Do not overwrite evidence from a different artifact or present a historical report as a current run.

Before publishing a change, verify a fresh checkout rather than a worktree with untracked dependencies. Run relevant tests and the reference smoke; for package changes, build/install the wheel and smoke it outside the source tree. Verify GitHub's resulting commit/tree after updating the branch.

## 8. Definition of done for this handoff

- [x] All 32 prototype files restored; root tree equals the bundled tree at restoration commit.
- [x] Remote history retained; branch update used the observed expected head.
- [x] Fresh GitHub clone passed all 38 automated tests.
- [x] Reference smoke returned exit 2 with FINISHED, matching run ID, expected lanes and no harness errors.
- [x] Reviewed SDLC and measurable isolated-runner roadmap added.
- [ ] Version 0.2.0 isolation acceptance matrix completed and externally reviewed.
- [ ] Fixed real-subject acceptance run completed.

The final two items are future development gates, not prerequisites for acknowledging that the repository repair is complete.


## 9. Checkpoint 3 handoff

Implementation: fixed trusted infrastructure helpers, not configured MCP commands. Network evidence covers named IPv4/IPv6 loopback TCP endpoints with external receipts and mandatory host positive controls. The cgroup self-test requires genuine delegated v2 controls; it verifies new-leaf limit readback, join-before-release, detached-child membership and recursive kill/empty/removal. CPU bandwidth and sampled lifetime CPU budgets are reported separately. Reported isolation policy has its own digest.

Host result: loopback positive controls work, the bubblewrap namespace operation is blocked, and no cgroup filesystem is exposed here. Keep the live cgroup test skipped/explicitly missing until MCP_BEHAVIOR_CGROUP_PARENT names a capable delegated host. Resource-stress acceptance, full network coverage, actual Runner/transport supervision, protected oracle/controller storage and external read/write/race observation remain open. Both direct and Runner namespace launches must remain disabled until their required run-level gates are real.

Update every current user-facing document and CHANGELOG.md when checkpoint behavior changes. Keep proof/ immutable. Preserve exact uploaded tree identity, local versus live evidence distinctions, installed-wheel verification and a fresh-checkout test result in the PR before merge.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.

Hosted verification attempt [41122595917](https://github.com/holeyfield33-art/mcp-behavior/actions/runs/41122595917), on 2026-10-30, failed before the live-helper job executed any steps and produced no job log. Its failure annotation was not retrievable in this session. No positive hosted containment evidence is recorded. [Checkpoint 3 PR #3](https://github.com/holeyfield33-art/mcp-behavior/pull/3) remains unmerged pending successful hosted verification; local validation is 108 passing tests with one explicitly skipped live cgroup test.
