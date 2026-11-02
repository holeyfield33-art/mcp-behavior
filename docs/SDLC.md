# MCP Behavior — reviewed SDLC and handoff

Review date: 2026-10-30. Current development package version: **0.2.0.dev5** (original prototype: 0.1.0). Next development target: **0.2.0, one validated Linux isolation backend**. Checkpoint 3 helper live evidence is recorded for its stated container environment. Checkpoint 4 adds experimental, explicitly opted-in supervised subject sessions. Version 0.2.0 is not released and containment remains UNKNOWN.

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

## 5. Historical checkpoint status (current authority: [STATUS.md](STATUS.md))

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

## 7. Historical development order and change discipline (current priorities: [STATUS.md](STATUS.md))

1. Preserve the restored v0.1.0 tree and original proof as the baseline.
2. Validate the implemented namespace/TCP/cgroup helpers on a capable explicitly delegated Linux host, then integrate one supervised subject backend against [ROADMAP.md](ROADMAP.md). --cgroup-parent only selects an existing delegated path; never auto-enable parent controllers or change parent limits. Unsupported prerequisites must fail closed; no automatic native fallback.
3. Add independent observation and synchronized race cases before expanding claims about reads/writes.
4. Retest an actual fixed Sentinel-Zero release against the same four behavioral gates. Preserve both failing and fixed artifact/config/profile identities. The reference server cannot substitute for this gate.
5. Decide on finding-level fixtures separately before claiming scanner correctness. HTTP/authentication and real-model experiments remain deferred.

Use a branch for each bounded implementation change. A review identifies the property, independent oracle, deliberate failure control, test result and limitations. Do not change grading policy or weaken a check just to make a target pass. A profile/normalization change needs an explicit version/digest change and a reviewed reason.

Keep original proof immutable. New runs go to `out/` or a distinct versioned proof directory and record the commit, interpreter, environment, profile/config hashes and final exit state. Do not overwrite evidence from a different artifact or present a historical report as a current run.

Before publishing a change, verify a fresh checkout rather than a worktree with untracked dependencies. Run relevant tests and the reference smoke; for package changes, build/install the wheel and smoke it outside the source tree. Verify GitHub's resulting commit/tree after updating the branch.

## 8. Historical definition of done for restoration handoff

- [x] All 32 prototype files restored; root tree equals the bundled tree at restoration commit.
- [x] Remote history retained; branch update used the observed expected head.
- [x] Fresh GitHub clone passed all 38 automated tests.
- [x] Reference smoke returned exit 2 with FINISHED, matching run ID, expected lanes and no harness errors.
- [x] Reviewed SDLC and measurable isolated-runner roadmap added.
- [ ] Version 0.2.0 isolation acceptance matrix completed and externally reviewed.
- [ ] Fixed real-subject acceptance run completed.

The final two items are future development gates, not prerequisites for acknowledging that the repository repair is complete.


## 9. Historical checkpoint 3 handoff

Implementation: fixed trusted infrastructure helpers, not configured MCP commands. Network evidence covers named IPv4/IPv6 loopback TCP endpoints with external receipts and mandatory host positive controls. The cgroup self-test requires genuine delegated v2 controls; it verifies new-leaf limit readback, join-before-release, detached-child membership and recursive kill/empty/removal. CPU bandwidth and sampled lifetime CPU budgets are reported separately. Reported isolation policy has its own digest.

Host result: loopback positive controls work, the bubblewrap namespace operation is blocked, and no cgroup filesystem is exposed here. Keep the live cgroup test skipped/explicitly missing until MCP_BEHAVIOR_CGROUP_PARENT names a capable delegated host. Resource-stress acceptance, full network coverage, actual Runner/transport supervision, protected oracle/controller storage and external read/write/race observation remain open. Both direct and Runner namespace launches must remain disabled until their required run-level gates are real.

Update every current user-facing document and CHANGELOG.md when checkpoint behavior changes. Keep proof/ immutable. Preserve exact uploaded tree identity, local versus live evidence distinctions, installed-wheel verification and a fresh-checkout test result in the PR before merge.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.

Subsequent state: PR #3 is merged as d434494; local capable-host helper validation is 109 passed, zero skipped. Hosted run 41133686609 never started because of a confirmed account billing lock. Checkpoint 4 and finite actual-subject acceptance supersede this historical handoff; see SUBJECT_ACCEPTANCE.md. Full containment remains UNKNOWN.


## 10. Repository maintenance and OWASP phase coverage

This is the **project-specific maintenance contract**, adapted from the [OWASP Web Security Testing Framework](https://wstg.owasp.org/stable/3-The_OWASP_Testing_Framework/0-The_Web_Security_Testing_Framework/) and the existing [Studio repository knowledge/maintenance guide](https://github.com/holeyfield33-art/software-research-studio/blob/main/docs/REPOSITORY_KNOWLEDGE_LAYOUT.md). Both provide **selection guidance**; they do not add a Studio engine dependency, require a waterfall process, confer certification or authorize hostile-subject execution. The target's implementation and tool output are untrusted. The existing profile, isolation invariants and independent oracles still govern the product.

### Ownership of facts and documents

- [README](../README.md): user-facing product and examples. [AGENTS](../AGENTS.md): **one** agent entrypoint and read order. [STATUS](STATUS.md): **one** mutable authority for current revision, evidence, decisions, blockers and next actions.
- [SPEC](SPEC.md): behavioral requirements, profile assumptions and independent-oracle semantics. [ARCHITECTURE](ARCHITECTURE.md): controller/subject trust split and backend decisions. [ROADMAP](ROADMAP.md): detailed acceptance matrix and longer-term candidate milestones. The prior numbered sections of this SDLC remain historical design/restoration evidence; **do not append session-by-session current handoffs here**.
- [SUBJECT_ACCEPTANCE](SUBJECT_ACCEPTANCE.md), [CHECKPOINT4](CHECKPOINT4.md), [ADVERSARIAL_REVIEW](ADVERSARIAL_REVIEW.md) and `proof/`: bounded historical evidence and open attack scenarios; do not overwrite preserved reports or interpret a test on one kernel as a general product guarantee.
- Operator/maintainer approves subjects, capabilities, review cadence and releases. Host operator owns real Linux/cgroup/strace/bubblewrap constraints. Independent reviewer checks consequential containment and scoring claims. If an owner or authoritative CI revision is unknown, record `UNKNOWN`, not a fabricated approval.

### OWASP testing stages selected for MCP Behavior

| Stage | Relevant product-specific review | Concrete check/trace |
| --- | --- | --- |
| **Before development** | Pin project intent, Linux/Python support, security policy, authorized hosts/subjects, scoring invariants and quantitative criteria **before** implementation. Record independent oracle, positive/failing control and a measurable result for each proposed requirement. | Reviewed spec/profile and acceptance row; trace requirement → code/control → observed independent result. No automatic registration of assessed targets |
| **Definition / design** | Challenge ambiguous use of `PASS`, `UNKNOWN`, `INCOMPLETE`, trusted versus server-reported identities and process controls; review controller/subject trust zones, isolation, evidence paths, failure attribution and recovery. Use a short diagram/ADR when relevant, not mandatory UML. | SPEC, ARCHITECTURE, scoped threat scenario and independent observer/negative control |
| **Development** | Walk source flow (CLI/config → isolation/preflight → transport → oracle → verdict/evidence) before detailed review. Preserve FAIL precedence and no native fallback; test parser/transport boundaries, resource budgets, cancellation, observer loss, time-of-check/time-of-use, cgroup descendants, replay/determinism and malformed inputs as applicable. | Relevant `tests/` plus exact commands/outputs; add a failing regression before a fix where feasible |
| **Release / deployment** | Separate local prototype usage from allowing new hosts or unknown subjects. Verify installed wheel, Python/runtime and bubblewrap/strace/cgroup prerequisites, required host permissions, network/mount/FD/credential containment, observer integrity and denial behavior on the **exact candidate/environment**. | Actually executed deterministic and live acceptance suites, explicit skips, independent host observables, reviewed rollback/recovery and owner release decision |
| **Maintenance / operations** | Track upstream protocol/runtime/kernel/dependency changes, CI and environment drift, regressions, false assurance, source/proof integrity, documentation and incidents. After each meaningful code/config change, recheck the affected oracle and containment boundary on authorized environments and preserve evidence. | Current STATUS plus scoped CI/private proof artifacts and a retained issue/decision history |

This is a **behavioral harness** rather than a general deployed web application. Web sessions, login/account controls and live penetration-testing of unrelated services are inapplicable unless the accepted product scope changes. Do not use any broad checklist as permission to add HTTP/auth/model scoring.

### Repository maintenance triggers and checks

| Trigger | Maintain and verify | Record |
| --- | --- | --- |
| **Every PR / code or policy change** | Pin HEAD, inspect diff and code flow, evaluate affected trust boundary, verify positive+negative controls and verdict precedence, rerun scoped suite; do not silently edit fixture answers, hash manifests or grading policy. Check README/CLI consistency and exact output/exit codes. | Changed requirement/control, code paths, test commands, PASS/FAIL/SKIP/NOT_RUN, review owner, rollback and current STATUS |
| **Kernel/namespace/cgroup/bubblewrap/strace change** | Use an explicitly disposable delegated Linux host. Validate required capabilities and actual independent host evidence; test denied preflight, controller-owned fixtures, run-scoped cgroups, descendants, UID/paths, network, observer integrity and cleanup. No missing proof yields containment PASS. | Kernel/runtime/tool versions, capability matrix, source/runtime hashes, positive/unsafe controls, observed results and denied/UNKNOWN cases |
| **Before packaging/releasing** | Rebuild/install the wheel in a clean environment outside checkout, run reference smoke and appropriately scoped live acceptance, verify release dependencies/provenance, CI executed steps on exact SHA, compatibility notes, version and recovery. Keep full 0.2.0 release HOLD until matrix and external subject gate close. | Release candidate SHA, environment, verified artifacts, independent review and authorized release/HOLD |
| **After an authorized deployed/host change** | Re-evaluate actual fixture and host observables, forbidden canary access, report/oracle protection, resource ceilings, descendant cleanup, TCP evidence and exact machine-readable verdicts. Refuse silent native fallback or incident-contaminated proof. | Before/after result, host changes, explicit remaining UNKNOWN, rollback/containment decision |
| **New vulnerability, protocol/host advisory or incident** | Recheck dependent Python, MCP stdio semantics, bubblewrap and kernel/WSL/cgroup assumptions, exposed observer or file/IPC channels, failed/hidden cases and recovery/credential paths. Use synthetic controlled reproductions; do not run untrusted targets casually. | Advisory revision, independent reproduction, affected versions, remediation, owner and deadline/trigger |
| **Periodic health review** | **Proposed monthly**, subject to maintainer/host-owner agreement; inspect outstanding PR/issues, stale docs, test/CI environment, source/proof hashes, toolchain drift, open containment matrix, operator runbooks and unmet fixed-subject acceptance. More frequent after incidents/advisories; low-change archives may need less. | Date, exact head, actual checks/skips, open risks and next trigger. **Not automatically scheduled by this document** |
| **Transfer / retirement** | Explicitly review authority and access revocation, confidential fixture/log retention, artifact custody, dependent users, rollback/cleanup and continuity. | Operator-approved disposition and custody without destructive default behavior |

### One bounded maintenance change and evidence contract

1. **Orient:** verify real branch/HEAD and dirty tree; read [STATUS](STATUS.md), affected SPEC/ARCHITECTURE and current tests, then select only relevant practices and requirements. If the target is not authorized or host safety is uncertain, restrict work to analysis/fixtures.
2. **Define and preserve controls:** write the expected positive and deliberate failing behavior, external oracle and stop conditions; preserve the old output/manifest, avoid weakening the denominator or reclassifying absence of observation as safe.
3. **Implement narrowly:** maintain existing profile, one backend and no target-derived grading. No unrelated architectural changes, scripts, dependencies or feature additions.
4. **Verify correctly:** for a normal code change, `PYTHONPATH=src python3 -m unittest discover -s tests -v`; confirm documented reference smoke returns **exit 2 / INCOMPLETE**, not 0. When a capability claim changes, add an authorized live matrix with positive and unsafe controls and inspect raw kernel/observer evidence. Run clean-wheel smoke when packaging changes. `NOT_RUN`, `BLOCKED` and `SKIP` must not be renamed `PASS`.
5. **Recheck release/host effects:** compare old/new evidence on pinned candidates; only an actual independent host review may authorize a stronger containment or product decision. If security-sensitive verification is blocked, HOLD the affected claim.
6. **Update only owned facts:** record current SHA, environment, commands/results, incident or issue, owner, verdict, remaining unknowns and up to three next steps in `STATUS.md`. Put immutable run artifacts in approved external/versioned storage; do **not** mutate the original `proof/` directory. Update CHANGELOG for user-visible behavior and SPEC/ARCHITECTURE/ROADMAP only when their stable contract changes.

**Current adoption scope:** documentation/agent workflow, not new enforcement code or executed CI. The older local 128-test result remains limited to its recorded environment; CI jobs that ran zero steps remain NOT_RUN. Full containment and fixed Sentinel-Zero acceptance remain open; no 0.2.0 release authorization or security certification follows from adopting this SDLC.
