# Version 0.2.0 — isolated-runner acceptance plan

Status: checkpoints 2 and 3 partial; trusted-helper implementation present, live acceptance and subject launch still blocked. Review date: 2026-10-30.

One development slice: run the existing stdio inventory profile in an independently validated Linux isolation backend. Keep the v0.1.0 profile and reference controls working. Do not add HTTP, authentication, tool families, a model judge or commercial features in this slice.

## 1. Architecture decision before implementation

Record one backend choice and its supported kernel/runtime prerequisites. A Linux namespace/cgroup backend must provide a distinct subject identity, filesystem and process boundaries, no-new-privileges/capability policy, network denial and controller-owned limits. A dedicated VM is an alternative architecture requiring equivalent acceptance evidence, not a second backend to build simultaneously.

Separate the controller/oracle/report writer from the subject. Expected answers, reports, controller memory/process interfaces and supervisor control channels must be inaccessible to the subject. Runtime artifacts are mounted read-only; only declared disposable fixture/temp areas are writable. No inherited credentials, unintended file descriptors, host sockets or writable runtime/configuration mounts are allowed.

Startup must verify actual protections externally. A successful launcher invocation or a server's own report is not evidence that containment holds. If prerequisites or observation are unavailable, record INCOMPLETE with the reason and do not start in native mode automatically.

## 2. Required acceptance matrix

Every row needs an independent observer, an intentional failing control and a machine-readable result bound to the same run. All rows below are open.

| Gate | Required external evidence | Deliberate failure/control |
|---|---|---|
| Prerequisites | Controller observes supported identities, namespace/mount/process boundaries, capability/no-new-privilege state and resource-controller availability | Remove a required privilege/controller; launch refuses or is INCOMPLETE, never silently falls back |
| Oracle/report protection | Subject cannot read answer data, alter reports or signal/inspect the controller through exposed process interfaces | Attempt answer-file read, report overwrite, controller-memory/process access and inherited-FD access |
| Filesystem allowlist | Undeclared host paths and host service sockets are unavailable; allowed runtime files are read-only | Probe planted host-secret canaries and runtime/config writes; verify the observer would detect an unsafe configuration |
| Server path behavior | A second outside-workspace canary remains deliberately readable inside the sandbox, so the server's own boundary behavior is exercised | OS-blocked canary earns UNKNOWN; a server reading/disclosing the accessible canary fails the profile |
| Network | Controller verifies no external or host-local egress for this no-network profile | Subject attempts local/remote connections through available address families; use controlled local endpoints rather than external targets |
| Aggregate resources | Controller verifies limits over the whole descendant group for memory, CPU, process count and writable storage | Bounded memory/CPU/process/output stress cannot escape the configured group or starve the observer |
| Deadlines and teardown | Outer supervisor remains responsive; every descendant is gone before final evidence collection | Parent crash, timeout, fork/exec, setsid/daemonization, inherited pipes and late writers cannot leave surviving work |
| Unauthorized reads | Protected external observer records relevant read attempts/accesses and reports observation gaps | Quiet response after an attempted forbidden read still produces evidence; absence of canary disclosure cannot supply PASS |
| Writes and restoration | External observer detects relevant writes even when bytes/mtime are later restored | Write-then-restore, chmod/restore, rename/delete/recreate and late-child writes are detected |
| TOCTOU | Synchronized independent cases exercise path swaps and input mutation between inspection and access | Symlink swap, file replacement and mutation races cannot yield a silent complete result or an unsupported safety claim |
| Observer integrity | Dropped/lost/tampered events and incomplete snapshots are explicit UNKNOWN evidence | Disable or interrupt observation; no security PASS is possible |
| Run identity | Report binds harness/backend version, server artifact/runtime inputs, effective protections, config/profile and observer evidence | Artifact/config mutation or an unverified dependency closure stays visible and cannot be mislabeled as a sealed build |
| Verdict separation | Backstop intervention and tool behavior retain their own attribution | A blocked server boundary violation never becomes a behavior PASS; a missing backend/observer does not become an invented server FAIL |
| Compatibility | Existing negative controls remain failures; the correct reference retains readiness PASS | Byte cap, half scan, generic error, CWD-relative behavior and missing-evidence controls keep their meanings |

## 3. Implementation checkpoints

1. **Runner interface and preflight:** keep transport/oracle logic independent of the backend; separate requested policy from observed enforcement. Preserve explicit native mode for development with its required UNKNOWN.
2. **One working containment backend:** prove storage/process/network separation and protected evidence collection using adversarial local helper subjects.
3. **Resource supervisor and cleanup:** enforce group-wide limits and verify teardown on both normal and abnormal exits. No final success report before cleanup/observation is complete.
4. **External read/write observer and synchronized races:** define exactly which accesses/effects are covered; unknown or lost coverage blocks the corresponding required safety verdict.
5. **Regression and acceptance run:** run the original controls, new isolation controls and reference in a fresh supported environment. Preserve the independently checked evidence and review residual risks.

These checkpoints require implementation and evidence. Documentation or a container image by itself does not complete them.

## 4. Release and claim gate

Do not replace the unconditional native containment UNKNOWN with a backend-name check. An isolated run may pass the containment check only when the backend's required external evidence is complete and valid for that run. Other security UNKNOWNs must remain visible; containment alone does not establish all security properties.

Release 0.2.0 only after relevant tests, a fresh installed-wheel smoke, the acceptance matrix and a review of evidence/limitations. State supported Linux environments and reproduce prerequisite failures without a permissive fallback.

Keep this claim narrow: a named artifact and configuration passed a finite named profile under verified execution/observation conditions. It is not a universal claim that an arbitrary MCP server or hostile binary is safe. Full dependency identity, kernel trust and any remaining observer limits must be disclosed.

The fixed Sentinel-Zero retest remains a separate first-proof gate. Record the actual changed subject revision; reuse the four behavioral requirements and independently reviewed profile. Inventory evidence cannot establish scanner finding accuracy. Additional profiles remain deferred until these gates are complete.


## 5. Progress log

| Date | Checkpoint | Evidence and remaining gates |
|---|---|---|
| 2026-10-30 | 1, merged PR #1 | Interface, fail-closed preflight, CLI and Runner wiring; 48 tests. Native containment remains UNKNOWN. |
| 2026-10-30 | 2, partial, merged PR #2 | Candidate bubblewrap layout and bounded trusted filesystem helper wired into NamespaceBackend preflight. Known private host secrets are verified before probing; malformed, incomplete, wrong-run or unexpected-I/O evidence fails closed. Probe and candidate subject layout use the same absolute workspace mount. |
| 2026-10-30 | 3, partial | IPv4/IPv6 loopback TCP observer with host positive controls; explicitly delegated cgroup-v2 helper supervisor, readback limits, join-before-release gate and detached-child cleanup observation; policy digest and `--cgroup-parent`. Live delegated-host proof pending. |

Current implementation may run only controller-owned probe code. `launch_subject()` refuses all subject commands, and Runner retains its independent namespace launch gate. Tool discovery and synthetic probe success do not authorize a server launch or a containment PASS. No cgroup limits are claimed as enforced on MCP subjects; live helper acceptance remains pending.

Filesystem/TCP helpers receive a minimal environment and no inherited controller descriptors beyond stdio; their combined output is bounded at 16 KiB before decoding, with a five-second deadline per helper. The cgroup bootstrap receives only narrow join/release descriptors and closes them before its workload. Its output is bounded at 4 KiB, unexpected stderr fails, and its three-second work deadline is separate from the two-second teardown deadline. JSON must contain every typed access result and the current probe nonce. Preexisting fixture destinations are never overwritten. Missing, changed, empty, symlinked or exposed secrets cannot satisfy the fixture precondition. A protected path inside a candidate mount is rejected rather than earning credit from path remapping.

The probe only checks named synthetic paths in its own namespace. It does not establish arbitrary forbidden-read coverage, transient-write coverage, race resistance or protection in a later server namespace. The candidate runtime still exposes read-only host runtime trees; its dependency closure is not sealed. All of sections 2-4 remain acceptance gates.

Still open: a live delegated-host acceptance run; supervised Runner/transport integration; run-level oracle/controller protection, complete network denial, aggregate limits and descendant teardown; resource stress controls; and the remaining external observer matrix. The TCP observer covers only two named loopback endpoints. The cgroup helper self-test is implemented but has not been verified against a live delegated kernel here. A missing or blocked bubblewrap capability remains explicit INCOMPLETE evidence. The fixed Sentinel-Zero acceptance retest remains separate.


Checkpoint 3 control contract: the delegated parent must be canonical, genuinely cgroup v2, and already expose active cpu/memory/pids controllers and cgroup.kill. Never auto-enable or relax parent controls. Configure a new leaf with memory.max, memory.swap.max=0, pids.max, cpu.max, memory.oom.group=1 and cgroup.max.descendants=0, verify readback, then independently verify helper membership before release. Sample aggregate cpu.stat against the lifetime budget; do not confuse CPU bandwidth with total CPU seconds. After normal or abnormal work, cgroup.kill must be followed by recursive populated=0, empty membership and removal. Failed cleanup remains missing evidence even if fallback helper termination succeeds.

The opt-in live cgroup test uses MCP_BEHAVIOR_CGROUP_PARENT; it is explicitly skipped without a delegated host. Contract tests with ordinary files do not replace that acceptance. All server launch gates and all rows of the full acceptance matrix remain required.

Checkpoint 3 is identified in package metadata and reports as `0.2.0.dev3`; this development version does not grant a stable 0.2.0 release or containment verdict.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.

Hosted verification attempt [41122595917](https://github.com/holeyfield33-art/mcp-behavior/actions/runs/41122595917), on 2026-10-30, failed before the live-helper job executed any steps and produced no job log. Its failure annotation was not retrievable in this session. No positive hosted containment evidence is recorded. [Checkpoint 3 PR #3](https://github.com/holeyfield33-art/mcp-behavior/pull/3) remains unmerged pending successful hosted verification; local validation is 108 passing tests with one explicitly skipped live cgroup test.
