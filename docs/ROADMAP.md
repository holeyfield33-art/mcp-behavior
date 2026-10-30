# Version 0.2.0 — isolated-runner acceptance plan

Status: planned, not implemented. Review date: 2026-10-30.

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
