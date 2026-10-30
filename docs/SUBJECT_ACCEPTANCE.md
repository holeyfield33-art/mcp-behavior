# Finite actual-subject boundary acceptance

Profile: `finite-subject-boundary/v1`. This is the finite follow-up to checkpoint
4, not closure of the full containment matrix in ROADMAP.md. Containment stays
UNKNOWN and the correct reference assessment stays INCOMPLETE.

The controls are actual configured stdio MCP subjects using `SubjectSession`,
initialize/tool discovery/tool calls and normal bounded transport. They import no
harness or oracle code. The controller independently reads kernel cgroup counters,
pidfds and procfs, owns network endpoints, and attaches strace to the kernel-
identified subject PID for the storage/process/network attempts. JSON evidence
binds a control run ID, profile, harness version, control-source digest and unique
session scopes. The complete source commit and environment belong in the offline
evidence manifest.

| Finite control | Independent observation | Deliberate failure / result |
|---|---|---|
| Oracle/report/config mount protection | Canonical mount overlap and explicit artifact inode checks; actual host report bytes and subject root view | Runtime-mounted protected paths and artifact hardlinks are refused; an intentionally unsafe test layout exposes the oracle and changes the actual report, which the controller detects |
| Controller process/FD/credentials | Kernel PID/user/mount namespaces, CapEff=0, no_new_privs=1, actual procfs/open/kill syscalls; existing inheritable-FD/credential control | The fixed subject attempts controller memory access and signal-0; these fail in its PID view. This is not a claim of kernel/process-interface completeness |
| Host paths/runtime/Unix socket | External syscall trace and known planted paths; read-only runtime mutation attempt | Oracle read, runtime write and external Unix socket connection fail; no arbitrary-path read observer is claimed |
| Host IPv4/IPv6 TCP | Controller-owned positive controls and exact nonce-bound external receipts | Safe subject attempts both endpoints without receipts; deliberately inherited-network control reaches both and is detected. UDP and arbitrary routes remain ungraded |
| Aggregate CPU and memory | Owned cgroup cpu.stat and memory.events, with limit readback | Forked CPU workload exceeds sampled total CPU seconds; forked memory workload triggers group OOM; both fail the subject and receive recursive cleanup |
| PID and per-file storage | pids.events and external file size | PID stress triggers the kernel ceiling; a file hits RLIMIT_FSIZE at 32 MiB. A total writable-storage quota is NOT implemented |
| Crash/timeout/detach/late writer | Kernel cgroup membership, pidfd readiness, empty/removal and delayed marker check | Parent crash and setsid descendants cannot leave running late writers in these cases; timeout coverage is retained from checkpoint 4 |
| Interrupted observer | Intentional controller-side usage-observer error during a real reference subject session | The report is INCOMPLETE, records a harness error, cleans up, and refuses all later subject sessions |

A subject can create a private same-path report shadow inside its own tmpfs when
mount-point parent directories exist. That is not alteration of the host report.
The test checks distinct device/inode identities and unchanged host bytes rather
than awarding credit from a server's claimed write denial. The unsafe control
changes the host inode's bytes and must be detected.

The injected unsafe layout and interrupted observer exist only in acceptance
tests through explicit patches. They are not product switches or native fallback
paths. Evidence loss, failed observation, unexpected receipts and failed cleanup
cannot earn a security PASS. Product CLI sessions protect their actual config and
both report destinations; API callers must supply any additional protected paths.

## Reproduce on a disposable capable host

Install bubblewrap and strace, prepare an explicit genuine cgroup-v2 parent with
cpu/memory/pids already enabled, then run:

```bash
PYTHONPATH=src MCP_BEHAVIOR_SUBJECT_LIVE=1 \
MCP_BEHAVIOR_CGROUP_PARENT=/sys/fs/cgroup/YOUR_DELEGATED_DIRECTORY \
MCP_BEHAVIOR_ACCEPTANCE_OUTPUT=out/subject-acceptance \
python3 -m unittest discover -s tests -v
```

Without explicit live settings, integration cases skip and do not provide live
evidence. When live tests are requested, unavailable strace/ptrace or missing
namespace/controller capabilities fail the tests. Hosted execution remains
unverified until the known GitHub billing lock is resolved.

Still open: general forbidden-read and transient-write observation, synchronized
TOCTOU cases, arbitrary egress, aggregate disk quota, adversarial observer tamper/
loss coverage, complete controller-crash acceptance and a sealed runtime/dependency
closure. These gaps prevent containment PASS. Fixed Sentinel-Zero behavioral
acceptance is a separate requirement; the control/reference cannot replace it.

## Recorded local run — 2026-10-30

Version 0.2.0.dev5 passed **128 tests, zero skipped** with explicit live settings.
All five live finite-acceptance records have `assertions_passed=true`; the sixth
new case checks mount/alias refusals. Installed-wheel native and namespace subject
smokes each completed 14 reference cases with readiness PASS, overall INCOMPLETE
and containment UNKNOWN. Helper-only mode retained zero cases.

Environment: privileged Ubuntu 24.04 container on Docker Desktop/WSL2 kernel
6.18.33.2, Python 3.12.3, bubblewrap 0.9.0 and strace 6.8. Evidence remains in an
offline project-named pack. An initial isolated wheel build hit a dependency
download timeout; a build using distro-provided setuptools/wheel succeeded and
the resulting wheel was installed and tested outside the source tree. No hosted
result or stronger environment claim follows from this run.
