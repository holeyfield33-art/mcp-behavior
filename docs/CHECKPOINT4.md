# Checkpoint 4: supervised subject sessions

Base: merged checkpoint 3, `d434494`. This slice enables reviewed MCP subjects
under an explicit experimental `--namespace-subject` opt-in. Helper-only mode
remains the default. No containment PASS is available.

## Acceptance criteria

1. Without the opt-in, namespace runs retain zero subject cases. With it, Linux,
   namespace tools, host-path, IPv4/IPv6 endpoint and cgroup supervisor probes
   must all pass under the requested policy. Missing evidence refuses launch.
2. Each session owns a new cgroup with limits read back before startup. A fixed
   bootstrap joins it, acknowledges attachment, and blocks. The controller checks
   sole membership and resource evidence before releasing it to exec bubblewrap.
   A failed gate never executes the configured command and never retries native.
3. Bubblewrap exposes the watched fixture tree at its original absolute path,
   declared artifact files read-only, runtime roots read-only, private /tmp,
   PID/user/network namespaces and a minimal environment. The controller's code,
   oracle and reports are not broadly mounted. Artifact overlap is rejected.
   Namespace UID/GID overrides are refused in this slice.
4. The bounded stdio client uses the supervised process, samples aggregate usage
   while waiting/sending, and always tears down the entire cgroup. Per-session
   evidence includes a unique scope, effective limits, release gate, final usage
   and observed empty/removal. Cleanup faults remain explicit UNKNOWN evidence.
5. Tests cover refused gates, no native fallback, rejected layouts, actual MCP
   handshake/tool calls, bounded timeout and detached-descendant cleanup on a
   capable host. The reference is a control, never a Sentinel-Zero substitute.
6. Overall containment stays UNKNOWN even after green sessions. Full oracle/
   controller protection, egress/resource intervention and race/descendant
   acceptance matrices are not established by synthetic probes or this slice.

## Deliberate limits

Runtime roots are inherited read-only and are not a sealed dependency closure.
Only explicit artifact files outside runtime roots are mounted; undeclared local
imports may fail. Symlinked artifact paths and unsafe mount overlaps are refused.
Fixture siblings (including behavioral canaries and CWD) are intentionally visible
to preserve behavioral boundary tests; expected answers remain in the controller.
The sampled CPU budget is distinct from kernel CPU bandwidth throttling. Harness
termination, observer failures and a hostile subject attacking kernel/runtime
surfaces still need a wider matrix. No hostile-binary safety claim is made.

## Checkpoint 3 evidence prerequisite

The user recorded 109 passed / zero skipped on `d434494` in a privileged Ubuntu
24.04 container on Docker Desktop/WSL2, including all three helper probes. This
is environment-specific evidence, not bare-metal or non-root delegated-harness
acceptance. Hosted jobs never started due to GitHub's account billing lock.
Local evidence bundles remain offline; no machine-specific bundle path belongs
in source, docs or CI artifacts.

## Local implementation validation — 2026-10-30

On the same stated Docker Desktop/WSL2 class of environment, Python 3.12.3 and
bubblewrap 0.9.0: **122 tests passed, zero skipped**, with explicit delegation and
`MCP_BEHAVIOR_SUBJECT_LIVE=1`. Live coverage includes 14 real reference MCP cases,
timeout with a detached descendant, controller descriptor/credential/secret-path
isolation and kernel PID-limit intervention. The full matrix remains incomplete.

CLI reports verified matching run IDs and FINISHED state. Helper-only mode kept
zero cases; subject mode completed 14 with readiness PASS, overall INCOMPLETE and
containment UNKNOWN. Installed-wheel native and namespace subject checks also
completed 14 cases with the same verdicts. The wheel harness ran outside the source
tree; the reviewed subject used an explicitly configured system Python executable.
No fixed Sentinel-Zero revision was tested. Hosted CI remains billing-blocked.
