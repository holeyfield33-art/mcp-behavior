# MCP Behavior

A standalone Linux CLI that drives a running MCP server and checks its behavior against independent fixtures.

The question is narrow: **can a caller rely on this tool's results and failure reports, under this versioned profile?** The server's description is never the answer key. The Python package uses only the standard library. Namespace preflight additionally needs Linux bubblewrap and an explicitly delegated cgroup-v2 directory.

**Status: development version `0.2.0.dev3`, checkpoint 3; the original behavioral prototype was 0.1.0.** Native mode runs reviewed subjects and always keeps containment UNKNOWN. Namespace mode runs fixed trusted preflight helpers only; it launches **zero MCP subjects**, even when individual helper probes succeed. Overall containment remains unverified. Version 0.2.0 has not been released.

## Run the first proof

Requires Linux and Python 3.11 or newer.

```bash
PYTHONPATH=src python -m mcp_behavior run \
  --config examples/reference.json \
  --output out/reference.json \
  --native
```

Expected: readiness PASS, security INCOMPLETE, overall INCOMPLETE, exit 2. The required containment check explains the missing evidence. No hidden option converts it into a pass.

The reference server is an independent file inventory implementation. It has deliberate defect modes for testing the harness. It imports no harness code and does not know the oracle's expected results.

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

To install the CLI into an existing Python environment:

```bash
python -m pip install .
mcp-behavior --version
```

## Namespace preflight and supervision checkpoint

```bash
PYTHONPATH=src python -m mcp_behavior run \
  --config examples/reference.json \
  --output out/namespace.json \
  --isolation namespace
```

Expected at this checkpoint: **exit 2, FINISHED/INCOMPLETE, zero subject cases, containment UNKNOWN**. Preflight may launch controller-owned helper processes. It never launches the configured MCP command or falls back to native execution.

To exercise the cgroup helper self-test, pass an existing, canonical, host-delegated directory with `cpu`, `memory` and `pids` controllers already enabled:

```bash
PYTHONPATH=src python -m mcp_behavior run \
  --config examples/reference.json \
  --output out/namespace.json \
  --isolation namespace \
  --cgroup-parent /sys/fs/cgroup/YOUR_DELEGATED_DIRECTORY
```

The path is a placeholder; a normal directory containing files named like cgroup controls is rejected. The harness creates and removes its own leaf and never enables parent controllers or changes parent limits. `--cgroup-parent` is rejected in native mode. The JSON report records the requested isolation policy and its digest separately from the profile/config digest.

| Helper evidence | What it establishes |
|---|---|
| Host-path probe | Known nonempty private canary/answer fixtures are inaccessible in the candidate mount view; strict typed results and a fresh nonce are required |
| TCP endpoint probe | Host positive controls arrive at controller-owned IPv4/IPv6 loopback listeners; isolated traffic is independently detected. Only these TCP paths are covered |
| Cgroup supervision self-test | On a capable delegated host: limits read back, bootstrap membership verified before release, detached child observed, recursive kill followed by `populated=0`, empty membership and leaf removal |

The helper supervisor requests a memory ceiling, zero swap, a PID ceiling, group OOM behavior, no nested cgroups and one CPU of bandwidth. It samples aggregate CPU usage against the configured CPU-seconds budget. This is a helper self-test, not a full stress test or supervision of an MCP server. Missing evidence, lost observer coverage, timeout, cutoff or failed cleanup remains an unsuccessful precondition; it never becomes a server PASS or an invented server FAIL.

Run the optional live cgroup integration test only on an explicitly delegated host:

```bash
MCP_BEHAVIOR_CGROUP_PARENT=/sys/fs/cgroup/YOUR_DELEGATED_DIRECTORY \
  PYTHONPATH=src python -m unittest discover -s tests -p test_supervisor.py -v
```

The default suite explicitly skips that live test when no delegated path is supplied. A skipped live test does not supply containment evidence. This development host exposes no cgroup filesystem and blocks the bubblewrap network-namespace operation; the reports retain those reasons.

## What v1 checks

One profile family: synchronous, read-only repository/file inventory operations. Fixtures include Python, JavaScript and text, empty files, nested paths, Unicode, hidden files, an unsupported extension, mode-000 input, escaping/internal/dangling symlinks, a directory loop, a FIFO, a missing directory, a file used as the root, relative and outside paths, and a larger repository.

| Property | Independent evidence |
|---|---|
| Reasoned errors | A failing input must be identified with a concrete cause under the profile's literal reason contract |
| Bounded output | Wire bytes counted before JSON decoding; a client cutoff is a server FAIL |
| Coverage | Every planted input reconciles with disjoint processed/excluded/failed records |
| Honest completion | Completion is checked against omitted/failed required inputs |
| Content correctness | Returned inventory hashes must match known fixture bytes |
| Path boundaries | A decoy CWD, readable outside canaries, explicit root refusals, and unsafe-entry refusals |
| Repeatability | Two calls in one session and a third call in a fresh session, on the same fixture |
| Read-only behavior | External snapshots of bytes, entries, permissions and modification metadata |
| Scripted recovery | After a reasoned missing-input error, a repaired request in the same session must produce correct evidence |

These are finite observations, not proofs of absence of every possible defect. In particular, a quiet canary does not establish that no unauthorized read happened, and snapshots cannot establish that no transient write occurred.

## Connect another server

Copy `examples/reference.json` and edit the argv, identity, tool name, argument binding, supported suffixes, and response-field mappings. The executable and artifact files must use absolute paths; `${python}` and `${config_dir}` are supported. No shell is invoked.

Mappings use JSON pointers into `structuredContent` or a single JSON text result. They locate evidence. They cannot synthesize file lists, substitute counts for files, convert an absent completion flag into true, import a target's code, or execute custom scoring functions. An unmapped required observation is UNKNOWN. A mapped field that violates the agreed shape is FAIL.

Only the selected tool is assessed; discovering additional tools does not grade them. An inventory content-hash oracle does not prove a vulnerability scanner's semantic accuracy. Such an assessment needs its own finding-level fixtures and oracle, and currently remains UNKNOWN.

The native runner supplies a small environment without inherited credentials. HOME and TMPDIR are disposable. Linux capabilities are dropped and `no_new_privs` is set; memory, CPU, file-size, descriptor, byte, message, request, case and suite ceilings are enforced where implemented. These are backstops, not a host sandbox. `--server-uid` and `--server-gid` optionally drop identity when the parent has the required privilege and UID mapping; this environment supports only its existing UID.

## Verdict and automation contract

Each check is PASS, FAIL, UNKNOWN or N/A. Required FAIL takes precedence over missing evidence. Any required UNKNOWN or required N/A prevents PASS. Optional out-of-scope model runs cannot supply required evidence.

Reports contain separate readiness/security verdicts, explicit missing evidence, exact profile/config hashes, reviewer-provided version labels, handshake identity labeled as server-reported, explicit artifact/executable hashes, fixture manifests, response hashes/byte counts, and snapshot hashes. Artifact identity covers the named files, not a sealed dependency closure.

JSON is authoritative. The adjacent Markdown is a readable view. Before launching a server, the CLI writes a new INCOMPLETE/RUNNING marker; it replaces it with the final JSON only after the readable report is written. Consumers must check **exit status, matching run_id and FINISHED state**. If a destination cannot be written at all, stdout and exit status report the error; an old file must not be accepted.

| Exit | Meaning |
|---|---|
| 0 | All required evidence passed |
| 1 | At least one required property was disproved |
| 2 | Evidence/configuration/reporting was incomplete |

## Boundaries and next work

Protocol conformance remains the official conformance suite's responsibility. This client supports the stateful stdio lifecycle for 2025-03-26, 2025-06-18 and 2025-11-25. It does not claim support for subsequent stateless revisions. Unsupported revisions, task-only tools, sampling, elicitation, media or resource results cannot silently pass.

HTTP, authentication, real-model runs, concurrent sessions, mutating-tool profiles, broad attack-surface benchmarking, commercial features and integrations are outside v1.

The next engineering gate is a supported-host acceptance run of the new helpers, followed by supervised Runner/transport integration with protected evidence storage, independently verified fixture permissions, complete network/process enforcement and external read/write/race observation. Synthetic helper success cannot waive these run-level gates. A fixed version of the real first test subject must then be retested. The passing reference implementation is a harness control, not evidence that the real subject was fixed.

Read the [behavioral specification](docs/SPEC.md), [architecture](docs/ARCHITECTURE.md), [acceptance roadmap](docs/ROADMAP.md), [adversarial review](docs/ADVERSARIAL_REVIEW.md), [current status and historical proof](docs/STATUS.md), [development handoff](docs/SDLC.md) and [changelog](CHANGELOG.md).
