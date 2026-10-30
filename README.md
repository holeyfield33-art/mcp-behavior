# MCP Behavior

A standalone Linux CLI that drives a running MCP server and checks its behavior against independent fixtures.

The question is narrow: **can a caller rely on this tool's results and failure reports, under this versioned profile?** The server's description is never the answer key. The runtime has no dependencies outside Python's standard library.

**Status: working 0.1.0 prototype.** Native subprocess execution cannot prove containment. Every native run includes a required security UNKNOWN, so an otherwise successful run is INCOMPLETE overall. Use reviewed test subjects in a disposable environment. This release does not certify arbitrary hostile binaries as safe to run.

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

The next engineering gate is an isolated runner with protected evidence storage, independently verified fixture permissions, descendant/process/network limits, and observation of unauthorized reads and transient writes. A fixed version of the real first test subject must then be retested. The passing reference implementation is a harness control, not evidence that the real subject was fixed.

Read [the closed specification](docs/SPEC.md), [adversarial review and risk decisions](docs/ADVERSARIAL_REVIEW.md), and [implementation/proof status](docs/STATUS.md).
