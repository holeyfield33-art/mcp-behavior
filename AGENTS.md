# MCP Behavior — coding-agent entrypoint

**Product:** Standalone, Linux-first, standard-library MCP behavioral assessment CLI. It invokes one explicitly selected stdio tool with reviewer-owned fixtures and an independent oracle. It is **not** universal MCP conformance, a model judge, or a certified hostile-code sandbox.

**Default:** Preserve established engineering knowledge and make the smallest authorized, demonstrably correct change. Studio's [engineering/maintenance guidance](https://github.com/holeyfield33-art/software-research-studio/blob/main/docs/REPOSITORY_KNOWLEDGE_LAYOUT.md) is **advisory**, not a runtime dependency, product registry, authorization, or proof of integration. This project was previously an assessment subject; do not recreate an unintended reciprocal Studio product link.

## Five-minute read order

1. [README.md](README.md) — current user journey, CLI usage, platform and non-goals.
2. [docs/STATUS.md](docs/STATUS.md) — **single living current state**: baseline SHA, executed versus historical checks, release blockers and next 1–3 steps. Confirm the real HEAD/working tree before using an old SHA.
3. [docs/SPEC.md](docs/SPEC.md) — behavioral requirement/profile and independent oracle contract; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — controller/subject isolation and risk decisions.
4. [docs/SDLC.md](docs/SDLC.md) — change procedure, OWASP-informed security review and repository maintenance; [docs/ROADMAP.md](docs/ROADMAP.md) — remaining acceptance matrix.
5. **On demand:** [finite subject acceptance](docs/SUBJECT_ACCEPTANCE.md), [adversarial review](docs/ADVERSARIAL_REVIEW.md), [checkpoint 4](docs/CHECKPOINT4.md), code/tests/workflow. `proof/` and dated checkpoints are historical evidence, **not the current status or instructions**.

## Non-negotiable behavior and trust boundaries

- **Never let the target grade itself.** Tool descriptions, schemas, outputs, handshake identities and target logs are untrusted observations; only reviewer-owned fixtures and external oracles grade applicable behavior.
- **Verdict priority:** any demonstrated required FAIL stays FAIL; otherwise missing, UNKNOWN or required N/A yields INCOMPLETE; PASS only when all required checks are actually supported and passed. Resource-limit violations observed by an independent controller can be FAIL; broken setup/observers are UNKNOWN. Never turn a prevented failure into PASS.
- **Native mode:** only operator-reviewed subjects; required containment remains UNKNOWN. **Namespace mode:** helper-only default; opt-in supervised subjects require actual preflight and controls. No automatic native fallback; bubblewrap or cgroup config is not proof of containment. Full containment remains UNKNOWN even after successful finite controls.
- **Host safety:** keep secrets, fixture answers, report storage, controller state and host paths unavailable to subjects; enforce constraints at the host boundary rather than via prompt rules. Do not run unreviewed hostile code or change privileged cgroups, network or mounts outside authorized disposable fixtures.
- **Evidence honesty:** source/tree/profiles and actual test environments must be pinned. An old local run, skipped live test, disabled observer, CI job with zero executed steps or a green helper-only probe cannot certify full containment or fixed Sentinel-Zero behavior.
- **No feature creep:** maintain the stdio inventory profile and one Linux backend. Do not add HTTP, auth, new scoring families, model judging, hosted multi-user execution, additional backends or a second documentation authority without a separately accepted scope.

## Bounded change and verification

Inspect actual source flow, relevant requirements and threat assumptions; choose a few applicable Studio/OWASP practices; define a positive control and a deliberate failing/negative control for changed behavior; make a surgical diff. Keep original evidence immutable and never weaken a baseline to obtain a passing score.

From a clean Linux checkout, supported smoke commands are:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m mcp_behavior run --config examples/reference.json --output out/reference.json --native
```

The reference run is expected to report readiness PASS / overall INCOMPLETE and exit 2; that is **not** a failed implementation test. Live namespace acceptance requires reviewed bubblewrap/strace and an explicitly delegated cgroup-v2 host with `MCP_BEHAVIOR_SUBJECT_LIVE=1` and `MCP_BEHAVIOR_CGROUP_PARENT` set; read [the finite test contract](docs/SUBJECT_ACCEPTANCE.md) and do not invoke privileged tests casually. Only record **actually executed** test results, skips, environment and outputs. Verify clean installed-wheel behavior when packaging changes.

## End-of-task handoff

Report base/head SHA, files changed, actual commands/results and environment, verdict implications, missing checks, operators/reviewers and the next 1–3 bounded actions. Update **only** `docs/STATUS.md` for current state, `CHANGELOG.md` for changed behavior, and `docs/SDLC.md`/`SPEC.md`/`ROADMAP.md` when their stable contracts change. Keep `proof/` immutable; add external or separately archived evidence only after a real run. Do not create extra STATUS/HANDOFF/SDLC copies or approve a production release from an agent statement.
