# Adversarial review of the proposed harness

Initial review: 2026-10-29; updated for checkpoint 3 on 2026-10-30. Decision: GO for the standalone behavioral prototype and local proof; NO-GO for claiming full security certification or running arbitrary hostile servers on the host.

The original two rules are retained: the target never supplies the answer key, and harness interception never turns a target failure into PASS. The most dangerous remaining failures are false assurance from an unprotected oracle, weak adapters, insufficient observation, and unsupported cases disappearing from the denominator.

## Gaps closed in the specification and first implementation

| ID | What could go wrong | Decision / verification |
|---|---|---|
| G01 | Target reads or edits oracle/report data under the same UID | Native containment is a required UNKNOWN; no full PASS is possible |
| G02 | “Any MCP server” gets universal correctness claims | Universal stdio client; correctness restricted to a named tool/profile with a meaningful oracle |
| G03 | Server's success/count fields become their own ground truth | Reconcile exact external input set; validate disjoint records, hashes and counts |
| G04 | Missing coverage/completion fields are filled in by the adapter | Missing mapping UNKNOWN; no synthetic evidence or programmable grading hooks |
| G05 | A mapped field is malformed, but gets treated as optional | Strict field/path/type contract; booleans cannot impersonate integers |
| G06 | Omitted/duplicated inputs hide a half scan | Seeded mixed-language fixture; exact set accounting; overlap and unknown paths fail |
| G07 | Processed-file list is mistaken for semantic scanner correctness | No content/finding oracle gives required content UNKNOWN |
| G08 | Client buffers a huge line before checking its size | Incremental byte cap before newline/JSON decoding; defect server verified |
| G09 | Paging or silent truncation hides lost results | This v1 permits complete bounded results or explicit size refusal; shortened evidence fails coverage |
| G10 | A client timeout/cap protects itself and gets called a server pass | ServerFault FAIL; safety intervention is evidence of failed behavior |
| G11 | Endless notifications, cursors, stderr or slow progress exhaust resources | Byte/message/page limits and fixed request/case/suite deadlines; ordinary stderr remains allowed |
| G12 | JSON duplicate keys, NaN, malformed framing or wrong IDs change the meaning | Strict JSON/envelope/ID checks; wire defect cases tested |
| G13 | Structured result and JSON text disagree | Contradictory machine-readable representations fail |
| G14 | Generic “Error” passes an errors-present check | Cause plus input context required; echoing `missing_<token>` alone is insufficient |
| G15 | Agent-recovery claim sneaks in a model judge | Same-session deterministic repair only; model evaluation separately N/A |
| G16 | Relative paths accidentally target server CWD | Decoy CWD, advertised client root and explicit reject/workspace policy |
| G17 | Prefix checks accept `/root-other`, `..` or ambiguous path strings | Component-aware record containment and parent/backslash rejection |
| G18 | OS blocks an outside read, so the server falsely gets credit | Independent same-identity/capability probe confirms outside/CWD canary readability; a failed precondition is UNKNOWN |
| G19 | Mode-000 file remains readable to a privileged test process | Independent probe under the server's capability/identity setup; unsatisfied precondition UNKNOWN |
| G20 | Oracle cannot hash the unreadable file afterward | Non-inherited descriptor opened before chmod; bytes and inode still observed externally |
| G21 | FIFO/loop causes the observer itself to hang | lstat, no symlink recursion, bounded regular-file reads; observer FIFO/loop test |
| G22 | Server follows escaping/internal/dangling symlinks or loops | Separate unsafe-entry cases; all-symlink refusal is explicit v1 policy |
| G23 | “Read only” annotation substitutes for checking effects | Watched-tree before/after bytes, entries, modes, ownership and modification metadata |
| G24 | Same-session cache masks unstable fresh starts | Same-session and fresh-session repeats use identical fixture bytes |
| G25 | Timestamp ignores can mask real findings or arbitrary fields | Only validated timestamp leaves, limited array traversal; ordinary arrays retain ordering |
| G26 | A harmless per-finding timestamp causes a misleading instability finding | Live-subject difference inspected; explicit `/plans/*/generated_at` mapping added, with profile digest changed |
| G27 | Failed setup, unavailable capability or broken observer gets a pass | UNKNOWN with structured harness error; forced setup/observer fault tests |
| G28 | Missing evidence is swallowed by average scores | No scoring/averaging; required UNKNOWN blocks PASS, demonstrated FAIL still wins |
| G29 | Tool schemas change mid-test | Fingerprints across sessions and tool-list-change notifications remain visible |
| G30 | Returned commands, resources or schema references execute during evaluation | Inert response handling; no fetching, shell, eval, agent or executable plugins |
| G31 | Child inherits API keys or writes bytecode into the subject tree | Small explicit environment, disposable HOME/TMPDIR, bytecode disabled; capabilities dropped |
| G32 | Killed leader leaves ordinary children behind | Process-group termination, including after leader exit; escaped descendants remain an isolation gap |
| G33 | Old PASS file survives a crashed new run | RUNNING/INCOMPLETE marker, run IDs, FINISHED commit marker and exit-code contract |
| G34 | Report output overwrites config or follows a destination symlink | Destination overlap/symlink checks and atomic writes; tested |
| G35 | Server's version string is treated as a verified artifact | Reviewer label and handshake identity separated; named files/executable hashed before and after |
| G36 | A newer protocol lifecycle is incorrectly exercised as an old one | Dated support allowlist; unsupported negotiation is INCOMPLETE |
| G37 | Large fixture response is described as a guessed token count | Measured wire bytes only; original token estimate not adopted |
| G38 | A mock passing is advertised as the real subject being fixed | Passing reference and live-subject failures reported separately; fixed real-subject retest pending |

## Open engineering risks, explicitly outside a passing claim

| Risk | What is still needed |
|---|---|
| Host compromise or evidence tampering | Separate UID/namespace/VM boundary, protected oracle/report storage and independently tested mounts/permissions |
| Unauthorized read with no disclosed canary | External syscall/filesystem observation; a quiet response is insufficient |
| Transient write then restore | External write observation; snapshots only establish observable final-state integrity |
| Race between inspection and file access | TOCTOU/symlink-swap/mutation fixtures with independent synchronization and observation |
| Fork bombs, daemonized or session-escaping descendants | Cgroup-wide PID/memory/CPU constraints and verified teardown; per-process rlimits do not suffice |
| Non-interruptible host I/O | Isolated controller/worker plus a verified external watchdog; request deadlines cannot interrupt every kernel stall |
| Runtime dependency substitution | Sealed image/dependency closure, executable/config/build identity and isolated artifact verification |
| Benchmark gaming | Larger independent/withheld fixture packs and metamorphic cases; randomized tokens alone do not prevent deliberate test detection |
| Provider/model variability | Separate pinned-model/host/policy agent experiments; never merge their grade into deterministic fixture correctness |
| Concurrency/cross-tenant state leaks | Concurrent session/client/root/cache tests in an isolated runner |
| Streaming/pagination/cancellation semantics | A versioned profile for exact total coverage, page tokens, cancellation, late replies and resumability |
| More OS/path semantics | Dedicated profiles for Windows/UNC/drives, case-folding, Unicode normalization, mount boundaries, hardlinks, devices and sockets |
| Live services and auth | Separate transport/auth state, secret handling, scopes, expiry/revocation/rate-limit profiles; no inherited credentials in v1 |
| Scanner finding correctness | Positive/negative finding fixtures, lines/symbols and independently validated expectations; inventory hashes cannot replace them |
| Supply chain / signed certification | Explicit governance, signing/revocation/expiry and reproducible builds; no badge or certification service in this scope |

These are not waved through as successful tests. Native containment is required UNKNOWN, and every report states observational and identity limitations. Broader profiles require their own gates before a broader claim is allowed.


## Isolation checkpoint review — 2026-10-30

| Risk | Implemented control / evidence limit |
|---|---|
| Empty, malformed or stale helper output becomes isolation success | Strict complete typed schema, fresh nonce, known nonempty private secrets and explicit failed preconditions |
| Probe and subject paths refer to different mount layouts | One canonical absolute workspace layout; protected-path mount overlap rejected; subject launch still disabled |
| Helper inherits credentials or controller descriptors | Minimal environment and closed descriptors; only trusted cgroup bootstrap gets narrow join/release channels, closed before its workload phase |
| Network helper lies or observer silence is called denial | External IPv4/IPv6 TCP receipts, mandatory real host positive controls and strict helper coverage; isolated receipts defeat claimed denial |
| Unsupported network families, unexpected traffic or broken shutdown disappear | Explicit observer failure; finite TCP coverage stated; no general egress or run-level grade |
| Ordinary files impersonate kernel controls | Genuine cgroup-v2 filesystem check before creation; required existing delegation; no automatic parent changes |
| Configured resource limits are assumed enforced | New-leaf writes and readback; sampled aggregate CPU separate from CPU bandwidth; actual resource-stress proof remains pending |
| Helper executes before joining its cgroup | Trusted bootstrap blocks on release; controller verifies sole membership and resource evidence first |
| Session-detached child escapes process-group cleanup | Fixed detached-child self-test with cgroup.kill, recursive populated=0, empty membership and leaf removal; live delegated-host test pending |
| Fallback termination erases failed teardown | Failed cgroup cleanup remains failed evidence even after fixed-helper pidfd fallback |
| Synthetic successes unlock arbitrary MCP execution | Runner and launch_subject remain independently disabled for namespace subjects; all successful-probe regression still yields INCOMPLETE |
| Documentation claims shipped isolation from prototype version | README, specification, status, architecture, roadmap, SDLC and changelog distinguish pre-release helper work from run-level protection |

Default validation includes an explicitly skipped live cgroup integration test. Ordinary-file contract models and this host's blocked namespace operation cannot establish a positive kernel containment result. The open-risk table above remains in force; no security-certification gate is closed by these helper observations alone.

Checkpoint 3 is identified in package metadata and reports as `0.2.0.dev3`; this development version does not grant a stable 0.2.0 release or containment verdict.

Linux CI is configured in `.github/workflows/checkpoints.yml` for deterministic checks and live trusted-helper acceptance on an explicitly delegated disposable VM, with JSON evidence retained as an artifact. Hosted results must be inspected; an unrun or infrastructure-blocked job supplies no containment evidence. The harness never enables parent controllers; delegation setup belongs to the CI host fixture.

Hosted verification attempt [41122595917](https://github.com/holeyfield33-art/mcp-behavior/actions/runs/41122595917), on 2026-10-30, failed before the live-helper job executed any steps and produced no job log. Its failure annotation was not retrievable in this session. No positive hosted containment evidence is recorded. [Checkpoint 3 PR #3](https://github.com/holeyfield33-art/mcp-behavior/pull/3) remains unmerged pending successful hosted verification; local validation is 108 passing tests with one explicitly skipped live cgroup test.
