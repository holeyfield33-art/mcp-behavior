"""Scenario orchestration. A new server session prevents failure contamination."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config, canonical, digest
from .fixtures import Fixture, bounded_hash, build_fixture, snapshot
from .isolation import ExecutionMode, IsolationBackend, IsolationPolicy, NativeBackend, PreflightResult
from .model import Check, ContractError, HarnessError, ServerFault, Status, UnsupportedEvidence, verdict
from .oracle import Answer, at, decode, fixture_checks, reasoned_error, repeatable_payload
from .transport import StdioClient, child_setup

CASES = ("normal", "missing", "file_as_root", "relative", "outside", "traversal",
         "escaping_symlink", "dangling_symlink", "internal_symlink", "directory_loop",
         "special_file", "unreadable", "large")


class Runner:
    def __init__(self, config: Config, uid: int | None = None, gid: int | None = None,
                 isolation_backend: IsolationBackend | None = None,
                 isolation_preflight: PreflightResult | None = None,
                 cgroup_parent: Path | None = None):
        if sys.platform != "linux":
            raise HarnessError("v1 requires Linux")
        if uid is not None and (type(uid) is not int or uid <= 0 or os.geteuid() != 0):
            raise HarnessError("--server-uid requires a nonzero UID and a privileged parent")
        if gid is not None and (uid is None or gid < 0):
            raise HarnessError("--server-gid requires --server-uid and a nonnegative GID")
        self.config = config
        self.uid, self.gid = uid, gid
        self.isolation_backend = isolation_backend if isolation_backend is not None else NativeBackend()
        self.isolation_policy = IsolationPolicy(
            mode=self.isolation_backend.mode, server_uid=uid, server_gid=gid,
            memory_mib=config.limits.memory_mib, cpu_seconds=config.limits.cpu_seconds,
            network="inherit" if self.isolation_backend.mode == ExecutionMode.NATIVE else "deny",
            cgroup_parent=str(cgroup_parent) if cgroup_parent is not None else None,
        )
        self.isolation_preflight = (isolation_preflight if isolation_preflight is not None
                                    else self.isolation_backend.preflight(self.isolation_policy))
        if self.isolation_preflight.mode != self.isolation_backend.mode:
            raise HarnessError("isolation preflight mode does not match the selected backend")
        self.checks: list[Check] = []
        self.cases: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []
        self.tool_fingerprints: set[str] = set()
        self.repeat_values: list[bytes] = []
        self.missing_error_actionable = False
        self.normal_correct = False
        self.recovery_status = Status.UNKNOWN
        self.suite_deadline: float | None = None

    def add(self, id: str, lane: str, status: Status, reason: str, **evidence: Any) -> None:
        self.checks.append(Check(id, lane, status, reason, evidence))

    def execution_allowed(self) -> bool:
        # Trusted helper self-tests do not implement subject-run supervision.
        # Feature presence or an injected successful probe must not start a native
        # subprocess while the report says namespace isolation was selected.
        return self.isolation_preflight.ok and self.isolation_backend.mode == ExecutionMode.NATIVE

    def isolation_evidence(self) -> dict[str, Any]:
        return {"mode": self.isolation_backend.mode.value,
                "preflight_ok": self.isolation_preflight.ok,
                "requested_policy": vars(self.isolation_policy),
                "policy_sha256": digest(vars(self.isolation_policy)),
                "findings": [vars(f) for f in self.isolation_preflight.findings],
                "observed": self.isolation_preflight.observed,
                "reasons": self.isolation_preflight.reasons(),
                "subject_launch_supported": self.isolation_backend.mode == ExecutionMode.NATIVE}

    def identity(self) -> dict[str, Any]:
        files = list(self.config.artifacts)
        executable = Path(self.config.command[0]).resolve(strict=True)
        if executable not in files:
            files.append(executable)
        return {"reviewer_declared": self.config.identity,
                "command_sha256": digest(self.config.command),
                "artifacts": [{"path": str(p), "sha256": bounded_hash(p, 128 * 1024**2), "bytes": p.stat().st_size} for p in files],
                "scope": "Explicit files and executable only; dependency closure is not attested."}

    def preflight(self, fixture: Fixture) -> None:
        """Permission/readability oracle uses our own code under the server's UID."""
        probe = '''import os,sys,json
def readable(path):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
  try: os.read(fd,1)
  finally: os.close(fd)
  return True
 except PermissionError: return False
status=dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line)
result={"outside_canary_readable":readable(sys.argv[1]),"cwd_decoy_readable":readable(sys.argv[2]),
        "probe_uid":os.geteuid(),"probe_gid":os.getegid(),"probe_cap_eff":status["CapEff"].strip(),
        "probe_no_new_privs":status["NoNewPrivs"].strip()}
if len(sys.argv)>3: result["permission_denied_under_server_identity"]=not readable(sys.argv[3])
print(json.dumps(result))
'''
        paths = [str(fixture.watched / "outside" / (fixture.canaries[0] + ".py")),
                 str(fixture.cwd / (fixture.canaries[1] + ".py"))]
        if fixture.name == "unreadable":
            paths.append(str(fixture.root / "unreadable.py"))
        try:
            proc = subprocess.run([sys.executable, "-I", "-S", "-c", probe, *paths],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                                  timeout=2, cwd=fixture.cwd,
                                  preexec_fn=lambda: child_setup(self.config.limits, self.uid, self.gid))
        except (OSError, subprocess.SubprocessError) as exc:
            raise HarnessError("independent permission preflight failed") from exc
        if proc.returncode != 0:
            raise HarnessError("permission preflight failed before it could test readability")
        fixture.preconditions.update(json.loads(proc.stdout))

    def handle_answer(self, fixture: Fixture, answer: Answer) -> None:
        name = fixture.name
        profile = self.config.profile
        if name in ("outside", "traversal", "escaping_symlink", "relative") and not fixture.preconditions.get("outside_canary_readable"):
            self.add(name + ".path_precondition", "security", Status.UNKNOWN,
                     "outside canary was not independently readable; OS denial cannot earn server credit")
        if name == "relative" and not fixture.preconditions.get("cwd_decoy_readable"):
            self.add(name + ".cwd_precondition", "security", Status.UNKNOWN,
                     "CWD decoy was not independently readable")
        if answer.error and answer.payload is not None and profile.complete is not None:
            try:
                claimed_complete = at(answer.payload, profile.complete)
            except ContractError:
                claimed_complete = None
            if claimed_complete is True:
                self.add(name + ".error_completion_conflict", "readiness", Status.FAIL,
                         "error result also claims successful completion in its mapped completion field")
        self.add(name + ".output_budget", "readiness", Status.PASS,
                 "observed tool reply stayed within the profile's wire byte limit",
                 response_bytes=answer.wire_bytes, response_sha256=answer.wire_sha256)
        if name == "unreadable" and not fixture.preconditions.get("permission_denied_under_server_identity"):
            self.add("unreadable.precondition", "readiness", Status.UNKNOWN,
                     "independent probe could read the mode-000 file; permission failure was not exercised")
            return
        if name in ("missing", "file_as_root"):
            actionable = reasoned_error(answer, fixture.argument, name, profile.path_argument)
            self.add(name + ".error_reason", "readiness", Status.PASS if actionable else Status.FAIL,
                     "bad input needs an error identifying the input and its cause", message=answer.message[:1024])
            if name == "missing":
                self.missing_error_actionable = actionable
            return
        if name in ("outside", "traversal") or (name == "relative" and profile.relative_paths == "reject"):
            good = reasoned_error(answer, fixture.argument, name, profile.path_argument)
            self.add(name + ".path_boundary", "security", Status.PASS if good else Status.FAIL,
                     "out-of-contract paths require an explicit, reasoned refusal", message=answer.message[:1024])
            return
        if name == "large" and answer.error:
            explicit = reasoned_error(answer, fixture.argument, "large", profile.path_argument)
            self.add("large.bounded_output", "readiness", Status.PASS if explicit else Status.UNKNOWN,
                     "stress request was explicitly refused for size" if explicit else "an unrelated error prevented exercising the output-size contract",
                     message=answer.message[:1024], fixture_file_count=len(fixture.files))
            if not explicit:
                self.add("large.error_reason", "readiness", Status.FAIL,
                         "stress request failed without a usable size refusal", message=answer.message[:1024])
            return
        if name in ("escaping_symlink", "dangling_symlink", "internal_symlink", "directory_loop", "special_file", "unreadable") and answer.error:
            good = reasoned_error(answer, fixture.argument, name, profile.path_argument)
            self.add(name + ".honest_refusal", "readiness", Status.PASS if good else Status.FAIL,
                     "whole-request refusal must explain the unsafe/unreadable input", message=answer.message[:1024])
            self.add(name + ".boundary_refusal", "security", Status.PASS if good else Status.FAIL,
                     "unsafe input was refused" if good else "no reasoned refusal of unsafe input")
            return
        if not answer.error and answer.payload is not None:
            raw = canonical(answer.payload).decode()
            found = [token for token in fixture.canaries if token in raw]
            self.add(name + ".canary", "security", Status.FAIL if found else Status.PASS,
                     "response disclosed an outside/CWD decoy canary" if found else "no outside/CWD decoy canary was disclosed",
                     disclosed=found)
        new_checks = fixture_checks(fixture, profile, answer)
        self.checks.extend(new_checks)
        if name == "normal":
            self.normal_correct = all(c.status == Status.PASS for c in new_checks)
        if name == "large":
            self.add("large.bounded_output", "readiness", Status.PASS,
                     "stress reply stayed inside the profile limit; coverage is graded separately",
                     fixture_file_count=len(fixture.files), response_bytes=answer.wire_bytes)

    def execute(self, fixture: Fixture, label: str | None = None, repeat: bool = False) -> None:
        label = label or fixture.name
        client: StdioClient | None = None
        evidence: dict[str, Any] = {"id": label, "input_manifest": fixture.hash_manifest(),
                                    "unsafe_entries": sorted(fixture.problems), "root": str(fixture.root)}
        try:
            if not self.execution_allowed():
                raise UnsupportedEvidence("selected isolation backend is not ready to launch a subject")
            self.preflight(fixture)
            evidence["preconditions"] = dict(fixture.preconditions)
            client = StdioClient(self.config.command, fixture.cwd, fixture.root, fixture.home,
                                 self.config.limits, self.uid, self.gid, self.suite_deadline)
            client.initialize()
            client.tool(self.config.profile.tool)
            self.tool_fingerprints.add(client.tools_sha256)
            args = {**self.config.profile.arguments, self.config.profile.path_argument: fixture.argument}
            frame = client.call(self.config.profile.tool, args)
            # Inspect the whole bounded wire result for canaries, including error data.
            leaked = [s for s in fixture.canaries if s in canonical(frame.message).decode()]
            if leaked:
                self.add(label + ".wire_canary", "security", Status.FAIL,
                         "wire result disclosed an outside/CWD decoy canary", disclosed=leaked)
            answer = decode(frame)
            evidence["response"] = {"wire_bytes": answer.wire_bytes, "wire_sha256": answer.wire_sha256,
                                    "is_error": answer.error}
            if label != "normal_fresh":
                self.handle_answer(fixture, answer)
            elif answer.error:
                self.add("repeatability.fresh", "readiness", Status.FAIL, "identical request failed in a fresh session")
            if fixture.name == "missing":
                if not self.missing_error_actionable:
                    self.recovery_status = Status.FAIL
                else:
                    repaired_args = {**self.config.profile.arguments,
                                     self.config.profile.path_argument: str(fixture.root)}
                    repaired = decode(client.call(self.config.profile.tool, repaired_args))
                    repaired_fixture = replace(fixture, name="recovery", argument=str(fixture.root))
                    repaired_checks = fixture_checks(repaired_fixture, self.config.profile, repaired)
                    self.checks.extend(repaired_checks)
                    grade = verdict(repaired_checks)
                    self.recovery_status = {"PASS": Status.PASS, "FAIL": Status.FAIL, "INCOMPLETE": Status.UNKNOWN}[grade]
                    evidence["repaired_response"] = {"wire_bytes": repaired.wire_bytes, "wire_sha256": repaired.wire_sha256}
            if fixture.name == "normal" and not answer.error and answer.payload is not None:
                self.repeat_values.append(repeatable_payload(answer.payload, self.config.profile))
            if repeat:
                repeated = decode(client.call(self.config.profile.tool, args))
                if repeated.error or repeated.payload is None:
                    self.add("repeatability.session", "readiness", Status.FAIL, "identical repeat request failed")
                else:
                    self.repeat_values.append(repeatable_payload(repeated.payload, self.config.profile))
            if "notifications/tools/list_changed" in client.events:
                self.add(label + ".tool_changes", "readiness", Status.UNKNOWN,
                         "server changed its tool surface during a fixed-profile run")
            if any(e.startswith("unsupported:") for e in client.events):
                self.add(label + ".client_capabilities", "readiness", Status.UNKNOWN,
                         "server requested a capability outside the v1 test client", events=client.events)
        except ServerFault as exc:
            code = "bounded_output" if exc.code in ("frame_limit", "result_limit", "session_limit") else "bounded_completion" if exc.code == "timeout" else "server_behavior"
            self.add(label + "." + code, "readiness", Status.FAIL,
                     str(exc), failure_kind=exc.code, **exc.evidence)
            if fixture.name in ("outside", "traversal", "escaping_symlink", "special_file", "directory_loop"):
                self.add(label + ".boundary_evidence", "security", Status.UNKNOWN,
                         "server failed before usable boundary evidence was collected")
        except ContractError as exc:
            self.add(label + ".response_contract", "readiness", Status.FAIL, str(exc))
        except UnsupportedEvidence as exc:
            self.add(label + ".profile_evidence", "readiness", Status.UNKNOWN, str(exc))
        except Exception as exc:
            self.errors.append({"case": label, "kind": type(exc).__name__, "message": str(exc)[:512]})
            self.add(label + ".harness_evidence", "readiness", Status.UNKNOWN,
                     "harness could not collect evidence; this is not a server pass", kind=type(exc).__name__)
        finally:
            if client is not None:
                evidence["transport"] = client.metadata()
                try:
                    client.close()
                except (OSError, subprocess.SubprocessError) as exc:
                    self.errors.append({"case": label, "kind": "cleanup", "message": str(exc)[:256]})
                    self.add(label + ".cleanup", "security", Status.UNKNOWN, "server cleanup could not be confirmed")
            try:
                after = snapshot(fixture.watched, fixture.read_fds)
                changed = sorted(k for k in set(after) | set(fixture.before) if after.get(k) != fixture.before.get(k))
                evidence["snapshot_before_sha256"] = digest(fixture.before)
                evidence["snapshot_after_sha256"] = digest(after)
                evidence["changed_paths"] = changed[:32]
                if changed:
                    self.add(label + ".read_only", "security", Status.FAIL, "server changed the watched workspace/canary/CWD tree",
                             changed_paths=changed[:32], changed_count=len(changed))
                elif any(row.get("unreadable") for row in after.values()):
                    self.add(label + ".read_only", "security", Status.UNKNOWN, "metadata stayed fixed but some file bytes were unreadable to the oracle")
                else:
                    self.add(label + ".read_only", "security", Status.PASS,
                             "observable bytes, entries, permissions, and modification metadata stayed fixed")
                fixture.before = after
            except (OSError, HarnessError) as exc:
                self.add(label + ".read_only", "security", Status.UNKNOWN, "post-run filesystem evidence could not be collected", kind=type(exc).__name__)
            self.cases.append(evidence)
            for fd in fixture.read_fds.values():
                os.close(fd)
            fixture.read_fds.clear()

    def collect_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mcp-behavior-") as temporary:
            parent = Path(temporary)
            normal: Fixture | None = None
            for name in CASES:
                if time.monotonic() >= self.suite_deadline:
                    self.add(name + ".suite_budget", "readiness", Status.UNKNOWN, "suite budget exhausted; scenario was not run")
                    continue
                try:
                    fixture = build_fixture(parent, name, self.config.profile.supported_suffixes, self.uid, self.gid)
                    if name == "normal":
                        normal = fixture
                    self.execute(fixture, repeat=name == "normal")
                except (OSError, HarnessError) as exc:
                    self.errors.append({"case": name, "kind": type(exc).__name__, "message": str(exc)[:512]})
                    self.add(name + ".setup", "readiness", Status.UNKNOWN, "fixture setup failed; scenario was not tested", kind=type(exc).__name__)
            if normal is not None and time.monotonic() < self.suite_deadline:
                self.execute(normal, label="normal_fresh")

    def run(self) -> dict[str, Any]:
        self.suite_deadline = time.monotonic() + self.config.limits.suite_timeout_seconds
        try:
            before_identity = self.identity()
        except (OSError, HarnessError) as exc:
            before_identity = {"reviewer_declared": self.config.identity, "error": type(exc).__name__, "reason": str(exc)[:512]}
            self.errors.append({"case": "identity", "kind": type(exc).__name__, "message": str(exc)[:512]})
            self.add("artifact_identity", "readiness", Status.UNKNOWN, "could not hash the configured server artifacts")
        if self.execution_allowed():
            self.collect_cases()
        else:
            self.add("isolation_preflight", "security", Status.UNKNOWN,
                     "selected isolation backend cannot launch a subject; no fixture probes or MCP sessions were started",
                     **self.isolation_evidence())
        if len(self.repeat_values) < 3:
            self.add("repeatability", "readiness", Status.UNKNOWN, "three usable results across same and fresh sessions were not collected")
        else:
            stable = len(set(self.repeat_values)) == 1
            self.add("repeatability", "readiness", Status.PASS if stable else Status.FAIL,
                     "same and fresh sessions produced equivalent evidence" if stable else "fixed inputs changed beyond approved timestamp/set-order normalization",
                     payload_sha256=[hashlib.sha256(v).hexdigest() for v in self.repeat_values],
                     ignored_timestamps=list(self.config.profile.ignored_timestamps))
        self.add("scripted_recovery", "readiness",
                 self.recovery_status,
                 "bounded recovery requires a useful missing-input error and an independently correct repaired request",
                 scope="Scripted fixture repair only; no model ability is inferred.")
        self.add("tool_surface_stability", "readiness",
                 Status.PASS if len(self.tool_fingerprints) == 1 else Status.UNKNOWN if not self.tool_fingerprints else Status.FAIL,
                 "tool-definition fingerprint must stay fixed across this profile's sessions",
                 fingerprints=sorted(self.tool_fingerprints))
        try:
            after_identity = self.identity()
            stable = before_identity == after_identity
            self.add("artifact_stability", "security", Status.UNKNOWN if "error" in before_identity else Status.PASS if stable else Status.FAIL,
                     "configured artifact bytes stayed fixed" if stable else "configured artifact bytes changed during the run")
        except (OSError, HarnessError) as exc:
            self.add("artifact_stability", "security", Status.UNKNOWN, "could not collect final artifact identity", kind=type(exc).__name__)
        containment_status, containment_reason, containment_evidence = self.isolation_backend.containment_check(self.isolation_preflight)
        self.add("execution_containment", "security", Status(containment_status), containment_reason,
                 **containment_evidence, resource_limits_are_not_a_sandbox=True)
        self.checks.append(Check("real_model_recovery", "agent_run", Status.NA,
                                 "real-model runs are outside v1 and never substitute for fixture grades", required=False))
        lanes = {name: verdict([c for c in self.checks if c.lane == name]) for name in ("readiness", "security")}
        return {"schema_version": "mcp-behavior-report/v1", "harness_version": __version__,
                "run_id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "verdict": verdict(self.checks), "lanes": lanes,
                "scope": "Finite Linux stdio, synchronous, read-only repository profile; not protocol conformance or a general security certification.",
                "target": before_identity, "config_sha256": self.config.config_sha256,
                "isolation": self.isolation_evidence(),
                "execution": {"mode": self.isolation_backend.mode.value, "server_uid": self.uid if self.uid is not None else os.geteuid(),
                              "server_gid": self.gid if self.gid is not None else self.uid if self.uid is not None else os.getegid(),
                              "environment_policy": "minimal-v1"},
                "profile": {"id": self.config.profile.id, "version": self.config.profile.version,
                            "sha256": self.config.profile.sha256, "tool": self.config.profile.tool,
                            "supported_suffixes": list(self.config.profile.supported_suffixes),
                            "relative_paths": self.config.profile.relative_paths},
                "limits": vars(self.config.limits), "platform": {"sys_platform": sys.platform, "python": sys.version.split()[0]},
                "case_count": len(self.cases), "checks": [c.to_dict() for c in self.checks],
                "cases": self.cases, "harness_errors": self.errors,
                "limitations": ["Native mode cannot certify containment or absence of unobserved host effects.",
                                "Namespace mode runs trusted preflight helpers only; MCP subject launch remains disabled.",
                                "Synthetic filesystem, TCP endpoint and cgroup helper evidence does not prove actual subject containment.",
                                "Snapshots do not prove absence of transient writes or reads that leave no observable evidence.",
                                "Artifact identity covers explicit files, not the installed dependency closure.",
                                "Behavioral field mappings and expected capabilities are reviewer-owned assertions; review their digest.",
                                "A PASS applies only to the named tool, fixtures, profile, limits, and configuration.",
                                "Content hashes verify the inventory profile, not the semantic accuracy of a vulnerability scanner."]}
