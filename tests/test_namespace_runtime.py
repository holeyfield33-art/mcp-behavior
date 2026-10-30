from __future__ import annotations

import dataclasses
import errno
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from mcp_behavior import namespace_runtime as runtime
from mcp_behavior.isolation import ExecutionMode, IsolationPolicy, NamespaceBackend
from mcp_behavior.namespace_runtime import (
    LaunchPlan,
    ProbeResult,
    launch_subject,
    prepare_isolation_dirs,
    run_host_canary_probe,
    tool_preflight,
)


class NamespaceRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.workspace = self.base / "ws"
        self.workspace.mkdir()
        self.canary, self.oracle, _ = prepare_isolation_dirs(self.base, "tok")
        self.plan = LaunchPlan(self.workspace, ["/bin/true"], self.canary, self.oracle)
        self.tools = ProbeResult(True, "candidate tools", {"bwrap": "/usr/bin/bwrap", "user_ns_hint": True})

    def output_probe(self, payload_or_factory, returncode=0) -> ProbeResult:
        def capture(command, cwd):
            nonce = command[-4]
            payload = {
                "nonce": nonce,
                "host_canary": {"readable": False, "errno": errno.ENOENT},
                "oracle_dir": {"readable": False, "errno": errno.ENOENT},
                "oracle_answers": {"readable": False, "errno": errno.ENOENT},
            }
            output = payload_or_factory(payload) if callable(payload_or_factory) else payload_or_factory
            raw = output if isinstance(output, bytes) else json.dumps(output).encode()
            return subprocess.CompletedProcess(command, returncode, raw, b"")
        with mock.patch.object(runtime, "tool_preflight", return_value=self.tools), \
             mock.patch.object(runtime, "_capture_probe", side_effect=capture):
            return run_host_canary_probe(self.plan, "tok")

    def test_tool_preflight_reports_structure_without_claiming_enforcement(self) -> None:
        result = tool_preflight()
        self.assertIn("bwrap", result.evidence)
        self.assertIn("user_ns_hint", result.evidence)
        self.assertIsInstance(result.ok, bool)
        self.assertTrue(result.detail)
        if result.ok:
            self.assertIn("probe still required", result.detail)

    def test_prepare_isolation_dirs_writes_private_nonempty_known_secrets(self) -> None:
        self.assertEqual(self.canary.read_text(), "HOST_SECRET_tok\n")
        self.assertEqual(json.loads((self.oracle / "answers.json").read_text()), {"token": "tok"})
        self.assertEqual(stat.S_IMODE(self.canary.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.oracle.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.oracle / "answers.json").stat().st_mode), 0o600)
        self.assertFalse(self.canary.is_relative_to(self.workspace))
        self.assertFalse(self.oracle.is_relative_to(self.workspace))

    def test_canary_probe_fails_closed_without_bwrap(self) -> None:
        with mock.patch.object(runtime, "which_bwrap", return_value=None), \
             mock.patch.object(runtime.subprocess, "Popen") as launch:
            probe = run_host_canary_probe(self.plan, "tok")
        launch.assert_not_called()
        self.assertFalse(probe.ok)
        self.assertIn("bwrap", probe.detail)

    def test_namespace_feature_hint_failure_does_not_launch(self) -> None:
        with mock.patch.object(runtime, "which_bwrap", return_value="/usr/bin/bwrap"), \
             mock.patch.object(runtime, "user_ns_usable", return_value=False), \
             mock.patch.object(runtime.subprocess, "Popen") as launch:
            probe = run_host_canary_probe(self.plan, "tok")
        launch.assert_not_called()
        self.assertFalse(probe.ok)
        self.assertIn("disabled", probe.detail)

    def test_valid_denial_is_only_synthetic_probe_evidence(self) -> None:
        probe = self.output_probe(lambda payload: payload)
        self.assertTrue(probe.ok, probe)
        self.assertIn("containment remains unverified", probe.detail)
        self.assertIn("synthetic", probe.evidence["scope"])
        self.assertEqual(probe.evidence["workspace_mount"], str(self.workspace))

    def test_missing_wrong_type_and_wrong_run_evidence_cannot_pass(self) -> None:
        def wrong_bool(payload):
            payload["host_canary"]["readable"] = 0
            return payload
        def missing(payload):
            del payload["oracle_answers"]
            return payload
        def wrong_nonce(payload):
            payload["nonce"] = "a different run"
            return payload
        def unexpected_io(payload):
            payload["oracle_dir"]["errno"] = errno.EIO
            return payload
        def boolean_errno(payload):
            payload["oracle_dir"]["errno"] = True
            return payload
        def contradictory(payload):
            payload["host_canary"] = {"readable": True, "errno": errno.ENOENT}
            return payload
        for payload in ({}, [], None, {"host_canary_readable": "", "oracle_dir_readable": 0},
                        wrong_bool, missing, wrong_nonce, unexpected_io, boolean_errno, contradictory):
            with self.subTest(payload=payload):
                self.assertFalse(self.output_probe(payload).ok)

    def test_invalid_duplicate_or_extra_json_cannot_pass(self) -> None:
        for raw in (b"", b"{}", b'{"nonce":"one","nonce":"two"}', b"NaN",
                    b"{}\n{}", b"diagnostic\n{}", b"\xff"):
            with self.subTest(raw=raw):
                self.assertFalse(self.output_probe(raw).ok)

    def test_any_protected_path_access_is_detected(self) -> None:
        for label in ("host_canary", "oracle_dir", "oracle_answers"):
            def leaked(payload):
                payload[label] = {"readable": True, "errno": None}
                return payload
            with self.subTest(label=label):
                probe = self.output_probe(leaked)
                self.assertFalse(probe.ok)
                self.assertIn("can reach", probe.detail)

    def test_nonzero_helper_exit_cannot_pass(self) -> None:
        probe = self.output_probe(lambda payload: payload, returncode=1)
        self.assertFalse(probe.ok)
        self.assertIn("exit 1", probe.detail)

    def test_missing_empty_changed_and_wrong_run_secrets_cannot_supply_denial_credit(self) -> None:
        for contents in (b"", b"changed", b"HOST_SECRET_other_run\n"):
            with self.subTest(contents=contents), mock.patch.object(runtime, "_capture_probe") as capture:
                self.canary.write_bytes(contents)
                self.assertFalse(run_host_canary_probe(self.plan, "tok").ok)
                capture.assert_not_called()
        self.canary.unlink()
        with mock.patch.object(runtime, "_capture_probe") as capture:
            self.assertFalse(run_host_canary_probe(self.plan, "tok").ok)
        capture.assert_not_called()

    def test_changed_oracle_answers_cannot_pass(self) -> None:
        (self.oracle / "answers.json").write_text("{}")
        with mock.patch.object(runtime, "_capture_probe") as capture:
            self.assertFalse(run_host_canary_probe(self.plan, "tok").ok)
        capture.assert_not_called()

    def test_secrets_inside_workspace_or_runtime_mount_are_rejected(self) -> None:
        for plan in (dataclasses.replace(self.plan, workspace=self.base),
                     dataclasses.replace(self.plan, oracle_dir=Path("/usr"))):
            with self.subTest(plan=plan), mock.patch.object(runtime, "_capture_probe") as capture:
                probe = run_host_canary_probe(plan, "tok")
                self.assertFalse(probe.ok)
                self.assertIn("overlap", probe.detail)
                capture.assert_not_called()

    def test_workspace_alias_cannot_hide_exposed_secrets(self) -> None:
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with mock.patch.object(runtime, "_capture_probe") as capture:
            probe = run_host_canary_probe(dataclasses.replace(self.plan, workspace=alias), "tok")
        self.assertFalse(probe.ok)
        capture.assert_not_called()

    def test_symlink_hardlink_and_special_secret_files_are_rejected(self) -> None:
        self.canary.unlink()
        self.canary.symlink_to(self.oracle / "answers.json")
        self.assertFalse(run_host_canary_probe(self.plan, "tok").ok)
        self.canary.unlink()
        os.mkfifo(self.canary, 0o600)
        self.assertFalse(run_host_canary_probe(self.plan, "tok").ok)
        self.canary.unlink()
        self.canary.write_text("HOST_SECRET_tok\n")
        self.canary.chmod(0o600)
        os.link(self.canary, self.base / "alias.secret")
        self.assertFalse(run_host_canary_probe(self.plan, "tok").ok)

    def test_public_secret_permissions_are_rejected(self) -> None:
        for path, mode in ((self.canary, 0o644), (self.oracle, 0o755)):
            with self.subTest(path=path):
                path.chmod(mode)
                self.assertFalse(run_host_canary_probe(self.plan, "tok").ok)
                path.chmod(0o700 if path.is_dir() else 0o600)

    def test_invalid_tokens_and_existing_paths_are_not_overwritten(self) -> None:
        for token in ("", "../escape", "a/b", "a" * 129):
            with self.subTest(token=token), self.assertRaises(ValueError):
                prepare_isolation_dirs(self.base, token)
        with self.assertRaises(FileExistsError):
            prepare_isolation_dirs(self.base, "tok")
        self.assertEqual(self.canary.read_text(), "HOST_SECRET_tok\n")
        self.base.chmod(0o755)
        try:
            with self.assertRaises(ValueError):
                prepare_isolation_dirs(self.base, "other")
        finally:
            self.base.chmod(0o700)

    def test_probe_uses_same_absolute_workspace_and_clean_candidate_environment(self) -> None:
        with mock.patch.object(runtime, "tool_preflight", return_value=self.tools), \
             mock.patch.object(runtime, "_capture_probe", side_effect=OSError("blocked")) as capture:
            probe = run_host_canary_probe(self.plan, "tok")
        self.assertFalse(probe.ok)
        command, cwd = capture.call_args.args
        self.assertEqual(cwd, self.workspace)
        bind = command.index("--bind")
        self.assertEqual(command[bind + 1:bind + 3], [str(self.workspace), str(self.workspace)])
        self.assertLess(command.index("--tmpfs"), bind)
        self.assertIn("--clearenv", command)
        self.assertIn("--new-session", command)
        self.assertIn("--cap-drop", command)
        self.assertNotIn("/etc/resolv.conf", command)
        self.assertNotIn("HOST_SECRET_tok", " ".join(command))

    def test_host_view_negative_control_detects_access_without_disclosure(self) -> None:
        # Run the actual trusted helper without the namespace: it must detect the
        # readable planted files even though it never prints their contents.
        def host_view(plan, bwrap, command):
            return [sys.executable, *command[1:]]
        with mock.patch.object(runtime, "tool_preflight", return_value=self.tools), \
             mock.patch.object(runtime, "_bwrap_command", side_effect=host_view):
            probe = run_host_canary_probe(self.plan, "tok")
        self.assertFalse(probe.ok, probe)
        self.assertIn("can reach", probe.detail)
        self.assertTrue(probe.evidence["probe"]["host_canary"]["readable"])
        self.assertNotIn("HOST_SECRET_tok", json.dumps(probe.evidence))

    def test_helper_does_not_inherit_controller_credentials_or_open_fds(self) -> None:
        fd = os.open(self.canary, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        os.set_inheritable(fd, True)
        script = """
import json, os, sys
try:
    os.fstat(int(sys.argv[1]))
    inherited = True
except OSError:
    inherited = False
print(json.dumps({"credential": "MCP_TEST_CREDENTIAL" in os.environ, "fd": inherited}))
"""
        with mock.patch.dict(os.environ, {"MCP_TEST_CREDENTIAL": "should-never-be-forwarded"}):
            result = runtime._capture_probe([sys.executable, "-I", "-S", "-c", script, str(fd)], self.workspace)
        self.assertEqual(json.loads(result.stdout), {"credential": False, "fd": False})

    def test_helper_output_is_bounded_before_json_and_without_newlines(self) -> None:
        for output_fd in (1, 2):
            with self.subTest(output_fd=output_fd), \
                 mock.patch.object(runtime, "PROBE_MAX_BYTES", 512), \
                 self.assertRaisesRegex(ValueError, "output byte limit"):
                runtime._capture_probe([sys.executable, "-I", "-S", "-c",
                                        f"import os; os.write({output_fd}, b'x'*1000000)"], self.workspace)

    def test_helper_timeout_cleans_up_instead_of_waiting_for_output(self) -> None:
        started = time.monotonic()
        with mock.patch.object(runtime, "PROBE_TIMEOUT_SECONDS", 0.2), \
             self.assertRaisesRegex(TimeoutError, "wall deadline"):
            runtime._capture_probe([sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"], self.workspace)
        self.assertLess(time.monotonic() - started, 2)

    def test_closed_pipes_cannot_bypass_helper_deadline(self) -> None:
        with mock.patch.object(runtime, "PROBE_TIMEOUT_SECONDS", 0.2), \
             self.assertRaises(subprocess.TimeoutExpired):
            runtime._capture_probe([sys.executable, "-I", "-S", "-c",
                                    "import os,time; os.close(1); os.close(2); time.sleep(30)"], self.workspace)

    def test_exited_helper_parent_does_not_leave_a_pipe_holder_running(self) -> None:
        marker = self.workspace / "helper-child.pid"
        script = """
import os, sys, time
child = os.fork()
if child == 0:
    time.sleep(30)
else:
    with open(sys.argv[1], "w") as fh:
        fh.write(str(child))
    os._exit(0)
"""
        with mock.patch.object(runtime, "PROBE_TIMEOUT_SECONDS", 0.3), \
             self.assertRaisesRegex(TimeoutError, "wall deadline"):
            runtime._capture_probe([sys.executable, "-I", "-S", "-c", script, str(marker)], self.workspace)
        child = int(marker.read_text())
        for _ in range(50):
            status = Path(f"/proc/{child}/status")
            if not status.exists() or "\nState:\tZ" in status.read_text():
                break
            time.sleep(0.01)
        else:
            os.kill(child, 9)
            self.fail("trusted helper descendant kept running after timeout cleanup")

    def test_probe_failure_and_cutoff_are_failed_preconditions(self) -> None:
        for error in (TimeoutError("deadline"), ValueError("output byte limit"), OSError("not permitted")):
            with self.subTest(error=error), \
                 mock.patch.object(runtime, "tool_preflight", return_value=self.tools), \
                 mock.patch.object(runtime, "_capture_probe", side_effect=error):
                probe = run_host_canary_probe(self.plan, "tok")
            self.assertFalse(probe.ok)
            self.assertIn("could not establish", probe.detail)

    def test_standalone_canary_success_cannot_authorize_subject_launch(self) -> None:
        with mock.patch.object(runtime, "tool_preflight", return_value=self.tools), \
             mock.patch.object(runtime, "run_host_canary_probe", return_value=ProbeResult(True, "synthetic pass")) as probe, \
             mock.patch.object(runtime.subprocess, "Popen") as launch:
            result = launch_subject(self.plan)
        probe.assert_not_called()
        launch.assert_not_called()
        self.assertIsNone(result.process)
        self.assertFalse(result.probe.ok)
        self.assertFalse(result.evidence["subject_launch_supported"])

    def test_backend_collects_probe_evidence_without_waiving_unimplemented_gates(self) -> None:
        with mock.patch("mcp_behavior.isolation.tool_preflight", return_value=self.tools), \
             mock.patch("mcp_behavior.isolation.run_host_canary_probe", return_value=ProbeResult(True, "synthetic pass")) as probe:
            result = NamespaceBackend().preflight(IsolationPolicy(mode=ExecutionMode.NAMESPACE))
        probe.assert_called_once()
        plan, token = probe.call_args.args
        self.assertFalse(plan.workspace.exists())  # Private fixture cleaned after the probe.
        self.assertFalse(plan.host_canary.exists())
        self.assertFalse(plan.oracle_dir.exists())
        self.assertEqual(plan.command, [])
        self.assertTrue(token)
        self.assertTrue(result.observed["host_path_probe"]["ok"])
        self.assertFalse(result.ok)
        for gate in ("launcher_implemented", "oracle_storage_protection", "network_denial",
                     "aggregate_resources", "teardown_verified"):
            self.assertTrue(any(f.id == gate and not f.ok and f.required for f in result.findings))
        self.assertEqual(NamespaceBackend().containment_check(result)[0], "UNKNOWN")

    def test_backend_missing_tools_does_not_start_any_probe(self) -> None:
        with mock.patch("mcp_behavior.isolation.tool_preflight", return_value=ProbeResult(False, "bwrap missing")), \
             mock.patch("mcp_behavior.isolation.run_host_canary_probe") as probe:
            result = NamespaceBackend().preflight(IsolationPolicy(mode=ExecutionMode.NAMESPACE))
        probe.assert_not_called()
        self.assertFalse(result.ok)
        self.assertIn("bwrap missing", result.observed["host_path_probe"]["detail"])

    def test_backend_probe_setup_failure_remains_an_explicit_precondition(self) -> None:
        with mock.patch("mcp_behavior.isolation.tool_preflight", return_value=self.tools), \
             mock.patch("mcp_behavior.isolation.prepare_isolation_dirs", side_effect=OSError("read-only host")):
            result = NamespaceBackend().preflight(IsolationPolicy(mode=ExecutionMode.NAMESPACE))
        self.assertFalse(result.ok)
        self.assertFalse(result.observed["host_path_probe"]["ok"])
        self.assertIn("read-only host", result.observed["host_path_probe"]["detail"])


if __name__ == "__main__":
    unittest.main()
