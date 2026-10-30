from __future__ import annotations

import dataclasses
import contextlib
import io
import json
import os
import selectors
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mcp_behavior.config import Config, Limits
from mcp_behavior.cli import main
from mcp_behavior.fixtures import build_fixture
from mcp_behavior.isolation import (ExecutionMode, IsolationPolicy, NamespaceBackend,
                                    PreflightFinding, PreflightResult)
from mcp_behavior.model import HarnessError, ServerFault
from mcp_behavior.runner import Runner
from mcp_behavior.subject import SubjectSession, subject_command
from mcp_behavior.supervisor import ResourceLimitExceeded
from mcp_behavior.transport import StdioClient

ROOT = Path(__file__).resolve().parents[1]
GATES = ("platform", "cgroup_v2", "user_namespace", "namespace_tools", "host_path_probe",
         "network_endpoint_probe", "cgroup_supervisor_probe")


def green(policy):
    return PreflightResult(ExecutionMode.NAMESPACE, False,
                           [PreflightFinding(key, True, "test") for key in GATES],
                           {"launch_policy": dict(vars(policy))})


class SubjectTests(unittest.TestCase):
    def test_opt_in_with_failed_probes_records_zero_subjects(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            with patch("mcp_behavior.runner.StdioClient") as client, \
                 contextlib.redirect_stdout(io.StringIO()):
                code = main(["run", "--config", str(ROOT / "examples/reference.json"),
                             "--output", str(output), "--isolation", "namespace", "--namespace-subject",
                             "--cgroup-parent", str(Path(tmp) / "missing-cgroup")])
            report = json.loads(output.read_text())
        client.assert_not_called()
        self.assertEqual(code, 2)
        self.assertEqual(report["state"], "FINISHED")
        self.assertEqual(report["case_count"], 0)
        self.assertFalse(report["isolation"]["subject_launch_supported"])

    def test_cli_rejects_incompatible_subject_options(self):
        common = ["run", "--config", str(ROOT / "examples/reference.json"), "--output", "/unused.json"]
        for options in (["--native", "--namespace-subject"],
                        ["--isolation", "namespace", "--namespace-subject"],
                        ["--isolation", "namespace", "--namespace-subject", "--cgroup-parent", "/test", "--server-uid", "123"]):
            with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main(common + options)
                self.assertEqual(error.exception.code, 2)

    def test_every_gate_and_policy_binding_required(self):
        policy = IsolationPolicy(ExecutionMode.NAMESPACE, cgroup_parent="/sys/fs/cgroup/test", namespace_subject=True)
        result = green(policy)
        self.assertTrue(NamespaceBackend.launch_ready(result, policy))
        for key in GATES:
            with self.subTest(key=key):
                bad = green(policy)
                bad.findings = [f for f in bad.findings if f.id != key]
                self.assertFalse(NamespaceBackend.launch_ready(bad, policy))
                bad = green(policy)
                next(f for f in bad.findings if f.id == key).ok = False
                self.assertFalse(NamespaceBackend.launch_ready(bad, policy))
        for change in ({"namespace_subject": False}, {"server_uid": 123},
                       {"cgroup_parent": "/different"}, {"memory_mib": 1024}):
            self.assertFalse(NamespaceBackend.launch_ready(result, dataclasses.replace(policy, **change)))
        self.assertFalse(NamespaceBackend.launch_ready(PreflightResult(ExecutionMode.NAMESPACE, True), policy))

    def test_launch_failure_never_falls_back_to_native(self):
        config = Config.load(ROOT / "examples/reference.json")
        runner = Runner(config, isolation_backend=NamespaceBackend(),
                        isolation_preflight=PreflightResult(ExecutionMode.NAMESPACE, False),
                        cgroup_parent=Path("/sys/fs/cgroup/test"), namespace_subject=True)
        runner.isolation_preflight = green(runner.isolation_policy)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_fixture(Path(tmp), "normal", config.profile.supported_suffixes)
            with patch.object(runner, "preflight"), \
                 patch("mcp_behavior.subject.which_bwrap", return_value=None), \
                 patch("mcp_behavior.transport.subprocess.Popen") as native:
                runner.execute(fixture)
            native.assert_not_called()
        self.assertFalse(runner.cases[0]["subject_session"]["joined_before_release"])
        self.assertTrue(runner.errors)
        self.assertEqual(runner.cases[0]["subject_session"]["cleanup"]["created"], False)

    def test_failed_teardown_blocks_further_subject_sessions(self):
        config = Config.load(ROOT / "examples/reference.json")
        runner = Runner(config, isolation_backend=NamespaceBackend(),
                        isolation_preflight=PreflightResult(ExecutionMode.NAMESPACE, False),
                        cgroup_parent=Path("/sys/fs/cgroup/test"), namespace_subject=True)
        runner.isolation_preflight = green(runner.isolation_policy)
        session = Mock(evidence={"cleanup": {"ok": False, "detail": "kill denied"}})
        client = Mock()
        client.initialize.side_effect = HarnessError("observation lost")
        client.close.side_effect = HarnessError("cleanup unverified")
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_fixture(Path(tmp), "normal", config.profile.supported_suffixes)
            with patch.object(runner, "preflight"), patch.object(runner, "subject_session", return_value=session), \
                 patch("mcp_behavior.runner.StdioClient", return_value=client) as launch:
                runner.execute(fixture)
                self.assertTrue(runner.namespace_aborted)
                self.assertFalse(runner.execution_allowed())
                runner.execute(fixture, label="must-not-launch")
                launch.assert_called_once()
        self.assertTrue(any(error["kind"] == "cleanup" for error in runner.errors))

    def test_unverified_membership_never_releases_or_executes_subject(self):
        # A real fixed bootstrap receives an ordinary write-only fd, then blocks
        # at the gate. Fake membership must never release it to the marker code.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            marker = base / "executed"
            session = SubjectSession(base, Limits())
            control = base / "cgroup.procs"
            control.touch()
            session.scope.fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(lambda: os.close(session.scope.fd))
            with patch("mcp_behavior.subject.subject_command",
                       return_value=[sys.executable, "-c", f"open({str(marker)!r},'w').write('bad')"]), \
                 patch.object(session.scope, "prepare"), \
                 patch.object(session.scope, "members", return_value=set()), \
                 patch.object(session.scope, "check_budget", return_value={}), \
                 patch.object(session.scope, "cleanup", return_value={"ok": True}):
                with self.assertRaisesRegex(HarnessError, "membership"):
                    session.start((sys.executable,), base, base, (), time.monotonic() + 2)
            self.assertFalse(marker.exists())
            self.assertFalse(session.evidence["joined_before_release"])

    def test_artifacts_do_not_mount_parent_or_controller_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = base / "watched"
            workspace.mkdir()
            artifact = base / "server.py"
            artifact.write_text("pass")
            with patch("mcp_behavior.subject.which_bwrap", return_value="/usr/bin/bwrap"):
                argv = subject_command((sys.executable, str(artifact)), workspace, workspace, (artifact,))
                self.assertIn(str(artifact), argv)
                self.assertNotIn(str(base), argv)
                self.assertIn("--unshare-net", argv)
                self.assertIn("--clearenv", argv)
                alias = base / "alias"
                alias.symlink_to(artifact)
                for path in (alias, workspace, workspace / "bad"):
                    if path.name == "bad":
                        path.write_text("pass")
                    with self.assertRaises(HarnessError):
                        subject_command((sys.executable,), workspace, workspace, (path,))

    def test_resource_intervention_and_observer_failure_are_distinct(self):
        session = SubjectSession(Path("/missing"), Limits())
        with patch.object(session.scope, "check_budget", side_effect=ResourceLimitExceeded("PID limit")):
            with self.assertRaises(ServerFault):
                session.check()
        with patch.object(session.scope, "check_budget", side_effect=ValueError("missing counters")):
            with self.assertRaises(HarnessError):
                session.check()

    def test_cleanup_failure_remains_visible_and_idempotent(self):
        session = SubjectSession(Path("/missing"), Limits())
        with patch.object(session.scope, "cleanup", return_value={"ok": False, "detail": "kill denied"}) as cleanup:
            with self.assertRaisesRegex(HarnessError, "cleanup unverified"):
                session.close()
            session.close()
        cleanup.assert_called_once()
        self.assertFalse(session.evidence["cleanup"]["ok"])


@unittest.skipUnless(os.environ.get("MCP_BEHAVIOR_SUBJECT_LIVE") == "1"
                     and os.environ.get("MCP_BEHAVIOR_CGROUP_PARENT"),
                     "requires explicit experimental subject live run and cgroup delegation")
class LiveSubjectTests(unittest.TestCase):
    def test_real_reference_sessions_remain_containment_unknown(self):
        config = Config.load(ROOT / "examples/reference.json")
        runner = Runner(config, isolation_backend=NamespaceBackend(),
                        cgroup_parent=Path(os.environ["MCP_BEHAVIOR_CGROUP_PARENT"]), namespace_subject=True)
        self.assertTrue(runner.execution_allowed(), runner.isolation_preflight.reasons())
        report = runner.run()
        self.assertFalse(report["harness_errors"], report["harness_errors"])
        self.assertEqual(report["case_count"], 14)
        self.assertEqual(report["lanes"]["readiness"], "PASS", report["checks"])
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(next(c["status"] for c in report["checks"] if c["id"] == "execution_containment"), "UNKNOWN")
        scopes = set()
        for case in report["cases"]:
            session = case["subject_session"]
            self.assertTrue(session["joined_before_release"])
            self.assertTrue(session["cleanup"]["ok"])
            self.assertTrue(session["cleanup"]["removed"])
            self.assertEqual(session["cleanup"]["populated"], 0)
            self.assertNotIn(session["scope"], scopes)
            scopes.add(session["scope"])

    def test_timeout_kills_detached_descendants(self):
        parent = Path(os.environ["MCP_BEHAVIOR_CGROUP_PARENT"])
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            session = SubjectSession(parent, Limits(timeout_seconds=.2, case_timeout_seconds=.4))
            # Both parent and detached child keep stdio open without responding.
            script = "import os,time; child=os.fork(); os.setsid() if child==0 else None; time.sleep(30)"
            client = StdioClient((sys.executable, "-I", "-S", "-c", script), workspace, workspace, workspace,
                                 session.limits, subject_session=session, workspace=workspace)
            try:
                with self.assertRaises(ServerFault) as fault:
                    client.initialize()
                self.assertEqual(fault.exception.code, "timeout")
                members = session.scope.members()
                self.assertGreaterEqual(len(members), 2)
                handles = [os.pidfd_open(pid) for pid in members]
            finally:
                client.close()
            self.assertTrue(session.evidence["cleanup"]["ok"])
            self.assertFalse(session.scope.path.exists())
            try:
                for fd in handles:
                    with selectors.DefaultSelector() as selector:
                        selector.register(fd, selectors.EVENT_READ)
                        self.assertTrue(selector.select(1), "subject member survived recursive teardown")
            finally:
                for fd in handles:
                    os.close(fd)

    def test_subject_does_not_inherit_controller_fds_credentials_or_secret_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = base / "watched"
            workspace.mkdir()
            secret = base / "controller.secret"
            secret.write_text("controller-only")
            fd = os.open(secret, os.O_RDONLY)
            os.set_inheritable(fd, True)
            session = SubjectSession(Path(os.environ["MCP_BEHAVIOR_CGROUP_PARENT"]), Limits())
            script = '''
import json,os,sys
try:
    os.fstat(int(sys.argv[1]))
    inherited=True
except OSError:
    inherited=False
print(json.dumps(dict(inherited=inherited,credential="MCP_TEST_CREDENTIAL" in os.environ,
                      protected=os.path.exists(sys.argv[2]))))
'''
            try:
                with patch.dict(os.environ, {"MCP_TEST_CREDENTIAL": "must-not-inherit"}):
                    proc = session.start((sys.executable, "-I", "-S", "-c", script, str(fd), str(secret)),
                                         workspace, workspace, (), time.monotonic() + 3)
                    stdout, stderr = proc.communicate(timeout=3)
                    self.assertEqual(proc.returncode, 0, stderr)
                    self.assertEqual(json.loads(stdout), {"inherited": False, "credential": False, "protected": False})
            finally:
                os.close(fd)
                session.close()

    def test_kernel_pid_intervention_is_a_subject_failure_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            session = SubjectSession(Path(os.environ["MCP_BEHAVIOR_CGROUP_PARENT"]), Limits(timeout_seconds=3))
            script = '''
import os,time
for i in range(100):
    try:
        child=os.fork()
    except OSError:
        break
    if child==0:
        time.sleep(30)
        os._exit(0)
time.sleep(30)
'''
            client = StdioClient((sys.executable, "-I", "-S", "-c", script), workspace, workspace, workspace,
                                 session.limits, subject_session=session, workspace=workspace)
            try:
                with self.assertRaises(ServerFault) as failure:
                    client.initialize()
                self.assertEqual(failure.exception.code, "resource_limit")
            finally:
                client.close()
            self.assertTrue(session.evidence["cleanup"]["ok"])
            self.assertTrue(session.evidence["final_resource_intervention"])


if __name__ == "__main__":
    unittest.main()
