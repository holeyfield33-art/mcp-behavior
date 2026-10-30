"""Finite live subject controls, not the full containment acceptance matrix."""
from __future__ import annotations

import dataclasses
import errno
import hashlib
import json
import os
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from mcp_behavior import __version__
from mcp_behavior.config import Config, Limits, digest
from mcp_behavior.isolation import NamespaceBackend
from mcp_behavior.model import HarnessError, ServerFault
from mcp_behavior.network_probe import EndpointObserver
from mcp_behavior.runner import Runner
from mcp_behavior.subject import SubjectSession, subject_command
from mcp_behavior.transport import StdioClient

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "examples/boundary_control_server.py"
LIVE = os.environ.get("MCP_BEHAVIOR_SUBJECT_LIVE") == "1" and bool(os.environ.get("MCP_BEHAVIOR_CGROUP_PARENT"))


class StorageContractTests(unittest.TestCase):
    def test_protected_storage_cannot_be_a_runtime_or_artifact_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            for path in (Path("/usr/local/private-oracle.json"), workspace / "report.json", SERVER):
                with self.subTest(path=path), self.assertRaisesRegex(HarnessError, "protected"):
                    subject_command((sys.executable,), workspace, workspace, (SERVER,), (path,))
            oracle = Path(temporary) / "answers.json"
            oracle.write_text("private")
            alias = Path(temporary) / "artifact.py"
            os.link(oracle, alias)
            with self.assertRaisesRegex(HarnessError, "protected"):
                subject_command((sys.executable,), workspace, workspace, (alias,), (oracle,))


@unittest.skipUnless(LIVE, "requires explicit subject live acceptance and delegated cgroup")
class SubjectAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mcp-behavior-acceptance-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base / "watched"
        self.workspace.mkdir()
        self.oracle = self.base / "oracle.json"
        self.report = self.base / "report.json"
        self.oracle.write_text(json.dumps({"token": uuid.uuid4().hex}))
        self.report.write_text("RUNNING")
        self.parent = Path(os.environ["MCP_BEHAVIOR_CGROUP_PARENT"])
        self.evidence = {"run_id": str(uuid.uuid4()), "control": self._testMethodName,
                         "harness_version": __version__, "profile": "finite-subject-boundary/v1",
                         "control_source_sha256": hashlib.sha256(SERVER.read_bytes()).hexdigest(),
                         "assertions_passed": False, "containment": "UNKNOWN", "sessions": []}

    def tearDown(self):
        destination = os.environ.get("MCP_BEHAVIOR_ACCEPTANCE_OUTPUT")
        if destination:
            output = Path(destination)
            output.mkdir(parents=True, exist_ok=True)
            (output / (self._testMethodName + ".json")).write_text(json.dumps(self.evidence, indent=2) + "\n")

    def client(self, mode, extra=(), limits=None):
        limits = limits or Limits(timeout_seconds=3, case_timeout_seconds=8)
        session = SubjectSession(self.parent, limits, (self.oracle, self.report))
        self.evidence["sessions"].append(session.evidence)
        command = (sys.executable, str(SERVER), "--mode", mode, *extra)
        client = StdioClient(command, self.workspace, self.workspace, self.workspace, limits,
                             subject_session=session, workspace=self.workspace, artifacts=(SERVER,))
        self.addCleanup(client.close)
        client.initialize()
        client.tool("attack_boundary")
        return client, session

    def traced_call(self, client, session, nonce):
        # Identify the actual configured Python process from kernel cgroup and
        # procfs observations, not a subject-supplied host PID.
        pids = []
        for pid in session.scope.members():
            try:
                args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                if nonce.encode() in args and Path(f"/proc/{pid}/exe").resolve().name.startswith("python"):
                    pids.append(pid)
            except ProcessLookupError:
                continue
        self.assertEqual(len(pids), 1, pids)
        pid = pids[0]
        observed = {key: os.readlink(f"/proc/{pid}/ns/{key}") for key in ("pid", "user", "net", "mnt")}
        self.evidence.setdefault("process_views", []).append({"host_pid": pid, "namespaces": observed})
        for key, value in observed.items():
            self.assertNotEqual(value, os.readlink(f"/proc/self/ns/{key}"))
        status = Path(f"/proc/{pid}/status").read_text()
        self.assertIn("NoNewPrivs:\t1", status)
        self.assertIn("CapEff:\t0000000000000000", status)
        tracer_path = shutil.which("strace")
        self.assertIsNotNone(tracer_path, "live syscall acceptance requires strace")
        trace = self.base / ("trace-" + nonce)
        tracer = subprocess.Popen([tracer_path, "-f", "-s", "256", "-o", str(trace),
                                   "-e", "trace=openat,connect,kill", "-p", str(pid)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 2
            while f"TracerPid:\t{tracer.pid}" not in Path(f"/proc/{pid}/status").read_text():
                if time.monotonic() >= deadline or tracer.poll() is not None:
                    self.fail("external syscall observer failed to attach")
                time.sleep(.01)
            frame = client.call("attack_boundary", {})
            return json.loads(frame.message["result"]["content"][0]["text"])
        finally:
            tracer.send_signal(signal.SIGINT)
            _, stderr = tracer.communicate(timeout=2)
            self.assertIn(tracer.returncode, (0, -signal.SIGINT), stderr)
            self.assertIn("TracerPid:\t0", Path(f"/proc/{pid}/status").read_text())
            raw = trace.read_text()
            self.assertLess(len(raw), 1024**2)
            # These paths in actual syscalls prove the fixed subject exercised
            # them; return values alone would be server-supplied assertions.
            self.assertIn(str(self.oracle), raw)
            self.assertIn(str(self.report), raw)
            self.assertIn("connect(", raw)
            self.evidence.setdefault("syscall_traces", []).append(raw)

    def test_storage_process_and_network_controls_detect_deliberately_unsafe_layout(self):
        observer = EndpointObserver()
        observer.start()
        sock = socket.socket(socket.AF_UNIX)
        host_socket = self.base / "host.sock"
        sock.bind(str(host_socket))
        sock.listen(1)
        self.addCleanup(sock.close)
        oracle_before = self.oracle.read_bytes()
        nonce = uuid.uuid4().hex
        try:
            for endpoint in observer.endpoints:
                family = socket.AF_INET if endpoint["family"] == "ipv4" else socket.AF_INET6
                with socket.socket(family) as connection:
                    connection.settimeout(1)
                    connection.connect((endpoint["host"], endpoint["port"]))
                    connection.sendall(("host:" + nonce + "\n").encode())
                    self.assertEqual(connection.recv(3), b"ACK")
            args = ("--oracle", str(self.oracle), "--report", str(self.report), "--controller", str(os.getpid()),
                    "--host-socket", str(host_socket), "--endpoints", json.dumps(observer.endpoints), "--nonce", nonce)
            client, session = self.client("boundary", args)
            try:
                safe = self.traced_call(client, session, nonce)
                for key in ("oracle_read", "controller_mem", "controller_signal", "runtime_write", "socket_path"):
                    self.assertFalse(safe[key]["allowed"], (key, safe))
                self.assertTrue(all(not row["allowed"] for row in safe["network"].values()))
                actual_pid = self.evidence["process_views"][-1]["host_pid"]
                self.assertFalse(Path(f"/proc/{actual_pid}/root{self.oracle}").exists())
                shadow = Path(f"/proc/{actual_pid}/root{self.report}")
                if shadow.exists():
                    host_info, shadow_info = self.report.stat(), shadow.stat()
                    self.assertNotEqual((host_info.st_dev, host_info.st_ino), (shadow_info.st_dev, shadow_info.st_ino))
                    self.evidence["private_report_shadow"] = {"same_host_inode": False,
                                                               "host_report_unchanged": self.report.read_text() == "RUNNING"}
            finally:
                client.close()
            self.assertEqual(self.oracle.read_bytes(), oracle_before)
            self.assertEqual(self.report.read_text(), "RUNNING")
            receipts = observer.snapshot()["messages"]
            self.assertEqual(len(receipts), 2)
            self.evidence["safe"] = safe

            original = subject_command
            def deliberately_unsafe(command, workspace, cwd, artifacts, protected=()):
                argv = original(command, workspace, cwd, artifacts)
                argv.remove("--unshare-net")
                split = argv.index("--")
                return [*argv[:split], "--ro-bind", str(self.oracle), str(self.oracle),
                        "--bind", str(self.report), str(self.report), *argv[split:]]
            with patch("mcp_behavior.subject.subject_command", side_effect=deliberately_unsafe):
                client, session = self.client("boundary", args)
            try:
                frame = client.call("attack_boundary", {})
                unsafe = json.loads(frame.message["result"]["content"][0]["text"])
                self.assertTrue(unsafe["oracle_read"]["allowed"])
                self.assertTrue(unsafe["report_write"]["allowed"])
                self.assertTrue(all(row["allowed"] for row in unsafe["network"].values()))
            finally:
                client.close()
            self.assertEqual(self.report.read_text(), "tampered")
            receipts = observer.snapshot()["messages"]
            for family in ("ipv4", "ipv6"):
                self.assertIn((family, "isolated:" + nonce), receipts)
            self.assertEqual(sorted(receipts), sorted((family, phase + ":" + nonce)
                             for family in ("ipv4", "ipv6") for phase in ("host", "isolated")))
            self.evidence["unsafe_control_detected"] = True
            self.evidence["unsafe"] = unsafe
        finally:
            observer.close()
            self.evidence["network_observer"] = observer.snapshot()
        self.assertFalse(self.evidence["network_observer"]["errors"])
        self.evidence["assertions_passed"] = True

    def test_aggregate_cpu_and_memory_interventions(self):
        for mode in ("cpu", "memory"):
            limits = Limits(timeout_seconds=5, case_timeout_seconds=8, cpu_seconds=1, memory_mib=64)
            client, session = self.client(mode, limits=limits)
            try:
                with self.assertRaises(ServerFault):
                    client.call("attack_boundary", {})
                usage = session.scope.usage()
                if mode == "cpu":
                    self.assertGreater(usage["cpu"]["usage_usec"], 1_000_000)
                else:
                    self.assertGreater(usage["memory"]["oom_kill"], 0)
                self.evidence.setdefault("kernel_interventions", {})[mode] = usage
            finally:
                client.close()
            self.assertTrue(session.evidence["cleanup"]["ok"])
        self.evidence["assertions_passed"] = True

    def test_per_file_ceiling_is_observed_without_claiming_aggregate_storage_quota(self):
        marker = self.workspace / "large.bin"
        client, session = self.client("file_size", ("--marker", str(marker)))
        try:
            frame = client.call("attack_boundary", {})
            payload = json.loads(frame.message["result"]["content"][0]["text"])
            self.assertEqual(payload["write"]["errno"], errno.EFBIG)
            self.assertEqual(marker.stat().st_size, 32 * 1024**2)
            self.evidence["externally_observed_bytes"] = marker.stat().st_size
            self.evidence["aggregate_storage_quota"] = "UNKNOWN: only per-file RLIMIT_FSIZE is implemented"
        finally:
            client.close()
        self.evidence["assertions_passed"] = True

    def test_parent_crash_and_late_writer_are_recursively_stopped(self):
        for mode in ("crash", "late_writer"):
            marker = self.workspace / mode
            client, session = self.client(mode, ("--marker", str(marker)), Limits(timeout_seconds=.3))
            try:
                if mode == "crash":
                    with self.assertRaises(ServerFault):
                        client.call("attack_boundary", {})
                else:
                    client.call("attack_boundary", {})
                handles = [os.pidfd_open(pid) for pid in session.scope.members()]
            finally:
                client.close()
            try:
                for handle in handles:
                    with selectors.DefaultSelector() as selector:
                        selector.register(handle, selectors.EVENT_READ)
                        self.assertTrue(selector.select(1))
            finally:
                for handle in handles:
                    os.close(handle)
            time.sleep(1.05)
            self.assertFalse(marker.exists(), "late descendant wrote after final teardown")
            self.assertTrue(session.evidence["cleanup"]["ok"])
        self.evidence["assertions_passed"] = True

    def test_interrupted_observer_aborts_actual_subject_run(self):
        config = Config.load(ROOT / "examples/reference.json")
        original = SubjectSession.check
        def lose_observation(session):
            if session.evidence.get("command_sha256") == digest(config.command):
                with patch.object(session.scope, "usage", side_effect=OSError("intentional observer interruption")):
                    original(session)
            else:
                original(session)
        with patch.object(SubjectSession, "check", lose_observation):
            report = Runner(config, isolation_backend=NamespaceBackend(), cgroup_parent=self.parent,
                            namespace_subject=True, protected_paths=(self.oracle, self.report)).run()
        self.assertEqual(report["case_count"], 1)
        self.assertTrue(report["isolation"]["subject_launch_aborted"])
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertTrue(report["harness_errors"])
        self.assertTrue(report["cases"][0]["subject_session"]["cleanup"]["ok"])
        self.evidence["interrupted_run"] = report
        self.evidence["assertions_passed"] = True
