from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_behavior.cli import main
from mcp_behavior.config import Config
from mcp_behavior.fixtures import build_fixture
from mcp_behavior.model import HarnessError
from mcp_behavior.runner import Runner

from mcp_behavior.isolation import (
    ExecutionMode,
    IsolationPolicy,
    NativeBackend,
    NamespaceBackend,
    PreflightResult,
    get_backend,
)

ROOT = Path(__file__).resolve().parents[1]


class IsolationTests(unittest.TestCase):
    def test_native_preflight_ok_on_linux(self) -> None:
        backend = NativeBackend()
        result = backend.preflight(IsolationPolicy(mode=ExecutionMode.NATIVE))
        self.assertTrue(result.ok)
        status, reason, evidence = backend.containment_check(result)
        self.assertEqual(status, "UNKNOWN")
        self.assertIn("native", reason.lower())
        self.assertEqual(evidence.get("mode"), "native")

    def test_namespace_preflight_fails_closed_until_implemented(self) -> None:
        backend = NamespaceBackend()
        result = backend.preflight(IsolationPolicy(mode=ExecutionMode.NAMESPACE))
        self.assertFalse(result.ok)
        self.assertTrue(any("launcher_implemented" in r for r in result.reasons()))
        status, reason, evidence = backend.containment_check(result)
        self.assertEqual(status, "UNKNOWN")
        self.assertFalse(evidence.get("preflight_ok", True))

    def test_get_backend(self) -> None:
        self.assertIsInstance(get_backend("native"), NativeBackend)
        self.assertIsInstance(get_backend(ExecutionMode.NAMESPACE), NamespaceBackend)

    def test_no_silent_mode_confusion(self) -> None:
        native = get_backend("native")
        ns = get_backend("namespace")
        self.assertIsNot(type(native), type(ns))
        self.assertEqual(native.mode, ExecutionMode.NATIVE)
        self.assertEqual(ns.mode, ExecutionMode.NAMESPACE)

    def test_namespace_cli_refuses_without_launch_and_replaces_old_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            output.write_text('{"verdict":"PASS","run_id":"old"}')
            with patch("mcp_behavior.runner.StdioClient") as client, \
                 patch.object(Runner, "preflight") as fixture_probe, \
                 patch("mcp_behavior.runner.build_fixture") as fixture_builder, \
                 contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = main(["run", "--config", str(ROOT / "examples/reference.json"),
                             "--output", str(output), "--isolation", "namespace"])
            client.assert_not_called()
            fixture_probe.assert_not_called()
            fixture_builder.assert_not_called()
            summary = json.loads(stdout.getvalue())
            report = json.loads(output.read_text())
            self.assertEqual(code, 2)
            self.assertEqual(report["verdict"], "INCOMPLETE")
            self.assertEqual(report["state"], "FINISHED")
            self.assertEqual(report["run_id"], summary["run_id"])
            self.assertNotEqual(report["run_id"], "old")
            self.assertEqual(report["case_count"], 0)
            self.assertEqual(report["execution"]["mode"], "namespace")
            self.assertFalse(report["isolation"]["preflight_ok"])
            self.assertTrue(any("launcher_implemented" in reason for reason in report["isolation"]["reasons"]))

    def test_native_cli_reports_backend_without_containment_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["run", "--config", str(ROOT / "examples/reference.json"),
                             "--output", str(output), "--isolation", "native"])
            report = json.loads(output.read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["lanes"], {"readiness": "PASS", "security": "INCOMPLETE"})
        self.assertEqual(report["execution"]["mode"], "native")
        self.assertTrue(report["isolation"]["preflight_ok"])
        self.assertEqual(report["isolation"]["requested_policy"]["memory_mib"], report["limits"]["memory_mib"])
        self.assertEqual(report["isolation"]["requested_policy"]["cpu_seconds"], report["limits"]["cpu_seconds"])
        containment = next(c for c in report["checks"] if c["id"] == "execution_containment")
        self.assertEqual(containment["status"], "UNKNOWN")
        self.assertEqual(report["case_count"], 14)

    def test_direct_runner_namespace_never_starts_native_subject(self) -> None:
        config = Config.load(ROOT / "examples/reference.json")
        with patch("mcp_behavior.runner.StdioClient") as client, \
             patch.object(Runner, "preflight") as fixture_probe, \
             patch("mcp_behavior.runner.build_fixture") as fixture_builder:
            report = Runner(config, isolation_backend=NamespaceBackend()).run()
        client.assert_not_called()
        fixture_probe.assert_not_called()
        fixture_builder.assert_not_called()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["case_count"], 0)
        self.assertEqual(report["execution"]["mode"], "namespace")
        # Calling the per-fixture API must enforce the same launch gate.
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_fixture(Path(tmp), "normal", config.profile.supported_suffixes)
            runner = Runner(config, isolation_backend=NamespaceBackend())
            with patch("mcp_behavior.runner.StdioClient") as client, \
                 patch.object(Runner, "preflight") as fixture_probe:
                runner.execute(fixture)
        client.assert_not_called()
        fixture_probe.assert_not_called()
        self.assertTrue(any(c.id == "normal.profile_evidence" and c.status == "UNKNOWN" for c in runner.checks))

    def test_preflight_exception_is_incomplete_and_cannot_leave_old_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            output.write_text('{"verdict":"PASS","run_id":"old"}')
            with patch.object(NamespaceBackend, "preflight", side_effect=OSError("probe blocked")), \
                 patch("mcp_behavior.runner.StdioClient") as client, \
                 contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = main(["run", "--config", str(ROOT / "examples/reference.json"),
                             "--output", str(output), "--isolation", "namespace"])
            report = json.loads(output.read_text())
        client.assert_not_called()
        self.assertEqual(code, 2)
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["run_id"], json.loads(stdout.getvalue())["run_id"])
        self.assertIn("probe blocked", json.loads(stdout.getvalue())["harness_error"])

    def test_preflight_mode_must_match_backend(self) -> None:
        config = Config.load(ROOT / "examples/reference.json")
        with self.assertRaises(HarnessError):
            Runner(config, isolation_backend=NamespaceBackend(),
                   isolation_preflight=PreflightResult(mode=ExecutionMode.NATIVE, ok=True))

    def test_successful_feature_probe_cannot_waive_missing_namespace_launcher(self) -> None:
        config = Config.load(ROOT / "examples/reference.json")
        with patch("mcp_behavior.runner.StdioClient") as client, \
             patch.object(Runner, "preflight") as fixture_probe, \
             patch("mcp_behavior.runner.build_fixture") as fixture_builder:
            report = Runner(config, isolation_backend=NamespaceBackend(),
                            isolation_preflight=PreflightResult(mode=ExecutionMode.NAMESPACE, ok=True)).run()
        client.assert_not_called()
        fixture_probe.assert_not_called()
        fixture_builder.assert_not_called()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["case_count"], 0)
        self.assertTrue(report["isolation"]["preflight_ok"])
        self.assertFalse(report["isolation"]["subject_launch_supported"])
        containment = next(c for c in report["checks"] if c["id"] == "execution_containment")
        self.assertEqual(containment["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
