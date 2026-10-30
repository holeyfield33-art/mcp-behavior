from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from mcp_behavior.namespace_runtime import (
    LaunchPlan,
    prepare_isolation_dirs,
    run_host_canary_probe,
    tool_preflight,
)


class NamespaceRuntimeTests(unittest.TestCase):
    def test_tool_preflight_reports_structure(self) -> None:
        result = tool_preflight()
        self.assertIn("bwrap", result.evidence)
        self.assertIn("user_ns_usable", result.evidence)
        self.assertIsInstance(result.ok, bool)
        self.assertTrue(result.detail)

    def test_prepare_isolation_dirs_writes_secrets_outside_workspace(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            host_canary, oracle_dir, _ = prepare_isolation_dirs(base, "tok")
            self.assertTrue(host_canary.is_file())
            self.assertIn("HOST_SECRET", host_canary.read_text())
            self.assertTrue((oracle_dir / "answers.json").is_file())

    def test_canary_probe_fails_closed_without_bwrap(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = base / "ws"
            ws.mkdir()
            host_canary, oracle_dir, _ = prepare_isolation_dirs(base, "x")
            plan = LaunchPlan(workspace=ws, command=["/bin/true"], host_canary=host_canary, oracle_dir=oracle_dir)
            with mock.patch("mcp_behavior.namespace_runtime.which_bwrap", return_value=None):
                probe = run_host_canary_probe(plan, "x")
            self.assertFalse(probe.ok)
            self.assertIn("bwrap", probe.detail.lower())


if __name__ == "__main__":
    unittest.main()
