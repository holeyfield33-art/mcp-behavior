from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_behavior.cli import atomic_write, main

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_native_mode_rejects_namespace_only_cgroup_option(self):
        with patch("mcp_behavior.cli.Runner") as runner, \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(["run", "--config", "unused", "--output", "unused.json", "--native",
                  "--cgroup-parent", "/sys/fs/cgroup/delegated"])
        runner.assert_not_called()
        self.assertEqual(error.exception.code, 2)

    def test_native_execution_requires_explicit_flag(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(["run", "--config", "unused", "--output", "unused.json"])
        self.assertEqual(error.exception.code, 2)

    def test_interrupted_run_overwrites_previous_pass_with_incomplete_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            output.write_text('{"verdict":"PASS"}')
            with patch("mcp_behavior.cli.Runner.run", side_effect=RuntimeError("injected oracle failure")), contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = main(["run", "--config", str(ROOT / "examples/reference.json"), "--output", str(output), "--native"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.read_text())["verdict"], "INCOMPLETE")
            self.assertEqual(json.loads(output.read_text())["run_id"], json.loads(stdout.getvalue())["run_id"])

    def test_atomic_report_does_not_follow_destination_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, alias = Path(tmp) / "target", Path(tmp) / "alias"
            target.write_text("original")
            alias.symlink_to(target)
            with self.assertRaises(Exception):
                atomic_write(alias, "changed")
            self.assertEqual(target.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
