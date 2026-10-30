from __future__ import annotations

import copy
import dataclasses
import json
import os
import tempfile
import unittest
from pathlib import Path

from mcp_behavior.config import Config, Limits, Profile, strict_json
from mcp_behavior.fixtures import build_fixture, snapshot
from mcp_behavior.model import Check, ContractError, HarnessError, Status, verdict
from mcp_behavior.oracle import Answer, at, decode, observe, relative_record, repeatable_payload, reasoned_error
from mcp_behavior.transport import Frame

ROOT = Path(__file__).resolve().parents[1]


class OracleTests(unittest.TestCase):
    def test_verdict_truth_table(self):
        for states, expected in (([], "INCOMPLETE"), ([Status.PASS], "PASS"),
                                 ([Status.UNKNOWN], "INCOMPLETE"), ([Status.NA], "INCOMPLETE"),
                                 ([Status.PASS, Status.UNKNOWN], "INCOMPLETE"),
                                 ([Status.FAIL, Status.UNKNOWN], "FAIL")):
            with self.subTest(states=states):
                self.assertEqual(verdict([Check(str(i), "r", s, "reason") for i, s in enumerate(states)]), expected)

    def test_optional_scope_exclusion_cannot_supply_missing_required_checks(self):
        self.assertEqual(verdict([Check("agent", "agent_run", Status.NA, "not run", required=False)]), "INCOMPLETE")

    def test_json_duplicate_keys_nonfinite_and_pointer_escaping(self):
        for raw in ('{"a":1,"a":2}', '{"n":NaN}', '{"n":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(raw)
        self.assertEqual(at({"a/b": {"~": [3]}}, "/a~1b/~0/0"), 3)
        for pointer in ("/x", "/a~1b/~0/00", "/a~1b/~0/-1"):
            with self.assertRaises(ContractError):
                at({"a/b": {"~": [3]}}, pointer)

    def test_boolean_cannot_impersonate_numeric_limit(self):
        for raw in ({"max_result_bytes": True}, {"timeout_seconds": float("nan")}, {"max_frame_bytes": 1}, {"typo": 5}):
            with self.assertRaises(HarnessError):
                Limits.parse(raw)

    def test_profile_cannot_ignore_behavior_fields_or_unknown_keys(self):
        profile = json.loads((ROOT / "examples/reference.json").read_text())["profile"]
        for change in ({"ignored_timestamps": ["/processed"]}, {"ignored_timestamps": [""]},
                       {"relative_paths": "server-cwd"}, {"supported_suffixes": [".py", ".py"]},
                       {"arguments": {"path": "override"}}, {"unknowable": True}):
            with self.subTest(change=change), self.assertRaises(HarnessError):
                Profile.parse({**profile, **change})

    def test_mapped_boolean_completion_and_counts_need_exact_types(self):
        profile = Config.load(ROOT / "examples/reference.json").profile
        base = {"processed": [], "excluded": [], "failed": [], "complete": True,
                "counts": {"processed": 0, "excluded": 0, "failed": 0}}
        for change in ({"complete": 1}, {"counts": {"processed": False, "excluded": 0, "failed": 0}}):
            with self.assertRaises(ContractError):
                observe({**base, **change}, profile, Path("/fixture"))

    def test_overlapping_paths_and_empty_reason_are_rejected(self):
        profile = Config.load(ROOT / "examples/reference.json").profile
        base = {"processed": [{"path": "a.py", "sha256": "0" * 64}],
                "excluded": [{"path": "a.py", "reason": "excluded"}], "failed": [], "complete": True,
                "counts": {"processed": 1, "excluded": 1, "failed": 0}}
        with self.assertRaises(ContractError):
            observe(base, profile, Path("/fixture"))
        base["excluded"][0] = {"path": "b.bin", "reason": ""}
        with self.assertRaises(ContractError):
            observe(base, profile, Path("/fixture"))

    def test_outside_paths_parent_traversal_and_backslashes_rejected(self):
        for value in ("../a.py", "/fixture-other/a.py", "a/../b.py", "a\\b.py", "", "."):
            with self.subTest(value=value), self.assertRaises(ContractError):
                relative_record(value, Path("/fixture"))
        self.assertEqual(relative_record("/fixture/nested/a.py", Path("/fixture")), "nested/a.py")

    def test_structured_and_text_json_cannot_disagree(self):
        message = {"result": {"structuredContent": {"a": 1}, "content": [{"type": "text", "text": '{"a":2}'}]}}
        with self.assertRaises(ContractError):
            decode(Frame(message, 100, "0" * 64))

    def test_both_mcp_error_channels_preserve_the_reason(self):
        rpc = {"error": {"code": -32602, "message": "invalid path", "data": {"reason": "not a directory"}}}
        answer = decode(Frame(rpc, 100, "0" * 64))
        self.assertTrue(answer.error)
        self.assertIn("not a directory", answer.message)
        tool = {"result": {"isError": True, "content": [{"type": "text", "text": "path is not a directory"}],
                           "structuredContent": {"complete": True}}}
        answer = decode(Frame(tool, 100, "0" * 64))
        self.assertTrue(answer.payload["complete"])

    def test_echoing_missing_filename_does_not_supply_a_cause(self):
        error = Answer(True, "Error: missing_abcd", None, 40, "0" * 64)
        self.assertFalse(reasoned_error(error, "/fixture/missing_abcd", "missing", "path"))

    def test_nested_timestamp_arrays_are_narrowly_normalized(self):
        raw = json.loads((ROOT / "examples/reference.json").read_text())["profile"]
        raw["ignored_timestamps"] = ["/plans/*/generated_at"]
        profile = Profile.parse(raw)
        a = {"processed": [], "excluded": [], "failed": [], "plans": [{"generated_at": "2026-10-29T00:00:00Z", "sink": "open"}]}
        b = copy.deepcopy(a)
        b["plans"][0]["generated_at"] = "2026-10-29T01:00:00Z"
        self.assertEqual(repeatable_payload(a, profile), repeatable_payload(b, profile))
        b["plans"][0]["sink"] = "exec"
        self.assertNotEqual(repeatable_payload(a, profile), repeatable_payload(b, profile))

    def test_repeatability_normalizes_only_known_sets_and_valid_timestamps(self):
        profile = Config.load(ROOT / "examples/reference.json").profile
        a = {"processed": [{"path": "b"}, {"path": "a"}], "excluded": [], "failed": [],
             "generated_at": "2026-10-29T00:00:00+00:00", "ordered": [1, 2]}
        b = copy.deepcopy(a)
        b["processed"].reverse()
        b["generated_at"] = "2026-10-29T01:00:00Z"
        self.assertEqual(repeatable_payload(a, profile), repeatable_payload(b, profile))
        b["ordered"].reverse()
        self.assertNotEqual(repeatable_payload(a, profile), repeatable_payload(b, profile))
        b["generated_at"] = "not-a-time"
        with self.assertRaises(ContractError):
            repeatable_payload(b, profile)

    def test_snapshot_does_not_follow_symlink_loop_or_open_fifo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "loop").symlink_to(root, target_is_directory=True)
            os.mkfifo(root / "blocking.py")
            result = snapshot(root)
            self.assertTrue(result["blocking.py"]["special"])
            self.assertEqual(result["loop"]["target"], str(root))
            self.assertEqual(len(result), 3)


if __name__ == "__main__":
    unittest.main()
