"""Run deliberately defective servers; do not substitute mocks for the wire boundary."""
from __future__ import annotations

import dataclasses
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_behavior.config import Config, Limits
from mcp_behavior.fixtures import build_fixture
from mcp_behavior.model import Status, verdict
from mcp_behavior.runner import Runner
from mcp_behavior.oracle import Answer

ROOT = Path(__file__).resolve().parents[1]


def configuration(mode="good", timeout=1.5):
    config = Config.load(ROOT / "examples/reference.json")
    return dataclasses.replace(config, command=(*config.command, "--mode", mode),
                               limits=dataclasses.replace(config.limits, timeout_seconds=timeout))


class BehavioralTests(unittest.TestCase):
    def scenario(self, mode, name="normal", repeat=False, limits=None):
        config = configuration(mode)
        if limits is not None:
            config = dataclasses.replace(config, limits=limits)
        runner = Runner(config)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = build_fixture(Path(temporary), name, config.profile.supported_suffixes)
            runner.execute(fixture, repeat=repeat)
        self.assertFalse(runner.errors, runner.errors)
        return runner

    def assert_check(self, runner, id, status):
        selected = [c for c in runner.checks if c.id == id]
        self.assertEqual(len(selected), 1, [(c.id, c.status) for c in runner.checks])
        self.assertEqual(selected[0].status, status, selected[0])

    def test_good_server_readiness_pass_but_containment_incomplete(self):
        report = Runner(configuration()).run()
        self.assertFalse(report["harness_errors"])
        self.assertEqual(report["lanes"]["readiness"], "PASS", [c for c in report["checks"] if c["status"] not in ("PASS", "N/A")])
        self.assertEqual(report["lanes"]["security"], "INCOMPLETE")
        self.assertEqual(report["verdict"], "INCOMPLETE")
        unknown = [c["id"] for c in report["checks"] if c["status"] == "UNKNOWN"]
        self.assertEqual(unknown, ["execution_containment"])
        self.assertEqual(report["case_count"], 14)

    def test_four_original_defect_classes_are_detected(self):
        cases = [("generic_error", "missing", "missing.error_reason"),
                 ("half_scan", "normal", "normal.coverage"),
                 ("oversized", "normal", "normal.bounded_output"),
                 ("cwd_relative", "relative", "relative.path_boundary")]
        for mode, name, id in cases:
            with self.subTest(mode=mode):
                self.assert_check(self.scenario(mode, name), id, Status.FAIL)

    def test_false_complete_with_real_permission_failure(self):
        runner = self.scenario("false_complete", "unreadable")
        self.assertTrue(runner.cases[0]["preconditions"]["permission_denied_under_server_identity"])
        self.assert_check(runner, "unreadable.honest_completion", Status.FAIL)

    def test_os_denial_cannot_supply_server_boundary_credit(self):
        config = configuration()
        runner = Runner(config)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_fixture(Path(tmp), "outside", config.profile.supported_suffixes)
            runner.handle_answer(fixture, Answer(True, "outside authorized workspace root", None, 100, "0" * 64))
        self.assert_check(runner, "outside.path_precondition", Status.UNKNOWN)
        self.assertEqual(verdict([c for c in runner.checks if c.lane == "security"]), "INCOMPLETE")

    def test_mutating_read_only_tool_fails_external_snapshot(self):
        self.assert_check(self.scenario("writes"), "normal.read_only", Status.FAIL)

    def test_digest_is_checked_against_fixture_bytes(self):
        self.assert_check(self.scenario("wrong_digest"), "normal.content_correctness", Status.FAIL)

    def test_silent_truncation_is_not_a_bounded_output_pass(self):
        runner = self.scenario("silently_truncate")
        self.assert_check(runner, "normal.coverage", Status.FAIL)
        self.assert_check(runner, "normal.honest_completion", Status.FAIL)
        self.assertEqual(verdict(runner.checks), "FAIL")

    def test_duplicate_conflicting_count_and_dual_outputs_fail(self):
        for mode in ("duplicate", "bad_count", "contradictory", "bad_timestamp"):
            with self.subTest(mode=mode):
                self.assert_check(self.scenario(mode, repeat=True), "normal.response_contract", Status.FAIL)

    def test_outside_root_success_and_canary_disclosure_fail(self):
        runner = self.scenario("ignore_roots", "outside")
        self.assert_check(runner, "outside.path_boundary", Status.FAIL)
        self.assert_check(runner, "outside.wire_canary", Status.FAIL)

    def test_harness_timeout_is_a_server_failure(self):
        runner = self.scenario("slow", "special_file", limits=Limits(timeout_seconds=.3))
        self.assert_check(runner, "special_file.bounded_completion", Status.FAIL)
        self.assertEqual(verdict(runner.checks), "FAIL")

    def test_no_newline_is_bounded_before_json(self):
        runner = self.scenario("no_newline", limits=Limits(max_frame_bytes=4096, max_result_bytes=4096))
        self.assert_check(runner, "normal.bounded_output", Status.FAIL)
        failure = next(c for c in runner.checks if c.status == Status.FAIL)
        self.assertEqual(failure.evidence["failure_kind"], "frame_limit")

    def test_case_deadline_does_not_reset_between_requests(self):
        runner = self.scenario("slow_each_request", limits=Limits(timeout_seconds=.3, case_timeout_seconds=.25))
        self.assert_check(runner, "normal.bounded_completion", Status.FAIL)

    def test_suite_budget_leaves_unrun_cases_unknown(self):
        config = configuration("hang", timeout=.15)
        config = dataclasses.replace(config, limits=dataclasses.replace(config.limits, case_timeout_seconds=.3, suite_timeout_seconds=1))
        report = Runner(config).run()
        self.assertTrue(any(c["id"].endswith("suite_budget") and c["status"] == "UNKNOWN" for c in report["checks"]))
        self.assertLess(report["case_count"], 14)

    def test_malformed_id_nan_pagination_and_floods_fail(self):
        for mode, code in (("wrong_id", "response_id"), ("invalid_json", "invalid_json"),
                           ("pagination_loop", "pagination"), ("notification_flood", "message_limit"),
                           ("stderr_flood", "stderr_limit"), ("exit", "disconnect")):
            with self.subTest(mode=mode):
                runner = self.scenario(mode)
                failures = [c for c in runner.checks if c.status == Status.FAIL]
                self.assertTrue(failures)
                self.assertEqual(failures[0].evidence["failure_kind"], code)

    def test_ordinary_stderr_does_not_fail(self):
        runner = self.scenario("stderr_log")
        self.assertEqual(verdict(runner.checks), "PASS")
        self.assertGreater(runner.cases[0]["transport"]["stderr_bytes"], 0)

    def test_unsupported_features_are_incomplete_not_failed_or_passed(self):
        for mode in ("unsupported", "future_protocol", "task_only"):
            with self.subTest(mode=mode):
                runner = self.scenario(mode)
                self.assert_check(runner, "normal.profile_evidence", Status.UNKNOWN)
                self.assertEqual(verdict(runner.checks), "INCOMPLETE")

    def test_no_digest_mapping_does_not_certify_scanner_semantics(self):
        config = configuration()
        mapping = dataclasses.replace(config.profile.processed, sha256=None)
        config = dataclasses.replace(config, profile=dataclasses.replace(config.profile, processed=mapping))
        runner = Runner(config)
        with tempfile.TemporaryDirectory() as tmp:
            runner.execute(build_fixture(Path(tmp), "normal", config.profile.supported_suffixes))
        self.assert_check(runner, "normal.content_correctness", Status.UNKNOWN)
        self.assertEqual(verdict(runner.checks), "INCOMPLETE")

    def test_changed_non_timestamp_results_fail_repeatability(self):
        report = Runner(configuration("unstable")).run()
        check = next(c for c in report["checks"] if c["id"] == "repeatability")
        self.assertEqual(check["status"], "FAIL")

    def test_uncollected_evidence_and_internal_fault_never_become_pass(self):
        config = configuration()
        runner = Runner(config)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_fixture(Path(tmp), "normal", config.profile.supported_suffixes)
            with patch("mcp_behavior.runner.StdioClient", side_effect=RuntimeError("oracle failure")):
                runner.execute(fixture)
        self.assert_check(runner, "normal.harness_evidence", Status.UNKNOWN)
        self.assertEqual(verdict(runner.checks), "INCOMPLETE")
        self.assertEqual(runner.errors[0]["kind"], "RuntimeError")

    def test_error_flag_cannot_hide_a_successful_completion_claim(self):
        config = configuration()
        runner = Runner(config)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_fixture(Path(tmp), "missing", config.profile.supported_suffixes)
            runner.handle_answer(fixture, Answer(True, "path is not a directory", {"complete": True}, 100, "0" * 64))
        self.assert_check(runner, "missing.error_completion_conflict", Status.FAIL)

    def test_fixture_setup_failure_is_incomplete_without_recovery_false_failure(self):
        with patch("mcp_behavior.runner.build_fixture", side_effect=OSError("disk full")):
            report = Runner(configuration()).run()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["case_count"], 0)
        self.assertFalse(any(c["status"] == "FAIL" for c in report["checks"]))


if __name__ == "__main__":
    unittest.main()
