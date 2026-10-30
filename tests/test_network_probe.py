from __future__ import annotations

import errno
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_behavior import network_probe as network
from mcp_behavior.namespace_runtime import LaunchPlan, ProbeResult, prepare_isolation_dirs


class NetworkProbeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        workspace = self.base / "ws"
        workspace.mkdir()
        canary, oracle, _ = prepare_isolation_dirs(self.base, "network")
        self.plan = LaunchPlan(workspace, [], canary, oracle)
        self.tools = ProbeResult(True, "candidate tools", {"bwrap": "/test/bwrap"})
        self.capture = network._capture_probe

    def candidate(self, isolated):
        def capture(command, cwd):
            # Host positive controls always use real subprocesses and listeners.
            if command[0] == sys.executable:
                return self.capture(command, cwd)
            return isolated(command, cwd)
        with patch.object(network, "tool_preflight", return_value=self.tools), \
             patch.object(network, "_capture_probe", side_effect=capture):
            return network.run_network_probe(self.plan, "network")

    def denied(self, command, cwd):
        nonce = command[-2]
        payload = {"nonce": nonce, "phase": "isolated", "results": {
            label: {"connected": False, "errno": errno.ECONNREFUSED} for label in ("ipv4", "ipv6")}}
        return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode(), b"")

    def test_complete_endpoint_contract_requires_real_positive_controls(self):
        result = self.candidate(self.denied)
        self.assertTrue(result.ok, result)
        self.assertEqual(len(result.evidence["observer"]["messages"]), 2)
        self.assertEqual(result.evidence["observer"]["errors"], [])
        self.assertIn("other egress remains ungraded", result.detail)
        self.assertIn("no general or run-level", result.evidence["scope"])

    def test_host_network_negative_control_is_detected_by_external_listener(self):
        def host_view(command, cwd):
            split = command.index("--")
            return self.capture([sys.executable, *command[split + 2:]], cwd)
        result = self.candidate(host_view)
        self.assertFalse(result.ok)
        self.assertIn("external observer received isolated traffic", result.detail)
        self.assertEqual(len(result.evidence["observer"]["messages"]), 4)

    def test_lying_helper_cannot_hide_externally_observed_traffic(self):
        def lie_after_connect(command, cwd):
            split = command.index("--")
            observed = self.capture([sys.executable, *command[split + 2:]], cwd)
            self.assertEqual(observed.returncode, 0)
            return self.denied(command, cwd)
        result = self.candidate(lie_after_connect)
        self.assertFalse(result.ok)
        self.assertIn("external observer", result.detail)

    def test_unavailable_tools_do_not_start_listeners_or_helpers(self):
        with patch.object(network, "tool_preflight", return_value=ProbeResult(False, "bwrap missing")), \
             patch.object(network.EndpointObserver, "start") as listener, \
             patch.object(network, "_capture_probe") as capture:
            result = network.run_network_probe(self.plan, "network")
        listener.assert_not_called()
        capture.assert_not_called()
        self.assertFalse(result.ok)

    def test_listener_failure_cannot_pass(self):
        with patch.object(network, "tool_preflight", return_value=self.tools), \
             patch.object(network.EndpointObserver, "start", side_effect=OSError("no IPv6 socket")), \
             patch.object(network, "_capture_probe") as capture:
            result = network.run_network_probe(self.plan, "network")
        capture.assert_not_called()
        self.assertFalse(result.ok)
        self.assertIn("IPv6", result.detail)

    def test_missing_positive_control_receipts_cannot_pass(self):
        original = network.EndpointObserver.snapshot
        def omit(observer):
            result = original(observer)
            result["messages"] = []
            return result
        with patch.object(network.EndpointObserver, "snapshot", omit):
            result = self.candidate(self.denied)
        self.assertFalse(result.ok)
        self.assertIn("positive controls", result.detail)

    def test_invalid_or_incomplete_helper_evidence_cannot_pass(self):
        for raw in (b"{}", b"[]", b"NaN", b"\xff", b'{"nonce":"a","nonce":"b"}'):
            def malformed(command, cwd):
                return subprocess.CompletedProcess(command, 0, raw, b"")
            with self.subTest(raw=raw):
                self.assertFalse(self.candidate(malformed).ok)

    def test_nonzero_exit_timeout_and_cutoff_remain_failed_preconditions(self):
        def failed(command, cwd):
            return subprocess.CompletedProcess(command, 1, b"", b"operation not permitted")
        result = self.candidate(failed)
        self.assertFalse(result.ok)
        self.assertIn("exit 1", result.detail)
        for error in (subprocess.TimeoutExpired("probe", 1), ValueError("output byte limit")):
            def interrupted(command, cwd):
                raise error
            with self.subTest(error=error):
                self.assertFalse(self.candidate(interrupted).ok)

    def test_observer_shutdown_failure_cannot_pass(self):
        original = network.EndpointObserver.close
        def incomplete(observer):
            original(observer)
            observer.errors.append("event coverage lost")
        with patch.object(network.EndpointObserver, "close", incomplete):
            result = self.candidate(self.denied)
        self.assertFalse(result.ok)
        self.assertIn("event coverage lost", result.detail)

    def test_duplicate_or_unrelated_observer_traffic_blocks_success(self):
        original = network.EndpointObserver.snapshot
        for duplicate in (True, False):
            def extra(observer):
                result = original(observer)
                if result["messages"]:
                    result["messages"].append(result["messages"][0] if duplicate else ("ipv4", "unrelated"))
                return result
            with self.subTest(duplicate=duplicate), patch.object(network.EndpointObserver, "snapshot", extra):
                result = self.candidate(self.denied)
            self.assertFalse(result.ok)
            self.assertIn("coverage incomplete", result.detail)

    def test_unexpected_network_error_and_wrong_nonce_cannot_prove_denial(self):
        def payload(code=errno.ECONNREFUSED):
            return {"nonce": "run", "phase": "isolated", "results": {
                label: {"connected": False, "errno": code} for label in ("ipv4", "ipv6")}}
        for body in (payload(errno.EIO), payload(True), payload()):
            raw = json.dumps(body).encode()
            with self.subTest(body=body), self.assertRaises(ValueError):
                network._results(raw, "wrong-run" if body == payload() else "run", "isolated")
        body = payload()
        del body["results"]["ipv6"]
        with self.assertRaises(ValueError):
            network._results(json.dumps(body).encode(), "run", "isolated")

    def test_observer_bounds_untrusted_frames_and_stops(self):
        observer = network.EndpointObserver()
        try:
            observer.start()
            endpoint = observer.endpoints[0]
            with socket.create_connection((endpoint["host"], endpoint["port"]), timeout=1) as connection:
                connection.sendall(b"x" * 129)
                connection.settimeout(1)
                self.assertEqual(connection.recv(1), b"")
        finally:
            observer.close()
        self.assertTrue(observer.errors)
        self.assertFalse(any(thread.is_alive() for thread in observer.threads))


if __name__ == "__main__":
    unittest.main()
