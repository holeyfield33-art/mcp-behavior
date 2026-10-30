from __future__ import annotations

import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_behavior import supervisor
from mcp_behavior.supervisor import CgroupScope, SupervisorLimits, counters, run_cgroup_probe


@contextlib.contextmanager
def control_contract(ignore_limit=None, stuck=False, deny_kill=False):
    """Ordinary-file model for control-contract failure tests, not kernel proof."""
    with tempfile.TemporaryDirectory() as tmp:
        parent = Path(tmp)
        for name, value in {"cgroup.controllers": "cpu memory pids", "cgroup.subtree_control": "cpu memory pids",
                            "cgroup.kill": ""}.items():
            (parent / name).write_text(value)
        writes = []
        mkdir, rmdir = os.mkdir, os.rmdir
        defaults = {"cgroup.type": "domain", "cgroup.procs": "", "cgroup.events": "populated 0\nfrozen 0",
                    "cgroup.kill": "", "cpu.stat": "usage_usec 0", "memory.events": "oom_kill 0",
                    "pids.events": "max 0"}
        defaults.update({name: "max" for name in SupervisorLimits().controls()})

        def make(name, mode=0o777, *, dir_fd=None):
            mkdir(name, mode, dir_fd=dir_fd)
            leaf = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / name
            for control, value in defaults.items():
                (leaf / control).write_text(value)

        def write(fd, name, value):
            leaf = Path(os.readlink(f"/proc/self/fd/{fd}"))
            writes.append((leaf, name, value))
            if name == "cgroup.kill":
                if deny_kill:
                    raise PermissionError("kill rejected")
                if not stuck:
                    (leaf / "cgroup.procs").write_text("")
                    (leaf / "cgroup.events").write_text("populated 0\nfrozen 0")
            elif name != ignore_limit:
                (leaf / name).write_text(value)

        def remove(name, *, dir_fd=None):
            leaf = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / name
            for control in leaf.iterdir():
                control.unlink()
            rmdir(name, dir_fd=dir_fd)

        with patch.object(supervisor, "cgroup2_filesystem", return_value=True), \
             patch.object(supervisor.os, "mkdir", side_effect=make), \
             patch.object(supervisor.os, "rmdir", side_effect=remove), \
             patch.object(supervisor, "_write", side_effect=write):
            yield parent, writes


class SupervisorTests(unittest.TestCase):
    def test_no_delegation_is_explicit_and_starts_nothing(self):
        with patch.object(supervisor.subprocess, "Popen") as child:
            result = run_cgroup_probe(None, SupervisorLimits())
        child.assert_not_called()
        self.assertFalse(result.ok)
        self.assertIn("--cgroup-parent", result.detail)

    def test_fake_cgroup_files_on_ordinary_filesystem_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            for control in ("cgroup.controllers", "cgroup.subtree_control", "cgroup.kill"):
                (parent / control).write_text("cpu memory pids")
            before = set(parent.iterdir())
            with patch.object(supervisor.subprocess, "Popen") as child:
                result = run_cgroup_probe(parent, SupervisorLimits())
            child.assert_not_called()
            self.assertEqual(set(parent.iterdir()), before)
        self.assertFalse(result.ok)
        self.assertIn("genuine cgroup-v2", result.detail)
        self.assertTrue(result.evidence["cleanup"]["ok"])

    def test_missing_relative_and_symlinked_parents_refuse_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            alias = parent / "alias"
            alias.symlink_to(parent, target_is_directory=True)
            for path in (parent / "missing", Path("relative"), alias):
                with self.subTest(path=path), patch.object(supervisor.subprocess, "Popen") as child:
                    result = run_cgroup_probe(path, SupervisorLimits())
                child.assert_not_called()
                self.assertFalse(result.ok)

    def test_limits_are_bounded_and_booleans_are_not_integers(self):
        for limits in (SupervisorLimits(memory_mib=True), SupervisorLimits(memory_mib=0),
                       SupervisorLimits(cpu_seconds=0), SupervisorLimits(max_pids=2)):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                limits.controls()

    def test_blocked_pidfd_prerequisite_cannot_start_a_helper(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(supervisor.os, "pidfd_open", side_effect=OSError("pidfd denied")), \
             patch.object(supervisor.subprocess, "Popen") as child:
            result = run_cgroup_probe(Path(tmp), SupervisorLimits())
        child.assert_not_called()
        self.assertFalse(result.ok)
        self.assertIn("pidfd denied", result.detail)
        self.assertFalse(result.evidence["cleanup"]["created"])

    def test_kernel_controls_and_parent_remain_separate(self):
        with control_contract() as (parent, writes):
            before = {p.name: p.read_text() for p in parent.iterdir()}
            scope = CgroupScope(parent, SupervisorLimits(memory_mib=128, cpu_seconds=3, max_pids=8))
            try:
                scope.prepare()
                self.assertEqual(scope.effective["memory.max"], str(128 * 1024**2))
                self.assertEqual(scope.effective["memory.swap.max"], "0")
                self.assertEqual(scope.effective["pids.max"], "8")
                self.assertEqual(scope.effective["cpu.max"], "100000 100000")
                self.assertTrue(all(path == scope.path for path, _, _ in writes))
            finally:
                cleanup = scope.cleanup()
            self.assertTrue(cleanup["ok"], cleanup)
            self.assertTrue(cleanup["removed"])
            self.assertEqual({p.name: p.read_text() for p in parent.iterdir()}, before)

    def test_missing_controller_is_never_enabled_automatically(self):
        with control_contract() as (parent, writes):
            (parent / "cgroup.subtree_control").write_text("memory pids")
            scope = CgroupScope(parent, SupervisorLimits())
            try:
                with self.assertRaisesRegex(ValueError, "already be enabled"):
                    scope.prepare()
            finally:
                cleanup = scope.cleanup()
            self.assertEqual(writes, [])
            self.assertTrue(cleanup["ok"])
            self.assertFalse(scope.created)

    def test_missing_cgroup_kill_refuses_before_creating_leaf(self):
        with control_contract() as (parent, writes):
            (parent / "cgroup.kill").unlink()
            scope = CgroupScope(parent, SupervisorLimits())
            try:
                with self.assertRaises(FileNotFoundError):
                    scope.prepare()
            finally:
                scope.cleanup()
            self.assertFalse(scope.created)
            self.assertEqual(writes, [])

    def test_limit_readback_mismatch_refuses(self):
        with control_contract(ignore_limit="memory.max") as (parent, writes):
            scope = CgroupScope(parent, SupervisorLimits())
            try:
                with self.assertRaisesRegex(ValueError, "readback mismatch"):
                    scope.prepare()
            finally:
                cleanup = scope.cleanup()
            self.assertTrue(cleanup["ok"], cleanup)

    def test_missing_or_malformed_kernel_usage_cannot_satisfy_budget(self):
        for control, raw in (("cpu.stat", "user_usec 0"), ("memory.events", "oom 0"),
                             ("pids.events", ""), ("cpu.stat", "usage_usec 0\nusage_usec 0")):
            with self.subTest(control=control, raw=raw), control_contract() as (parent, _):
                scope = CgroupScope(parent, SupervisorLimits())
                try:
                    scope.prepare()
                    (scope.path / control).write_text(raw)
                    with self.assertRaises(ValueError):
                        scope.check_budget()
                finally:
                    self.assertTrue(scope.cleanup()["ok"])

    def test_resource_limit_interventions_are_recordable_failures(self):
        for control, raw in (("cpu.stat", "usage_usec 1000001"), ("memory.events", "oom_kill 1"),
                             ("pids.events", "max 1")):
            with self.subTest(control=control), control_contract() as (parent, _):
                scope = CgroupScope(parent, SupervisorLimits(cpu_seconds=1))
                try:
                    scope.prepare()
                    (scope.path / control).write_text(raw)
                    with self.assertRaises(ValueError):
                        scope.check_budget()
                finally:
                    self.assertTrue(scope.cleanup()["ok"])

    def test_populated_subtree_and_inconsistent_membership_block_cleanup(self):
        for events, members in (("populated 1\nfrozen 0", ""), ("populated 0\nfrozen 0", "123")):
            with self.subTest(events=events), control_contract(stuck=True) as (parent, _):
                scope = CgroupScope(parent, SupervisorLimits())
                scope.prepare()
                (scope.path / "cgroup.events").write_text(events)
                (scope.path / "cgroup.procs").write_text(members)
                with patch.object(supervisor, "TEARDOWN_SECONDS", 0.02):
                    cleanup = scope.cleanup()
                self.assertFalse(cleanup["ok"])
                self.assertNotIn("removed", cleanup)

    def test_failed_recursive_kill_cannot_become_cleanup_success(self):
        with control_contract(deny_kill=True) as (parent, _):
            scope = CgroupScope(parent, SupervisorLimits())
            scope.prepare()
            cleanup = scope.cleanup()
            self.assertFalse(cleanup["ok"])
            self.assertIn("kill rejected", cleanup["detail"])
            self.assertTrue(scope.path.exists())

    def test_replaced_leaf_path_is_never_removed_as_the_owned_cgroup(self):
        make = os.mkdir
        with control_contract() as (parent, _):
            scope = CgroupScope(parent, SupervisorLimits())
            scope.prepare()
            scope.path.rename(parent / "moved")
            make(scope.path)
            marker = scope.path / "replacement"
            marker.write_text("preserve")
            cleanup = scope.cleanup()
            self.assertFalse(cleanup["ok"])
            self.assertIn("identity changed", cleanup["detail"])
            self.assertEqual(marker.read_text(), "preserve")

    def test_symlinked_control_file_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outside = base / "outside"
            outside.write_text("untouched")
            controls = base / "controls"
            controls.mkdir()
            (controls / "memory.max").symlink_to(outside)
            fd = os.open(controls, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError):
                    supervisor._read(fd, "memory.max")
                with self.assertRaises(OSError):
                    supervisor._write(fd, "memory.max", "1")
            finally:
                os.close(fd)
            self.assertEqual(outside.read_text(), "untouched")

    def test_membership_failure_does_not_release_helper(self):
        # A real bootstrap child is safe here: the false membership observation
        # prevents its release, so it never forks or runs the detached phase.
        with control_contract() as (parent, _):
            releases = []
            write = os.write
            def record(fd, data):
                if data == b"G":
                    releases.append(fd)
                return write(fd, data)
            with patch.object(CgroupScope, "members", return_value=set()), \
                 patch.object(supervisor.os, "write", side_effect=record):
                result = run_cgroup_probe(parent, SupervisorLimits())
        self.assertFalse(result.ok)
        self.assertIn("before release", result.detail)
        self.assertEqual(releases, [])
        self.assertNotIn("joined_before_release", result.evidence)

    def test_invalid_counter_evidence_is_not_silently_ignored(self):
        for raw in ("usage_usec -1", "usage_usec NaN", "usage_usec 1\nusage_usec 2", "populated", "max True"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                counters(raw)

    @unittest.skipUnless(os.environ.get("MCP_BEHAVIOR_CGROUP_PARENT"),
                         "requires explicit delegated cgroup-v2 host; no live cgroup proof on this host")
    def test_live_delegated_cgroup_limits_membership_and_detached_teardown(self):
        parent = Path(os.environ["MCP_BEHAVIOR_CGROUP_PARENT"])
        result = run_cgroup_probe(parent, SupervisorLimits())
        self.assertTrue(result.ok, json.dumps(result.evidence, indent=2) + result.detail)
        self.assertTrue(result.evidence["joined_before_release"])
        self.assertTrue(result.evidence["detached_child_observed"])
        self.assertTrue(result.evidence["cleanup"]["removed"])
        self.assertEqual(result.evidence["cleanup"]["populated"], 0)


if __name__ == "__main__":
    unittest.main()
