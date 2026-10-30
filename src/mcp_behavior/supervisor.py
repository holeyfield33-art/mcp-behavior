"""Cgroup-v2 scope controls and fixed controller-owned helper self-test.

The helper probe never receives the configured MCP command. It prepares an explicitly
delegated child cgroup, verifies limits and membership before releasing a helper,
and verifies recursive kill/empty/removal after an intentionally detached child.
It is not run-level subject containment or a kernel stress-test certification.
"""
from __future__ import annotations

import ctypes
import json
import os
import selectors
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import strict_json
from .namespace_runtime import PROBE_ENV, ProbeResult

CGROUP2_SUPER_MAGIC = 0x63677270
CONTROL_MAX_BYTES = 32768
TEARDOWN_SECONDS = 2.0


class ResourceLimitExceeded(ValueError):
    """A valid kernel observation shows a configured budget intervention."""


@dataclass(frozen=True)
class SupervisorLimits:
    memory_mib: int = 256
    cpu_seconds: int = 30
    max_pids: int = 64

    def controls(self) -> dict[str, str]:
        for value, lower, upper in ((self.memory_mib, 64, 4096), (self.cpu_seconds, 1, 120),
                                    (self.max_pids, 4, 256)):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("invalid cgroup resource budget")
        return {"memory.max": str(self.memory_mib * 1024**2), "memory.swap.max": "0",
                "pids.max": str(self.max_pids), "cpu.max": "100000 100000",
                "memory.oom.group": "1", "cgroup.max.descendants": "0"}


def cgroup2_filesystem(fd: int) -> bool:
    """Check the kernel filesystem type, not file names in an ordinary directory."""
    buffer = (ctypes.c_long * 64)()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(fd, ctypes.byref(buffer)) != 0:
        raise OSError(ctypes.get_errno(), "cannot identify delegated cgroup filesystem")
    return buffer[0] == CGROUP2_SUPER_MAGIC


def _read(fd: int, name: str) -> str:
    control = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        raw = os.read(control, CONTROL_MAX_BYTES + 1)
        if len(raw) > CONTROL_MAX_BYTES:
            raise ValueError("cgroup control evidence exceeds its byte bound")
        return raw.decode("ascii").strip()
    finally:
        os.close(control)


def _write(fd: int, name: str, value: str) -> None:
    control = os.open(name, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
    try:
        data = (value + "\n").encode("ascii")
        if os.write(control, data) != len(data):
            raise OSError("short cgroup control write")
    finally:
        os.close(control)


def counters(raw: str) -> dict[str, int]:
    result = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[0] in result or not parts[1].isascii() or not parts[1].isdigit():
            raise ValueError("invalid or duplicate cgroup counter evidence")
        result[parts[0]] = int(parts[1])
    return result


class CgroupScope:
    """Own only a newly created leaf; never alter parent controllers or limits."""

    def __init__(self, parent: Path, limits: SupervisorLimits):
        self.parent, self.limits = parent, limits
        self.name = "mcp-behavior-" + uuid.uuid4().hex
        self.path = parent / self.name
        self.parent_fd = self.fd = -1
        self.created = False
        self.effective: dict[str, str] = {}

    def prepare(self) -> None:
        expected = self.limits.controls()
        if not self.parent.is_absolute() or self.parent.resolve(strict=True) != self.parent:
            raise ValueError("cgroup parent must be an absolute canonical path without symlink components")
        self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        if not cgroup2_filesystem(self.parent_fd):
            raise ValueError("cgroup parent is not on a genuine cgroup-v2 filesystem")
        required = {"cpu", "memory", "pids"}
        if not required <= set(_read(self.parent_fd, "cgroup.controllers").split()):
            raise ValueError("delegated cgroup lacks cpu, memory or pids controllers")
        if not required <= set(_read(self.parent_fd, "cgroup.subtree_control").split()):
            raise ValueError("cpu, memory and pids must already be enabled by the delegating host")
        # Missing kernel support must refuse before creating a disposable leaf.
        os.stat("cgroup.kill", dir_fd=self.parent_fd, follow_symlinks=False)
        os.mkdir(self.name, mode=0o700, dir_fd=self.parent_fd)
        self.created = True
        self.fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                          dir_fd=self.parent_fd)
        if _read(self.fd, "cgroup.type") != "domain":
            raise ValueError("supervisor requires a domain cgroup")
        kill_fd = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.fd)
        os.close(kill_fd)
        if self.members() or self.events().get("populated") != 0:
            raise ValueError("new supervisor cgroup was not empty")
        for name, value in expected.items():
            _write(self.fd, name, value)
            observed = " ".join(_read(self.fd, name).split())
            if observed != value:
                raise ValueError(f"cgroup limit readback mismatch for {name}")
            self.effective[name] = observed

    def events(self) -> dict[str, int]:
        events = counters(_read(self.fd, "cgroup.events"))
        if events.get("populated") not in (0, 1) or events.get("frozen") not in (0, 1):
            raise ValueError("missing or invalid populated/frozen evidence")
        return events

    def members(self) -> set[int]:
        raw = _read(self.fd, "cgroup.procs").split()
        if any(not value.isascii() or not value.isdigit() or int(value) <= 0 for value in raw):
            raise ValueError("invalid cgroup process membership")
        return {int(value) for value in raw}

    def usage(self) -> dict[str, Any]:
        cpu = counters(_read(self.fd, "cpu.stat"))
        memory = counters(_read(self.fd, "memory.events"))
        pids = counters(_read(self.fd, "pids.events"))
        if "usage_usec" not in cpu or "oom_kill" not in memory or "max" not in pids:
            raise ValueError("incomplete aggregate resource evidence")
        return {"cpu": cpu, "memory": memory, "pids": pids}

    def check_budget(self) -> dict[str, Any]:
        usage = self.usage()
        if usage["cpu"]["usage_usec"] > self.limits.cpu_seconds * 1_000_000:
            raise ResourceLimitExceeded("supervised process exceeded sampled aggregate CPU budget")
        if usage["memory"]["oom_kill"] or usage["pids"]["max"]:
            raise ResourceLimitExceeded("supervised process hit a memory or PID resource limit")
        return usage

    def cleanup(self) -> dict[str, Any]:
        result: dict[str, Any] = {"ok": False, "created": self.created, "path": str(self.path)}
        try:
            if not self.created:
                result.update(ok=True, detail="no child cgroup was created")
                return result
            if self.fd < 0:
                raise OSError("child cgroup could not be inspected for cleanup")
            # A failed kill stays an observer failure even if a fallback kills a helper.
            _write(self.fd, "cgroup.kill", "1")
            deadline = time.monotonic() + TEARDOWN_SECONDS
            while True:
                events, members = self.events(), self.members()
                if events["populated"] == 0 and not members:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("cgroup remained populated after recursive kill")
                time.sleep(0.01)
            original = os.fstat(self.fd)
            current = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("supervisor cgroup path identity changed")
            os.rmdir(self.name, dir_fd=self.parent_fd)
            result.update(ok=True, detail="recursive kill observed empty; owned leaf removed",
                          populated=events["populated"], remaining_pids=sorted(members), removed=True)
        except (OSError, ValueError) as exc:
            result["detail"] = str(exc)
        finally:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
            if self.parent_fd >= 0:
                os.close(self.parent_fd)
                self.parent_fd = -1
        return result


# No profile/server code is accepted here. The fixed helper joins before release,
# then deliberately detaches a child so a process-group kill alone is insufficient.
_HELPER = r'''
import json, os, sys, time
group_fd, ready_fd, release_fd = map(int, sys.argv[1:4])
os.write(group_fd, str(os.getpid()).encode())
os.close(group_fd)
os.write(ready_fd, b"J")
os.close(ready_fd)
if os.read(release_fd, 1) != b"G":
    raise SystemExit(3)
os.close(release_fd)
child = os.fork()
if child:
    os._exit(0)
os.setsid()
print(json.dumps({"nonce": sys.argv[4], "child_pid": os.getpid()}), flush=True)
time.sleep(30)
'''


def _wait_ready(proc: subprocess.Popen, ready: int, deadline: float) -> None:
    with selectors.DefaultSelector() as selector:
        selector.register(ready, selectors.EVENT_READ)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not selector.select(remaining) or os.read(ready, 2) != b"J":
            raise TimeoutError("helper did not confirm cgroup attachment before release")
    if proc.poll() is not None:
        raise ValueError("helper exited before the release gate")


def _child_evidence(proc: subprocess.Popen, scope: CgroupScope, nonce: str, deadline: float,
                    child_handles: list[int]) -> dict[str, Any]:
    raw = bytearray()
    with selectors.DefaultSelector() as selector:
        for stream in (proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while b"\n" not in raw:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("supervisor helper exceeded its wall deadline")
            scope.check_budget()
            for key, _ in selector.select(min(remaining, 0.02)):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selector.unregister(key.fileobj)
                elif key.fileobj == proc.stderr:
                    raise ValueError("supervisor helper emitted unexpected stderr")
                else:
                    raw.extend(data)
                    if len(raw) > 4096:
                        raise ValueError("supervisor helper exceeded its output byte limit")
    payload = strict_json(raw.decode("utf-8"))
    if (not isinstance(payload, dict) or set(payload) != {"nonce", "child_pid"}
            or payload["nonce"] != nonce or type(payload["child_pid"]) is not int or payload["child_pid"] <= 0):
        raise ValueError("supervisor helper evidence schema or nonce mismatch")
    child = payload["child_pid"]
    # This is a fixed trusted helper, never server-supplied PID evidence. Retain
    # a handle even if the following external membership observation fails.
    child_handles.append(os.pidfd_open(child))
    if child == proc.pid or child not in scope.members() or os.getsid(child) != child:
        raise ValueError("detached helper child was not externally observed in the owned cgroup")
    proc.wait(timeout=max(0.001, deadline - time.monotonic()))
    if proc.returncode != 0:
        raise ValueError("supervisor helper parent did not exit normally")
    return payload


def run_cgroup_probe(parent: Path | None, limits: SupervisorLimits) -> ProbeResult:
    evidence: dict[str, Any] = {"scope": "fixed detached-helper self-test; not subject-run containment",
                                "requested": vars(limits), "parent": str(parent) if parent is not None else None}
    if parent is None:
        return ProbeResult(False, "no delegated cgroup parent configured; supply --cgroup-parent", evidence)
    scope = CgroupScope(parent, limits)
    proc = None
    child_handles: list[int] = []
    descriptors: list[int] = []
    success = False
    detail = "supervisor evidence incomplete"
    try:
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise ValueError("pidfd support is required for fixed-helper fallback cleanup")
        pidfd = os.pidfd_open(os.getpid())
        os.close(pidfd)
        scope.prepare()
        evidence["effective_limits"] = scope.effective
        group_fd = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=scope.fd)
        ready_r, ready_w = os.pipe()
        release_r, release_w = os.pipe()
        descriptors.extend([group_fd, ready_r, ready_w, release_r, release_w])
        nonce = uuid.uuid4().hex
        deadline = time.monotonic() + 3.0
        proc = subprocess.Popen([sys.executable, "-I", "-S", "-c", _HELPER, str(group_fd),
                                 str(ready_w), str(release_r), nonce], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PROBE_ENV,
                                close_fds=True, pass_fds=(group_fd, ready_w, release_r), start_new_session=True)
        for fd in (group_fd, ready_w, release_r):
            os.close(fd)
            descriptors.remove(fd)
        _wait_ready(proc, ready_r, deadline)
        if scope.members() != {proc.pid}:
            raise ValueError("controller could not verify sole helper membership before release")
        scope.check_budget()
        os.write(release_w, b"G")
        evidence["joined_before_release"] = True
        payload = _child_evidence(proc, scope, nonce, deadline, child_handles)
        evidence.update(helper=payload, usage=scope.check_budget(), detached_child_observed=True)
        success = True
        detail = "limits read back, helper joined before release, detached child externally observed"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        detail = f"cgroup supervisor probe unavailable or failed: {exc}"
    finally:
        # Preserve fallback handles even if a helper failed before printing its
        # PID. Membership comes from the owned kernel cgroup, never a server.
        if scope.fd >= 0 and proc is not None:
            try:
                for pid in sorted(scope.members())[:limits.max_pids]:
                    if pid != proc.pid:
                        try:
                            child_handles.append(os.pidfd_open(pid))
                        except ProcessLookupError:
                            pass
            except (OSError, ValueError) as exc:
                evidence["fallback_observation_error"] = str(exc)
        cleanup = scope.cleanup()
        evidence["cleanup"] = cleanup
        for child_pidfd in child_handles:
            try:
                if not cleanup["ok"]:
                    signal.pidfd_send_signal(child_pidfd, signal.SIGKILL)
            except OSError as exc:
                if not isinstance(exc, ProcessLookupError):
                    success = False
                    detail += f"; helper fallback cleanup failed: {exc}"
            finally:
                os.close(child_pidfd)
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=1)
            proc.stdout.close()
            proc.stderr.close()
        for fd in descriptors:
            os.close(fd)
    if not cleanup["ok"]:
        success = False
        detail += "; cleanup unverified: " + cleanup["detail"]
    return ProbeResult(success, detail, evidence)
