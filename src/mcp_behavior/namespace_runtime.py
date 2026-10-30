"""Candidate namespace layout and a bounded, controller-owned filesystem probe.

This module runs trusted probes only. Experimental subject sessions live in
subject.py and require Runner's explicit policy/probe gate. A successful standalone
probe is not a containment verdict or permission to launch a server.
"""
from __future__ import annotations

import errno
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .config import strict_json

PROBE_MAX_BYTES = 16_384  # Combined stdout/stderr, enforced before JSON decoding.
PROBE_TIMEOUT_SECONDS = 5.0
RUNTIME_PATHS = ("/usr", "/lib", "/lib64", "/bin", "/sbin")
PROBE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}


@dataclass
class LaunchPlan:
    """Candidate layout; resource values are requests, not enforced limits."""

    workspace: Path
    command: list[str]
    host_canary: Path
    oracle_dir: Path
    memory_mib: int = 256
    cpu_seconds: int = 30
    max_pids: int = 64


@dataclass
class ProbeResult:
    ok: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class LaunchResult:
    process: subprocess.Popen | None
    probe: ProbeResult
    backend: str
    evidence: dict[str, Any] = field(default_factory=dict)


def which_bwrap() -> str | None:
    executable = shutil.which("bwrap")
    return str(Path(executable).resolve()) if executable else None


def user_ns_usable() -> bool:
    """Feature hint only: permissions/LSMs can still prevent namespace creation."""
    if not Path("/proc/self/ns/user").exists():
        return False
    setting = Path("/proc/sys/kernel/unprivileged_userns_clone")
    try:
        return not setting.exists() or setting.read_text().strip() == "1"
    except OSError:
        return False


def tool_preflight() -> ProbeResult:
    bwrap, user_ns_hint = which_bwrap(), user_ns_usable()
    evidence = {"bwrap": bwrap, "user_ns_hint": user_ns_hint, "platform": sys.platform}
    if sys.platform != "linux":
        return ProbeResult(False, "namespace probes require Linux", evidence)
    if bwrap is None:
        return ProbeResult(False, "bubblewrap (bwrap) not found on PATH", evidence)
    if not user_ns_hint:
        return ProbeResult(False, "unprivileged user namespace prerequisite missing or disabled", evidence)
    return ProbeResult(True, "candidate tools found; actual namespace probe still required", evidence)


def _check_token(token: str) -> None:
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", token):
        raise ValueError("fixture token must be 1-128 ASCII letters, digits, underscores or hyphens")


def _write_private(path: Path, contents: str) -> None:
    # Never overwrite a preexisting path or follow a planted final symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(contents)


def prepare_isolation_dirs(base: Path, token: str) -> tuple[Path, Path, Path]:
    """Create known nonempty secrets under a caller-owned private directory."""
    _check_token(token)
    base = base.resolve(strict=True)
    info = base.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("isolation fixture base must be an owned private directory (0700)")
    host_canary = base / f"host_canary_{token}.secret"
    oracle_dir = base / f"oracle_{token}"
    oracle_dir.mkdir(mode=0o700)
    _write_private(oracle_dir / "answers.json", json.dumps({"token": token}))
    _write_private(host_canary, f"HOST_SECRET_{token}\n")
    return host_canary, oracle_dir, base


def _verify_secret(path: Path, expected: bytes) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError("probe secrets must be owned private regular files without hardlink aliases")
        if stream.read(len(expected) + 1) != expected:
            raise ValueError("probe secret is missing, empty, changed or from a different run")


def _validated_plan(plan: LaunchPlan, token: str) -> LaunchPlan:
    _check_token(token)
    if plan.host_canary.is_symlink() or plan.oracle_dir.is_symlink():
        raise ValueError("protected fixture paths must not be symlinks")
    workspace = plan.workspace.resolve(strict=True)
    host_canary = plan.host_canary.resolve(strict=True)
    oracle_dir = plan.oracle_dir.resolve(strict=True)
    if not workspace.is_dir() or not oracle_dir.is_dir():
        raise ValueError("workspace and oracle paths must be directories")
    # Both the probe and the eventual launcher use the same absolute mount path.
    exposed = [workspace, *(Path(p).resolve() for p in RUNTIME_PATHS if Path(p).exists())]
    for protected in (host_canary, oracle_dir):
        if any(protected.is_relative_to(p) or p.is_relative_to(protected) for p in exposed):
            raise ValueError("protected fixture paths overlap a candidate mount")
    for reserved in (*RUNTIME_PATHS, "/proc", "/dev", "/tmp"):
        path = Path(reserved).resolve()
        if workspace == path or path.is_relative_to(workspace):
            raise ValueError("workspace would expose or replace a reserved filesystem root")
        if reserved != "/tmp" and workspace.is_relative_to(path):
            raise ValueError("workspace overlaps a reserved runtime mount")
    info = oracle_dir.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("oracle fixture directory must be owned and private (0700)")
    _verify_secret(host_canary, f"HOST_SECRET_{token}\n".encode())
    _verify_secret(oracle_dir / "answers.json", json.dumps({"token": token}).encode())
    return replace(plan, workspace=workspace, host_canary=host_canary, oracle_dir=oracle_dir)


def _bwrap_command(plan: LaunchPlan, bwrap: str, command: list[str]) -> list[str]:
    """One candidate mount/env layout; never remap only the probe to /workspace."""
    cmd = [bwrap, "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
           "--unshare-net", "--unshare-uts", "--unshare-ipc", "--cap-drop", "ALL", "--clearenv"]
    for source in RUNTIME_PATHS:
        if Path(source).exists():
            cmd.extend(["--ro-bind", source, source])
    cmd.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--bind", str(plan.workspace), str(plan.workspace), "--chdir", str(plan.workspace)])
    for key, value in {**PROBE_ENV, "HOME": "/tmp", "TMPDIR": "/tmp",
                       "PYTHONDONTWRITEBYTECODE": "1"}.items():
        cmd.extend(["--setenv", key, value])
    return [*cmd, "--", *command]


def _capture_probe(command: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """Bound the trusted helper, including noisy startup failures and open pipes.

    Process-group cleanup is only a backstop for this fixed helper. It does not
    implement the cgroup supervisor required before arbitrary subject launch.
    """
    stdout, stderr = bytearray(), bytearray()
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    completed = False
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=PROBE_ENV, cwd=cwd, close_fds=True,
                          start_new_session=True) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                for stream, destination in ((proc.stdout, stdout), (proc.stderr, stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, destination)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("namespace probe exceeded its wall deadline")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            key.data.extend(chunk)
                            if len(stdout) + len(stderr) > PROBE_MAX_BYTES:
                                raise ValueError("namespace probe exceeded its combined output byte limit")
            proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            completed = True
            return subprocess.CompletedProcess(command, proc.returncode, bytes(stdout), bytes(stderr))
        finally:
            if not completed:
                # The parent may already have exited while a helper child keeps
                # its pipes open. Kill the group before reaping the parent PID.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=1)


_PROBE_SCRIPT = r'''
import json, os, sys
out = {"nonce": sys.argv[1]}
for label, path, directory in (("host_canary", sys.argv[2], False),
                                ("oracle_dir", sys.argv[3], True),
                                ("oracle_answers", sys.argv[4], False)):
    try:
        if directory:
            os.listdir(path)
        else:
            with open(path, "rb") as fh:
                fh.read(1)
        out[label] = {"readable": True, "errno": None}
    except OSError as exc:
        out[label] = {"readable": False, "errno": exc.errno}
print(json.dumps(out))
'''


def _probe_denied(payload: Any, nonce: str) -> bool:
    labels = {"host_canary", "oracle_dir", "oracle_answers"}
    if (not isinstance(payload, dict) or set(payload) != labels | {"nonce"}
            or payload["nonce"] != nonce):
        raise ValueError("probe schema or run nonce mismatch")
    denied = True
    for label in labels:
        result = payload[label]
        if (not isinstance(result, dict) or set(result) != {"readable", "errno"}
                or type(result["readable"]) is not bool):
            raise ValueError("probe must report a typed result for every protected path")
        if result["readable"]:
            if result["errno"] is not None:
                raise ValueError("contradictory probe access result")
            denied = False
        elif type(result["errno"]) is not int or result["errno"] not in (errno.ENOENT, errno.EACCES, errno.EPERM):
            raise ValueError("unexpected probe I/O failure does not prove path denial")
    return denied


def run_host_canary_probe(plan: LaunchPlan, token: str) -> ProbeResult:
    """Observe this synthetic candidate view, never a different server's run."""
    try:
        plan = _validated_plan(plan, token)
    except (OSError, ValueError, RuntimeError) as exc:
        return ProbeResult(False, f"probe precondition failed: {exc}")
    tools = tool_preflight()
    if not tools.ok:
        return ProbeResult(False, f"cannot probe: {tools.detail}", {"tools": tools.evidence})
    nonce = uuid.uuid4().hex
    command = _bwrap_command(plan, tools.evidence["bwrap"], [
        "/usr/bin/python3", "-I", "-S", "-c", _PROBE_SCRIPT, nonce,
        str(plan.host_canary), str(plan.oracle_dir), str(plan.oracle_dir / "answers.json"),
    ])
    evidence: dict[str, Any] = {"tools": tools.evidence, "probe_nonce": nonce,
                                "workspace_mount": str(plan.workspace),
                                "max_output_bytes": PROBE_MAX_BYTES,
                                "timeout_seconds": PROBE_TIMEOUT_SECONDS,
                                "scope": "synthetic filesystem probe only; not run-level containment"}
    try:
        completed = _capture_probe(command, plan.workspace)
        evidence.update(returncode=completed.returncode, stderr_tail=completed.stderr[-500:].decode("utf-8", "replace"))
        if completed.returncode != 0:
            return ProbeResult(False, f"probe exit {completed.returncode}", evidence)
        payload = strict_json(completed.stdout.decode("utf-8"))
        denied = _probe_denied(payload, nonce)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        return ProbeResult(False, f"probe could not establish path denial: {exc}", evidence)
    evidence["probe"] = payload
    if not denied:
        return ProbeResult(False, "candidate view can reach a protected fixture path", evidence)
    return ProbeResult(True, "trusted helper could not read planted host paths; containment remains unverified", evidence)


def launch_subject(plan: LaunchPlan) -> LaunchResult:
    """Retain refusal for the legacy, ungated standalone launcher API.

    A standalone canary success must not authorize an unbounded Popen of an
    arbitrary binary. Runner integration must carry the full acceptance evidence.
    """
    probe = ProbeResult(False, "standalone subject launch disabled: use Runner's explicitly gated supervised session path")
    return LaunchResult(None, probe, "bwrap", {
        "subject_launch_supported": False,
        "requested_limits": {"memory_mib": plan.memory_mib, "cpu_seconds": plan.cpu_seconds, "max_pids": plan.max_pids},
    })
