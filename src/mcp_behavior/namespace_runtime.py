"""Namespace subject runtime: private mounts, host canary probe, fail-closed launch.

Checkpoint 2 implements a real launcher when the host provides the required tools
(unprivileged user namespaces + bubblewrap, or equivalent). Oracle/report paths and
host secret canaries stay outside the subject's mount view. Containment PASS still
requires the full acceptance matrix; this module supplies launch + one external
filesystem observer, not a complete certification.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class LaunchPlan:
    """Paths and policy for one isolated subject session."""

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
    return shutil.which("bwrap")


def user_ns_usable() -> bool:
    if not Path("/proc/self/ns/user").exists():
        return False
    max_path = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if max_path.exists():
        try:
            return max_path.read_text().strip() == "1"
        except OSError:
            return False
    return True


def tool_preflight() -> ProbeResult:
    evidence: dict[str, Any] = {
        "bwrap": which_bwrap(),
        "user_ns_usable": user_ns_usable(),
        "platform": os.uname().sysname if hasattr(os, "uname") else "unknown",
    }
    if which_bwrap() is None:
        return ProbeResult(False, "bubblewrap (bwrap) not found on PATH", evidence)
    if not user_ns_usable():
        return ProbeResult(False, "unprivileged user namespaces not usable", evidence)
    return ProbeResult(True, "bwrap + user namespaces available", evidence)


def _write_canary(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"HOST_SECRET_{token}\n", encoding="utf-8")
    os.chmod(path, 0o600)


def run_host_canary_probe(plan: LaunchPlan, token: str) -> ProbeResult:
    tools = tool_preflight()
    if not tools.ok:
        return ProbeResult(False, f"cannot probe: {tools.detail}", tools.evidence)

    bwrap = which_bwrap()
    assert bwrap is not None

    script = r"""
import json, os, sys
out = {"host_canary_readable": False, "oracle_dir_readable": False, "errors": []}
for label, path in (("host_canary_readable", sys.argv[1]), ("oracle_dir_readable", sys.argv[2])):
    try:
        if os.path.isdir(path):
            os.listdir(path)
            out[label] = True
        else:
            with open(path, "r", encoding="utf-8") as fh:
                data = fh.read(64)
            out[label] = bool(data)
    except OSError as exc:
        out["errors"].append(f"{label}:{type(exc).__name__}")
print(json.dumps(out))
"""
    cmd = [
        bwrap,
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-ipc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind-try", "/sbin", "/sbin",
        "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
        "--bind", str(plan.workspace.resolve()), "/workspace",
        "--chdir", "/workspace",
        "--tmpfs", "/tmp",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--",
        "python3", "-c", script,
        str(plan.host_canary.resolve()),
        str(plan.oracle_dir.resolve()),
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ProbeResult(False, f"bwrap probe failed to run: {exc}", {"tools": tools.evidence})

    evidence: dict[str, Any] = {
        "tools": tools.evidence,
        "returncode": completed.returncode,
        "stderr_tail": (completed.stderr or "")[-500:],
    }
    if completed.returncode != 0:
        return ProbeResult(False, f"probe exit {completed.returncode}", evidence)
    try:
        payload = json.loads((completed.stdout or "").strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        evidence["stdout_tail"] = (completed.stdout or "")[-300:]
        return ProbeResult(False, f"probe output not JSON: {exc}", evidence)

    evidence["probe"] = payload
    leaked = payload.get("host_canary_readable") or payload.get("oracle_dir_readable")
    if leaked:
        return ProbeResult(False, "subject mount view can still reach host canary or oracle dir", evidence)
    return ProbeResult(True, "host canary and oracle dir unreadable inside bubble", evidence)


def launch_subject(plan: LaunchPlan) -> LaunchResult:
    tools = tool_preflight()
    if not tools.ok:
        return LaunchResult(None, tools, "unavailable", {"tools": tools.evidence})

    probe = run_host_canary_probe(plan, token="launch")
    if not probe.ok:
        return LaunchResult(None, probe, "bwrap", {"probe": probe.evidence})

    bwrap = which_bwrap()
    assert bwrap is not None
    ws = str(plan.workspace.resolve())
    cmd = [
        bwrap,
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-ipc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind-try", "/sbin", "/sbin",
        "--bind", ws, ws,
        "--chdir", ws,
        "--tmpfs", "/tmp",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "TMPDIR", "/tmp",
        "--",
        *plan.command,
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ws,
            start_new_session=True,
        )
    except OSError as exc:
        return LaunchResult(None, ProbeResult(False, f"Popen failed: {exc}", {}), "bwrap", {"probe": probe.evidence})
    return LaunchResult(proc, probe, "bwrap", {"probe": probe.evidence, "pid": proc.pid})


def prepare_isolation_dirs(base: Path, token: str) -> tuple[Path, Path, Path]:
    host_canary = base / f"host_canary_{token}.secret"
    oracle_dir = base / f"oracle_{token}"
    oracle_dir.mkdir(parents=True, exist_ok=True)
    (oracle_dir / "answers.json").write_text(json.dumps({"token": token}), encoding="utf-8")
    _write_canary(host_canary, token)
    return host_canary, oracle_dir, base
