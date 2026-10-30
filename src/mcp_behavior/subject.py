"""Experimental namespace subject sessions; never supplies containment PASS."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .config import Limits, digest
from .model import HarnessError, ServerFault
from .namespace_runtime import LaunchPlan, RUNTIME_PATHS, _bwrap_command, which_bwrap
from .supervisor import CgroupScope, ResourceLimitExceeded, SupervisorLimits, _wait_ready


# Controller-owned bootstrap only. No configured code runs before release. All
# attachment/gate descriptors are closed before exec and are never subject fds.
_BOOTSTRAP = r'''
import ctypes, os, resource, sys
group, ready, release = map(int, sys.argv[1:4])
os.write(group, str(os.getpid()).encode())
os.close(group)
os.write(ready, b"J")
os.close(ready)
if os.read(release, 1) != b"G":
    raise SystemExit(3)
os.close(release)
memory, cpu = map(int, sys.argv[4:6])
resource.setrlimit(resource.RLIMIT_AS, (memory * 1024**2,) * 2)
resource.setrlimit(resource.RLIMIT_CPU, (cpu,) * 2)
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024**2,) * 2)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(38, 1, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "cannot set no_new_privs")
os.execv(sys.argv[6], sys.argv[6:])
'''


def subject_command(command: tuple[str, ...], workspace: Path, cwd: Path,
                    artifacts: tuple[Path, ...], protected_paths: tuple[Path, ...] = ()) -> list[str]:
    """Do not expose a source directory just to make an import succeed."""
    if (workspace.resolve(strict=True) != workspace or cwd.resolve(strict=True) != cwd
            or not cwd.is_relative_to(workspace)):
        raise HarnessError("namespace workspace must be canonical and contain CWD")
    if workspace == Path("/tmp"):
        raise HarnessError("namespace workspace cannot expose the temporary root")
    for reserved in (*RUNTIME_PATHS, "/proc", "/dev", "/sys"):
        path = Path(reserved).resolve()
        if workspace.is_relative_to(path) or path.is_relative_to(workspace):
            raise HarnessError("namespace workspace overlaps a reserved mount")
    bwrap = which_bwrap()
    if bwrap is None:
        raise HarnessError("bubblewrap disappeared after preflight; no native fallback")
    # The protected-secret fields are only used by synthetic probe validation.
    plan = LaunchPlan(workspace, list(command), Path("/unused-canary"), Path("/unused-oracle"))
    argv = _bwrap_command(plan, bwrap, [])[:-1]  # remove final --
    argv.extend(["--chdir", str(cwd)])
    exposed = (workspace, *(Path(p).resolve() for p in RUNTIME_PATHS if Path(p).exists()))
    protected = tuple(path.resolve() for path in protected_paths)
    protected_inodes = {(info.st_dev, info.st_ino) for path in protected if path.exists()
                        for info in (path.stat(),)}
    if any(path.is_relative_to(root) or root.is_relative_to(path)
           for path in protected for root in exposed):
        raise HarnessError("protected oracle/report/config path overlaps a namespace mount")
    executable = Path(command[0])
    # Interpreter symlinks in runtime roots (e.g. /usr/bin/python3) are already
    # visible there. Other executable and artifact aliases are refused.
    if (any(executable.is_relative_to(Path(root)) for root in RUNTIME_PATHS)
            and any(executable.resolve(strict=True).is_relative_to(root) for root in exposed[1:])):
        executable = executable.resolve(strict=True)
    for path in dict.fromkeys((*artifacts, executable)):
        if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_file():
            raise HarnessError("namespace artifacts must be canonical regular files")
        if path.is_relative_to(workspace):
            raise HarnessError("namespace artifact overlaps writable fixtures")
        info = path.stat()
        if path in protected or (info.st_dev, info.st_ino) in protected_inodes:
            raise HarnessError("namespace artifact overlaps protected oracle/report/config storage")
        if any(path.is_relative_to(root) for root in exposed[1:]):
            continue
        if any(path.is_relative_to(Path(root)) for root in ("/proc", "/dev", "/sys")):
            raise HarnessError("namespace artifact overlaps a reserved mount")
        argv.extend(["--ro-bind", str(path), str(path)])
    return [*argv, "--", *command]


class SubjectSession:
    """Own process and cgroup as one lifetime, including launch failure."""

    def __init__(self, parent: Path, limits: Limits, protected_paths: tuple[Path, ...] = ()):
        self.scope = CgroupScope(parent, SupervisorLimits(limits.memory_mib, limits.cpu_seconds, 64))
        self.limits = limits
        self.protected_paths = protected_paths
        self.process: subprocess.Popen | None = None
        self.closed = False
        self.evidence: dict[str, Any] = {"backend": "namespace", "scope": str(self.scope.path),
                                         "joined_before_release": False,
                                         "protected_paths": [str(p) for p in protected_paths]}

    def start(self, command: tuple[str, ...], workspace: Path, cwd: Path,
              artifacts: tuple[Path, ...], deadline: float) -> subprocess.Popen:
        fds: list[int] = []
        try:
            self.evidence["command_sha256"] = digest(command)
            argv = subject_command(command, workspace, cwd, artifacts, self.protected_paths)
            self.scope.prepare()
            self.evidence["effective_limits"] = dict(self.scope.effective)
            group = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.scope.fd)
            fds.append(group)
            ready_r, ready_w = os.pipe()
            fds.extend((ready_r, ready_w))
            release_r, release_w = os.pipe()
            fds.extend((release_r, release_w))
            self.process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-c", _BOOTSTRAP, str(group), str(ready_w), str(release_r),
                 str(self.limits.memory_mib), str(self.limits.cpu_seconds), *argv],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}, cwd=cwd,
                pass_fds=(group, ready_w, release_r), close_fds=True, start_new_session=True)
            for fd in (group, ready_w, release_r):
                os.close(fd)
                fds.remove(fd)
            _wait_ready(self.process, ready_r, min(deadline, time.monotonic() + 3))
            if self.scope.members() != {self.process.pid}:
                raise HarnessError("subject bootstrap membership not verified before release")
            self.scope.check_budget()
            if time.monotonic() >= deadline:
                raise HarnessError("subject startup deadline ended before release")
            if os.write(release_w, b"G") != 1:
                raise HarnessError("subject release gate write failed")
            self.evidence.update(joined_before_release=True, bootstrap_pid=self.process.pid)
            return self.process
        except Exception as exc:
            self.evidence["launch_error"] = str(exc)[:512]
            self.close()
            error = HarnessError(f"supervised namespace launch refused: {exc}")
            error.evidence = self.evidence
            raise error from exc
        finally:
            for fd in fds:
                os.close(fd)

    def check(self) -> None:
        try:
            self.evidence["usage"] = self.scope.check_budget()
        except (OSError, ValueError) as exc:
            self.evidence["resource_error"] = str(exc)
            # Missing/malformed observation is a harness fault, not server blame.
            if isinstance(exc, ResourceLimitExceeded):
                raise ServerFault("resource_limit", str(exc), dict(self.evidence)) from exc
            self.evidence["observer_error"] = str(exc)
            raise HarnessError(f"subject resource observation failed: {exc}") from exc

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        handles: list[int] = []
        try:
            if self.scope.fd >= 0:
                # Keep bounded kernel handles before cleanup closes the scope.
                # This fallback never turns failed recursive cleanup into PASS.
                try:
                    for pid in sorted(self.scope.members())[:64]:
                        try:
                            handle = os.pidfd_open(pid)
                            if pid in self.scope.members():
                                handles.append(handle)
                            else:
                                os.close(handle)
                        except ProcessLookupError:
                            pass
                except (OSError, ValueError) as exc:
                    self.evidence["fallback_observation_error"] = str(exc)
                try:
                    self.evidence["final_usage"] = self.scope.check_budget()
                except (OSError, ValueError) as exc:
                    self.evidence["final_resource_error"] = str(exc)
                    self.evidence["final_resource_intervention"] = isinstance(exc, ResourceLimitExceeded)
                    if not isinstance(exc, ResourceLimitExceeded):
                        self.evidence["observer_error"] = str(exc)
        finally:
            self.evidence["cleanup"] = self.scope.cleanup()
            for handle in handles:
                try:
                    if not self.evidence["cleanup"]["ok"]:
                        signal.pidfd_send_signal(handle, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    self.evidence["fallback_kill_error"] = str(exc)
                finally:
                    os.close(handle)
            if self.process is not None:
                try:
                    if self.process.poll() is None:
                        self.process.kill()
                    self.process.wait(timeout=2)
                finally:
                    for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                        if stream:
                            stream.close()
        if not self.evidence["cleanup"]["ok"]:
            raise HarnessError("subject cgroup cleanup unverified: " + self.evidence["cleanup"]["detail"])
