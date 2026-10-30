"""Execution backends and fail-closed preflight for subject isolation.

Native mode is explicit and always records containment UNKNOWN.
Namespace mode refuses to start (or marks INCOMPLETE) when required
controls cannot be observed. There is no silent fallback to native.
"""
from __future__ import annotations

import errno
import os
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable


class ExecutionMode(StrEnum):
    NATIVE = "native"
    NAMESPACE = "namespace"


@dataclass
class PreflightFinding:
    id: str
    ok: bool
    detail: str
    required: bool = True


@dataclass
class PreflightResult:
    mode: ExecutionMode
    ok: bool
    findings: list[PreflightFinding] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)

    def reasons(self) -> list[str]:
        return [f"{f.id}: {f.detail}" for f in self.findings if f.required and not f.ok]


@dataclass
class IsolationPolicy:
    """Requested policy. Enforcement must be confirmed by preflight/observers."""

    mode: ExecutionMode
    server_uid: int | None = None
    server_gid: int | None = None
    memory_mib: int = 256
    cpu_seconds: int = 30
    max_pids: int = 64
    network: str = "deny"  # deny | inherit (inherit only valid for native)


class IsolationBackend:
    """Launch and observe a subject under a named mode."""

    mode: ExecutionMode

    def preflight(self, policy: IsolationPolicy) -> PreflightResult:
        raise NotImplementedError

    def child_preexec(self, policy: IsolationPolicy) -> Callable[[], None] | None:
        """Optional preexec_fn for subprocess.Popen. Namespace may use a different launcher."""
        return None

    def containment_check(self, preflight: PreflightResult) -> tuple[str, str, dict[str, Any]]:
        """Return (status, reason, evidence) for the execution_containment check.

        status is PASS | FAIL | UNKNOWN matching model.Status values as strings.
        """
        raise NotImplementedError


class NativeBackend(IsolationBackend):
    mode = ExecutionMode.NATIVE

    def preflight(self, policy: IsolationPolicy) -> PreflightResult:
        findings: list[PreflightFinding] = []
        observed: dict[str, Any] = {
            "platform": sys.platform,
            "euid": os.geteuid(),
            "egid": os.getegid(),
        }
        if sys.platform != "linux":
            findings.append(PreflightFinding("platform", False, "v1 requires Linux", required=True))
        else:
            findings.append(PreflightFinding("platform", True, "linux"))

        if policy.server_uid is not None:
            if policy.server_uid <= 0 or os.geteuid() != 0:
                findings.append(PreflightFinding(
                    "server_uid", False,
                    "--server-uid requires a nonzero UID and a privileged parent",
                    required=True,
                ))
            else:
                findings.append(PreflightFinding("server_uid", True, f"uid={policy.server_uid}"))
            observed["requested_uid"] = policy.server_uid
            observed["requested_gid"] = policy.server_gid

        findings.append(PreflightFinding(
            "containment_claim", True,
            "native mode does not assert isolation; containment will be UNKNOWN",
            required=False,
        ))
        ok = all(f.ok for f in findings if f.required)
        return PreflightResult(mode=self.mode, ok=ok, findings=findings, observed=observed)

    def child_preexec(self, policy: IsolationPolicy) -> Callable[[], None] | None:
        return None

    def containment_check(self, preflight: PreflightResult) -> tuple[str, str, dict[str, Any]]:
        return (
            "UNKNOWN",
            "native subprocess mode does not isolate host files, network, same-UID processes, or escaped descendants",
            {
                "mode": "native",
                "preflight": preflight.observed,
                "no_new_privileges_requested": True,
                "drop_linux_capabilities_requested": True,
            },
        )


class NamespaceBackend(IsolationBackend):
    """Linux user/mount/pid/network namespaces + cgroup v2 (v0.2.0 target).

    This module implements preflight and the public contract. Full subject
    launch and external observers land in subsequent checkpoints. Until those
    exist, preflight reports incomplete controls and refuses a containment PASS.
    """

    mode = ExecutionMode.NAMESPACE

    def preflight(self, policy: IsolationPolicy) -> PreflightResult:
        findings: list[PreflightFinding] = []
        observed: dict[str, Any] = {
            "platform": sys.platform,
            "euid": os.geteuid(),
            "egid": os.getegid(),
        }

        if sys.platform != "linux":
            findings.append(PreflightFinding("platform", False, "namespace backend requires Linux", required=True))
            return PreflightResult(mode=self.mode, ok=False, findings=findings, observed=observed)
        findings.append(PreflightFinding("platform", True, "linux"))

        cgroup_v2 = Path("/sys/fs/cgroup/cgroup.controllers").is_file()
        observed["cgroup_v2"] = cgroup_v2
        findings.append(PreflightFinding(
            "cgroup_v2",
            cgroup_v2,
            "cgroup v2 controllers file present" if cgroup_v2 else "cgroup v2 not available at /sys/fs/cgroup",
            required=True,
        ))

        can_user_ns = Path("/proc/self/ns/user").exists()
        observed["user_ns_proc"] = can_user_ns
        findings.append(PreflightFinding(
            "user_namespace",
            can_user_ns,
            "/proc/self/ns/user present" if can_user_ns else "user namespace proc entry missing",
            required=True,
        ))

        findings.append(PreflightFinding(
            "launcher_implemented",
            False,
            "namespace subject launcher and external observers are not implemented yet (checkpoint 2+)",
            required=True,
        ))
        findings.append(PreflightFinding(
            "oracle_storage_protection",
            False,
            "oracle/report path isolation not yet externally verified",
            required=True,
        ))
        findings.append(PreflightFinding(
            "network_denial",
            False,
            "network namespace denial not yet externally verified",
            required=True,
        ))
        findings.append(PreflightFinding(
            "teardown_verified",
            False,
            "cgroup-wide teardown observer not yet implemented",
            required=True,
        ))

        ok = all(f.ok for f in findings if f.required)
        return PreflightResult(mode=self.mode, ok=ok, findings=findings, observed=observed)

    def child_preexec(self, policy: IsolationPolicy) -> Callable[[], None] | None:
        return None

    def containment_check(self, preflight: PreflightResult) -> tuple[str, str, dict[str, Any]]:
        if not preflight.ok:
            return (
                "UNKNOWN",
                "namespace isolation prerequisites or implementation incomplete; containment not established",
                {
                    "mode": "namespace",
                    "preflight_ok": False,
                    "reasons": preflight.reasons(),
                    "observed": preflight.observed,
                },
            )
        return (
            "UNKNOWN",
            "namespace backend preflight passed feature probes but run-level acceptance evidence is not yet collected",
            {"mode": "namespace", "preflight_ok": True, "observed": preflight.observed},
        )


def get_backend(mode: ExecutionMode | str) -> IsolationBackend:
    if isinstance(mode, str):
        mode = ExecutionMode(mode)
    if mode is ExecutionMode.NATIVE:
        return NativeBackend()
    if mode is ExecutionMode.NAMESPACE:
        return NamespaceBackend()
    raise ValueError(f"unsupported isolation mode: {mode}")
