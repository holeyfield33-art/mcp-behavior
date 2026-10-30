"""Scenario orchestration. A new server session prevents failure contamination."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config, canonical, digest
from .fixtures import Fixture, bounded_hash, build_fixture, snapshot
from .model import Check, ContractError, HarnessError, ServerFault, Status, UnsupportedEvidence, verdict
from .oracle import Answer, at, decode, fixture_checks, reasoned_error, repeatable_payload
from .transport import StdioClient, child_setup

CASES = ("normal", "missing", "file_as_root", "relative", "outside", "traversal",
         "escaping_symlink", "dangling_symlink", "internal_symlink", "directory_loop",
         "special_file", "unreadable", "large")


class Runner:
    def __init__(self, config: Config, uid: int | None = None, gid: int | None = None,
                 isolation_backend=None, isolation_preflight=None):
        if sys.platform != "linux":
            raise HarnessError("v1 requires Linux")
        if uid is not None and (type(uid) is not int or uid <= 0 or os.geteuid() != 0):
            raise HarnessError("--server-uid requires a nonzero UID and a privileged parent")
        if gid is not None and (uid is None or gid < 0):
            raise HarnessError("--server-gid requires --server-uid and a nonnegative GID")
        self.config = config
        self.uid, self.gid = uid, gid
        self.isolation_backend = isolation_backend
        self.isolation_preflight = isolation_preflight
        self.checks: list[Check] = []
        self.cases: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []
        self.tool_fingerprints: set[str] = set()
        self.repeat_values: list[bytes] = []
        self.missing_error_actionable = False
        self.normal_correct = False
        self.recovery_status = Status.UNKNOWN
        self.suite_deadline: float | None = None

    def add(self, id: str, lane: str, status: Status, reason: str, **evidence: Any) -> None:
        self.checks.append(Check(id, lane, status, reason, evidence))
