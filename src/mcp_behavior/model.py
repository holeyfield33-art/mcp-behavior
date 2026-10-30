"""Verdicts are evidence states, never averages or server self-reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NA = "N/A"


class Overall(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


@dataclass
class Check:
    name: str
    status: Status
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    required: bool = True
    lane: str = "readiness"  # readiness | security


@dataclass
class ContractError(Exception):
    message: str
    path: str = ""

    def __str__(self) -> str:
        if self.path:
            return f"{self.path}: {self.message}"
        return self.message


@dataclass
class UnsupportedEvidence:
    reason: str


def combine_overall(checks: list[Check]) -> Overall:
    """Required FAIL wins. Any required UNKNOWN/N/A blocks PASS."""
    has_fail = False
    has_unknown = False
    for c in checks:
        if not c.required:
            continue
        if c.status == Status.FAIL:
            has_fail = True
        elif c.status in (Status.UNKNOWN, Status.NA):
            has_unknown = True
    if has_fail:
        return Overall.FAIL
    if has_unknown:
        return Overall.INCOMPLETE
    return Overall.PASS


def lane_verdict(checks: list[Check], lane: str) -> Overall:
    return combine_overall([c for c in checks if c.lane == lane])


# Profile contract constants used by oracle and runner.
PROFILE_NAME = "read-only-repo-inventory"
PROFILE_VERSION = "1.0.0"
