"""Verdicts are evidence states, never a weighted score."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NA = "N/A"


@dataclass
class Check:
    id: str
    lane: str
    status: Status
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verdict(checks: list[Check]) -> str:
    """A demonstrated failure wins; missing required evidence prevents PASS."""
    required = [c for c in checks if c.required]
    if any(c.status == Status.FAIL for c in required):
        return "FAIL"
    if not required or any(c.status == Status.UNKNOWN for c in required):
        return "INCOMPLETE"
    # N/A requires an explicit, non-required scope exclusion. It cannot waive a gate.
    if any(c.status == Status.NA for c in required):
        return "INCOMPLETE"
    return "PASS"


class HarnessError(Exception):
    """An oracle, setup, configuration, or evidence collection failure."""


class ServerFault(Exception):
    """An observed failure of the running server, including client-enforced caps."""

    def __init__(self, code: str, message: str, evidence: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


class UnsupportedEvidence(Exception):
    """This client/profile cannot collect the required evidence."""


class ContractError(Exception):
    """A response violates an explicit, reviewer-owned profile contract."""
