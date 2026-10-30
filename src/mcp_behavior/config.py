"""Strict local configuration. No server-supplied code, grading rules, or schemas run."""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import HarnessError


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def strict_json(raw: str | bytes) -> Any:
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda s: (_ for _ in ()).throw(ValueError(f"nonfinite number {s}")))


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def keys(obj: Any, allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) - allowed:
        raise HarnessError(f"{label} must be an object with only: {', '.join(sorted(allowed))}")
    return obj


def text_value(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise HarnessError(f"{label} must be a nonempty string, at most {maximum} characters")
    return value


def pointer(value: Any, label: str, nullable: bool = True) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > 512 or (value and not value.startswith("/")):
        raise HarnessError(f"{label} must be an RFC 6901 JSON pointer")
    if re.search(r"~(?![01])", value):
        raise HarnessError(f"{label} has an invalid pointer escape")
    return value


@dataclass(frozen=True)
class Limits:
    timeout_seconds: float = 8.0
    case_timeout_seconds: float = 30.0
    suite_timeout_seconds: float = 180.0
    max_frame_bytes: int = 262144
    max_result_bytes: int = 65536
    max_session_bytes: int = 4194304
    max_stderr_bytes: int = 65536
    max_messages: int = 256
    memory_mib: int = 512
    cpu_seconds: int = 20

    @classmethod
    def parse(cls, raw: Any) -> Limits:
        raw = keys(raw, set(cls.__dataclass_fields__), "limits")
        bounds = {"timeout_seconds": (.1, 60), "case_timeout_seconds": (.1, 90), "suite_timeout_seconds": (1, 900),
                  "max_frame_bytes": (4096, 1048576),
                  "max_result_bytes": (1024, 1048576), "max_session_bytes": (4096, 16777216),
                  "max_stderr_bytes": (1024, 1048576), "max_messages": (8, 2048),
                  "memory_mib": (64, 4096), "cpu_seconds": (1, 120)}
        for name, val in raw.items():
            low, high = bounds[name]
            number = type(val) in (int, float) if name.endswith("seconds") and name != "cpu_seconds" else type(val) is int
            if not number or not math.isfinite(val) or not low <= val <= high:
                raise HarnessError(f"limits.{name} must be between {low} and {high}")
        result = cls(**raw)
        if result.max_result_bytes > result.max_frame_bytes or result.max_frame_bytes > result.max_session_bytes:
            raise HarnessError("limits must satisfy result <= frame <= session")
        if not result.timeout_seconds <= result.case_timeout_seconds <= result.suite_timeout_seconds:
            raise HarnessError("deadlines must satisfy request <= case <= suite")
        return result


@dataclass(frozen=True)
class RecordMap:
    pointer: str
    path: str = ""
    reason: str | None = None
    sha256: str | None = None

    @classmethod
    def parse(cls, raw: Any, label: str) -> RecordMap | None:
        if raw is None:
            return None
        raw = keys(raw, {"pointer", "path", "reason", "sha256"}, label)
        if "pointer" not in raw:
            raise HarnessError(f"{label}.pointer is required")
        return cls(pointer(raw["pointer"], label, False),
                   pointer(raw.get("path", ""), label, False),
                   pointer(raw.get("reason"), label), pointer(raw.get("sha256"), label))  # type: ignore[arg-type]


@dataclass(frozen=True)
class Profile:
    id: str
    version: str
    tool: str
    path_argument: str
    arguments: dict[str, Any]
    supported_suffixes: tuple[str, ...]
    relative_paths: str
    processed: RecordMap | None
    excluded: RecordMap | None
    failed: RecordMap | None
    complete: str | None
    counts: dict[str, str]
    ignored_timestamps: tuple[str, ...]
    sha256: str

    @classmethod
    def parse(cls, raw: Any) -> Profile:
        raw = keys(raw, {"id", "version", "tool", "path_argument", "arguments", "supported_suffixes",
                         "relative_paths", "observations", "ignored_timestamps"}, "profile")
        required = ("id", "version", "tool", "path_argument", "supported_suffixes", "observations")
        if any(k not in raw for k in required):
            raise HarnessError(f"profile requires {', '.join(required)}")
        for name in required[:4]:
            text_value(raw[name], f"profile.{name}")
        args = raw.get("arguments", {})
        if not isinstance(args, dict) or raw["path_argument"] in args or len(canonical(args)) > 32768:
            raise HarnessError("profile.arguments must be a bounded object without the path argument")
        suffixes = raw["supported_suffixes"]
        if not isinstance(suffixes, list) or not suffixes or len(suffixes) > 8 or any(s not in (".py", ".js", ".txt") for s in suffixes) or len(set(suffixes)) != len(suffixes):
            raise HarnessError("v1 supports unique .py, .js, .txt fixture suffixes only")
        relative = raw.get("relative_paths", "reject")
        if relative not in ("reject", "workspace"):
            raise HarnessError("profile.relative_paths must be reject or workspace")
        obs = keys(raw["observations"], {"processed", "excluded", "failed", "complete", "counts"}, "observations")
        records = {name: RecordMap.parse(obs.get(name), name) for name in ("processed", "excluded", "failed")}
        complete = pointer(obs.get("complete"), "complete")
        counts = keys(obs.get("counts", {}), {"processed", "excluded", "failed"}, "counts")
        counts = {k: pointer(v, f"counts.{k}", False) for k, v in counts.items()}
        ignored = raw.get("ignored_timestamps", [])
        if not isinstance(ignored, list) or len(ignored) > 8:
            raise HarnessError("ignored_timestamps must contain at most eight pointers")
        protected = [r.pointer for r in records.values() if r is not None] + list(counts.values())
        if complete is not None:
            protected.append(complete)
        for p in ignored:
            pointer(p, "ignored timestamp", False)
            parts = p.split("/")[1:]
            if not parts or parts[-1] not in ("generated_at", "generatedAt", "started_at", "finished_at", "timestamp") or len(parts) > 8 or parts.count("*") > 2:
                raise HarnessError("only explicit timestamp leaves may be ignored, with at most two array wildcards")
            def overlaps(q: str) -> bool:
                target = q.split("/")[1:] if q else []
                return all(a == b or a == "*" for a, b in zip(parts, target))
            if any(overlaps(q) for q in protected):
                raise HarnessError("timestamps cannot mask an observation field")
        if len(set(ignored)) != len(ignored):
            raise HarnessError("duplicate ignored timestamp")
        return cls(raw["id"], raw["version"], raw["tool"], raw["path_argument"], args,
                   tuple(suffixes), relative, records["processed"], records["excluded"], records["failed"],
                   complete, counts, tuple(ignored), digest(raw))  # type: ignore[arg-type]


@dataclass(frozen=True)
class Config:
    command: tuple[str, ...]
    identity: dict[str, Any]
    artifacts: tuple[Path, ...]
    profile: Profile
    limits: Limits
    config_sha256: str

    @classmethod
    def load(cls, path: Path) -> Config:
        try:
            if path.stat().st_size > 131072:
                raise HarnessError("configuration exceeds 128 KiB")
            raw = strict_json(path.read_bytes())
            raw = keys(raw, {"schema_version", "command", "identity", "profile", "limits"}, "config")
            if raw.get("schema_version") != "mcp-behavior-config/v1":
                raise HarnessError("unsupported configuration schema_version")
            command = raw.get("command")
            if not isinstance(command, list) or not command or len(command) > 32:
                raise HarnessError("command must be a nonempty argv array of at most 32 elements")
            def expand(s: str) -> str:
                return text_value(s, "command/artifact", 4096).replace("${python}", sys.executable).replace("${config_dir}", str(path.resolve().parent))
            command = tuple(expand(s) for s in command)
            if sum(map(len, command)) > 16384:
                raise HarnessError("command is too large")
            ident = keys(raw.get("identity"), {"name", "version", "artifacts"}, "identity")
            text_value(ident.get("name"), "identity.name")
            text_value(ident.get("version"), "identity.version")
            paths = ident.get("artifacts")
            if not isinstance(paths, list) or not 1 <= len(paths) <= 32:
                raise HarnessError("identity.artifacts requires one to 32 explicit regular files")
            artifacts = tuple(Path(expand(p)) for p in paths)
            if any(not p.is_absolute() for p in artifacts) or len(set(artifacts)) != len(artifacts):
                raise HarnessError("artifact paths must be absolute and unique; ${config_dir} is supported")
            if any(not p.is_absolute() for p in map(Path, command[:1])):
                raise HarnessError("command executable must be absolute; ${python} is supported")
            return cls(command, {k: ident[k] for k in ("name", "version")}, artifacts,
                       Profile.parse(raw.get("profile")), Limits.parse(raw.get("limits", {})), digest(raw))
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise HarnessError(f"invalid configuration: {exc}") from exc
