"""Reviewer-owned mappings locate evidence; fixture bytes decide correctness."""
from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import Profile, RecordMap, canonical, strict_json
from .fixtures import Fixture
from .model import Check, ContractError, Status, UnsupportedEvidence
from .transport import Frame


def at(value: Any, pointer: str) -> Any:
    for part in pointer.split("/")[1:] if pointer else []:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part) and int(part) < len(value):
            value = value[int(part)]
        else:
            raise ContractError(f"mapped response field {pointer!r} is missing or has an incompatible type")
    return value


@dataclass
class Answer:
    error: bool
    message: str
    payload: dict[str, Any] | None
    wire_bytes: int
    wire_sha256: str


def decode(frame: Frame) -> Answer:
    envelope = frame.message
    if "error" in envelope:
        err = envelope["error"]
        message = err["message"]
        if "data" in err:
            message += " " + canonical(err["data"]).decode()
        return Answer(True, message, None, frame.size_bytes, frame.sha256)
    result = envelope["result"]
    error = result.get("isError", False)
    if type(error) is not bool:
        raise ContractError("isError must be a boolean")
    content = result.get("content", [])
    if not isinstance(content, list):
        raise ContractError("tool result content must be an array")
    texts: list[str] = []
    unsupported = False
    for block in content:
        if not isinstance(block, dict):
            raise ContractError("invalid tool content block")
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            texts.append(block["text"])
        else:
            unsupported = True
    structured = result.get("structuredContent")
    if structured is not None and not isinstance(structured, dict):
        raise ContractError("structuredContent must be an object")
    if error:
        message = "\n".join(texts)
        if structured is not None:
            message += " " + canonical(structured).decode()
        return Answer(True, message, structured, frame.size_bytes, frame.sha256)
    if unsupported:
        raise UnsupportedEvidence("v1 does not inspect image, audio, embedded resource, or resource-link results")
    text_json: Any = None
    if len(texts) == 1:
        try:
            text_json = strict_json(texts[0])
        except (ValueError, RecursionError):
            pass
    if structured is not None:
        if isinstance(text_json, dict) and canonical(structured) != canonical(text_json):
            raise ContractError("structuredContent contradicts the JSON text representation")
        payload = structured
    elif isinstance(text_json, dict):
        payload = text_json
    else:
        raise UnsupportedEvidence("profile requires an object in structuredContent or a single JSON text block")
    return Answer(False, "", payload, frame.size_bytes, frame.sha256)


def relative_record(value: Any, root: Path) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ContractError("observation path must be a nonempty, unambiguous POSIX path")
    path = Path(value)
    if ".." in path.parts:
        raise ContractError("observation contains a parent traversal")
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError as exc:
            raise ContractError("observation names a file outside the authorized fixture root") from exc
    if path.as_posix() in (".", ""):
        raise ContractError("a file observation cannot name the repository directory")
    return path.as_posix()


@dataclass
class Observation:
    processed: dict[str, dict[str, Any]] = field(default_factory=dict)
    excluded: dict[str, dict[str, Any]] = field(default_factory=dict)
    failed: dict[str, dict[str, Any]] = field(default_factory=dict)
    complete: bool | None = None
    unknown: list[str] = field(default_factory=list)


def observe(payload: dict[str, Any], profile: Profile, root: Path) -> Observation:
    obs = Observation()
    seen: set[str] = set()
    for name in ("processed", "excluded", "failed"):
        mapping: RecordMap | None = getattr(profile, name)
        if mapping is None:
            obs.unknown.append(name)
            continue
        entries = at(payload, mapping.pointer)
        if not isinstance(entries, list):
            raise ContractError(f"{name} observations must be an array")
        target = getattr(obs, name)
        for entry in entries:
            path = relative_record(at(entry, mapping.path), root)
            if path in seen:
                raise ContractError("duplicate or overlapping processed/excluded/failed paths")
            seen.add(path)
            record: dict[str, Any] = {}
            if mapping.reason is not None:
                reason = at(entry, mapping.reason)
                if not isinstance(reason, str) or not reason.strip() or reason.strip().rstrip(".!:").casefold() in ("error", "failed", "unknown", "exception", "internal error", "error occurred", "skip", "skipped"):
                    raise ContractError("exclusion/failure reason must be a nonempty string")
                record["reason"] = reason
            elif name != "processed":
                obs.unknown.append(name + ".reasons")
            if mapping.sha256 is not None:
                value = at(entry, mapping.sha256)
                if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                    raise ContractError("file digest must be a full SHA-256 hex value")
                record["sha256"] = value.lower()
            target[path] = record
        if name in profile.counts:
            count = at(payload, profile.counts[name])
            if type(count) is not int or count != len(target):
                raise ContractError(f"reported {name} count disagrees with its evidence records")
    if profile.complete is None:
        obs.unknown.append("complete")
    else:
        obs.complete = at(payload, profile.complete)
        if type(obs.complete) is not bool:
            raise ContractError("mapped completion flag must be a boolean")
    return obs


def fixture_checks(fixture: Fixture, profile: Profile, answer: Answer) -> list[Check]:
    prefix = fixture.name
    def check(name: str, status: Status, reason: str, **evidence: Any) -> Check:
        return Check(prefix + "." + name, "readiness", status, reason, evidence)
    if answer.error:
        return [check("correctness", Status.FAIL, "valid fixture request returned an error",
                      message=answer.message[:1024])]
    assert answer.payload is not None
    obs = observe(answer.payload, profile, fixture.root)
    all_inputs = set(fixture.files) | fixture.problems
    accounted = set(obs.processed) | set(obs.failed) | set(obs.excluded)
    missing_supported = fixture.expected_processed - set(obs.processed)
    unexpected = accounted - all_inputs
    omitted = all_inputs - accounted
    bad_exclusion_reasons = [p for p in fixture.expected_excluded & set(obs.excluded)
                             if "reason" in obs.excluded[p] and not any(s in obs.excluded[p]["reason"].casefold()
                             for s in ("unsupported", "suffix", "type", "binary", "scope"))]
    checks: list[Check] = []
    if unexpected or (missing_supported and profile.processed is not None):
        checks.append(check("coverage", Status.FAIL, "fixture files were omitted, failed, or replaced by unexpected records",
                            missing_supported=sorted(missing_supported), unexpected=sorted(unexpected)))
    elif any(x in obs.unknown for x in ("processed", "excluded", "failed")):
        checks.append(check("coverage", Status.UNKNOWN, "profile lacks evidence selectors needed to reconcile every input",
                            unavailable=obs.unknown, unaccounted=sorted(omitted)))
    elif omitted:
        checks.append(check("coverage", Status.FAIL, "server did not account for every provided input", unaccounted=sorted(omitted)))
    elif fixture.expected_excluded - set(obs.excluded) or bad_exclusion_reasons:
        checks.append(check("coverage", Status.FAIL, "unsupported fixture inputs were not explicitly excluded"))
    elif any(x.endswith(".reasons") for x in obs.unknown):
        checks.append(check("coverage", Status.UNKNOWN, "exclusions/failures have no mapped reason evidence"))
    else:
        checks.append(check("coverage", Status.PASS, "all fixture inputs independently reconcile with disjoint evidence records",
                            input_count=len(all_inputs), processed=len(obs.processed), excluded=len(obs.excluded), failed=len(obs.failed)))
    if profile.processed is None or profile.processed.sha256 is None:
        checks.append(check("content_correctness", Status.UNKNOWN,
                            "no content oracle mapping; file enumeration does not prove scanner finding correctness"))
    else:
        bad = [p for p in fixture.expected_processed if p not in obs.processed or
               obs.processed[p].get("sha256") != hashlib.sha256(fixture.files[p]).hexdigest()]
        checks.append(check("content_correctness", Status.FAIL if bad else Status.PASS,
                            "returned file digests disagree with fixture bytes" if bad else "file digests match independent fixture bytes",
                            mismatches=sorted(bad)))
    actual_partial = bool(obs.failed) or bool(missing_supported)
    if obs.complete is True and actual_partial:
        checks.append(check("honest_completion", Status.FAIL, "server reported complete despite failed or omitted required work"))
    elif obs.complete is None:
        checks.append(check("honest_completion", Status.UNKNOWN, "completion evidence is not mapped"))
    elif not actual_partial and obs.complete is False and not fixture.problems:
        checks.append(check("honest_completion", Status.FAIL, "server reported partial without any accounted failure"))
    else:
        checks.append(check("honest_completion", Status.PASS, "completion status agrees with the observed work"))
    if fixture.problems:
        processed_problem = fixture.problems & set(obs.processed)
        refused = fixture.problems & (set(obs.failed) | set(obs.excluded))
        causes = ("regular", "special", "fifo", "named pipe") if fixture.name == "special_file" else (
            "permission", "denied", "unreadable", "eacces") if fixture.name == "unreadable" else (
            "symlink", "symbolic link", "outside", "escape", "no such", "does not exist")
        bad_reasons = [p for p in refused if "reason" in (obs.failed.get(p) or obs.excluded.get(p, {})) and
                       not any(s in (obs.failed.get(p) or obs.excluded[p])["reason"].casefold() for s in causes)]
        status = Status.FAIL if processed_problem or fixture.problems - refused or bad_reasons else Status.PASS
        if status == Status.PASS and any(x.endswith(".reasons") for x in obs.unknown):
            status = Status.UNKNOWN
        checks.append(Check(prefix + ".boundary_refusal", "security", status,
                            "unsafe or unreadable entries require an explicit refusal and reason",
                            {"processed_unsafe": sorted(processed_problem), "accounted_refusals": sorted(refused), "wrong_reasons": sorted(bad_reasons)}))
    return checks


def reasoned_error(answer: Answer, argument: str, kind: str, path_argument: str) -> bool:
    if not answer.error:
        return False
    message = answer.message.casefold()
    if kind in ("missing", "file_as_root"):
        causes = ("not found", "does not exist", "not a directory", "no such", "missing file", "missing directory", "directory required")
        context = Path(argument).name.casefold() in message or path_argument.casefold() in message
    elif kind == "relative":
        causes = ("absolute", "relative path")
        context = True
    elif kind == "large":
        causes = ("output limit", "too large", "size limit", "byte limit", "result limit", "output_limit")
        context = any(s in message for s in ("narrow", "reduce", "page", "smaller", "limit"))
    else:
        causes = ("outside", "boundary", "authorized", "workspace", "root", "traversal", "symlink", "special", "regular", "permission", "denied", "unreadable")
        context = True
    return context and any(c in message for c in causes)


def repeatable_payload(payload: dict[str, Any], profile: Profile) -> bytes:
    normalized = copy.deepcopy(payload)
    def remove_timestamp(node: Any, parts: list[str]) -> None:
        key, rest = parts[0], parts[1:]
        if key == "*":
            if not isinstance(node, list):
                raise ContractError("timestamp wildcard can only traverse an array")
            for child in node:
                remove_timestamp(child, rest)
            return
        if not isinstance(node, dict):
            raise ContractError("timestamp selector crossed a non-object")
        if key not in node:
            return
        if rest:
            remove_timestamp(node[key], rest)
        else:
            stamp = node[key]
            if not isinstance(stamp, str):
                raise ContractError("ignored timestamp is not a timestamp string")
            try:
                parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError("timestamp needs timezone")
            except ValueError as exc:
                raise ContractError("ignored timestamp is not an ISO timestamp with timezone") from exc
            del node[key]
    for pointer in profile.ignored_timestamps:
        remove_timestamp(normalized, [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]])
    # These three arrays represent sets of file evidence. Other arrays retain order.
    for mapping in (profile.processed, profile.excluded, profile.failed):
        if mapping is not None:
            entries = at(normalized, mapping.pointer)
            if not isinstance(entries, list):
                raise ContractError("mapped evidence collection is not an array")
            entries.sort(key=lambda item: canonical(at(item, mapping.path)))
    return canonical(normalized)
