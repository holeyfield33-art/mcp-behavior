"""Bounded stdio JSON-RPC, with limits applied before decoding server output.

This is a deliberately small MCP client, not a protocol conformance suite.
Never use readline() or the SDK's unbounded response buffering here.
"""
from __future__ import annotations

import hashlib
import errno
import json
import os
import resource
import selectors
import signal
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Limits, canonical, digest, strict_json
from .model import HarnessError, ServerFault, UnsupportedEvidence

VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")


def child_setup(limits: Limits, uid: int | None, gid: int | None) -> None:
    """Resource ceilings are a backstop, not a sandbox or a server success."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if os.geteuid() == 0:
        # Keep UID 0 from recovering capabilities on exec in single-UID containers.
        if libc.prctl(28, 15, 0, 0, 0) != 0 and ctypes.get_errno() != errno.EPERM:
            raise OSError(ctypes.get_errno(), "cannot lock securebits")
    if uid is not None:
        os.setgroups([])
        os.setgid(gid if gid is not None else uid)
        os.setuid(uid)
    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_mib * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024**2,) * 2)
    # Linux: a child cannot recover privilege through setuid executables.
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "cannot set no_new_privs")
    class CapHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class CapData(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]
    header, data = CapHeader(0x20080522, 0), (CapData * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "cannot drop server capabilities")


@dataclass
class Frame:
    message: dict[str, Any]
    size_bytes: int
    sha256: str


class StdioClient:
    def __init__(self, command: tuple[str, ...], cwd: Path, root: Path, home: Path,
                 limits: Limits, uid: int | None = None, gid: int | None = None,
                 suite_deadline: float | None = None):
        self.limits = limits
        self.root = root
        self.command = command
        self._id = 0
        self._buffer = bytearray()
        self._frames: deque[Frame] = deque()
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self.stderr_hash = hashlib.sha256()
        self.message_count = 0
        self.events: list[str] = []
        self.initialized = False
        self.server_info: dict[str, Any] = {}
        self.protocol_version = ""
        self.tools_sha256 = ""
        self.phase = "startup"
        self.last_frame: Frame | None = None
        self.selector = selectors.DefaultSelector()
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
               "HOME": str(home), "TMPDIR": str(home / "tmp"), "PYTHONDONTWRITEBYTECODE": "1"}
        started = time.monotonic()
        self.case_deadline = started + limits.case_timeout_seconds
        self.suite_deadline = suite_deadline
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, cwd=cwd, env=env, start_new_session=True,
                                            preexec_fn=lambda: child_setup(limits, uid, gid))
        except (OSError, subprocess.SubprocessError) as exc:
            self.selector.close()
            raise HarnessError(f"could not launch server: {type(exc).__name__}: {exc}") from exc
        self.launch_seconds = time.monotonic() - started
        assert self.process.stdout and self.process.stderr and self.process.stdin
        for stream, label in ((self.process.stdout, "stdout"), (self.process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(self.process.stdin.fileno(), False)

    def metadata(self) -> dict[str, Any]:
        return {"stdout_bytes": self.stdout_bytes, "stderr_bytes": self.stderr_bytes,
                "stderr_sha256": self.stderr_hash.hexdigest(), "messages": self.message_count,
                "server_reported_identity": self.server_info, "protocol_version": self.protocol_version,
                "tools_sha256": self.tools_sha256, "events": list(self.events), "phase": self.phase}

    def _fault(self, code: str, message: str, **extra: Any) -> ServerFault:
        return ServerFault(code, message, {**self.metadata(), **extra})

    def _deadline(self) -> float:
        if self.suite_deadline is not None and time.monotonic() >= self.suite_deadline:
            raise UnsupportedEvidence("suite budget ended before this scenario's evidence could be collected")
        deadline = min(time.monotonic() + self.limits.timeout_seconds, self.case_deadline)
        return min(deadline, self.suite_deadline) if self.suite_deadline is not None else deadline

    def _expired(self) -> None:
        if self.suite_deadline is not None and time.monotonic() >= self.suite_deadline:
            raise UnsupportedEvidence("suite budget ended before this scenario's evidence could be collected")
        raise self._fault("timeout", "server did not complete before the fixed deadline")

    def _send(self, message: dict[str, Any], deadline: float) -> None:
        raw = canonical(message) + b"\n"
        if len(raw) > 65536:
            raise HarnessError("client request exceeds 64 KiB")
        assert self.process.stdin
        view = memoryview(raw)
        while view:
            if time.monotonic() >= deadline:
                self._expired()
            try:
                sent = os.write(self.process.stdin.fileno(), view)
                view = view[sent:]
            except BlockingIOError:
                self._pump(deadline)
            except BrokenPipeError as exc:
                raise self._fault("disconnect", "server closed stdin before the request completed") from exc

    def _pump(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self._expired()
        events = self.selector.select(min(remaining, .1))
        for key, _ in events:
            try:
                chunk = os.read(key.fileobj.fileno(), 16384)
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                if key.data == "stdout":
                    # Finish already-framed replies first. A trailing partial frame is a failure.
                    if self._buffer:
                        raise self._fault("framing", "server closed stdout inside a JSON-RPC frame")
                    if not self._frames:
                        raise self._fault("disconnect", "server closed stdout before a reply")
                continue
            if key.data == "stderr":
                self.stderr_bytes += len(chunk)
                self.stderr_hash.update(chunk)
                if self.stderr_bytes > self.limits.max_stderr_bytes:
                    raise self._fault("stderr_limit", "server exceeded the stderr byte budget")
                continue
            self.stdout_bytes += len(chunk)
            if self.stdout_bytes > self.limits.max_session_bytes:
                raise self._fault("session_limit", "server exceeded the session output budget")
            self._buffer.extend(chunk)
            while b"\n" in self._buffer:
                end = self._buffer.index(b"\n")
                if end + 1 > self.limits.max_frame_bytes:
                    raise self._fault("frame_limit", "server exceeded the frame byte limit before JSON decoding",
                                      observed_frame_bytes=end + 1,
                                      observed_prefix_sha256=hashlib.sha256(self._buffer).hexdigest())
                raw = bytes(self._buffer[:end])
                del self._buffer[:end + 1]
                self.message_count += 1
                if self.message_count > self.limits.max_messages:
                    raise self._fault("message_limit", "server exceeded the message count budget")
                try:
                    msg = strict_json(raw.decode("utf-8", errors="strict"))
                except (ValueError, UnicodeError, RecursionError) as exc:
                    raise self._fault("invalid_json", "server emitted invalid, duplicate-key, or excessively nested JSON") from exc
                if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                    raise self._fault("invalid_envelope", "server emitted a non-JSON-RPC message")
                self._frames.append(Frame(msg, len(raw) + 1, hashlib.sha256(raw + b"\n").hexdigest()))
            if len(self._buffer) > self.limits.max_frame_bytes:
                raise self._fault("frame_limit", "server exceeded the frame byte limit before a newline or JSON decoding",
                                  observed_frame_bytes=len(self._buffer),
                                  observed_prefix_sha256=hashlib.sha256(self._buffer).hexdigest())
        if not events and self.process.poll() is not None and not self._frames:
            raise self._fault("disconnect", f"server exited with status {self.process.returncode}")

    def request(self, method: str, params: dict[str, Any]) -> Frame:
        self.phase = method
        self._id += 1
        request_id = self._id
        deadline = self._deadline()
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}, deadline)
        while True:
            if time.monotonic() >= deadline:
                self._expired()
            if not self._frames:
                self._pump(deadline)
                continue
            frame = self._frames.popleft()
            msg = frame.message
            if "method" in msg:
                if not isinstance(msg["method"], str) or "result" in msg or "error" in msg:
                    raise self._fault("invalid_envelope", "invalid server request/notification")
                if "id" not in msg:
                    self.events.append(msg["method"][:128])
                    continue
                if type(msg["id"]) not in (int, str):
                    raise self._fault("invalid_envelope", "invalid server request ID")
                response: dict[str, Any] = {"jsonrpc": "2.0", "id": msg["id"]}
                if msg["method"] == "ping":
                    response["result"] = {}
                elif msg["method"] == "roots/list" and self.initialized:
                    response["result"] = {"roots": [{"uri": self.root.as_uri(), "name": "fixture"}]}
                else:
                    response["error"] = {"code": -32601, "message": "Capability not supported by this test client"}
                    self.events.append("unsupported:" + msg["method"][:100])
                self._send(response, deadline)
                continue
            if type(msg.get("id")) is not int or msg["id"] != request_id:
                raise self._fault("response_id", "server response ID does not match the pending request")
            if ("result" in msg) == ("error" in msg):
                raise self._fault("invalid_envelope", "response must have exactly one of result/error")
            if "error" in msg:
                err = msg["error"]
                if not isinstance(err, dict) or type(err.get("code")) is not int or not isinstance(err.get("message"), str):
                    raise self._fault("invalid_envelope", "invalid JSON-RPC error")
            elif not isinstance(msg["result"], dict):
                raise self._fault("invalid_envelope", "MCP result must be an object")
            self.last_frame = frame
            return frame

    def initialize(self) -> None:
        frame = self.request("initialize", {"protocolVersion": VERSIONS[0],
                              "capabilities": {"roots": {"listChanged": False}},
                              "clientInfo": {"name": "mcp-behavior", "version": "0.1.0"}})
        result = frame.message.get("result")
        if result is None:
            raise self._fault("initialization", "server refused initialization")
        if result.get("protocolVersion") not in VERSIONS:
            raise UnsupportedEvidence("server negotiated a protocol revision this client does not implement")
        info = result.get("serverInfo")
        caps = result.get("capabilities")
        if not isinstance(info, dict) or not isinstance(info.get("name"), str) or not isinstance(info.get("version"), str) or not isinstance(caps, dict):
            raise self._fault("initialization", "incomplete initialization metadata")
        self.protocol_version = result["protocolVersion"]
        self.server_info = {k: info[k][:256] for k in ("name", "version")}
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"}, self._deadline())
        self.initialized = True

    def tool(self, name: str) -> dict[str, Any]:
        tools: dict[str, dict[str, Any]] = {}
        seen: set[str] = set()
        cursor: str | None = None
        for _ in range(16):
            frame = self.request("tools/list", {"cursor": cursor} if cursor is not None else {})
            result = frame.message.get("result", {})
            page = result.get("tools")
            if not isinstance(page, list):
                raise self._fault("tools_list", "server did not return a tool list")
            for item in page:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("inputSchema"), dict):
                    raise self._fault("tools_list", "invalid tool metadata")
                if item["name"] in tools or len(tools) >= 256:
                    raise self._fault("tools_list", "duplicate tool or tool-count budget exceeded")
                tools[item["name"]] = item
            cursor = result.get("nextCursor")
            if cursor is None:
                self.tools_sha256 = digest(tools)
                if name not in tools:
                    raise UnsupportedEvidence("profile's explicitly selected tool is not available")
                selected = tools[name]
                execution = selected.get("execution", {})
                if not isinstance(execution, dict):
                    raise self._fault("tools_list", "invalid tool execution metadata")
                if execution.get("taskSupport") == "required":
                    raise UnsupportedEvidence("task-only tools are outside v1's synchronous client")
                return selected
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise self._fault("pagination", "invalid or repeated tool-list cursor")
            seen.add(cursor)
        raise self._fault("pagination", "tool discovery exceeded its page budget")

    def call(self, name: str, arguments: dict[str, Any]) -> Frame:
        frame = self.request("tools/call", {"name": name, "arguments": arguments})
        if frame.size_bytes > self.limits.max_result_bytes:
            raise self._fault("result_limit", "tool response exceeded the profile's wire byte limit",
                              response_bytes=frame.size_bytes, response_sha256=frame.sha256)
        return frame

    def close(self) -> None:
        # Kill the process group even if its leader has already exited. A native
        # child that deliberately leaves the group is a documented containment gap.
        try:
            if self.process.stdin:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=.15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=.15)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=2)
            self.selector.close()
            for stream in (self.process.stdout, self.process.stderr):
                if stream:
                    stream.close()
