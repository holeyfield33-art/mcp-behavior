"""Externally observed IPv4/IPv6 loopback TCP probes for a candidate bubble.

The listener is controller-owned. A host positive control must arrive before the
isolated helper runs; matching isolated traffic disproves the candidate denial.
Silence alone cannot pass: typed helper results, both controls and intact observer
shutdown are required. Other protocols, routes and actual server runs are ungraded.
"""
from __future__ import annotations

import errno
import json
import socket
import subprocess
import sys
import threading
import uuid
from typing import Any

from .config import strict_json
from .namespace_runtime import (
    LaunchPlan, ProbeResult, _bwrap_command, _capture_probe, _validated_plan, tool_preflight,
)


class EndpointObserver:
    def __init__(self) -> None:
        self.listeners: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.endpoints: list[dict[str, Any]] = []
        self.messages: list[tuple[str, str]] = []
        self.errors: list[str] = []
        self.stopped = threading.Event()
        self.lock = threading.Lock()

    def start(self) -> None:
        try:
            for family, label, host in ((socket.AF_INET, "ipv4", "127.0.0.1"),
                                        (socket.AF_INET6, "ipv6", "::1")):
                listener = socket.socket(family, socket.SOCK_STREAM)
                self.listeners.append(listener)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((host, 0))
                listener.listen(4)
                listener.settimeout(0.05)
                self.endpoints.append({"family": label, "host": host, "port": listener.getsockname()[1]})
                thread = threading.Thread(target=self._receive, args=(listener, label), daemon=True)
                thread.start()
                self.threads.append(thread)
        except OSError:
            self.close()
            raise

    def _receive(self, listener: socket.socket, label: str) -> None:
        accepted = 0
        while not self.stopped.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stopped.is_set():
                    with self.lock:
                        self.errors.append(f"{label} listener failed: {exc}")
                break
            accepted += 1
            if accepted > 8:
                connection.close()
                with self.lock:
                    self.errors.append(f"{label} connection budget exceeded")
                break
            try:
                with connection:
                    connection.settimeout(0.2)
                    data = bytearray()
                    while b"\n" not in data and len(data) <= 128:
                        chunk = connection.recv(129 - len(data))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if len(data) > 128 or not data.endswith(b"\n") or data.count(b"\n") != 1:
                        raise ValueError("invalid or oversized observer frame")
                    message = data[:-1].decode("ascii")
                    with self.lock:
                        self.messages.append((label, message))
                    connection.sendall(b"ACK")
            except (OSError, ValueError) as exc:
                with self.lock:
                    self.errors.append(f"{label} observer connection failed: {exc}")

    def close(self) -> None:
        self.stopped.set()
        for listener in self.listeners:
            listener.close()
        for thread in self.threads:
            thread.join(timeout=1)
        with self.lock:
            if any(thread.is_alive() for thread in self.threads):
                self.errors.append("network observer did not stop within its deadline")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {"endpoints": list(self.endpoints), "messages": list(self.messages), "errors": list(self.errors)}


_NETWORK_HELPER = r'''
import errno, json, socket, sys
endpoints, nonce, phase = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
out = {"nonce": nonce, "phase": phase, "results": {}}
for endpoint in endpoints:
    family = socket.AF_INET if endpoint["family"] == "ipv4" else socket.AF_INET6
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            sock.connect((endpoint["host"], endpoint["port"]))
            sock.sendall((phase + ":" + nonce + "\n").encode("ascii"))
            if sock.recv(3) != b"ACK":
                raise OSError(errno.EPROTO, "observer did not acknowledge")
        out["results"][endpoint["family"]] = {"connected": True, "errno": None}
    except OSError as exc:
        out["results"][endpoint["family"]] = {"connected": False, "errno": exc.errno or errno.ETIMEDOUT}
print(json.dumps(out))
'''


def _results(raw: bytes, nonce: str, phase: str) -> dict[str, dict[str, Any]]:
    payload = strict_json(raw.decode("utf-8"))
    if (not isinstance(payload, dict) or set(payload) != {"nonce", "phase", "results"}
            or payload["nonce"] != nonce or payload["phase"] != phase
            or not isinstance(payload["results"], dict) or set(payload["results"]) != {"ipv4", "ipv6"}):
        raise ValueError("network helper schema, coverage or run nonce mismatch")
    for result in payload["results"].values():
        if (not isinstance(result, dict) or set(result) != {"connected", "errno"}
                or type(result["connected"]) is not bool):
            raise ValueError("invalid typed network helper evidence")
        if result["connected"]:
            if result["errno"] is not None:
                raise ValueError("contradictory network helper evidence")
        elif (type(result["errno"]) is not int or result["errno"] not in
              (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.EACCES, errno.EPERM, errno.ETIMEDOUT)):
            raise ValueError("unexpected network failure cannot prove endpoint denial")
    return payload["results"]


def run_network_probe(plan: LaunchPlan, token: str) -> ProbeResult:
    evidence: dict[str, Any] = {"scope": "synthetic IPv4/IPv6 loopback TCP only; no general or run-level network verdict"}
    observer = EndpointObserver()
    success, detail = False, "network evidence incomplete"
    try:
        plan = _validated_plan(plan, token)
        tools = tool_preflight()
        evidence["tools"] = tools.evidence
        if not tools.ok:
            return ProbeResult(False, f"network probe unavailable: {tools.detail}", evidence)
        observer.start()
        nonce = uuid.uuid4().hex
        endpoints = json.dumps(observer.endpoints)
        evidence["probe_nonce"] = nonce
        host = _capture_probe([sys.executable, "-I", "-S", "-c", _NETWORK_HELPER,
                               endpoints, nonce, "host"], plan.workspace)
        if host.returncode != 0:
            raise ValueError("network positive control helper failed")
        positive = _results(host.stdout, nonce, "host")
        received = set(map(tuple, observer.snapshot()["messages"]))
        if (not all(r["connected"] for r in positive.values())
                or not {("ipv4", "host:" + nonce), ("ipv6", "host:" + nonce)} <= received):
            raise ValueError("controller did not observe both network positive controls")
        evidence["positive_controls"] = positive
        isolated = _capture_probe(_bwrap_command(plan, tools.evidence["bwrap"], [
            "/usr/bin/python3", "-I", "-S", "-c", _NETWORK_HELPER, endpoints, nonce, "isolated",
        ]), plan.workspace)
        evidence["returncode"] = isolated.returncode
        evidence["stderr_tail"] = isolated.stderr[-500:].decode("utf-8", "replace")
        if isolated.returncode != 0:
            raise ValueError(f"candidate network helper exit {isolated.returncode}")
        negative = _results(isolated.stdout, nonce, "isolated")
        evidence["isolated_results"] = negative
        success = not any(result["connected"] for result in negative.values())
        detail = ("both tested host TCP endpoints denied to trusted helper; other egress remains ungraded"
                  if success else "candidate view reached a controlled host TCP endpoint")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        detail = f"network probe unavailable or failed: {exc}"
    finally:
        observer.close()
        observed = observer.snapshot()
        evidence["observer"] = observed
    nonce = evidence.get("probe_nonce")
    if any(message == "isolated:" + str(nonce) for _, message in observed["messages"]):
        success = False
        detail = "external observer received isolated traffic; candidate endpoint denial failed"
    if observed["errors"]:
        success = False
        detail += "; network observer incomplete: " + "; ".join(observed["errors"])
    allowed = {(family, phase + ":" + str(nonce)) for family in ("ipv4", "ipv6")
               for phase in ("host", "isolated")}
    messages = list(map(tuple, observed["messages"]))
    if any(message not in allowed for message in messages) or len(messages) != len(set(messages)):
        success = False
        detail += "; unexpected or duplicate traffic makes observer coverage incomplete"
    return ProbeResult(success, detail, evidence)
