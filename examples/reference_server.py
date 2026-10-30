"""Independent stdlib MCP test server. --mode injects known defects for self-tests.

This file imports no harness code. It enumerates files, rather than judging tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

parser = argparse.ArgumentParser()
parser.add_argument("--mode", default="good")
args = parser.parse_args()
MODE = args.mode
ROOT: Path | None = None
COUNT = 0


def emit(message):
    sys.stdout.write(json.dumps(message, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def tool_error(text):
    return {"isError": True, "content": [{"type": "text", "text": text}]}


def get_root():
    global ROOT
    if ROOT is None:
        emit({"jsonrpc": "2.0", "id": "fixture-root", "method": "roots/list", "params": {}})
        response = json.loads(sys.stdin.readline())
        ROOT = Path(unquote(urlparse(response["result"]["roots"][0]["uri"]).path)).resolve()
    return ROOT


def inspect(arguments):
    global COUNT
    COUNT += 1
    root = get_root()
    value = arguments.get("path")
    if not isinstance(value, str):
        return tool_error("path must be an absolute directory path")
    relative_bug = MODE == "cwd_relative" and not Path(value).is_absolute()
    if not Path(value).is_absolute() and not relative_bug:
        return tool_error("path must be absolute; relative paths are not accepted")
    path = Path(value).resolve()
    if MODE != "ignore_roots" and not relative_bug and not path.is_relative_to(root):
        return tool_error("path is outside the authorized workspace root")
    if not path.is_dir():
        return tool_error("Error" if MODE == "generic_error" else f"path {value} is not a directory or does not exist")
    if MODE == "oversized":
        return {"content": [], "structuredContent": {"padding": "X" * 1000000}}
    if MODE == "unsupported":
        return {"content": [{"type": "image", "mimeType": "image/png", "data": "AA=="}]}
    if MODE == "writes":
        (path / "unasked-for.txt").write_text("changed")
    if MODE == "slow" and (path / "blocked.py").exists():
        time.sleep(60)
    processed, excluded, failed = [], [], []
    for directory, directories, files in os.walk(path, followlinks=False):
        directories.sort()
        for dirname in list(directories):
            entry = Path(directory) / dirname
            if entry.is_symlink():
                directories.remove(dirname)
                failed.append({"path": entry.relative_to(path).as_posix(), "reason": "symlink directory refused"})
        for filename in sorted(files):
            entry = Path(directory) / filename
            relative = entry.relative_to(path).as_posix()
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode):
                failed.append({"path": relative, "reason": "symlink refused"})
                continue
            if not stat.S_ISREG(info.st_mode):
                failed.append({"path": relative, "reason": "not a regular file"})
                continue
            if entry.suffix not in (".py", ".js", ".txt"):
                excluded.append({"path": relative, "reason": "unsupported file suffix"})
                continue
            if MODE == "half_scan" and entry.suffix == ".js":
                continue
            try:
                data = entry.read_bytes()
            except OSError as exc:
                failed.append({"path": relative, "reason": f"{type(exc).__name__}: permission denied or file unreadable"})
                continue
            processed.append({"path": relative, "sha256": "0" * 64 if MODE == "wrong_digest" else hashlib.sha256(data).hexdigest()})
    payload = {"processed": processed, "excluded": excluded, "failed": failed,
               "complete": True if MODE == "false_complete" else not failed,
               "counts": {"processed": len(processed), "excluded": len(excluded), "failed": len(failed)},
               "generated_at": datetime.now(timezone.utc).isoformat()}
    if MODE == "duplicate" and processed:
        processed.append(processed[0])
        payload["counts"]["processed"] += 1
    if MODE == "unstable":
        payload["undeclared_nonce"] = os.urandom(8).hex()
    if MODE == "bad_timestamp":
        payload["generated_at"] = {"coverage": "hidden"}
    if MODE == "bad_count":
        payload["counts"]["processed"] += 1
    if MODE == "silently_truncate":
        payload["processed"] = processed[:2]
        payload["counts"]["processed"] = len(payload["processed"])
    result = {"content": [], "structuredContent": payload}
    if MODE == "contradictory":
        result["content"] = [{"type": "text", "text": json.dumps({"complete": False})}]
    if len(json.dumps({"jsonrpc": "2.0", "id": 999, "result": result}, separators=(",", ":")).encode()) + 1 > 65536:
        return tool_error("output limit: result is too large; narrow the directory or reduce the requested scope")
    return result


for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message.get("method")
    if MODE == "slow_each_request":
        time.sleep(.12)
    if MODE == "stderr_log":
        sys.stderr.write("ordinary diagnostic log\n")
        sys.stderr.flush()
    if MODE == "exit":
        sys.exit(7)
    if MODE == "invalid_json":
        sys.stdout.write('{"jsonrpc":"2.0","id":1,"result":NaN}\n')
        sys.stdout.flush()
        continue
    if MODE == "no_newline":
        sys.stdout.write("X" * 1000000)
        sys.stdout.flush()
        continue
    if MODE == "notification_flood":
        for _ in range(1000):
            emit({"jsonrpc": "2.0", "method": "notifications/progress"})
    if MODE == "stderr_flood":
        sys.stderr.write("X" * 1000000)
        sys.stderr.flush()
    if MODE == "hang":
        time.sleep(60)
    if method == "initialize":
        result = {"protocolVersion": "future-unsupported" if MODE == "future_protocol" else "2025-11-25",
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "reference-inventory", "version": "0.1.0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "inspect_repository", "description": "Inventory .py, .js, .txt files under the client root; reasoned errors; size refusal; read-only.",
                             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}]}
        if MODE == "pagination_loop":
            result["tools"] = []
            result["nextCursor"] = "again"
        if MODE == "task_only":
            result["tools"][0]["execution"] = {"taskSupport": "required"}
    elif method == "tools/call":
        result = inspect(message["params"].get("arguments", {}))
    elif method == "ping":
        result = {}
    else:
        emit({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "method not found"}})
        continue
    response_id = -99 if MODE == "wrong_id" else message["id"]
    emit({"jsonrpc": "2.0", "id": response_id, "result": result})
