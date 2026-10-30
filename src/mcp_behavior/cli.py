"""CLI with fail-closed exit codes and atomic reports."""
from __future__ import annotations

import argparse
import html
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .model import HarnessError
from .runner import Runner


def cell(value: Any) -> str:
    return html.escape(str(value)).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def readable(report: dict[str, Any]) -> str:
    lines = ["# MCP Behavior assessment", "", f"Overall: **{report['verdict']}**", ""]
    for lane, result in report.get("lanes", {}).items():
        lines.append(f"{lane.capitalize()}: **{result}**  ")
    lines.extend(["", report.get("scope", ""), "", "| Check | Lane | Result | Evidence / reason |",
                  "|---|---|---|---|"])
    for check in report.get("checks", []):
        lines.append("| " + " | ".join(cell(check[k]) for k in ("id", "lane", "status", "reason")) + " |")
    lines.extend(["", "## Assessment identity", "", "```json", json.dumps({k: report[k] for k in
                  ("target", "profile", "config_sha256", "limits") if k in report}, indent=2, ensure_ascii=True), "```", "",
                  "## Limits on the conclusion", ""])
    lines.extend("- " + cell(x) for x in report.get("limitations", []))
    if report.get("harness_errors"):
        lines.extend(["", "Harness errors prevented evidence collection. See the JSON report."])
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise HarnessError("report destination cannot be a symlink")
    fd, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-behavior")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run", help="run the read-only repository profile against a stdio server")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path, help="JSON report; adjacent .md report is also written")
    run.add_argument("--native", action="store_true",
                     help="allow host subprocess execution (isolation=native); containment remains UNKNOWN")
    run.add_argument("--isolation", choices=("native", "namespace"), default=None,
                     help="execution backend: native (dev) or namespace (v0.2.0 target). "
                          "No silent fallback between modes.")
    run.add_argument("--server-uid", type=int, help="privileged Linux parent only: drop the server to this nonzero UID")
    run.add_argument("--server-gid", type=int)
    args = parser.parse_args(argv)

    if args.isolation is None and args.native:
        args.isolation = "native"
    if args.isolation is None:
        parser.error("choose an execution backend: --native (containment UNKNOWN) or --isolation namespace")
    if args.native and args.isolation != "native":
        parser.error("--native conflicts with --isolation " + args.isolation)

    from .isolation import ExecutionMode, IsolationPolicy, get_backend
    backend = get_backend(args.isolation)
    policy = IsolationPolicy(
        mode=ExecutionMode(args.isolation),
        server_uid=args.server_uid,
        server_gid=args.server_gid,
    )
    preflight = backend.preflight(policy)
    if not preflight.ok:
        # Fail closed: do not launch the subject when required controls are missing.
        print(json.dumps({
            "run_id": str(uuid.uuid4()),
            "verdict": "INCOMPLETE",
            "harness_error": "isolation preflight failed",
            "isolation": {
                "mode": args.isolation,
                "reasons": preflight.reasons(),
                "observed": preflight.observed,
            },
        }))
        return 2
    run_id = str(uuid.uuid4())
    try:
        if args.output.suffix != ".json":
            raise HarnessError("--output must end in .json")
        config = Config.load(args.config)
        # Keep evidence outside explicitly identified target artifacts.
        destinations = (args.output.resolve(), args.output.with_suffix(".md").resolve())
        protected = {p.resolve() for p in config.artifacts} | {args.config.resolve()}
        if any(p in protected for p in destinations):
            raise HarnessError("report destination overlaps the configuration or a target artifact")
        pending = {"schema_version": "mcp-behavior-report/v1", "run_id": run_id,
                   "verdict": "INCOMPLETE", "state": "RUNNING", "checks": []}
        atomic_write(args.output, json.dumps(pending, indent=2) + "\n")
        atomic_write(args.output.with_suffix(".md"), "# MCP Behavior assessment\n\nINCOMPLETE: run has not finished.\n")
        report = Runner(config, args.server_uid, args.server_gid,
                        isolation_backend=backend, isolation_preflight=preflight).run()
        report["run_id"] = run_id
        report["state"] = "FINISHED"
        # JSON is the authoritative commit marker for this pair of files.
        atomic_write(args.output.with_suffix(".md"), readable(report))
        atomic_write(args.output, json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
        print(json.dumps({"run_id": run_id, "verdict": report["verdict"], "lanes": report["lanes"], "report": str(args.output.absolute())}))
        return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[report["verdict"]]
    except Exception as exc:
        # Consumers must require exit 0, matching run_id, and state FINISHED.
        # If the destination itself cannot be written, only stdout/exit status can be updated.
        print(json.dumps({"run_id": run_id, "verdict": "INCOMPLETE", "harness_error": str(exc)[:1024]}))
        return 2
