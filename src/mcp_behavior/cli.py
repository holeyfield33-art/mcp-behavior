"""CLI with fail-closed exit codes and atomic reports."""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import load_config
from .model import HarnessError, Status, verdict
from .runner import run_suite


def _atomic_write(path: Path, data: dict) -> None:
    path = path.resolve()
    if path.is_symlink() or path.parent.is_symlink():
        raise HarnessError(f"refusing to write through symlink: {path}")
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-behavior")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run the read-only repository profile against a stdio server")
    run_p.add_argument("--config", required=True, help="path to reviewer-owned config JSON")
    run_p.add_argument("--output", required=True, help="path for the JSON report")
    run_p.add_argument("--native", action="store_true", help="allow native (non-isolated) execution; records containment UNKNOWN")
    run_p.add_argument("--server-uid", type=int, default=None)
    run_p.add_argument("--server-gid", type=int, default=None)

    args = parser.parse_args(argv)
    if args.cmd != "run":
        parser.error("unknown command")

    if not args.native:
        print("native execution required for this release; pass --native after reviewing the subject", file=sys.stderr)
        return 2

    run_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc).isoformat()
    out_path = Path(args.output)

    # Write RUNNING marker so a crash cannot leave a stale PASS.
    try:
        _atomic_write(out_path, {
            "run_id": run_id,
            "status": "RUNNING",
            "started_at": started,
            "verdict": "INCOMPLETE",
        })
    except Exception as exc:
        print(f"cannot write output: {exc}", file=sys.stderr)
        return 2

    try:
        cfg = load_config(Path(args.config))
        report = run_suite(
            cfg,
            run_id=run_id,
            native=True,
            server_uid=args.server_uid,
            server_gid=args.server_gid,
        )
        report["started_at"] = started
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["status"] = "FINISHED"
        _atomic_write(out_path, report)

        overall = report.get("verdict", "INCOMPLETE")
        if overall == "PASS":
            return 0
        if overall == "FAIL":
            return 1
        return 2
    except HarnessError as exc:
        _atomic_write(out_path, {
            "run_id": run_id,
            "status": "FINISHED",
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "verdict": "INCOMPLETE",
            "harness_error": str(exc)[:1024],
        })
        print(json.dumps({"run_id": run_id, "verdict": "INCOMPLETE", "harness_error": str(exc)[:1024]}))
        return 2
    except Exception as exc:
        _atomic_write(out_path, {
            "run_id": run_id,
            "status": "FINISHED",
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "verdict": "INCOMPLETE",
            "harness_error": f"internal: {exc}"[:1024],
            "traceback": traceback.format_exc()[:4096],
        })
        print(json.dumps({"run_id": run_id, "verdict": "INCOMPLETE", "harness_error": str(exc)[:1024]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
