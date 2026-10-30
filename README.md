# MCP Behavior

A standalone Linux CLI that drives a running MCP server and checks its behavior against independent fixtures.

The question is narrow: **can a caller rely on this tool's results and failure reports, under this versioned profile?** The server's description is never the answer key. The runtime has no dependencies outside Python's standard library.

**Status: working 0.1.0 prototype.** Native subprocess execution cannot prove containment. Every native run includes a required security UNKNOWN, so an otherwise successful run is INCOMPLETE overall. Use reviewed test subjects in a disposable environment. This release does not certify arbitrary hostile binaries as safe to run.

## Run the first proof

Requires Linux and Python 3.11 or newer.

```bash
PYTHONPATH=src python -m mcp_behavior run \
  --config examples/reference.json \
  --output out/reference.json \
  --native
```

Expected: readiness PASS, security INCOMPLETE, overall INCOMPLETE, exit 2.

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## What v1 checks

One profile: synchronous, read-only repository/file inventory. Independent checks for reasoned errors, bounded output, coverage, honest completion, content hashes, path boundaries, repeatability, read-only snapshots, and scripted recovery.

## License

MIT
