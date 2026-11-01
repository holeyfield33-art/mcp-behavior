# Software Research Studio link

**Studio archive:** https://github.com/holeyfield33-art/software-research-studio  
**Freeze:** SRS-FREEZE-2026-10-31-v1 (immutable knowledge baseline for Block-Wise Studio research)  
**Product pointer inside Studio:** `linked_products/mcp-behavior.md`

## Relationship

| Software Research Studio | This repository (mcp-behavior) |
|---|---|
| Frozen deterministic selector / SDLC knowledge research | Live MCP behavioral assessment product |
| Do not mutate freeze digests or `current_003R/` | Develops on `main` under its own roadmap |
| Selector generalization remains NO-GO | Helper evidence GO in stated container env; full containment PASS NO-GO |

Studio patterns may *describe* this product (CLI tool, evidence gates, isolation architecture). They do **not** authorize releases. Product gates live only here: `docs/STATUS.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`.

## Using both

```bash
# Product work
git clone https://github.com/holeyfield33-art/mcp-behavior.git

# Knowledge archive (read-only baseline)
git clone https://github.com/holeyfield33-art/software-research-studio.git
# See software-research-studio/linked_products/mcp-behavior.md
```

New Studio research that treats mcp-behavior as a reference case must be a **new Studio checkpoint**, not an edit to the 2026-10-31 freeze.
