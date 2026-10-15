# Scan modes

This file is the only mode switch. Read it once before Phase A. Publication lists live in the lane files, not in the portal prompt.

## How a mode is chosen

| Caller says | Active lanes |
|---|---|
| Nothing (the skill is invoked directly) | **both** |
| `both` or `full` | **both** |
| `static` | **static** only |
| `logical` or `scanner_gaps` | **logical** only |

An unknown mode name is **both**. Do not invent a third publication list in the task text. If the task and this file disagree, this file wins.

## One pass, then route

Inventory, the file walk, and the coverage gate run **once** in every mode. `check_coverage_gate.py` still requires every `must_read_files` path. A mode filters what you publish. It does not mean a second read of the repo.

For each call site, pick **one** lane before G0–G5, adjudicate **once**, and emit **one** ID or one Appendix A row:

| What the code shows | Lane |
|---|---|
| Direct first-order sink, dangerous API, standalone secret, generic weak algorithm, handler-local missing auth, or a single-file header/CORS/TLS/IaC/mobile-manifest issue | **static** |
| Business, identity, ownership, state, trust-boundary, second-order, or multi-file issue, or a High/Critical control that a pattern scanner would treat as safe but a reachable path defeats | **logical** |
| A control is present and the reachable paths do not defeat it | Appendix A once. Do not reopen it in the other lane |

The same root cause is never both a static finding and a logical finding. A bypass is logical only; do not also publish the unprotected-sink version of that same path.

## What to load

Load a reference only when its lane is active. In **both**, load each file once and route candidates with the table above. Do not run a lang-pack sweep and then a second researcher sweep over those same sinks.

**Static lane** — read `references/scanner-static.md`. Also load, once:

- active `lang-packs/<pack>.md` (the sink list)
- `secrets-patterns.md` and `secret-type-labels.md`
- `iac-misconfig-scan.md` for **single-file** rules only
- `mobile-sast-manifest.md` for a flag that is visible in one manifest entry
- `xml-security-audit.md` for an unprotected parser or direct XML injection

**Logical lane** — read `references/scanner-blind-spots.md`. Also load, once, only when the repo triggers them:

- `senior-researcher.md` LOG-01…15
- `idor-bola-audit.md`, `authorization-privilege-escalation-audit.md`, `per-method-auth-audit.md` (effective route, not a missing local annotation)
- `business-logic-abuse-checklist.md`, `async-second-order-audit.md`, `jwt-deep-test.md`, `protocol-scans-graphql-ws-grpc.md`
- `mobile-sast-audit.md` and `deeplink-audit.md` when the finding needs the manifest plus the handler
- `iac-misconfig-scan.md` only for the multi-file cases named in `scanner-blind-spots.md`

Do not load the other lane’s files. In **logical**, do not publish from a lang-pack row; use a pack only as a hint that a control exists, then test item 5 in `scanner-blind-spots.md`. In **static**, do not load the logical audits above.

`senior-researcher.md` in **both**: static defects that match a lang-pack row stay static. Do not record them again as researcher findings.

## Report

One report. On each finding’s Classification line add `Lane: Static` or `Lane: Logical`. Logical findings also include `### Why conventional SAST misses this`. Static findings do not.

Phase C PoCs are only for findings the active lane will publish. Do not write a Burp request for a candidate this mode drops.

In the Completeness & Residual Risk Register, mark classes that belong to a lane you did not run as `N/A — other scan lane not selected`. Do not mark them PASS, and do not sweep them anyway.
