# AI Security Reviewer Pro Max Skills

Cursor and Claude agent skill. **You** are the scanner: read first-party code, trace source→sink, adjudicate with G0–G5, and deliver `<repo>_security_report.md` + HTML. No Semgrep-only pass, no dependency/CVE (SCA) mode.

**Version 4.59.0**

**GitHub:** https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills  
**Docs:** https://mukeshj008.github.io/Ai-Security-Reviewer-Pro-Max-Skills/

Search: `AI Security Reviewer Pro Max Skills` · `Mukeshj008 Ai-Security-Reviewer-Pro-Max-Skills`

---

## What you get

- `<repo>_security_report.md` and `.html` with executive summary, checklist, detailed findings, residual risk register, and appendices.
- Each finding: root-cause title, issue-specific description/impact/remediation, instances table, data flow, Burp PoC for HTTP issues, confidence (Confirmed / Firm / Tentative).
- False positives go to **Appendix A only** — not in the main finding list.
- Same root cause → **one finding ID** with an instances table (not one ID per path).

## Scan Modes

`references/scan-modes.md` is the mode switch and lane router:

| Mode | What runs |
|------|-----------|
| No mode / `both` / `full` | Static SAST lane + logical lane, one file walk |
| `static` | Conventional SAST-style issues only |
| `logical` / `scanner_gaps` | Business/auth/trust-boundary/control-bypass findings only |

Each call site is adjudicated once and published in one lane only. Unselected-lane classes are recorded as `N/A — other scan lane not selected`, not silently passed.

## What it looks for

Static lane: injection, dangerous APIs, handler-local missing auth, secrets in source, TLS/crypto misuse, CORS/headers, open redirects, XML/XXE, and single-file Docker/K8s/Terraform/mobile findings.

Logical lane: IDOR/BOLA/BFLA, business workflow abuse, JWT/session context flaws, cross-route auth gaps, second-order issues, webhook/callback trust, race/replay/idempotency bugs, mobile/deep-link correlation, multi-file IaC/CI relationships, and High/Critical control bypasses a pattern scanner would treat as safe.

Both lanes use the same G0–G5, AI Validate, severity, dedupe, and coverage gates.

**Out of scope:** `npm audit`, OSV, Trivy, SBOM, `SCA-NNN`, quantum-only/HNDL-only findings. Mark those rows **Residual — not in skill scope**.

## How a review runs (single agent)

1. **`enumerate_inventory.py`** — one inventory per target (files, HTTP modules, language packs).
2. **`scan-modes.md`** chooses static, logical, or both lanes.
3. **`appsec-specialist-operating-mode.md`** sets the senior AppSec / researcher frame: assets, actors, trust boundaries, sensitive operations, attacker stories, evidence discipline.
4. **`next_read_batch.py`** → read every batch → **`--ack`** until `BATCH_EMPTY` (tests included; no “continue” prompts).
5. Map configs/routes → active-lane review only: language-pack sinks for static, effective-route/business/logic walks for logical.
6. **Adjudicate** per call site (`ai-validate-precision-pass.md`); false positives go to Appendix A only.
7. **DAST:** Burp PoC on every HTTP finding; live **curl** only after user approval; never probe localhost.
8. **`check_coverage_gate.py` must exit 0** before you say “scan complete” or ship final HTML.
9. **`generate_html_report.py --strict`** on the derived `<repo>_security_report.md` filename.

Large repos: follow `references/large-repo-runner.md` — finish every module in one session (no shard workers).

## Install

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.cursor/skills/ai-security-reviewer
# Claude Code: ~/.claude/skills/ai-security-reviewer
```

Restart the IDE, attach the skill, then ask: `Review this code for security vulnerabilities`.

Report slug:

```bash
python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py
```

## Contract (short)

| Rule | Detail |
|------|--------|
| **Single agent** | No Task/subagent shards; you own reads, AUTH, flows, report. |
| **Coverage gate** | 100% of `must_read_files` acked in `.security-review/files-read.log`. |
| **TP/FP gate** | G0–G5 + class-specific ADJ + AI Validate before any finding ID. FP → Appendix A only. |
| **Lane discipline** | Static and logical findings are routed once per call site; no duplicate root causes across lanes. |
| **No SCA** | Dependency CVE tools forbidden (v4.46+). |
| **Helpers only** | `enumerate_inventory.py`, `next_read_batch.py`, `check_coverage_gate.py`, `derive_report_name.py`, `generate_html_report.py --strict`. |
| **DAST** | Burp PoC always; curl with permission. |

Full rules: **`SKILL.md`**. History: **`CHANGELOG.md`**.

## Layout

| Path | Role |
|------|------|
| `SKILL.md` | Entry instructions |
| `references/scan-modes.md` | Static/logical/both mode router |
| `references/appsec-specialist-operating-mode.md` | Senior AppSec / researcher reasoning frame |
| `references/scanner-static.md` | Conventional SAST publication contract |
| `references/scanner-blind-spots.md` | Logical/scanner-gaps publication contract |
| `references/` | Manifests, gates, templates, language packs |
| `references/finding-templates.md` | Description, endpoints, impact, remediation |
| `references/lang-packs/` | Per-language sink catalog (L01–L35) |
| `scripts/generate_html_report.py` | Markdown → HTML (`--strict`) |
| `scripts/check_coverage_gate.py` | Blocks “complete” until inventory read |

## Author

**Mukeshj008** — scan only systems you are authorized to test.
