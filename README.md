# AI Security Reviewer Pro Max Skills

Cursor and Claude agent skill. **You** are the scanner: read first-party code, trace source→sink, adjudicate with G0–G5, and deliver `<repo>_security_report.md` + HTML. No Semgrep-only pass, no dependency/CVE (SCA) mode.

**Version 4.57.0**

**GitHub:** https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills  
**Docs:** https://mukeshj008.github.io/Ai-Security-Reviewer-Pro-Max-Skills/

Search: `AI Security Reviewer Pro Max Skills` · `Mukeshj008 Ai-Security-Reviewer-Pro-Max-Skills`

---

## What you get

- `<repo>_security_report.md` and `.html` with executive summary, checklist, detailed findings, residual risk register, and appendices.
- Each finding: root-cause title, issue-specific description/impact/remediation, instances table, data flow, Burp PoC for HTTP issues, confidence (Confirmed / Firm / Tentative).
- False positives go to **Appendix A only** — not in the main finding list.
- Same root cause → **one finding ID** with an instances table (not one ID per path).

## What it looks for

Injection, missing auth, IDOR/BOLA/BFLA, JWT/session flaws, secrets in source, TLS/crypto misuse, CORS, open redirects, XML/XXE, Docker/K8s/Terraform misconfig, mobile/deep-link issues, and logic abuse beyond the legacy 109-check hint list — all at the same G0–G5 bar.

**Out of scope:** `npm audit`, OSV, Trivy, SBOM, `SCA-NNN`, quantum-only/HNDL-only findings. Mark those rows **Residual — not in skill scope**.

## How a review runs (single agent)

1. **`enumerate_inventory.py`** — one inventory per target (files, HTTP modules, language packs).
2. **`next_read_batch.py`** → read every batch → **`--ack`** until `BATCH_EMPTY` (tests included; no “continue” prompts).
3. Map configs/routes → per-method **AUTH** walk → source→sink on language packs → senior-researcher logic pass.
4. **Adjudicate** per call site (`ai-validate-precision-pass.md`); severity from route exposure + four-factor rubric.
5. **DAST:** Burp PoC on every HTTP finding; live **curl** only after user approval; never probe localhost.
6. **`check_coverage_gate.py` must exit 0** before you say “scan complete” or ship final HTML.
7. **`generate_html_report.py --strict`** on the derived `<repo>_security_report.md` filename.

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
| **No SCA** | Dependency CVE tools forbidden (v4.46+). |
| **Helpers only** | `enumerate_inventory.py`, `next_read_batch.py`, `check_coverage_gate.py`, `derive_report_name.py`, `generate_html_report.py --strict`. |
| **DAST** | Burp PoC always; curl with permission. |

Full rules: **`SKILL.md`**. History: **`CHANGELOG.md`**.

## Layout

| Path | Role |
|------|------|
| `SKILL.md` | Entry instructions |
| `references/` | Manifests, gates, templates, language packs |
| `references/finding-templates.md` | Description, endpoints, impact, remediation |
| `references/lang-packs/` | Per-language sink catalog (L01–L35) |
| `scripts/generate_html_report.py` | Markdown → HTML (`--strict`) |
| `scripts/check_coverage_gate.py` | Blocks “complete” until inventory read |

## Author

**Mukeshj008** — scan only systems you are authorized to test.
