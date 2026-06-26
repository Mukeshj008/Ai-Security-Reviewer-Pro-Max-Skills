# Agent-Only Execution (MANDATORY)

**You are the scanner.** This skill provides **directions and checklists** — not runnable scan pipelines.

**Quality bar:** Act as a Senior Application Security Engineer. Report only **realistic, exploitable** issues with **high confidence**. See **`manual-code-review.md`** for context-first methodology and pre-report gates.

## Do NOT use (agent workflow)

| Forbidden for analysis | Why |
|------------------------|-----|
| `scripts/run_sast_scan.sh` | Agent runs manifest `rg` commands directly |
| `scripts/run_cve_iac_scan.sh` | Agent runs `cve-exploitability.md` + `iac-misconfig-scan.md` patterns |
| `scripts/discover_burp_hosts.sh` | Agent runs `rg` in `burp-host-discovery.md` |
| `scripts/generate_coverage_appendix.py` | Agent writes Appendix E/F rows from `report-coverage-matrix.md` |
| Semgrep / OpenGrep CLI | Agent + `rg` + graphify + AI validation only |
| Subagents (`Task`, `explore`) | Single-session context for reachability |
| **Ollama** (`--backend ollama`, `OLLAMA_BASE_URL`) | Use **Cursor native AI** (you) for semantic work; AST-only `graphify extract <code-dirs>` or `/graphify .` for graph build |

## DO use (your tools)

| Tool | Purpose |
|------|---------|
| **Graphify** | `query`, `path`, `explain`, `affected` — attack surface + reachability |
| **rg / Grep** | Run each command block in manifest reference files |
| **Read** | Confirm hits ±5 lines; never whole files unless tiny |
| **npm audit** / lockfile Read | CVE-DEPS-* (you interpret output) |
| **Burp MCP** | `send_http1_request` per `dast_scan_manifest.md` |
| **curl** | Live DAST fallback when Burp MCP unavailable — `curl-dast-fallback.md` |
| **Your reasoning** | AI validation, CVE reachability, architect assessment, **pre-report gates G1–G5** |

## Review order (mandatory)

1. **Phase −1** — Application context (`manual-code-review.md`): language, framework, trust boundaries, auth, sensitive assets.
2. **Phase 0+** — Graphify, manifests, CVE, IaC, architect, auth audit, **extended taxonomy scans**, Burp per `SKILL.md`.
3. **Per candidate** — Taint trace source→sink; `graphify path` for injection/CVE/SSRF.
4. **Pre-report gates** — G1–G5 must PASS before FINDING; else Appendix A.

## Per-check execution loop

For **each** row in `report-coverage-matrix.md` (109 checks):

1. Open the manifest section for that check ID.
2. Run the documented `rg` / `graphify` / `npm audit` commands **yourself** (Shell or Grep tool).
3. On hits: narrow `Read` → `graphify path` if taint/reachability needed.
4. Apply **pre-report gates G1–G5** (`manual-code-review.md`) then the AI validation checklist → PASS or FINDING.
5. Record in Appendix E: Status, Finding Ref, Match Count, Notes.

**Reachability (CVE, injection, SSRF):** Always `graphify path "<source>" "<sink>"` before FINDING — never report from `rg` alone.

**False positives:** Pattern match without G1–G2 PASS → Appendix A with failed gate. When in doubt, do not report.

## Appendix E without scripts

Copy the 109-row table structure from `report-coverage-matrix.md` into `security_report.md`. Fill every row manually as you complete checks. No `PENDING` at handoff.

## Appendix F without scripts

Log each phase as you complete it (Phase −1 context, graphify query, manifest section, extended taxonomy scan, Burp probe). Tool column = what **you** ran (`rg`, `graphify path`, `npm audit`), not a script name.

## Appendix H — taxonomy attestation (mandatory)

After core 109 checks, run **`extended-category-scans.md`** for every **Partial** row in `vulnerability-taxonomy-coverage.md` that applies to the detected stack.

1. Mark **N/A** domain groups (e.g. TAX-MEM for Node-only, TAX-MOBILE without mobile code).
2. Run applicable `rg` blocks from `extended-category-scans.md`.
3. Fill **Appendix H** with 19 domain groups (TAX-INJ … TAX-FW): Status PASS / FINDING / N/A, notes, finding refs.
4. Supplemental FINDINGs use standard VULN-NNN format; link taxonomy row in Classification table.

## Optional (formatting only)

`scripts/generate_html_report.py` — **mandatory** markdown→HTML styling after **you** wrote `security_report.md`. Does not perform security analysis. Deliver both `.md` and `.html` at handoff.

**Before HTML export:** Verify finding count = remediation count (`report-finding-completeness.md`). Every `## [SEVERITY]` block in Detailed Findings must have **`### Remediation`**.

**Before sharing the skill:** Run privacy checks in `skill-privacy.md` — no real hosts, user paths, credentials, or engagement-specific data.
