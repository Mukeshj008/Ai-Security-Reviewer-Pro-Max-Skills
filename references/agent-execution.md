# Agent-Only Execution (MANDATORY)

**You are the scanner.** This skill provides **directions and checklists** — not runnable scan pipelines.

**Quality bar:** Senior AppSec engineer. Report only **realistic, exploitable** issues. See **`manual-code-review.md`** and **`report-output-spec.md`**.

## Do NOT use (agent workflow)

| Forbidden for analysis | Why |
|------------------------|-----|
| `scripts/run_sast_scan.sh` | Agent runs manifest `rg` commands directly |
| `scripts/run_cve_iac_scan.sh` | Agent runs `cve-exploitability.md` + `iac-misconfig-scan.md` |
| `scripts/discover_burp_hosts.sh` | Agent runs `rg` in `burp-host-discovery.md` |
| `scripts/generate_coverage_appendix.py` | Agent uses `internal-scan-log.md` — not Appendix E in user report |
| Semgrep / OpenGrep CLI | Agent + `rg` + graphify + AI validation only |
| Subagents (`Task`, `explore`) | Single-session reachability context |
| **Ollama** | Cursor native AI + AST-only graphify |

## DO use (your tools)

| Tool | Purpose |
|------|---------|
| **Tool bootstrap** | `dependency-install-policy.md` — install python3/curl/rg (**not Graphify/Burp**) |
| **Graphify** (optional) | `query`, `path`, `explain` when graph exists; manual trace if absent |
| **rg / Grep** | Manifest `rg` blocks |
| **Read** | Confirm hits ±5 lines |
| **Burp MCP** | `send_http1_request` when present — never install Burp |
| **curl** (terminal) | **Only** DAST tool when Burp absent — AUTH + HTTP VULN per `curl-dast-fallback.md` |
| **Your reasoning** | G1–G5, reachability, architect notes, **security-researcher discovery beyond 109 checks** |

## Review order (mandatory)

0. **Phase 0a** — Tool bootstrap (`dependency-install-policy.md`).
0b. **Phase 0b — Derive report slug (mandatory, `report-naming-convention.md`)** — Run `python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py` once at the start of the review and capture the output as `<repo>`. All final artifacts must be written as `<repo>_security_report.md` / `<repo>_security_report.html` (and `<repo>_security_report_gap_analysis.md` if a gap pass is done). If the workspace already contains legacy `security_report.{md,html}` from earlier runs, rename them to the new convention before writing new content (script in `report-naming-convention.md` § Migration). Use `--project "<Free-form>"` to override when the user supplied an explicit project name.
1. **Phase −1** — Application context + scan scope (`scan-scope-metrics.md` → Executive Summary + Coverage Overview).
1a. **Phase −1c — Module enumeration (mandatory for multi-module repos)** — Run `multi-module-enumeration.md`. Build module inventory; every subsequent `rg`/`Read` MUST cover **every** module in the inventory, not just one. Populate `### Module & Profile Enumeration` block in the Scan Attestation.
1b. **Phase −1d — Profile config audit (mandatory when configs exist)** — Run `multi-profile-config-audit.md`. Read **every** `application-*.{yml,properties}` and equivalent per-environment file; do not sample. Build `### Config / Profile Audit` block.
2. **Phase 0+** — Graphify or rg recon, manifests, IaC (**source/config Read only — every Dockerfile\***), **git/protocol/mobile scans when applicable**, architect (internal), AUTH audit, **per-method auth audit (`per-method-auth-audit.md`)**, **IDOR/BOLA**, **JWT deep test**, **business logic** (commerce), **security-researcher pass** (issues outside 109 matrix), DAST (Burp or curl-only), extended scans. **No OSV/npm/Maven/trivy dependency scanning (v4.16).**
3. **Phase 6e — Researcher pass (mandatory)** — After checklist scans, read code as a senior AppSec researcher; validate with G1–G5; tag findings `Discovery: Researcher`.
4. **Per candidate** — Taint trace; `graphify path` when graph exists else manual ≥3 hops.
5. **Pre-report gates** — G1–G5 before FINDING; **check the "forbidden exclusion reasons" table in `manual-code-review.md` before moving anything to Appendix A** — unverified "trust the gateway" exclusions are no longer allowed.

## Per-check execution loop

For **each** row in `report-coverage-matrix.md` (109 checks):

1. Open manifest section for that check ID.
2. Run documented `rg` / `graphify` / `Read` **yourself**. Bootstrap CLIs if missing (**except Graphify**). Skip SCA/CVE/DEPS rows as **N/A (code-only mode)**.
3. On hits: narrow `Read` → reachability trace.
4. G1–G5 + AI checklist → PASS or FINDING.
5. Record in **internal scan log** (`internal-scan-log.md`) — Status, Finding Ref, Match Count, Notes.

**Do not** paste 109 rows into `security_report.md`. Summarize layers in the Verification Checklist `<details>` toggle only.

**Reachability:** `graphify path` when graph exists; else manual file:line trace — never report from `rg` alone.

## Scan agent & matrices (mandatory in report)

Header fields per `report-scan-matrices-agent.md`:
- **Scan Agent** — Cursor model slug; **must match** attribution table rows
- **AI Validation Agent** — usually same
- **Graph Backend** / **DAST Backend**

Include **`## Scan Agent & Backend Attribution`** and **`## Scan Matrices Executed`**. Add **`## Scan Attestation Summary`** per `scan-attestation-summary.md`. MX-COV reconciles with internal scan log layer totals. MX-VERIFY row count = checklist findings.

## Vulnerability coverage overview (mandatory)

Per `vulnerability-coverage-overview.md` — files/LOC, layer summary, **not** full 109-row matrix.

Supplemental FINDINGs: **VULN-NNN**; note internal check ID in agent log when from checklist; tag **`Discovery: Researcher`** when not mapped to any check ID.

## HTML export (formatting only)

```bash
REPO=$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)
python scripts/generate_html_report.py "${REPO}_security_report.md" \
  -o "${REPO}_security_report.html" --strict
```

**Before export:** Finding count = snippet = trace = remediation counts (`report-finding-completeness.md`). Classification Source/Sink must match checklist. Input and output filenames must follow `report-naming-convention.md` (`<repo>_security_report.*`); the bare `security_report.{md,html}` filename is no longer the artifact name (`--strict` prints a Recommendation if you pass an unprefixed input).

**Before sharing skill:** `skill-privacy.md` hygiene.
