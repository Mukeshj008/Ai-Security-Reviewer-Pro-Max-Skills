# Scan Matrices & AI Agent Attribution (MANDATORY)

Every `security_report.md` must document **which matrices were executed** and **which AI agent/backend performed each scan layer**. No subagents for analysis — one Cursor session agent is the primary scanner.

**Report contract:** `report-output-spec.md` (v4.14)

---

## Report header (mandatory fields)

```markdown
**Report ID:** SEC-[YYYYMMDD]-[XXXX]
**Generated:** [ISO date]
**Project:** [Name]
**Skill Version:** AI Security Reviewer v4.14
**Scan Agent:** [Cursor agent model slug — e.g. claude-opus-4-8-thinking-high]
**AI Validation Agent:** [Same as Scan Agent unless user specified otherwise]
**Graph Backend:** Cursor native AI (`/graphify .`) OR tree-sitter AST-only (`graphify extract`) OR `rg + manual trace (graphify not installed)`
**DAST Backend:** Burp MCP (`user-burp`) | curl (terminal — Burp MCP not present) | Not run (no host in code)
**Method:** agent-native SAST · OSV SCA · DAST · ARCH (no scan scripts · no subagents)
```

**Rules:**
- **Scan Agent** = the Cursor model executing this review. **Must match exactly** in every row of the attribution table below.
- **AI Validation Agent** = agent that ran G1–G5 — normally identical to Scan Agent.
- Never attribute scanning to Ollama, Semgrep CLI, or skill shell scripts.

---

## Scan agent attribution matrix (mandatory section)

Add **`## Scan Agent & Backend Attribution`** after Executive Summary:

```markdown
## Scan Agent & Backend Attribution

| Layer | Scan Agent / Backend | Tooling | Output |
|-------|----------------------|---------|--------|
| **Dependency bootstrap** | [Scan Agent] | dependency-install-policy.md | Appendix F Phase 0a |
| Application context | [Scan Agent] | manual-code-review.md Phase −1 | internal notes |
| Attack surface | [Scan Agent] + graphify or rg | `graphify query` OR rg recon | — |
| SAST (109 checks) | [Scan Agent] | rg per manifests + reachability | internal scan log |
| Extended category scans | [Scan Agent] | extended-category-scans.md | internal |
| Vulnerability coverage | [Scan Agent] | vulnerability-coverage-overview.md | Coverage Overview |
| SCA / CVE | [Scan Agent] | OSV API + npm audit + reachability | SCA section |
| IaC | [Scan Agent] | iac-misconfig-scan.md rg | IAC findings |
| ARCH / STRIDE | [Scan Agent] | security-architect.md | Top Structural Risks (≤3) |
| AUTH audit | [Scan Agent] | route_auth_audit.md | Appendix D |
| DAST | Burp MCP / **terminal curl** | send_http1_request or Shell curl | Appendix C |
| AI validation | [AI Validation Agent] | G1–G5 + checklist | Verification Checklist |
| Report authoring | [Scan Agent] | security_report.md | Appendices A–D, F |
| HTML export | generate_html_report.py | Formatting only | security_report.html |
```

---

## Scan matrices inventory (mandatory summary)

```markdown
## Scan Matrices Executed

| Matrix ID | Name | Rows | Executed | PASS | FINDING | Notes |
|-----------|------|------|----------|------|---------|-------|
| MX-VERIFY | Security Verification Checklist | K | K | — | K | User-facing |
| MX-COV | Vulnerability coverage (internal) | 109 | X | — | — | Layer toggle |
| MX-SCA | OSV packages | N | N | — | — | filtered |
| MX-F | Phase execution log | 14 | X | X | 0 | Appendix F |
```

| Matrix ID | Source | What it attests |
|-----------|--------|-----------------|
| **MX-VERIFY** | `report-findings-verification-register.md` | Checklist row count = findings |
| **MX-COV** | `internal-scan-log.md` | 109 checks — internal only |
| **MX-SCA** | `osv-sca-scan.md` + `maven-sca-scan.md` | All prod packages OSV queried |
| **MX-F** | Phase log | Appendix F |
| **MX-D** | `route_auth_audit.md` | Appendix D inventory |

**Not in user report:** MX-E (full 109-row matrix), MX-I (platform checklist), MX-G (full architecture appendix).

---

## Completion gate

```bash
rg "^\*\*Scan Agent:\*\*" security_report.md
rg -c "^## Scan Matrices Executed" security_report.md   # must be 1
rg -c "^## Scan Agent & Backend Attribution" security_report.md   # must be 1
```

HTML `sync_attribution_agent()` fixes header/table mismatches — fix in markdown before `--strict` handoff.

---

## HTML rendering

`generate_html_report.py` displays Scan Agent, backends, and deduped Executive Summary per `report-html-design.md`.
