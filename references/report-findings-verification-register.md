# Security Findings Verification Register (user-facing report)

**Replaces:** Appendix E (109-check coverage matrix) and Appendix I (platform checklist) in **`security_report.md`** and HTML.

The agent still executes all 109 checks internally (`report-coverage-matrix.md`, manifests) — results are **not** copied into the user report. Only confirmed findings appear here with verification status.

---

## Mandatory section

```markdown
## Security Verification Checklist

HTML export auto-wraps the findings table in a **collapsible toggle** (`<details>`). Add a second toggle for internal scan-layer status.

| ID | Severity | Category | Confidence | Discovery | Source (full path) | Sink (full path) | Exploitable | AI Verdict | Verification Status | DAST Status | PoC |
|----|----------|----------|------------|-----------|--------------------|------------------|-------------|------------|----------------------|-------------|-----|
| VULN-001 | High | SQL Injection | Confirmed | Checklist | `src/.../UserController.java:142` | `src/.../UserController.java:150` | Yes | TRUE POSITIVE | Verified in curl | Verified in curl | Yes |

<details>
<summary>Scan layer checklist (109 internal checks) — click to expand</summary>

| Layer | Checks | Status | Notes |
|-------|--------|--------|-------|
| SAST | 60 | PASS | — |
| **Total** | **109** | **PASS** | Internal only |

</details>
```

**Not in user report:** Appendix G (architecture assessment) — agent runs `security-architect.md` internally only. Surface **Top Structural Risks** (≤3 bullets) in Executive Summary per `report-output-spec.md`.

### AUTH vs VULN deduplication

| Situation | Checklist row |
|-----------|---------------|
| Missing auth + confirmed data exposure on same route | **VULN-NNN** only; route still in Appendix D |
| Missing auth, inventory / gateway unknown | **AUTH-NNN** |
| Injection on protected route | **VULN-NNN** only |

One checklist row per unique finding ID. Register count = detailed finding count.

### Column rules

| Column | Required | Values |
|--------|----------|--------|
| **Confidence** | **Yes** | `Confirmed` / `Firm` / `Tentative` (see `finding-confidence-validation.md`) |
| **Discovery** | **Yes** | `Checklist` / `Researcher` |
| **Source (full path)** | **Yes** | `path/to/file:line` — HTTP entry, config key, import, or route registration |
| **Sink (full path)** | **Yes** | `path/to/file:line` — dangerous operation, missing auth handler, or misconfigured property line |
| **Exploitable** | Yes | `Yes` / `No` / `Hardening` only |
| **AI Verdict** | Yes | `TRUE POSITIVE` / `FILTERED` |
| **Verification Status** | Yes | How the finding was validated (see enum below) |
| **DAST Status** | Yes | Live probe result when HTTP applies |
| **PoC** | Yes | `Yes` / `N/A` |

### Verification Status enum

| Status | When |
|--------|------|
| **Code confirmed** | Static trace + G1–G5 pass; no live HTTP surface |
| **Verified in Burp** | Burp MCP probe confirms |
| **Verified in curl** | Terminal curl confirms |
| **Not Verified** | Code finding; live test skipped or inconclusive |
| **Not Verified (no target host in code)** | No external host for DAST |
| **Config confirmed** | IaC/properties finding validated in repo only |
| **Filtered** | Downgraded hardening — still listed if reported as HARDEN-* |

### DAST Status enum

`Verified in Burp` · `Verified in curl` · `Not Verified` · `Not Verified (internal port)` · `WAF blocked` · `N/A`

---

## Source / Sink by finding type

| Type | Source | Sink |
|------|--------|------|
| **VULN** (injection, XSS) | User input entry `file:line` | Dangerous sink `file:line` |
| **AUTH** | Route registration `file:line` | Handler/business logic `file:line` |
| **CVE** | Import `file:line` | Vulnerable API call `file:line` |
| **IAC** | Config/resource `file:line` (first misconfig line) | Same or adjacent `file:line` (property that enables risk) |
| **HARDEN** | Code/config `file:line` | Same file effect line |

**Never** use free-text sinks like `Spring Actuator shutdown` — always `application-production.properties:8`.

---

## Classification table sync

Every detailed finding `### Classification` **must** include:

```markdown
| **Source (full path)** | `path:line` |
| **Sink (full path)**   | `path:line` |
```

These values **must match** the Verification Register row for that ID.

---

## Completion gate (before HTML export)

```bash
# Count findings vs Source/Sink in Classification
grep -cE '^## \[(CRITICAL|HIGH|MEDIUM|LOW)\]' security_report.md
grep -c 'Source (full path)' security_report.md   # must be >= 2 × finding count (register + classification)
grep -c 'Sink (full path)' security_report.md

# Register row count must equal unique finding IDs in Detailed Findings
```

HTML generator **warns** when Classification lacks Source/Sink. With `--strict`, export **fails** — fix Classification in markdown (do not rely on register backfill).

---

## What stays internal (not in report)

- Full 109-check matrix (`report-coverage-matrix.md`) — agent workflow only
- Platform checklist (`platform-coverage-checklist.md`) — agent attestation only
- Phase log remains **Appendix F** (short, not 109 rows)
