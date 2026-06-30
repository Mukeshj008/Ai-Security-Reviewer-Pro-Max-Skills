# Report Output Spec (v4.20 — canonical)

**Single source of truth** for what goes in the user-facing security report vs agent-internal notes. All other report references must align with this file.

**v4.20 adds** the mandatory report-file naming convention (see below). **v4.19 adds** Module/Profile/Per-Method Audit blocks inside Scan Attestation Summary (mandatory when triggers fire). **v4.15 adds** optional/recommended sections below — **all v4.14 mandatory sections remain unchanged.**

---

## Report filenames (mandatory — v4.20)

Reports must be written under a workspace-derived slug, **not** the bare `security_report.md`:

| Artifact | Filename |
|----------|----------|
| Primary markdown report | `<repo>_security_report.md` |
| HTML export | `<repo>_security_report.html` |
| Gap-analysis pass (optional) | `<repo>_security_report_gap_analysis.md` |
| Baseline-delta (optional) | `<repo>_security_report_delta.md` |

Where `<repo>` is computed by `scripts/derive_report_name.py` per **`report-naming-convention.md`** — it strips org/team prefixes (`acmeteam-`, `acme-`, `internal-`, `gh-`, …) and trailing hash / date / version / branch suffixes (`-48e5b67f7489`, `-20260630`, `-v1.2.3`, `-main`) from the workspace folder basename. Example: `acmeteam-oauth-user-mgmt-service-48e5b67f7489` → `oauth-user-mgmt-service_security_report.md`.

User overrides via `--project "Free-form Project Name"` take precedence (sanitised to a slug); never write bare `security_report.*`.

The `--strict` HTML pass emits a stderr Recommendation when given an input that does **not** match `*_security_report.md`.

---

## User-facing report (mandatory sections)

| Order | Section | Reference |
|-------|---------|-----------|
| 1 | Title block + **Scan Agent** (must match attribution table) | `report-scan-matrices-agent.md` |
| 2 | Executive Summary (scan metrics, **risk score per rubric**, severity distribution) | `risk-score-rubric.md`, `report-html-design.md` |
| 3 | Vulnerability Coverage Overview (files, LOC, layer summary — **not** 109-row matrix) | `vulnerability-coverage-overview.md` |
| 4 | Scan Agent & Backend Attribution | `report-scan-matrices-agent.md` |
| 5 | Scan Matrices Executed (MX-VERIFY, MX-COV, MX-F) | `report-scan-matrices-agent.md` |
| 6 | **Scan Attestation Summary** (short accountability; note code-only mode; **must include `### Module & Profile Enumeration`, `### Config / Profile Audit`, `### Per-Method Auth Audit` blocks when their triggers fire**) | `scan-attestation-summary.md`, `multi-module-enumeration.md`, `multi-profile-config-audit.md`, `per-method-auth-audit.md` |
| 6b | **Completeness & Residual Risk Register** (OWASP/API/CWE/ASVS/LLM verdicts; nothing silently missed) | `standards-coverage-map.md` |
| 7 | **Top Structural Risks** (3 bullets max, linked to finding IDs) | below |
| 8 | **Security Verification Checklist** (findings table w/ **Confidence** + **Discovery** + collapsible scan-layer toggle) | `report-findings-verification-register.md`, `finding-confidence-validation.md` |
| 9 | Detailed Findings | `finding-templates.md` |
| 10 | Remediation Priority | — |
| 11 | Appendix A — False Positives Filtered | — |
| 12 | Appendix B — Scan Coverage (languages/frameworks) | — |
| 13 | Appendix C — Burp/curl Testing Notes | `curl-dast-fallback.md` |
| 14 | Appendix D — Unauthenticated Endpoint Inventory | `route_auth_audit.md` |
| 15 | Appendix F — Phase Execution Log | `agent-execution.md` |

---

## Recommended additive sections (v4.15 — include when applicable)

| Section | When | Reference |
|---------|------|-----------|
| **Attack Chain Analysis** | ≥2 chainable findings | `attack-chain-narrative.md` |
| **Business Logic Review Summary** | Commerce/fintech/payments | `business-logic-abuse-checklist.md` |
| **Delta Since Last Review** | Prior report in repo | `baseline-delta-report.md` |
| **Git History Secrets (summary)** | `.git` present | `git-history-secrets-scan.md` |
| **Container Image Scan (summary)** | Dockerfile/K8s — **IaC misconfig from source only**; no trivy/grype |

---

## Forbidden in user report (unchanged — full matrix still internal)

| Item | Where it lives instead |
|------|------------------------|
| Appendix E (109-check matrix) | Agent internal scan log (`internal-scan-log.md`) — **legacy Appendix E in markdown still OK; HTML suppresses** |
| Appendix G (architecture assessment) | Agent working notes + Top Structural Risks + optional Attack Chains |
| Appendix I (platform checklist) | Agent attestation + `platform-coverage-checklist.md` |
| Duplicate AUTH + VULN rows for same route/root cause | Dedup rules below |

HTML export suppresses Appendix E, G, I if present in markdown (unchanged behavior).

---

## Security Verification Checklist (canonical name)

Use **`## Security Verification Checklist`** only. Legacy aliases accepted by HTML parser: `Security Findings Verification Register`, `Master Findings Register`.

Columns: ID · Severity · Category · **Confidence** (`Confirmed` \| `Firm` \| `Tentative`) · **Discovery** (`Checklist` \| `Researcher`) · Source (full path) · Sink (full path) · Exploitable · AI Verdict · Verification Status · DAST Status · PoC.

Optional second toggle (markdown `<details>`):

```markdown
<details>
<summary>Scan layer checklist (109 internal checks) — click to expand</summary>
| Layer | Checks | PASS | FINDING | N/A | Notes |
</details>
```

---

## Top Structural Risks (mandatory — Executive Summary or before checklist)

After architect review (`security-architect.md`), surface **at most 3** one-line risks in the user report:

```markdown
### Top Structural Risks
1. [Risk] — linked: VULN-001, IAC-001
2. [Risk] — linked: AUTH-002
3. [Risk] — internal-only control gap (no finding ID if filtered)
```

Do **not** emit full STRIDE / trust-boundary appendix.

---

## AUTH vs VULN deduplication

| Situation | Report as |
|-----------|-----------|
| Missing auth + sensitive data exposure on same route | **VULN-NNN** (primary); list route in **Appendix D** only — **no separate AUTH-NNN** unless access control is the sole issue |
| Missing auth, no exploitable data path yet (inventory) | **AUTH-NNN** in checklist + Appendix D; Medium default |
| Injection on authenticated route | **VULN-NNN** only |
| Same ID in checklist and Detailed Findings | **One row per unique ID** — register row count = detailed finding count |

Appendix D may list more routes than the checklist (full inventory). Checklist = confirmed findings only.

---

## G2 reachability (graphify vs manual)

| Graph exists | Required |
|--------------|----------|
| Yes | `graphify path "<source>" "<sink>"` before FINDING |
| No | Manual trace table: **≥3 hops** (source → steps → sink) with file:line |

Never report from `rg` pattern match alone.

---

## Scan Agent header rule

`**Scan Agent:**` in the title block **must equal** every `[Scan Agent]` placeholder in the attribution table. HTML export auto-syncs mismatches and logs a stderr note — fix in markdown before handoff.

---

## SCA section (v4.16 — excluded)

**Do not** include `## Software Composition Analysis (SCA)` or CVE-NNN / SCA-NNN findings from dependency tools. In **Scan Attestation Summary**, note: *Third-party dependency scanning disabled (code-only mode).*

---

## HTML export

```bash
python ~/.cursor/skills/ai-security-reviewer/scripts/generate_html_report.py security_report.md \
  -o security_report.html --project "[Project Name]"
```

Use `--strict` before handoff to fail on missing Classification Source/Sink, field inconsistencies, or missing `### Assumptions` / `### Remediation` on findings.

**`--strict` recommendations (stderr only, export still succeeds):** missing `## Scan Attestation Summary`, missing risk score method line, missing v4.19 audit blocks (`### Module & Profile Enumeration`, `### Config / Profile Audit`, `### Per-Method Auth Audit`) when their triggers fire (multi-module repo / configs present / annotation-based framework).

Deliver **both** `.md` and `.html`.
