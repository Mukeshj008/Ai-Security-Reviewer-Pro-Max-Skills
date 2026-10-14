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

## Review status (v4.50 — title block)

| Value | When |
|-------|------|
| `Review status: complete` | **Only** after `check_coverage_gate.py` exits 0 and `scan-session-memory.md` has `status: complete` |
| `Review status: in_progress` | Any unread `must_read_files`, unwalked HTTP module, or unread config; partial reports; user `stop and ship partial` |

Agents must **not** use Executive Summary language implying a finished full-repo review while `in_progress`. See **`coverage-complete-gate.md`**.

---

## User-facing report (mandatory sections)

| Order | Section | Reference |
|-------|---------|-----------|
| 1 | Title block + **Scan Agent** (must match attribution table) | `report-scan-matrices-agent.md` |
| 2 | Executive Summary (scan metrics, **risk score per rubric**, severity distribution) | `risk-score-rubric.md`, `report-html-design.md` |
| 3 | Vulnerability Coverage Overview (files, LOC, layer summary — **not** 109-row matrix) | `vulnerability-coverage-overview.md` |
| 4 | Scan Agent & Backend Attribution | `report-scan-matrices-agent.md` |
| 5 | Scan Matrices Executed (MX-VERIFY, MX-COV, MX-F) | `report-scan-matrices-agent.md` |
| 6 | **Scan Attestation Summary** (short accountability; note code-only/SCA mode; **must include `### Module & Profile Enumeration`, `### Config / Profile Audit`, `### Per-Method Auth Audit`, and `### Authorization / Privilege Escalation Audit` for authenticated apps; `### XML Security Audit` when XML/SOAP/SAML exists; `### Deep Link Audit` / `### Mobile SAST Audit (static)` when mobile/deeplink triggers fire**) | `scan-attestation-summary.md`, `multi-module-enumeration.md`, `multi-profile-config-audit.md`, `per-method-auth-audit.md`, `authorization-privilege-escalation-audit.md`, `xml-security-audit.md`, **`deeplink-audit.md`**, **`mobile-sast-audit.md`** |
| 6b | **Completeness & Residual Risk Register** (OWASP/API/CWE/ASVS/LLM verdicts; nothing silently missed) | `standards-coverage-map.md` |
| 7 | **Top Structural Risks** (3 bullets max, linked to finding IDs) | below |
| 8 | **Security Verification Checklist** (findings table w/ **Confidence** + **Discovery** + collapsible scan-layer toggle) | `report-findings-verification-register.md`, `finding-confidence-validation.md` |
| 9 | Detailed Findings (incl. **`### Severity Rationale`**) | `finding-templates.md`, `severity-calibration.md` |
| 10 | Remediation Priority | — |
| 11 | Appendix A — False Positives Filtered | `ai-validate-precision-pass.md` — **all** FP candidates; ≥3-sentence reason with gate/ADJ cite; **never** duplicate as Detailed Findings |
| 12 | Appendix B — Scan Coverage (languages/frameworks) | — |
| 13 | Appendix C — Burp/curl Testing Notes | `curl-dast-fallback.md` |
| 14 | Appendix D — Unauthenticated Endpoint Inventory | `route_auth_audit.md` |
| 15 | Appendix F — Phase Execution Log | `agent-execution.md` |

### Detailed finding narrative gate (v4.55)

Every Detailed Finding must be useful to an engineer without relying on the checklist row:

- **Description:** 3–6 sentences covering actor, input/route, missing control, source→sink behavior, result, and preconditions.
- **Impact Assessment:** 2–5 sentences naming the exact data/action/resource and applicable business harm.
- **Remediation:** exact repository fix location, secure replacement pattern, coverage of every instance, and a regression verification step.

Generic CWE definitions, title restatements, severity-only impact, and one-line advice such as “sanitize input” or “add authentication” are report defects. `generate_html_report.py --strict` must reject them.

---

## Recommended additive sections (v4.15 — include when applicable)

| Section | When | Reference |
|---------|------|-----------|
| **Attack Chain Analysis** | ≥2 chainable findings | `attack-chain-narrative.md` |
| **Business Logic Review Summary** | Commerce/fintech/payments | `business-logic-abuse-checklist.md` |
| **Delta Since Last Review** | Prior report in repo | `baseline-delta-report.md` |
| **Git History Secrets (summary)** | `.git` present | `git-history-secrets-scan.md` |
| **Container Image Scan (summary)** | Dockerfile/K8s — **IaC misconfig from source only**; image CVE scanners are out of scope (v4.46) |

---

## Forbidden in user report (unchanged — full matrix still internal)

| Item | Where it lives instead |
|------|------------------------|
| Appendix E (109-check matrix) | Agent internal scan log (`internal-scan-log.md`) — **legacy Appendix E in markdown still OK; HTML suppresses** |
| Appendix G (architecture assessment) | Agent working notes + Top Structural Risks + optional Attack Chains |
| Appendix I (platform checklist) | Agent attestation + `platform-coverage-checklist.md` |
| Duplicate AUTH + VULN rows for same route/root cause | Dedup rules below |

HTML export (`generate_html_report.py`, v4.39) is a **reader report**. Markdown may still hold agent internals; HTML only includes:

| Order | HTML section |
|-------|----------------|
| 1 | Contents |
| 2 | Scan facts — repository, branch, scan agent, files scanned, lines scanned, report date |
| 3 | Executive Summary — severity pie + table, OWASP category pie + table |
| 4 | Standards and coverage — taxonomies followed and issue types examined |
| 5 | Findings table |
| 6 | Detailed Findings (impact as **prose**, not a CIA table) |

Omitted from HTML: Scan Agent/Matrices, Vulnerability Coverage Overview, Scan Attestation, Residual Register (summarized under Standards), Top Structural Risks, Verification Checklist (replaced by Findings table), SCA, Remediation Priority, Appendices A–F.

HTML **keeps:** the sections in the table above. Impact CIA tables in markdown are converted to sentences.

---

## Security Verification Checklist (canonical name)

Use **`## Security Verification Checklist`** only. Legacy aliases accepted by HTML parser: `Security Findings Verification Register`, `Master Findings Register`.

Columns: ID · Severity · Category · **Confidence** (`Confirmed` \| `Firm` \| `Tentative`) · **Discovery** (`Checklist` \| `Researcher`) · Source (full path) · Sink (full path) · Exploitable · AI Verdict · Verification Status · DAST Status · PoC (Burp request ref — mandatory for HTTP even when live probe skipped; see `dast-verification-flow.md`).

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
| Missing auth on routes sharing one root cause (e.g. global `permitAll`) | **One AUTH-NNN** with **N instances** (one per endpoint method). Each instance has its own Source/Sink. Checklist = 1 row; Appendix D = N rows linked to that AUTH ID + Instance #. See **`finding-instances.md`**. |
| Missing auth with **different** root causes | Separate AUTH-NNNs (do not merge) |
| Missing auth + sensitive data on same routes | Still that **AUTH-NNN** (instances). Optional separate **VULN-NNN** only for a **distinct** second CWE |
| Injection on authenticated route | **VULN-NNN** only |
| Same ID in checklist and Detailed Findings | **One checklist/Detailed Finding ID** — instances live *inside* the finding, not as extra IDs |

**Completion gate (v4.28):**  
- Every unauthenticated endpoint appears as an **Appendix D row** with `Finding ID` + `Instance`.  
- `sum(AUTH instance counts) == Appendix D unauthenticated endpoint rows`.  
- Checklist AUTH row count == distinct AUTH finding IDs (not instance count).  
- No inventory-only endpoints without a finding ID. `/health` without secrets → Low instance under the shared AUTH (or its own AUTH if root cause differs).

**Same-finding merge (all finding types):** identical CWE + root cause + remediation family → **one finding, multiple instances** — never repeat AUTH-001/AUTH-002/… or LEAK-001/LEAK-002/… for the same pattern. Full rules: **`finding-instances.md`**.

---

## Appendix A — false positives (v4.53)

Every candidate adjudicated as **False Positive** per `ai-validate-precision-pass.md` **must** appear here, not in Detailed Findings or the Security Verification Checklist as an open issue.

| Column | Content |
|--------|---------|
| Candidate | Short label + `file:line` or route |
| Reason | ≥3 sentences: what was read, control or ADJ rule (`SSRF-ADJ-01`, G3 cite), why not exploitable |
| Exploitability | **Not Exploitable** |

Stored-taint FPs must note `injection_order: stored` and cite writer + ingest control.

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

## Dependency / CVE coverage (v4.46 — no SCA)

Never include `## Software Composition Analysis (SCA)` or `SCA-NNN` findings. In **Scan Attestation Summary**, note: *Third-party dependency/CVE analysis is out of scope for this skill.* Mark OWASP A06 / API10 / ASVS V15 rows in the Residual Register as **not in skill scope**.

---

## HTML export

```bash
REPO=$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)
python ~/.cursor/skills/ai-security-reviewer/scripts/generate_html_report.py "${REPO}_security_report.md" \
  -o "${REPO}_security_report.html" --project "[Project Name]" --strict
```

Use `--strict` before handoff to fail on missing Classification Source/Sink, field inconsistencies, or missing `### Assumptions` / `### Remediation` on findings.

**`--strict` recommendations (stderr only, export still succeeds):** missing `## Scan Attestation Summary`, missing risk score method line, missing audit blocks (`### Module & Profile Enumeration`, `### Config / Profile Audit`, `### Per-Method Auth Audit`, `### Authorization / Privilege Escalation Audit`, and triggered `### XML Security Audit`).

Deliver **both** `.md` and `.html`.
