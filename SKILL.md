---
name: ai-security-reviewer
description: >-
  Agent-native SAST+DAST+IaC code review: 109 security checks · 85+ vulnerability classes ·
  760+ pattern signatures. v4.31: evidence-based false-positive control (effective-controls
  catalogue, exploitability preconditions) + Go/Ruby/Rust/C-C++/Elixir/Scala/Apex stack packs,
  constant-time MAC, SAML, OAuth, CI workflow injection, ZipSlip, weak RNG. v4.33 G3/G4 hardened:
  IDOR token-bind, empty-200, probe-safe, dummy-token (IDOR-ADJ-01, AUTH-ADJ-02/03, EXPLOIT-ADJ-01).
  v4.32.1 gate-precision fixes
  (G3/G4 SSRF labels, pathSegment, Feign @Url, redirect chain). v4.30 static mobile
  SAST (ATS, exported IPC, on-device storage); v4.29 deeplink session theft. Burp/curl DAST.
  Code-only — no npm/OSV/Maven/trivy SCA; mobile runtime Frida/MITM = Residual.
---

# AI Security Reviewer

**Version 4.33.0** — **Harder G3/G4:** IDOR-ADJ-01 (token-bound / unused attacker ID), AUTH-ADJ-02 (`200 []` ≠ Confirmed BOLA), AUTH-ADJ-03 (probe-safe), EXPLOIT-ADJ-01 (dead sink / dummy token), CORS-ADJ-01. v4.32.1 SSRF G3 labels retained.


**Report contract (read first):** `references/report-output-spec.md`

## Model-proof quick start (read first, token-efficient)

Before scanning, read these references in this order. Do **not** read every reference eagerly; use progressive disclosure.

1. `references/agent-execution.md`
2. `references/report-output-spec.md`
3. `references/manual-code-review.md`
4. `references/model-proof-operating-contract.md`
5. `references/finding-confidence-validation.md`
5b. `references/effective-controls-catalogue.md` — **read before excluding anything as a false positive (G3/G4 evidence)**
5c. `references/precision-false-positive-adjudication.md` — **read before reporting SSRF, LDAP, IDOR, or unauth-success claims**
6. `references/severity-calibration.md` — **read before assigning Critical/High/Medium**
6b. `references/finding-instances.md` — **same root cause → instances, not duplicate IDs**
7. `references/multi-module-enumeration.md`
8. `references/multi-profile-config-audit.md`
9. `references/per-method-auth-audit.md`
10. `references/async-second-order-audit.md`
10b. `references/deeplink-audit.md` — **when mobile / deeplink / Linking / App Links triggers match**
10c. `references/mobile-sast-audit.md` — **when Android/iOS/RN/Flutter mobile code present (static)**
11. `references/dast-verification-flow.md` — **read before Phase 7 DAST**
12. `references/standards-coverage-map.md`

Then execute the shortest complete loop:

```
scope → modules/profiles/routes → candidates ledger → source→sink validation →
severity calibration (Impact × Exploitability × Exposure × Complexity) →
DAST/curl where reachable → adjudication → residual register → strict report
```

**Candidate ledger rule:** every plausible candidate ends as `Finding`, `Tentative`, or `Appendix A` with a named reason. Nothing silently disappears.

**Tool wording:** use the platform's file-read and ripgrep tools (`ReadFile`/`Read`, `rg`/Grep equivalents). Prefer direct `rg` + scoped reads; do not rely on skill scan scripts.

## Scope & honesty statement (read first)

No reviewer — human or AI — can guarantee it catches **every** vulnerability known to the world: it is undecidable in general, business-logic/design flaws need domain context, and **code-only mode does not assess dependency CVEs**. This skill instead guarantees two achievable things:

1. **Completeness of consideration** — every class in the authoritative taxonomies (`standards-coverage-map.md`) is examined.
2. **No silent misses** — anything not verifiable in the current mode/environment is explicitly published in the **Completeness & Residual Risk Register**, not dropped.

Do **not** claim "zero vulnerabilities" or "100% coverage" in any report. Claim **what was assessed, with what confidence, and what remains residual.**

## Out of scope (mandatory — do not run)

**Default mode is code-only:** do not scan third-party libraries or run dependency/CVE tooling unless the user explicitly requests **SCA / dependency audit / full-spectrum security review**. In default code-only mode, mark dependency classes **Residual — not assessed**.

**Optional SCA mode:** when explicitly requested, run `references/sca-dependency-audit.md`. Keep SCA findings in a clearly separated **Software Composition Analysis** section; do not mix advisory-only issues into VULN/AUTH/IAC/LEAK. Use `SCA-NNN` only in SCA mode.

| Forbidden | Examples |
|-----------|----------|
| Forbidden in default code-only mode | Examples |
| Dependency/CVE databases | OSV API, `npm audit`, `pip-audit`, Maven/Gradle dependency CVE lookup |
| Container image CVE scanners | trivy, grype, Snyk container scan |
| SBOM / supply-chain tooling | CycloneDX export, KEV prioritization for library CVEs |
| Import-only VULN claims | "Jackson 2.8.5 has CVE-…" reported as VULN without a **code-level** vulnerable usage path |

**In scope:** vulnerabilities visible in **first-party code and config** — auth gaps, injection sinks, secrets in source, IaC misconfigs read from Dockerfile/K8s YAML, logic flaws, IDOR/BOLA, JWT handling, CORS/filter bugs, open redirects, **static mobile issues** (ATS/cleartext, exported Activities/Receivers/Providers/Services, on-device sensitive storage, WebView), deep-link session theft, etc.

---

## Execution model

**You are the scanner.** This skill gives **directions only** — you execute checks with `graphify`, `rg`, `Read`, and Burp MCP / `curl`. **Do not run skill scan scripts** (`run_sast_scan.sh`, `run_cve_iac_scan.sh`, `discover_burp_hosts.sh`, `generate_coverage_appendix.py`). See **`references/agent-execution.md`**.

| Layer | Who runs it | What it does |
|-------|-------------|--------------|
| **SAST** | **This agent (you)** | `graphify query/path` when graph exists → `rg` per manifest → narrow `Read` → AI validation |
| **DAST** | **This agent (you)** | Burp MCP or **mandatory terminal `curl`** — AUTH + VULN + **IDOR dual-session** + **JWT probes** |
| **IaC** | **This agent (you)** | `rg` + `Read` per `iac-misconfig-scan.md` — **source/config review only** (no image CVE scanners) |
| **ARCH** | **This agent (you)** | Threat model (`security-architect.md`) → **Top 3 structural risks** + optional **attack chains** |
| **RESEARCH** | **This agent (you)** | Senior security-researcher pass — issues **outside** the 109-check matrix; same G1–G5 validation |
| **SCA** | **This agent (you), only when explicitly requested** | `sca-dependency-audit.md` with package manifests + package-manager/advisory tools; separate SCA section |
| **Report** | **This agent (you)** | `<repo>_security_report.md` + **`## Scan Attestation Summary`** → `generate_html_report.py --strict` |

### Do NOT use scan scripts or subagents

- **No skill scripts for analysis** — run manifest `rg` / `graphify` yourself (`references/agent-execution.md`).
- **No subagents** — `Task` / `explore` / `generalPurpose` break reachability context.
- **No dependency/CVE tools** — see **Out of scope** above.

### Reference stack (read as needed)

| # | File | Purpose |
|---|------|---------|
| 0 | `dependency-install-policy.md` | Install python3/curl/rg before SKIP (**not** npm/mvn/trivy for SCA) |
| 0b | `manual-code-review.md` | Context, taint, G1–G5 gates |
| 1 | `agent-execution.md` | Agent-only loop + internal scan log |
| 2–5 | SAST manifests (sast, LEAK, SECRET, INJ) | Core patterns |
| 6 | `extended-category-scans.md` | Spring/Node/Java supplemental `rg` |
| 7–8 | `vulnerability-coverage-overview.md`, `scan-scope-metrics.md` | Coverage + files/LOC |
| 12–14 | `secret-type-labels.md`, `iac-misconfig-scan.md`, `security-architect.md` | Secrets, IaC (code), ARCH |
| 15 | `report-findings-verification-register.md` | **Security Verification Checklist** |
| 16 | `internal-scan-log.md` + `scan-attestation-summary.md` | Internal checks + user attestation |
| 17 | `report-output-spec.md` | **Canonical** report sections (v4.18) |
| 18 | `finding-templates.md` | VULN/AUTH/IAC/LEAK formats; SCA only in explicit SCA mode |
| **C1** | **`standards-coverage-map.md`** | **MANDATORY** — OWASP/CWE/ASVS/LLM sweep + Completeness & Residual Risk Register |
| **C2** | **`finding-confidence-validation.md`** | **MANDATORY** — two-stage validation, confidence levels, fail-open policy |
| **C2b** | **`effective-controls-catalogue.md`** | **MANDATORY** — what truly neutralizes each CWE (G3), exploitability preconditions (G4), third-party-response trust-boundary rule, plus SIG/SAML/OAuth/CI/ZipSlip/RAND/XXE precision patterns |
| **C2c** | **`precision-false-positive-adjudication.md`** | **MANDATORY** — SSRF/LDAP/INJ/DESER plus **IDOR-ADJ-01**, **AUTH-ADJ-02/03**, **EXPLOIT-ADJ-01**; Stage-2 before pattern-only or empty-200 findings |
| **C3** | **`severity-calibration.md`** | **MANDATORY** — Impact × Exploitability × Exposure × Complexity; caps; `### Severity Rationale` |
| **I1** | **`finding-instances.md`** | **MANDATORY** — same root cause → one finding with multi-instance Source/Sink; no duplicate IDs |
| **S1** | **`multi-module-enumeration.md`** | **MANDATORY** (multi-module repos) — enumerate ALL modules, controllers, configs, Dockerfiles |
| **S2** | **`multi-profile-config-audit.md`** | **MANDATORY** (multi-profile configs) — read EVERY `application-*.{yml,properties}`, not a sample |
| **S3** | **`per-method-auth-audit.md`** | **MANDATORY** — per-endpoint-method walk; prevents per-controller-annotation masking |
| **N1** | **`report-naming-convention.md`** | **MANDATORY (Phase 4)** — derive `<repo>_security_report.{md,html}` slug; rename legacy `security_report.*` on entry |
| **A1** | **`async-second-order-audit.md`** | **MANDATORY** — queues, cron, Lambda/EMR/Spark, stored filters, save-now-exploit-later flows |
| **DL1** | **`deeplink-audit.md`** | **MANDATORY when triggered** — deep-link session theft, unvalidated handlers, App Links gaps |
| **M1** | **`mobile-sast-audit.md`** | **MANDATORY when mobile code present** — static ATS, exported IPC, on-device storage (no Frida) |
| **Q1** | **`model-proof-operating-contract.md`** | **MANDATORY** — token-efficient execution, candidate ledger, final compliance gate |
| **D4** | **`dast-verification-flow.md`** | **MANDATORY (Phase 7)** — Burp PoC always; curl only with user permission |
| **SCA1** | `sca-dependency-audit.md` | Explicit SCA mode only — dependency health/advisory findings |
| **19+** | **v4.15 additive (code-only)** | See table below |
| 19–24 | finding-completeness, dataflow, impact, field-consistency, html-design, scan-matrices | Quality gates |

**Skipped in default code-only mode:** `osv-sca-scan.md`, `maven-sca-scan.md`, `cve-exploitability.md`, `kev-prioritization.md`, `sbom-export.md`, `container-image-scan.md` (trivy path). If explicit SCA mode is requested, use **`sca-dependency-audit.md`** as the active SCA contract instead of these legacy references.

**v4.15 additive references (run when applicable):**

| File | When |
|------|------|
| `idor-bola-audit.md` | APIs with object IDs |
| `jwt-deep-test.md` | JWT/Bearer auth |
| `business-logic-abuse-checklist.md` | Commerce/fintech/payments |
| `protocol-scans-graphql-ws-grpc.md` | GraphQL / WebSocket / gRPC detected |
| `git-history-secrets-scan.md` | `.git` present — **git log/grep only**, not secret scanners as primary |
| `risk-score-rubric.md` | Executive Summary risk score (after severity calibration) |
| `severity-calibration.md` | **Every review** — assign Critical/High/Medium/Low |
| `attack-chain-narrative.md` | ≥2 chainable findings |
| `baseline-delta-report.md` | Prior report exists |
| `mobile-sast-manifest.md` | android/ or ios/ tree — MOB-01…26 checklist |
| **`mobile-sast-audit.md`** | **Full static mobile audit** (ATS, exported components, on-device secrets) |
| **`deeplink-audit.md`** | **Deep links / App Links / Universal Links / backend minting `myapp://` or session in link URL** |
| `large-repo-playbook.md` | >500 files or >100k LOC |

**Internal only (never required in user report):** full `report-coverage-matrix.md`, `platform-coverage-checklist.md`. Legacy Appendix E/G/I in markdown still OK — HTML suppresses.

### Burp MCP / DAST (mandatory — v4.23)

**Full decision tree:** `references/dast-verification-flow.md`

#### Always (before any live probe)

For **every** HTTP-exploitable `AUTH-NNN` / `VULN-NNN`, **craft and publish** `### Burp Suite PoC` with a complete raw HTTP/1.1 request in Detailed Findings — **even when** Burp MCP is unavailable, curl is skipped, the user declines live probes, or no target host exists (use `[TARGET_HOST]` placeholder). See `burp_poc_templates.md` + `finding-templates.md`.

Non-HTTP findings (`LEAK`, `IAC`) → `Burp PoC: N/A — not HTTP-exploitable`.

#### Live verification (in order)

1. Discover hosts with `rg` per **`burp-host-discovery.md`**
2. **Never probe `localhost` / `127.0.0.1`**
3. **Burp MCP present** → `send_http1_request` using the crafted PoC (AUTH + HTTP VULN + IDOR/JWT)
4. **Burp MCP absent or rejected** + external host in code → **ask user permission before any `curl`** (AskQuestion or explicit Approve/Deny). **Do not run curl silently.**
5. **User approves curl** → terminal `curl` only (`curl-dast-fallback.md`, `network` permission) — no Playwright, Python `requests`, or other HTTP clients
6. **User declines curl** / no external host → `Not Verified` — **Burp PoC still mandatory** in the finding; document reason in Appendix C

| DAST backend | When |
|--------------|------|
| Burp MCP | `send_http1_request` probes executed |
| curl (terminal) | Burp absent/unavailable **and user approved** curl |
| None — Burp PoC only | User declined curl, or no external host — crafted requests still in findings |
| Not Verified (no target host in code) | No host in code — PoC uses `[TARGET_HOST]` placeholder |

**User permission is mandatory for curl.** If the user skips/denies, Phase 7 is still complete when every HTTP finding has a Burp PoC block.

---

## Coverage completeness (mandatory — so no known class is missed)

Run the full taxonomy sweep in **`standards-coverage-map.md`** every review. It maps the target against:

- **OWASP Top 10 (2021)** · **OWASP API Security Top 10 (2023)** · **CWE Top 25 (2024)** · **OWASP ASVS 5.0 (2025, 17 chapters)** · **OWASP Top 10 for LLM Apps (2025)** when the target is an LLM/GenAI app.

For each taxonomy row, assign **Covered** / **N/A (justified)** / **Residual (not assessable in this mode/env)**. Then publish the **`## Completeness & Residual Risk Register`** in the report — this is how the skill proves it did not *silently* miss anything. Mark dependency-CVE classes (OWASP A06, API10, ASVS V15, LLM03) as **Residual — not assessed** in code-only mode; never label an unassessed area "PASS".

## Accuracy & confidence (mandatory — fewer false positives, zero silent drops)

Apply the two-stage model in **`finding-confidence-validation.md`**:

1. **Stage 1 — wide net:** generate every plausible candidate (`rg` + graphify + researcher pass). Favor recall.
2. **Stage 2 — adjudicate:** per candidate, apply G1–G5 + CWE micro-rubric + **`effective-controls-catalogue.md`** (§1 control must be read and cited to exclude; §2 preconditions gate exploitability) + **severity calibration** (four factors only — **not** DAST/Not Verified) + DAST for **Verification Status** separately. Assign **Confidence** and **Severity** with mandatory `### Severity Rationale`.
3. **Fail-open + ledger:** when uncertain, **never silently drop** — keep as Tentative or send to Appendix A *with a named reason*. Maintain an internal candidate ledger until every candidate has a terminal status.
4. **CVE-override:** never suppress a known-active exploited pattern (e.g., Log4Shell-style JNDI, deserialization gadget) just because it sits in a "utils/test" path — flag for human review.

Add a **Confidence** column to the Security Verification Checklist.

## Security researcher layer (mandatory — beyond 109 checks)

The **109-check matrix is a floor, not a ceiling.** After running applicable checklist rows, act as an **independent security researcher** and hunt for issues the matrix does not cover.

### When to use

- After Phase 2 (SAST manifests) and before final report
- While reading controllers, interceptors, filters, config, and business flows
- When architecture, domain, or framework patterns suggest risks not mapped to a check ID

### What to look for (examples not exhaustively in 109)

- Cross-interceptor auth gaps, ordering bugs, exclude-mapping mistakes
- Header/body trust confusion (`uid` vs token subject, S2S vs session paths)
- Domain-specific abuse (KYC/fintech/payments, role assignment, PII exposure)
- Logic flaws, race conditions, cache poisoning, async/second-order flows
- Queue/cron/Lambda/EMR/Spark flows where untrusted data is stored first and executed later
- **Deep-link session theft** — tokens/OTP/session in URL; unvalidated `redirect`/`url` from deep links; custom-scheme hijack; missing App Links `autoVerify` / AASA
- **Mobile IPC / storage** — exported Activities/Receivers/Providers; plaintext tokens in prefs/DB; ATS exceptions (see `mobile-sast-audit.md`)
- Shadow endpoints, debug/ops routes, commented-out security controls
- Framework misuse unique to this codebase (Spring interceptor chains, custom filters)

### Validation (same bar as checklist findings)

Every researcher-discovered candidate **must** pass **G1–G5** (`manual-code-review.md`) with:

1. **Source → sink trace** (≥3 hops) or documented missing auth on reachable route
2. **AI validation** — confirm realistic exploit, not pattern noise
3. **HTTP verification** when applicable — Burp MCP or **curl only** per DAST table above
4. **False positives** → Appendix A with reason

### Reporting researcher findings

- Use normal IDs: **VULN-NNN**, **AUTH-NNN**, **IAC-NNN**, **LEAK-NNN** (continue numbering after checklist findings)
- Tag each row in **Security Verification Checklist** with **`Discovery: Researcher`**
- Checklist findings from the 109 matrix use **`Discovery: Checklist`** (optional if obvious from check ID)
- In **Detailed Findings**, add under Classification: `Discovery: Researcher — not mapped to internal check ID`
- Record count in **Scan Attestation Summary**: `Researcher-discovered findings: N`

**Do not** skip researcher pass because all 109 checks PASS — zero checklist findings can still yield valid researcher findings.

---

## Senior manual review (mandatory)

Full methodology: **`references/manual-code-review.md`**.

### Pre-report gates (G1–G5)

| Gate | Verify |
|------|--------|
| **G1** | Attacker-controlled input or missing auth on reachable route? |
| **G2** | **`graphify path` if graph exists; else manual trace ≥3 hops** |
| **G3** | Effective protection? → Appendix A |
| **G4** | Practically exploitable? |
| **G5** | Assumptions in **`### Assumptions`** on each detailed finding |

### AUTH vs VULN dedup

See **`report-output-spec.md`** — unchanged from v4.14.

---

## Review sequence (v4.19 — scope completeness + per-method auth + new pattern classes)

```
−1. Application context     → manual-code-review.md → internal ARCH notes
−1b. Scan scope             → scan-scope-metrics.md (+ large-repo-playbook.md if huge)
−1c. **Module enumeration** → multi-module-enumeration.md — list EVERY module, controller, profile, Dockerfile
−1d. **Profile config audit** → multi-profile-config-audit.md — read every application-*.{yml,properties}
0a. Tool bootstrap          → dependency-install-policy.md (curl, rg, python3 only)
0.  Host discovery          → burp-host-discovery.md
1.  Attack surface          → graphify query OR rg recon — scope = ALL modules from −1c
2.  SAST manifests          → rg per sast + LEAK + SECRET + INJ (scope = ALL modules)
2a. **Precision adjudication** → `precision-false-positive-adjudication.md` on **every** matching candidate:
                               **SSRF-ADJ-01**, **LDAP-ADJ-01**, **INJ/DESER/LOG/AUTH/XXE-ADJ-***,
                               **IDOR-ADJ-01**, **AUTH-ADJ-02/03**, **EXPLOIT-ADJ-01**, **CORS-ADJ-01**
                               — G3/G4 hard fails before VULN ID; `200 []` ≠ Confirmed BOLA
2b. Extended scans          → extended-category-scans.md (§3.11–§3.12, §6.10–§6.12, §14.8–§14.9)
2b.1 Stack pack             → extended-category-scans.md §19.x for EVERY language present
                               (Spring/Node/PHP/Python/Java/.NET/mobile/**Go/Ruby/Rust/C-C++/Elixir/Scala/Apex/shell**)
2b.2 Precision patterns     → effective-controls-catalogue.md §3 — SIG-01 constant-time MAC, SIG-02, SAML-01,
                               OAUTH-01, CI-01 workflow injection, ARCHIVE-01 ZipSlip, RAND-01,
                               **SSRF-ADJ-01, LDAP-ADJ-01** (mandatory on HTTP-client / `.search()` hits)
2b.5 Async/second-order     → async-second-order-audit.md (queues, cron, Spark/EMR, Lambda, stored filters)
2c. + Protocol scans        → protocol-scans-graphql-ws-grpc.md (if detected)
2d. + Git history secrets   → git-history-secrets-scan.md (if .git)
2e. + **Deep-link audit**   → deeplink-audit.md (if mobile / Linking / App Links / deeplink minting)
2f. + **Mobile SAST (static)** → mobile-sast-audit.md + mobile-sast-manifest.md MOB-01…26 (if android/ios/RN/Flutter)
4.  IaC (source only)       → iac-misconfig-scan.md — Read EVERY Dockerfile* + K8s/config files
5.  Architect review        → security-architect.md → Top 3 risks (+ attack chains optional)
6.  Route auth audit        → route_auth_audit.md
6a. **Per-method auth audit** → per-method-auth-audit.md — one row per HTTP method, NOT per controller
6b. + IDOR/BOLA audit       → idor-bola-audit.md (if object IDs)
6c. + JWT deep test         → jwt-deep-test.md (if JWT)
6d. + Business logic        → business-logic-abuse-checklist.md (if commerce)
6e. + Researcher pass       → manual-code-review.md — issues OUTSIDE 109 matrix; G1–G5
6f. + Standards sweep       → standards-coverage-map.md — OWASP/API/CWE/ASVS/LLM completeness
7.  DAST verify             → craft Burp PoC per finding first → Burp MCP if present → **ask user** → curl only if approved (`dast-verification-flow.md`)
8.  Reachability traces     → graphify path OR manual (≥3 hops)
9.  Adjudicate + confidence → finding-confidence-validation.md — G1–G5 + CWE rubric + fail-open
9a. **Severity calibration** → severity-calibration.md — four factors, Step 1 caps, `### Severity Rationale`
                               + manual-code-review.md "forbidden exclusion reasons" check
9b. Candidate ledger close  → every candidate = Finding / Tentative / Appendix A
10. Live PoC                → Burp PoC block in **every** HTTP finding; live Burp/curl when permitted; TRUE POSITIVE + every AUTH-NNN
11. `<repo>_security_report.md` → report-output-spec.md (+ attestation + researcher count + Residual Register
                               + Module/Profile/Per-Method Audit completion gates)
12. HTML                    → generate_html_report.py [--strict]
```

**Default code-only removed from sequence:** OSV SCA, KEV, CVE reachability, container image CVE scan, SBOM. Explicit SCA mode re-adds dependency review via `sca-dependency-audit.md` only.

Record applicable checks in **internal scan log**; mark SCA/CVE/DEPS rows **N/A (code-only mode)**; publish **Scan Attestation Summary** in user report.

---

## Finding formats

Required sections: **Classification** (Source/Sink), **Description**, **Assumptions**, **Vulnerable Code Snippet**, **Data Flow Trace**, **Impact Assessment**, **`### Severity Rationale`**, **Remediation**, **`### Burp Suite PoC`** for every HTTP finding (mandatory even when live verification skipped), plus `### Live Verification (Burp MCP)` or `### Live Verification (curl)` when a probe actually ran.

Templates: **`finding-templates.md`**, **`report-vulnerable-code-dataflow.md`**, **`report-impact-assessment.md`**.

**Finding IDs:** VULN-NNN, AUTH-NNN, IAC-NNN, LEAK-NNN. In explicit SCA mode only, dependency findings use SCA-NNN in a separate SCA section. **Same CWE + root cause → one ID with `### Instances`** (per-instance Source/Sink) — see `finding-instances.md`. Do not repeat finding IDs for the same pattern across files/endpoints.

**Report secret redaction:** show enough evidence to prove a secret exists (type, file, line, first/last 4 chars or hash), but redact raw values in reports and PoCs unless the user explicitly asks for raw evidence in a secure context.

**Discovery tag (mandatory in checklist):** `Checklist` or `Researcher` — researcher findings are first-class; same format and verification bar.

**Confidence (mandatory per finding):** `Confirmed` / `Firm` / `Tentative` per `finding-confidence-validation.md`.

---

## Phase 4: Generate report

Per **`report-output-spec.md` v4.20**.

**Mandatory:** Executive Summary with **risk score rubric** · Coverage Overview · Scan Agent attribution · Scan Matrices · **Scan Attestation Summary** · **Completeness & Residual Risk Register** (`standards-coverage-map.md`) · Top Structural Risks · Verification Checklist (with **Confidence** column) · Detailed Findings · Remediation Priority · Appendices A, B, C, D, F.

**SCA section:** omit entirely in default code-only mode and note: *Third-party dependency scanning disabled (code-only mode).* Include `## Software Composition Analysis (SCA)` only when explicit SCA mode was requested and completed.

**Recommended when applicable:** Attack Chain Analysis · Business Logic Summary · Delta Since Last Review · Git History summary.

### Report file naming (mandatory — `report-naming-convention.md`)

Reports must be prefixed with a clean repo slug derived from the workspace folder. Run the helper once and reuse its output for every artifact this review produces (markdown, HTML, gap analysis, baseline delta, attachments).

```bash
# 1. Derive slug from the current workspace (strips org/team prefixes, -<hash>, -<date>, -v1.2.3, -main, …)
REPO=$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)
MD="${REPO}_security_report.md"
HTML="${REPO}_security_report.html"

# 2. Migrate any legacy unprefixed files left from earlier runs
#    ("${f#security_report}" only strips the literal "security_report" stem,
#    keeping ".md" / ".html" / "_gap_analysis.md" / "_delta.md".)
for f in security_report.md security_report.html security_report_gap_analysis.md security_report_delta.md; do
  [ -f "$f" ] && mv "$f" "${REPO}_security_report${f#security_report}"
done

# 3. Write the new report to "$MD", then render HTML
python ~/.cursor/skills/ai-security-reviewer/scripts/generate_html_report.py "$MD" \
  -o "$HTML" --project "[Project Name]" --strict
```

Override the derived slug with `--project "Your Name"` when the user has supplied an explicit project label. Never write to the bare `security_report.md` / `security_report.html` filenames.

`--strict` fails on: missing Source/Sink, field inconsistencies, register backfill, missing **Assumptions** or **Remediation** per finding.

Deliver **both** `.md` and `.html` using the derived `<repo>_*` filenames.

---

## Usage

```
Review this code for security vulnerabilities
Run comprehensive security audit, verify unauthenticated endpoints, generate <repo>_security_report.html
/graphify .   # optional
```

**Direct execution only** — do not delegate to subagents.

---

## Extended references

See **`CHANGELOG.md`** for version history. **v4.32.1** gate-precision fixes; **v4.32** SSRF/LDAP precision adjudication; **v4.31** effective-controls catalogue + stack packs; **v4.30** full static mobile SAST; **v4.29** deeplink session theft.
