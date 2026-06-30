---
name: ai-security-reviewer
description: >-
  Agent-native SAST+DAST+IaC code review: 109 security checks · 85+ vulnerability classes ·
  760+ pattern signatures. v4.19 adds scope completeness enforcement (every module, every
  config profile, every Dockerfile), per-method auth audit (per-endpoint, not per-controller),
  and new pattern classes for CORS endsWith() bypass, controller Authorization-header overrides,
  JWT minted without exp, and plaintext token/headers logging. Plus security-researcher discovery
  beyond the 109-check matrix. IDOR/BOLA, JWT deep test, business-logic abuse cases, git-history
  secrets, IaC misconfig review from source. Burp MCP when present; curl-only DAST when Burp
  absent. Code-only findings — no npm/OSV/Maven/trivy dependency scanning. Agent runs rg/Read/curl.
---

# AI Security Reviewer

**Version 4.20** — Adds **mandatory report-file naming convention** (`report-naming-convention.md` + `scripts/derive_report_name.py`): every report is prefixed with a clean repo slug derived from the workspace folder, stripping org/team prefixes (`paytmteam-`, `paytm-`, `internal-`, `gh-`, …) and trailing hash / numeric / version / branch suffixes (`-48e5b67f7489`, `-20260630`, `-v1.2.3`, `-main`). Output files become `<repo>_security_report.md` / `<repo>_security_report.html` (e.g. `oauth-user-mgmt-service_security_report.md`) so multiple scans in one workspace, ticket attachments, and SIEM ingestion stay unambiguous. v4.19 scope-completeness enforcement (`multi-module-enumeration.md`, `multi-profile-config-audit.md`, `per-method-auth-audit.md`), new pattern classes (CORS `endsWith` bypass, controller Authorization-header override, JWT without `exp`, plaintext token/header logging in `extended-category-scans.md` §3.11–§3.12, §6.10–§6.12, §14.8–§14.9), tightened Appendix A rules (`manual-code-review.md`), v4.18 standards completeness mapping, v4.17 researcher layer, and v4.16 code-only mode are all retained.

**Report contract (read first):** `references/report-output-spec.md`

## Scope & honesty statement (read first)

No reviewer — human or AI — can guarantee it catches **every** vulnerability known to the world: it is undecidable in general, business-logic/design flaws need domain context, and **code-only mode does not assess dependency CVEs**. This skill instead guarantees two achievable things:

1. **Completeness of consideration** — every class in the authoritative taxonomies (`standards-coverage-map.md`) is examined.
2. **No silent misses** — anything not verifiable in the current mode/environment is explicitly published in the **Completeness & Residual Risk Register**, not dropped.

Do **not** claim "zero vulnerabilities" or "100% coverage" in any report. Claim **what was assessed, with what confidence, and what remains residual.**

## Out of scope (mandatory — do not run)

**Do not** scan third-party libraries or run dependency/CVE tooling. **Do not** report CVE-NNN or SCA-NNN findings from advisory databases.

| Forbidden | Examples |
|-----------|----------|
| Dependency/CVE databases | OSV API, `npm audit`, `pip-audit`, Maven/Gradle dependency CVE lookup |
| Container image CVE scanners | trivy, grype, Snyk container scan |
| SBOM / supply-chain tooling | CycloneDX export, KEV prioritization for library CVEs |
| Import-only CVE claims | "Jackson 2.8.5 has CVE-…" without a **code-level** vulnerable usage path |

**In scope:** vulnerabilities visible in **first-party code and config** — auth gaps, injection sinks, secrets in source, IaC misconfigs read from Dockerfile/K8s YAML, logic flaws, IDOR/BOLA, JWT handling, CORS/filter bugs, open redirects, etc.

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
| **Report** | **This agent (you)** | `security_report.md` + **`## Scan Attestation Summary`** → `generate_html_report.py [--strict]` |

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
| 18 | `finding-templates.md` | VULN/AUTH/IAC formats (**not** CVE/SCA) |
| **C1** | **`standards-coverage-map.md`** | **MANDATORY** — OWASP/CWE/ASVS/LLM sweep + Completeness & Residual Risk Register |
| **C2** | **`finding-confidence-validation.md`** | **MANDATORY** — two-stage validation, confidence levels, fail-open policy |
| **S1** | **`multi-module-enumeration.md`** | **MANDATORY** (multi-module repos) — enumerate ALL modules, controllers, configs, Dockerfiles |
| **S2** | **`multi-profile-config-audit.md`** | **MANDATORY** (multi-profile configs) — read EVERY `application-*.{yml,properties}`, not a sample |
| **S3** | **`per-method-auth-audit.md`** | **MANDATORY** — per-endpoint-method walk; prevents per-controller-annotation masking |
| **N1** | **`report-naming-convention.md`** | **MANDATORY (Phase 4)** — derive `<repo>_security_report.{md,html}` slug; rename legacy `security_report.*` on entry |
| **19+** | **v4.15 additive (code-only)** | See table below |
| 19–24 | finding-completeness, dataflow, impact, field-consistency, html-design, scan-matrices | Quality gates |

**Skipped in v4.16 (do not read for findings):** `osv-sca-scan.md`, `maven-sca-scan.md`, `cve-exploitability.md`, `kev-prioritization.md`, `sbom-export.md`, `container-image-scan.md` (trivy path).

**v4.15 additive references (run when applicable):**

| File | When |
|------|------|
| `idor-bola-audit.md` | APIs with object IDs |
| `jwt-deep-test.md` | JWT/Bearer auth |
| `business-logic-abuse-checklist.md` | Commerce/fintech/payments |
| `protocol-scans-graphql-ws-grpc.md` | GraphQL / WebSocket / gRPC detected |
| `git-history-secrets-scan.md` | `.git` present — **git log/grep only**, not secret scanners as primary |
| `risk-score-rubric.md` | Executive Summary risk score |
| `attack-chain-narrative.md` | ≥2 chainable findings |
| `baseline-delta-report.md` | Prior report exists |
| `mobile-sast-manifest.md` | android/ or ios/ tree |
| `large-repo-playbook.md` | >500 files or >100k LOC |

**Internal only (never required in user report):** full `report-coverage-matrix.md`, `platform-coverage-checklist.md`. Legacy Appendix E/G/I in markdown still OK — HTML suppresses.

### Burp MCP / DAST (mandatory)

1. Discover hosts with `rg` per **`burp-host-discovery.md`**
2. **Never probe `localhost` / `127.0.0.1`**
3. No external host → `Not Verified (no target host in code)`
4. **Burp MCP present** → `send_http1_request` for AUTH + HTTP VULN + IDOR/JWT probes
5. **Burp MCP absent** → **terminal `curl` only** — no Playwright, no Python `requests`, no other HTTP clients for verification (`curl-dast-fallback.md`, `network` permission)

| DAST backend | Allowed verification tool |
|--------------|---------------------------|
| Burp MCP available | **Burp MCP only** (`send_http1_request`) |
| Burp MCP unavailable | **curl only** (Shell tool) |
| No external host in code | Skip live probes — document in Appendix C |

---

## Coverage completeness (mandatory — so no known class is missed)

Run the full taxonomy sweep in **`standards-coverage-map.md`** every review. It maps the target against:

- **OWASP Top 10 (2021)** · **OWASP API Security Top 10 (2023)** · **CWE Top 25 (2024)** · **OWASP ASVS 5.0 (2025, 17 chapters)** · **OWASP Top 10 for LLM Apps (2025)** when the target is an LLM/GenAI app.

For each taxonomy row, assign **Covered** / **N/A (justified)** / **Residual (not assessable in this mode/env)**. Then publish the **`## Completeness & Residual Risk Register`** in the report — this is how the skill proves it did not *silently* miss anything. Mark dependency-CVE classes (OWASP A06, API10, ASVS V15, LLM03) as **Residual — not assessed** in code-only mode; never label an unassessed area "PASS".

## Accuracy & confidence (mandatory — fewer false positives, zero silent drops)

Apply the two-stage model in **`finding-confidence-validation.md`**:

1. **Stage 1 — wide net:** generate every plausible candidate (`rg` + graphify + researcher pass). Favor recall.
2. **Stage 2 — adjudicate:** per candidate, apply G1–G5 + a **CWE-specific micro-rubric** + DAST. Assign **Confidence: Confirmed / Firm / Tentative**.
3. **Fail-open:** when uncertain, **never silently drop** — keep as Tentative or send to Appendix A *with a named reason*. A real bug downgraded to nothing with no trace is the worst outcome.
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
- Logic flaws, race conditions, cache poisoning, second-order flows
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
2b. Extended scans          → extended-category-scans.md (includes new §3.11–§3.12, §6.10–§6.12, §14.8–§14.9)
2c. + Protocol scans        → protocol-scans-graphql-ws-grpc.md (if detected)
2d. + Git history secrets   → git-history-secrets-scan.md (if .git)
4.  IaC (source only)       → iac-misconfig-scan.md — Read EVERY Dockerfile* + K8s/config files
5.  Architect review        → security-architect.md → Top 3 risks (+ attack chains optional)
6.  Route auth audit        → route_auth_audit.md
6a. **Per-method auth audit** → per-method-auth-audit.md — one row per HTTP method, NOT per controller
6b. + IDOR/BOLA audit       → idor-bola-audit.md (if object IDs)
6c. + JWT deep test         → jwt-deep-test.md (if JWT)
6d. + Business logic        → business-logic-abuse-checklist.md (if commerce)
6e. + Researcher pass       → manual-code-review.md — issues OUTSIDE 109 matrix; G1–G5
6f. + Standards sweep       → standards-coverage-map.md — OWASP/API/CWE/ASVS/LLM completeness
7.  DAST verify             → Burp MCP if present; **curl only** if Burp absent
8.  Reachability traces     → graphify path OR manual (≥3 hops)
9.  Adjudicate + confidence → finding-confidence-validation.md — G1–G5 + CWE rubric + fail-open
                               + manual-code-review.md "forbidden exclusion reasons" check
10. Live PoC                → Burp or curl per DAST table; TRUE POSITIVE + every AUTH-NNN
11. security_report.md      → report-output-spec.md (+ attestation + researcher count + Residual Register
                               + Module/Profile/Per-Method Audit completion gates)
12. HTML                    → generate_html_report.py [--strict]
```

**Removed from sequence:** OSV SCA, KEV, CVE reachability, container image CVE scan, SBOM.

Record applicable checks in **internal scan log**; mark SCA/CVE/DEPS rows **N/A (code-only mode)**; publish **Scan Attestation Summary** in user report.

---

## Finding formats

Required sections: **Classification** (Source/Sink), **Description**, **Assumptions**, **Vulnerable Code Snippet**, **Data Flow Trace**, **Impact Assessment**, **Remediation**, live PoC when HTTP applies (Burp or curl).

Templates: **`finding-templates.md`**, **`report-vulnerable-code-dataflow.md`**, **`report-impact-assessment.md`**.

**Finding IDs:** VULN-NNN, AUTH-NNN, IAC-NNN, LEAK-NNN only — **never** CVE-NNN or SCA-NNN from dependency tools.

**Discovery tag (mandatory in checklist):** `Checklist` or `Researcher` — researcher findings are first-class; same format and verification bar.

**Confidence (mandatory per finding):** `Confirmed` / `Firm` / `Tentative` per `finding-confidence-validation.md`.

---

## Phase 4: Generate report

Per **`report-output-spec.md` v4.20**.

**Mandatory:** Executive Summary with **risk score rubric** · Coverage Overview · Scan Agent attribution · Scan Matrices · **Scan Attestation Summary** · **Completeness & Residual Risk Register** (`standards-coverage-map.md`) · Top Structural Risks · Verification Checklist (with **Confidence** column) · Detailed Findings · Remediation Priority · Appendices A, B, C, D, F.

**Excluded:** `## Software Composition Analysis (SCA)` — omit entirely; note in attestation: *Third-party dependency scanning disabled (code-only mode).*

**Recommended when applicable:** Attack Chain Analysis · Business Logic Summary · Delta Since Last Review · Git History summary.

### Report file naming (mandatory — `report-naming-convention.md`)

Reports must be prefixed with a clean repo slug derived from the workspace folder. Run the helper once and reuse its output for every artifact this review produces (markdown, HTML, gap analysis, baseline delta, attachments).

```bash
# 1. Derive slug from the current workspace (strips paytmteam-, -<hash>, -<date>, -v1.2.3, -main, …)
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
Run comprehensive security audit, verify unauthenticated endpoints, generate security_report.html
/graphify .   # optional
```

**Direct execution only** — do not delegate to subagents.

---

## Extended references

See **`CHANGELOG.md`** for version history. v4.20 adds the **mandatory report-file naming convention** (`report-naming-convention.md` + `scripts/derive_report_name.py`) so reports are written as `<repo>_security_report.{md,html}` derived from the workspace folder (org/team prefixes and trailing hash/numeric/version/branch suffixes stripped); v4.19 adds scope completeness enforcement, per-method auth audit, new mandatory pattern classes, and tighter Appendix A rules; v4.18 adds standards completeness mapping + residual-risk register + confidence/fail-open validation; v4.17 adds security-researcher discovery; v4.16 disables dependency tool scanning.
