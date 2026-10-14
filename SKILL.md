---
name: ai-security-reviewer
description: >-
  Agent-native security code review (SAST + IaC + logic abuse, Burp/curl DAST) for any
  language: 16 language packs × 35 vulnerability classes, G0–G5 false-positive gates,
  IDOR/business-logic/async flow walks, secrets, mobile, CI. Mandatory AI Validate–style
  precision pass (per call site, stored-taint before FP) so false positives land in Appendix A only.
  Single agent only — no parallel workers. Read every must_read file, tests included, via
  next_read_batch.py (full text, many files per call).
  Never skip a file. Never ask the user to type continue.
  Severity from route exposure; v4.54 Medium default for missing auth on internal/webhook/cron; quantum/HNDL/PQC findings out of scope (v4.56).
  First-party code only — no dependency/CVE (SCA) mode.
  Do not declare scan complete until production files, configs, and HTTP modules are covered
  (check_coverage_gate.py). Never ask the user to type continue.
  Use when the user asks for a security review, SAST, vulnerability scan, or pentest-style
  code audit.
---

# AI Security Reviewer

**Version 4.57.0** — **Single agent only.** Read every path in `must_read_files`, tests included. Speed is `scripts/next_read_batch.py`: one call prints the next unread files **in full** (about 120KB). Look at every file in that output, run `--ack`, then the next batch, in this same session, until it prints `BATCH_EMPTY`. **Do not open files one at a time. Do not skip tests. Never ask the user to say continue.** **Do not say “scan complete” until `check_coverage_gate.py` exits 0.** The gate diffs `.security-review/files-read.log` against every inventory path. No shard workers. History: `CHANGELOG.md`.


## Quick start — load references by phase (token-efficient)

Read a reference **when its phase starts**, once per session. Do not pre-read later phases. Never re-read a reference already in context.

**Phase A — explore & find (read before opening code):**

1. `scripts/enumerate_inventory.py` — run once (skip if `.security-review/scan-session-memory.md` is fresh). Sole enumeration: files, LOC, modules, configs, HTTP files, language packs. `inventory.json` `parallel` / `read_ranges` are optional read hints for **you** — not worker routing.
2. `references/exploration-first.md` — map + **Read** files; `rg` is a hint after Read. Zero hits ≠ coverage.
3. `references/senior-researcher.md` — static defects **and** logic abuse (LOG-01…15) on every sensitive operation; runs continuously, not as a separate later pass.
4. `references/lang-packs/README.md` + **only active packs** — the single source of language sinks (L01–L35 index: vulnerable | safe | FP trap). Apply **G0**. Packs flagged `test/fixture only` are not production attack surface. Never load `vuln-class-matrix.md` during a scan.
5. If large (2+ HTTP modules / 15+ configs / >500 files) → `references/large-repo-runner.md` (finish every module this session; do not pause). Else → `references/weak-model-parity.md` (same rule: do not stop after one module).
6. Conditional, when triggered: `express-auth-audit.md` (Express/Koa) · `async-second-order-audit.md` (queues/cron/workers) · `idor-bola-audit.md` (object references) · **`authorization-privilege-escalation-audit.md`** (every authenticated app: horizontal + vertical/BFLA) · `xml-security-audit.md` (any XML/SOAP/SAML parse or construction) · `business-logic-abuse-checklist.md` (payments/commerce) · `jwt-deep-test.md` · `protocol-scans-graphql-ws-grpc.md` · `mobile-sast-audit.md` + `deeplink-audit.md` (mobile) · `iac-misconfig-scan.md` (Docker/K8s/CI).

**Phase B — adjudicate (read when the first candidate needs a verdict):** `ai-validate-precision-pass.md` (commit TP/FP per call site; stored-taint before FP; **no FP in Detailed Findings**) · `manual-code-review.md` (G0–G5) · `effective-controls-catalogue.md` (G3/G4 evidence) · `precision-false-positive-adjudication.md` (SSRF/LDAP/IDOR/unauth/fail-open) · `finding-confidence-validation.md` · `severity-calibration.md` (LEAK never Critical) · `finding-instances.md`.

**Phase C — DAST (only if HTTP findings exist):** `dast-verification-flow.md` (Burp PoC always; curl only with user permission).

**Phase D — report (only after coverage gate):** `coverage-complete-gate.md` · `check_coverage_gate.py` · `report-output-spec.md` · `finding-templates.md` · `report-naming-convention.md` · `standards-coverage-map.md` (Residual Register).

## Scan complete gate (mandatory — v4.50)

**Production coverage must be 100%** before you tell the user the scan is finished or set `Review status: complete`.

1. Read **`references/coverage-complete-gate.md`** — forbidden phrases, G1–G7 checklist, no P0-only handoff.
2. Coverage is `.security-review/files-read.log` written by `next_read_batch.py --ack`. Do not bump a counter instead of logging the path.
3. Run **`scripts/check_coverage_gate.py`** from the repo root. **Exit 0 required** before:
   - saying “scan complete” / “review complete” / “audit complete” in chat;
   - setting `status: complete` in memory or report header;
   - delivering final `<repo>_security_report.html` as the completed deliverable.
4. If the gate would fail, **keep reading in this same turn**. Do not end the chat to wait. **Never** ask the user to type `continue`, and **never** print `CONTINUE LARGE-REPO`. `stop and ship partial` exists only when the user explicitly asks to stop (still not “complete”).

**Fast, without skipping.** After inventory, the read loop is only this:

```bash
python3 ~/.cursor/skills/ai-security-reviewer/scripts/next_read_batch.py
# look at every FILE block in the output
python3 ~/.cursor/skills/ai-security-reviewer/scripts/next_read_batch.py --ack
```

Repeat until `BATCH_EMPTY`. Each file is printed whole. Tests are in the list. `--ack` only logs the batch you just saw. The coverage gate ignores typed counters and checks `files-read.log` against `must_read_files`.

**Clarification:** “100% coverage” means every `must_read_files` path was in a batch you looked at and acked — not “zero vulnerabilities” and not “dependency CVEs.”

Then execute the shortest complete loop:

```
explore (map + Read configs/routes) → candidates ledger → source→sink validation →
severity calibration (Impact × Exploitability × Exposure × Complexity) →
DAST/curl where reachable → adjudication → residual register → strict report
```

**Candidate ledger rule:** every plausible candidate ends as `Finding`, `Tentative`, or `Appendix A` with a named reason. Nothing silently disappears.

**Tool wording:** prefer `Glob`/`find` + `Read`. Use `rg` as a hint after you have opened configs and route files. Do not rely on skill scan scripts. Do not treat a 109-check `rg` pass as the review.

## Scope & honesty statement (read first)

No reviewer — human or AI — can guarantee it catches **every** vulnerability known to the world: it is undecidable in general, business-logic/design flaws need domain context, and **third-party dependency CVEs are out of scope** (use a dedicated composition scanner). This skill instead guarantees two achievable things:

1. **Completeness of consideration** — every class in the authoritative taxonomies (`standards-coverage-map.md`) is examined.
2. **No silent misses** — anything not verifiable in the current mode/environment is explicitly published in the **Completeness & Residual Risk Register**, not dropped.

Do **not** claim "zero vulnerabilities" or that no bugs remain in the universe. **Do** claim **inventory coverage 100%** only when `check_coverage_gate.py` passes (`files-read.log` contains every `must_read_files` path). Until then, run the next batch. Do not stop to ask the user to continue. For anything not assessable (SCA/CVE, live DAST declined), use the **Residual Risk Register** — never silent PASS.

## Out of scope (mandatory — do not run)

**Dependency / composition analysis is not part of this skill** — even if the user asks for `npm audit`, SCA, SBOM, or CVE dashboards. Decline politely and point them to OSV/Snyk/Dependabot/etc. Mark taxonomy rows for vulnerable components (OWASP A06, API10, ASVS V15) as **Residual — not in skill scope** in the Completeness register.

| Always forbidden | Examples |
|-----------|----------|
| Dependency/CVE databases | OSV API, `npm audit`, `pip-audit`, Maven/Gradle dependency CVE lookup |
| Container image CVE scanners | trivy, grype, Snyk container scan |
| SBOM / supply-chain tooling | CycloneDX export, KEV prioritization for library CVEs |
| Advisory-only findings | "Library X has CVE-…" without a **first-party** vulnerable usage path in VULN/AUTH/IAC/LEAK |
| `SCA-NNN` finding IDs | Removed — do not add a Software Composition Analysis report section |
| **Quantum / post-quantum / HNDL** | PQC migration, “quantum-vulnerable” RSA/ECC with **no classical break**, Shor/CRQC-only impact — see **`quantum-crypto-out-of-scope.md`**; Residual register only |

**In scope:** vulnerabilities visible in **first-party code and config** — auth gaps, injection sinks, secrets in source, IaC misconfigs read from Dockerfile/K8s YAML, logic flaws, IDOR/BOLA, JWT handling, CORS/filter bugs, open redirects, **static mobile issues** (ATS/cleartext, exported Activities/Receivers/Providers/Services, on-device sensitive storage, WebView), deep-link session theft, etc.

---

## Execution model

**You are the scanner.** Use `graphify`, `rg`, `Read`, and Burp MCP / user-approved `curl`. **Do not run** `run_sast_scan.sh`, `run_cve_iac_scan.sh`, `discover_burp_hosts.sh`, or `generate_coverage_appendix.py`.

| Layer | Who runs it | What it does |
|-------|-------------|--------------|
| **SAST** | **This agent (you)** | Map + **Read** code/config (`exploration-first.md`) → optional hint `rg` → `graphify` when useful → G1–G5 |
| **DAST** | **This agent (you)** | Burp MCP or **mandatory terminal `curl`** — AUTH + VULN + **IDOR dual-session** + **JWT probes** |
| **IaC** | **This agent (you)** | `rg` + `Read` per `iac-misconfig-scan.md` — **source/config review only** (no image CVE scanners) |
| **ARCH** | **This agent (you)** | Threat model (`security-architect.md`) → **Top 3 structural risks** + optional **attack chains** |
| **RESEARCH** | **This agent (you)** | Senior security-researcher pass — issues **outside** the 109-check matrix; same G1–G5 validation |
| **Report** | **This agent (you)** | `<repo>_security_report.md` + **`## Scan Attestation Summary`** → `generate_html_report.py --strict` |

### Scripts (no subagents)

- **No skill scripts for analysis** — explore with `Read` / `Glob`; hint `rg` only. Allowed helpers: `enumerate_inventory.py`, `derive_report_name.py`, `check_coverage_gate.py`, `generate_html_report.py`, `check_lang_packs.py`.
- **No subagents** — do not use the Task tool, explore agents, or shard workers. You own inventory, reads, AUTH, flows, REACH-ADJ-01, G0–G5, route-exposure severity, and the report. On a large repo, keep walking the next module in this same session (`large-repo-runner.md`). A file with `read_ranges` in the inventory is a reading plan for you, not a worker assignment.
- **No dependency/CVE tools** — see **Out of scope** above.

### Reference index (each file listed once — load by phase, see Quick start)

| Phase | File | When / purpose |
|-------|------|----------------|
| A | `exploration-first.md` | Always — map + Read; patterns are hints |
| A | `senior-researcher.md` | Always — static + LOG-01…15 logic abuse |
| A | `lang-packs/README.md` + active `lang-packs/<pack>.md` | Always — the **only** language sink source (L01–L35 index). `vuln-class-matrix.md` = human reference, never load in a scan |
| A | `large-repo-runner.md` · `large-repo-playbook.md` | Large repo — same session, every module, no workers |
| A | `weak-model-parity.md` | Small model — AUTH after config Read |
| A | `scan-session-memory.md` | Large repo / likely compact — resume, do not re-scan |
| A | `multi-profile-config-audit.md` | Multi-profile configs — read EVERY profile (this **is** the config read; do it once) |
| A | `per-method-auth-audit.md` (+ `express-auth-audit.md` for Express, `route_auth_audit.md` for route tables) | The **one** AUTH walk — one row per HTTP method |
| A | `async-second-order-audit.md` | Queues, cron, workers, Lambda/Spark, stored filters |
| A | `idor-bola-audit.md` · `authorization-privilege-escalation-audit.md` · `business-logic-abuse-checklist.md` · `jwt-deep-test.md` · `protocol-scans-graphql-ws-grpc.md` | Object references · horizontal/vertical privilege (BOLA/BFLA) · commerce/payments · JWT · GraphQL/WS/gRPC |
| A | `xml-security-audit.md` | Any XML/SOAP/SAML parser or builder — XXE, entity expansion, structural XML/XPath/XSLT injection, signature wrapping |
| A | `mobile-sast-audit.md` + `mobile-sast-manifest.md` · `deeplink-audit.md` | Mobile code · deep links / App Links |
| A | `iac-misconfig-scan.md` · `secrets-patterns.md` · `secret-type-labels.md` · `git-history-secrets-scan.md` | Docker/K8s/CI · secrets (labels for LEAK) · `.git` history |
| A | `security-architect.md` | Top 3 structural risks (+ `attack-chain-narrative.md` when ≥2 chainable) |
| A (hint) | `additional_vulns.md` | SAST-EXT-01…07 (smuggling, JNDI, session fixation, ReDoS/zip-bomb) — classes not in packs |
| A (hint) | `patterns.md`, `sast_scan_manifest.md`, `injection-deep-scan.md`, `extended-category-scans.md` | Legacy cross-language catalogs: **only** for files whose language has no active pack. Never run them on a file a pack covers |
| B | `ai-validate-precision-pass.md` | TP/FP per site; stored-taint; exploitability alignment; FP never in Detailed Findings |
| B | `manual-code-review.md` | G0–G5 gates, taint, forbidden exclusion reasons |
| B | `effective-controls-catalogue.md` | G3/G4 evidence before excluding anything |
| B | `precision-false-positive-adjudication.md` | SSRF/LDAP/INJ/DESER, IDOR-ADJ-01, AUTH-ADJ-02/03/04, EXPLOIT-ADJ-01 |
| B | `finding-confidence-validation.md` | Two-stage validation, confidence, fail-open ledger |
| B | `severity-calibration.md` · `quantum-crypto-out-of-scope.md` · `risk-score-rubric.md` | Four-factor severity (LEAK never Critical) · quantum/HNDL excluded · executive risk score |
| B | `finding-instances.md` | Same root cause → one ID with instances |
| C | `dast-verification-flow.md` · `burp_poc_templates.md` · `burp-host-discovery.md` · `curl-dast-fallback.md` | Burp PoC always; curl only with user permission; never localhost |
| D | `report-output-spec.md` · `finding-templates.md` · `per-instance-narrative.md` · `report-naming-convention.md` | Report sections, finding format, per-instance Description/Impact/Remediation/code, `<repo>_security_report.*` |
| D | `coverage-complete-gate.md` | **Before** “scan complete” or final HTML — G1–G7 + forbidden phrases |
| D | `standards-coverage-map.md` | OWASP/CWE/ASVS/LLM sweep + Completeness & Residual Risk Register |
| D | `report-findings-verification-register.md` · `scan-attestation-summary.md` · `baseline-delta-report.md` | Checklist · attestation · delta vs prior report |
| — | `dependency-install-policy.md` | Missing python3/curl/rg |
| Skip | `sca-dependency-audit.md`, `osv-sca-scan.md`, `maven-sca-scan.md`, `sbom-export.md`, `kev-prioritization.md`, `cve-exploitability.md`, `container-image-scan.md` | **Deprecated (v4.46)** — SCA removed from skill; do not load |
| Skip | `parallel-shard-review.md`, `agent-execution.md`, `model-proof-operating-contract.md`, `multi-module-enumeration.md`, `scan-scope-metrics.md`, `vulnerability-coverage-overview.md`, `report-coverage-matrix.md` | Deprecated or superseded — do not load |

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

For each taxonomy row, assign **Covered** / **N/A (justified)** / **Residual (not assessable in this mode/env)**. Then publish the **`## Completeness & Residual Risk Register`** in the report — this is how the skill proves it did not *silently* miss anything. Mark dependency-CVE classes (OWASP A06, API10, ASVS V15, LLM03) as **Residual — not in skill scope**; never label an unassessed area "PASS".

## Accuracy & confidence (mandatory — fewer false positives, zero silent drops)

Apply the two-stage model in **`finding-confidence-validation.md`** plus **`ai-validate-precision-pass.md`**:

1. **Stage 1 — wide net:** generate every plausible candidate by **reading** maps, configs, routes, and workers (`exploration-first.md`). Optional hint `rg` after Read. Favor recall.
2. **Stage 2 — adjudicate:** per **call site** (file + line or method+path), apply G0–G5 + CWE micro-rubric + precision ADJ rules + **`ai-validate-precision-pass.md`** (TP/FP verdict, stored-taint check, exploitability alignment). **False Positive → Appendix A only** — never a Detailed Finding row.
3. **Stage 2b — promote:** only **True Positive** with source, sink, and `data_flow` (or AUTH gap evidence) become `VULN-*` / `AUTH-*` / `IAC-*` / `LEAK-*`. **`effective-controls-catalogue.md`** §1 must be cited to exclude; §2 for preconditions.
4. **Severity / DAST:** four-factor severity (**not** DAST/Not Verified) + DAST for **Verification Status** separately. Mandatory `### Severity Rationale`. **v4.54:** missing auth on **internal routes, webhooks, or cron/worker** triggers → **Medium** default (`severity-calibration.md`). **v4.56:** **quantum-only / HNDL / PQC** → **do not report** (`quantum-crypto-out-of-scope.md`); classical crypto unchanged.
5. **Fail-open + ledger:** uncertain → **Tentative** or Appendix A with reason — never silent drop. **Needs Manual Review &lt;5%** of candidates; prefer committed FP with evidence over weak TP.
6. **CVE-override:** never suppress known-active exploited patterns (Log4Shell-style JNDI, deserialization gadgets) without human-review trace.

Add a **Confidence** column to the Security Verification Checklist.

## Security researcher layer (mandatory — beyond 109 checks)

The **109-check matrix is a hint list, not the scanner.** From the first file you open, follow **`senior-researcher.md`**: static defects **and** product abuse. Checklist rows may catch a class you forgot — they do not replace unread handlers.

### When to use

- After configs/routes are opened and before final report
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

### Pre-report gates (G0–G5)

| Gate | Verify |
|------|--------|
| **G0** | **Language context** (`lang-packs/README.md` Step 3): sink is real in *this* language/framework; escaping default verified from config; content type matches the class; pattern came from this file's pack. Write `G0: <pack> — <rule>` in Assumptions |
| **G1** | Attacker-controlled input or missing auth on reachable route? |
| **G2** | **`graphify path` if graph exists; else manual trace ≥3 hops** |
| **G3** | Effective protection? → Appendix A |
| **G4** | Practically exploitable? |
| **G5** | Assumptions in **`### Assumptions`** on each detailed finding |

### AUTH vs VULN dedup

See **`report-output-spec.md`** — unchanged from v4.14.

---

## Review sequence (each step runs once)

```
1. Inventory        → enumerate_inventory.py (or fresh memory). Sole enumeration: modules, configs, HTTP files,
                      packs. No manual re-enumeration, no scan-scope recount.
2. Mode             → large ? large-repo-runner.md (same session, every module) : single pass.
3. Configs/secrets  → Read EVERY config/profile/.env/vault/pem ONCE (multi-profile-config-audit.md rules).
                      LEAK candidates to ledger.
4. Context brief    → framework, middleware order, auth mechanism, parsers, template/ORM facts (≤40 lines).
5. AUTH walk (once) → per-method table for every route (per-method-auth-audit.md; express-auth-audit.md
                      for Express; route_auth_audit.md rules). Replaces all separate AUTH passes.
6. Flow walk        → every sensitive operation end-to-end (route → middleware → handler → model →
                      queue/cron/webhook): IDOR/BOLA + vertical/BFLA privilege matrix, workflow skip, money/amount trust, mass assignment,
                      races (check → await → write), idempotency, async/second-order. senior-researcher
                      LOG-01…15 applied here — not repeated later.
7. Sinks            → active lang packs only (L01–L35 rows, scoped rg after Read). XML surface additionally
                      runs xml-security-audit.md even with an active pack. Legacy catalogs only for files with no active pack.
8. IaC / mobile / protocol / git history → when inventory lists them (one pass each).
9. Adjudicate       → per call site: G0–G5, precision ADJ rules (including XSS/XXE/XML/IDOR/PRIV),
                      ai-validate-precision-pass (TP/FP);
                      FP → Appendix A only; TP → confidence + severity + instances. Ledger closes:
                      Finding / Tentative / Appendix A (with ADJ/gate reason for every FP).
10. Architect       → security-architect.md Top 3 (+ attack chains) from findings already validated.
11. DAST            → write the Burp PoC once per HTTP finding; Burp MCP if present; curl only if the user
                      approves; never localhost.
12. Report          → only if check_coverage_gate.py exits 0: standards sweep →
                      <repo>_security_report.md (Review status: complete) →
                      generate_html_report.py --strict. Else: progress snapshot in_progress only.
```

**Never in sequence:** OSV, `npm audit`, KEV, CVE reachability, container image CVE scan, SBOM — SCA removed v4.46.

Record applicable checks in **internal scan log**; mark CVE/DEPS taxonomy rows **N/A (not in skill scope)**; publish **Scan Attestation Summary** in user report.

---

## Finding formats

Required sections: **Classification** (Source/Sink), **Description**, **`### Instances`** when N > 1, **`### Affected endpoints`** (method, path, auth today, instance — every HTTP route for this finding; `N/A` for LEAK/IAC), **Assumptions**, **Vulnerable Code Snippet**, **Data Flow Trace**, **Impact Assessment**, **`### Severity Rationale`**, **Remediation**, **`### Burp Suite PoC`** for every HTTP finding (one request per affected endpoint row).

### Detailed narrative contract (MANDATORY — every finding, v4.55)

Every `VULN-*`, `AUTH-*`, `IAC-*`, and `LEAK-*` Detailed Finding must be independently actionable:

- **`### Description` — 3–6 issue-specific sentences.** Name the attacker/actor, exact entry point and attacker-controlled value (or missing-auth route), missing/ineffective control, source→sink behavior, exploit result, and material preconditions. Do not restate the title or use category boilerplate.
- **`### Impact Assessment` — 2–5 issue-specific sentences.** Name the exact data, account, tenant, operation, infrastructure resource, or business workflow harmed. State confidentiality/integrity/availability/business consequences only when applicable. Do not write only “High impact,” “RCE,” or a generic CIA table.
- **`### Remediation` — repository-specific implementation plan.** Identify the file/component and control to change, show or describe the secure replacement pattern, address all affected instances, and include a regression-test or verification step. Add defense in depth separately; “validate input,” “add authentication,” “use encryption,” or “upgrade” alone is invalid.
- **No shared boilerplate.** Text must explain this finding even if read without its title or checklist row. Do not copy the same paragraph across unrelated findings.
- **Multi-instance findings:** provide `#### Instance N` narratives under Description, Impact, and Remediation (plus Vulnerable Code) as required by `per-instance-narrative.md`.

`generate_html_report.py --strict` must reject missing or generic Description, Impact, or Remediation before final handoff. Full quality rules: `finding-templates.md`, `report-impact-assessment.md`, and `report-finding-completeness.md`.

**Multi-instance (N ≥ 2):** under Description, Vulnerable Code, Impact, and Remediation, use **`#### Instance N`** (and optional **`#### Shared root cause` / `#### Shared fix`**) with path-specific prose and verbatim snippets — **`per-instance-narrative.md`**. `--strict` HTML export enforces instance heading counts.

**Title:** root cause + component, not a single-path nickname when several routes share the cause (`finding-templates.md` v4.35.3).

Templates: **`finding-templates.md`**, **`report-vulnerable-code-dataflow.md`**, **`report-impact-assessment.md`**.

**Finding IDs:** VULN-NNN, AUTH-NNN, IAC-NNN, LEAK-NNN only. **Same CWE + root cause → one ID with `### Instances`** (per-instance Source/Sink) — see `finding-instances.md`. Do not repeat finding IDs for the same pattern across files/endpoints.

**Report secret redaction:** show enough evidence to prove a secret exists (type, file, line, first/last 4 chars or hash), but redact raw values in reports and PoCs unless the user explicitly asks for raw evidence in a secure context.

**Discovery tag (mandatory in checklist):** `Checklist` or `Researcher` — researcher findings are first-class; same format and verification bar.

**Confidence (mandatory per finding):** `Confirmed` / `Firm` / `Tentative` per `finding-confidence-validation.md`.

---

## Phase 4: Generate report

Per **`report-output-spec.md` v4.20**.

**Mandatory:** Executive Summary with **risk score rubric** · Coverage Overview · Scan Agent attribution · Scan Matrices · **Scan Attestation Summary** · **Completeness & Residual Risk Register** (`standards-coverage-map.md`) · Top Structural Risks · Verification Checklist (with **Confidence** column) · Detailed Findings · Remediation Priority · Appendices A, B, C, D, F.

**No SCA section** — never include `## Software Composition Analysis (SCA)` or `SCA-NNN` findings. In **Scan Attestation Summary**, one line: *Third-party dependency/CVE analysis is out of scope for this skill.*

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

# 3. Gate — must pass before final handoff (v4.50)
python3 ~/.cursor/skills/ai-security-reviewer/scripts/check_coverage_gate.py

# 4. Write the new report to "$MD", then render HTML (final handoff only when gate passed)
python3 ~/.cursor/skills/ai-security-reviewer/scripts/generate_html_report.py "$MD" \
  -o "$HTML" --project "[Project Name]" --strict
```

Override the derived slug with `--project "Your Name"` when the user has supplied an explicit project label. Never write to the bare `security_report.md` / `security_report.html` filenames.

`--strict` fails on: missing Source/Sink, field inconsistencies, register backfill, missing **Assumptions** or **Remediation** per finding.

Deliver **both** `.md` and `.html` using the derived `<repo>_*` filenames **only when the coverage gate passes**. Partial progress: draft markdown OK with `Review status: in_progress`; do **not** present as finished.

---

## Usage

```
Run enumerate_inventory.py. Single agent only — no shard workers. Large repo: large-repo-runner.md.
Walk every production_must_read_files path and every HTTP module in this same session until
check_coverage_gate.py exits 0. Write the report before you stop. Never ask the user to say continue.
Do not say scan complete until the gate passes. APPLY coverage-complete-gate.md.
```

```
Run a comprehensive security audit. Finish it in one session.
Read every production file and AUTH-walk every HTTP module, then check_coverage_gate.py → HTML.
Do not pause for the user to type continue.
```

Optional: `/graphify .`

**You own the full report.** Do not delegate reads to subagents.

---

## Extended references

See **`CHANGELOG.md`** for version history.
