# Standards Coverage Map + Completeness & Residual Risk Register (MANDATORY)

**Purpose:** Guarantee that **no known vulnerability class is left unconsidered**, and that **anything code-only mode cannot verify is explicitly registered** — never silently missed.

This is the **completeness backbone** of the skill. The 109-check matrix is *implementation*; this file is the *coverage contract* against authoritative 2025/2026 taxonomies.

> **Honest scope:** No reviewer (human or AI) can guarantee zero missed vulnerabilities — it is undecidable in the general case, and business-logic/design flaws require domain context. The goal here is **completeness of consideration** (every known class is examined) and **transparency of gaps** (every un-verifiable area is registered), not an impossible "zero-miss" claim.

---

## How to use (mandatory each review)

1. **Sweep** every row of every taxonomy table below against the target code.
2. For each row decide: **Covered** (checklist/researcher finding or PASS with evidence), **N/A** (stack/feature absent — justify), or **Residual** (cannot verify in this mode/environment — register it).
3. Publish the **Completeness & Residual Risk Register** (template at end) in the report so the reader sees exactly what was and was not verifiable.
4. Any **Residual** row that is high-impact must be called out in **Top Structural Risks**.

---

## 1. OWASP Top 10 — 2021

| ID | Category | Primary coverage | Notes |
|----|----------|------------------|-------|
| A01 | Broken Access Control | `route_auth_audit.md`, `idor-bola-audit.md`, researcher pass | Core strength |
| A02 | Cryptographic Failures | `secrets-patterns.md`, SAST-OG-07/16, crypto review | Weak hash/cipher/IV, hardcoded keys |
| A03 | Injection | SAST-INJ-*, SAST-OG-03/18/25/27/28, `injection-deep-scan.md` | SQLi, CMD, XXE, SSTI, LDAP, XPath |
| A04 | Insecure Design | `security-architect.md`, `business-logic-abuse-checklist.md`, researcher pass | Manual — needs threat model |
| A05 | Security Misconfiguration | `iac-misconfig-scan.md`, config review, CORS/filter review | Source/config only |
| A06 | Vulnerable & Outdated Components | **RESIDUAL in code-only mode** | Dependency CVE scanning disabled — **must register** (see §6) |
| A07 | Identification & Auth Failures | `jwt-deep-test.md`, auth interceptor review, session checks | |
| A08 | Software & Data Integrity Failures | Deserialization (SAST-OG-15), CI/CD config, update integrity | Library-side gadgets = Residual |
| A09 | Security Logging & Monitoring Failures | `frontend-stacktrace-leaks.md`, log review (ASVS V16) | Often Manual |
| A10 | SSRF | SAST-OG-22, outbound-fetch trace | |

---

## 2. OWASP API Security Top 10 — 2023

| ID | Category | Primary coverage |
|----|----------|------------------|
| API1 | Broken Object Level Authorization (BOLA) | `idor-bola-audit.md` + dual-session DAST |
| API2 | Broken Authentication | `jwt-deep-test.md`, `route_auth_audit.md` |
| API3 | Broken Object Property Level Authorization (mass assignment / excessive data) | Researcher pass + response-shape review |
| API4 | Unrestricted Resource Consumption | Rate-limit / pagination review (ASVS V2/V4) — often Manual |
| API5 | Broken Function Level Authorization (BFLA) | Admin-vs-user route audit |
| API6 | Unrestricted Access to Sensitive Business Flows | `business-logic-abuse-checklist.md` |
| API7 | Server Side Request Forgery | SAST-OG-22 |
| API8 | Security Misconfiguration | `iac-misconfig-scan.md`, headers/CORS |
| API9 | Improper Inventory Management | Shadow/debug/ops endpoint hunt (researcher pass) |
| API10 | Unsafe Consumption of APIs | Outbound-trust review; library CVEs = **Residual** |

---

## 3. CWE Top 25 — 2024 (most dangerous weaknesses)

| CWE | Name | Coverage |
|-----|------|----------|
| CWE-79 | Cross-site Scripting | SAST-INJ-XSS, SAST-OG-06 |
| CWE-787 / 125 / 119 | Memory OOB write/read/bounds | **N/A for JVM/Node/managed** — register if native C/C++/Rust present |
| CWE-89 | SQL Injection | SAST-OG-25, SAST-INJ-* |
| CWE-352 | CSRF | SAST-OG-05 |
| CWE-22 | Path Traversal | SAST-OG-24 |
| CWE-78 / 77 | OS / Command Injection | SAST-OG-03, SAST-INJ-CMD |
| CWE-416 / 476 / 190 | Use-after-free / NULL deref / Integer overflow | **N/A for managed runtimes** — register for native |
| CWE-862 / 863 / 306 | Missing / Incorrect Authorization, Missing Auth for Critical Function | `route_auth_audit.md`, researcher pass |
| CWE-434 | Unrestricted File Upload | `extended-category-scans.md` + ASVS V5 |
| CWE-94 | Code Injection | SAST-OG-02, SAST-INJ-RCE |
| CWE-20 | Improper Input Validation | ASVS V1/V2 review |
| CWE-287 / 269 | Improper Authentication / Privilege Mgmt | auth + role review |
| CWE-502 | Deserialization of Untrusted Data | SAST-OG-15 |
| CWE-200 | Sensitive Info Exposure | SAST-LEAK-*, SAST-OG-21 |
| CWE-918 | SSRF | SAST-OG-22 |
| CWE-798 | Hardcoded Credentials | SAST-SECRET-*, `secrets-patterns.md` |
| CWE-400 | Uncontrolled Resource Consumption | DoS/ReDoS review (SAST-OG-09) |

---

## 4. OWASP ASVS 5.0 (May 2025) — 17 chapters (completeness sweep)

Walk each chapter; treat as a checklist of *control areas* that must each get a Covered / N/A / Residual verdict.

| Chapter | Area | Coverage anchor |
|---------|------|-----------------|
| V1 | Encoding & Sanitization | injection/XSS manifests |
| V2 | Validation & Business Logic | input validation + `business-logic-abuse-checklist.md` |
| V3 | Web Frontend Security | headers, cookies, CSP, CORS review |
| V4 | API & Web Service | `route_auth_audit.md`, `protocol-scans-graphql-ws-grpc.md` |
| V5 | File Handling | upload/path review (CWE-434/22) |
| V6 | Authentication | auth interceptor/session review |
| V7 | Session Management | session/cookie/timeout review |
| V8 | Authorization | `idor-bola-audit.md`, BFLA |
| V9 | Self-contained Tokens | `jwt-deep-test.md` |
| V10 | OAuth & OIDC | OAuth flow review when present |
| V11 | Cryptography | crypto + key review |
| V12 | Secure Communication | TLS/transport config review |
| V13 | Configuration | `iac-misconfig-scan.md`, config secrets |
| V14 | Data Protection | PII/data-at-rest/in-transit review |
| V15 | Secure Coding & Architecture | `security-architect.md`; dependency hygiene = **Residual** in code-only mode |
| V16 | Security Logging & Error Handling | log/error-leak review |
| V17 | WebRTC | N/A unless WebRTC present |

---

## 5. OWASP Top 10 for LLM Applications — 2025 (run only if the target is an LLM/GenAI app)

| ID | Category | When to apply |
|----|----------|---------------|
| LLM01 | Prompt Injection | App passes untrusted text into an LLM prompt |
| LLM02 | Sensitive Information Disclosure | LLM can echo secrets/PII |
| LLM03 | Supply Chain | model/plugin provenance — often Residual |
| LLM04 | Data & Model Poisoning | training/RAG ingestion paths |
| LLM05 | Improper Output Handling | LLM output → sink (XSS/SQL/exec) |
| LLM06 | Excessive Agency | tool/function-calling scope |
| LLM07 | System Prompt Leakage | system prompt exposure |
| LLM08 | Vector & Embedding Weaknesses | RAG/vector store access control |
| LLM09 | Misinformation | over-reliance on unverified output |
| LLM10 | Unbounded Consumption | token/cost DoS |

If the target is **not** an LLM app, mark this whole section **N/A** in the register (one line).

---

## 6. Completeness & Residual Risk Register (MANDATORY report section)

Publish this in `security_report.md` (after Scan Attestation Summary). It is how the skill proves it did not **silently** miss anything.

```markdown
## Completeness & Residual Risk Register

| Standard | Area | Status | Evidence / Reason |
|----------|------|--------|-------------------|
| OWASP 2021 | A01 Broken Access Control | Covered | AUTH-001, VULN-002 |
| OWASP 2021 | A06 Vulnerable Components | **Residual — not assessed** | Dependency/CVE scanning disabled (code-only mode). Recommend separate SCA run. |
| OWASP API 2023 | API4 Resource Consumption | Residual — partial | No rate-limit config found; runtime not tested (no reachable host) |
| ASVS 5.0 | V12 Secure Communication | Residual | TLS terminated at gateway, out of repo scope |
| CWE Top 25 | CWE-787 OOB Write | N/A | Managed runtime (JVM), no native code |
| LLM 2025 | All | N/A | Not an LLM application |
| DAST | Live exploit verification | Residual | No reachable host resolved; findings are Code/Config confirmed only |

**Residual ≠ safe.** Each Residual row is an area that requires additional tooling, environment, or scope to confirm. High-impact Residual rows are escalated to Top Structural Risks.
```

### Rules

- **Every** authoritative section above (1–5) must produce at least a summary verdict in the register — no taxonomy may be omitted.
- Use **Residual — not assessed** (not "PASS") whenever a class is out of the current mode/scope (e.g., dependency CVEs in code-only mode). Calling an unassessed area "PASS" is a reporting defect.
- If the target stack makes a class impossible (managed-memory runtime vs CWE-787), mark **N/A** with the reason.
- Reconcile: register sections ↔ Scan Attestation Summary counts ↔ Detailed Findings IDs.
