# Senior Manual Code Review Methodology (MANDATORY)

**Role:** Act as a Senior Application Security Engineer performing a manual code review.

**Objective:** Identify only **realistic, exploitable** security issues with **high confidence**. Avoid speculative findings and minimize false positives.

This reference **supplements** (does not replace) graphify recon, SAST manifests, route auth audit, Burp MCP / curl DAST, and the 109-check matrix. Every automated or pattern hit must still pass the gates below before becoming a FINDING.

**v4.17 — Security researcher mandate:** The 109 checks are a **minimum coverage floor**. You **must** also perform an independent researcher review (`SKILL.md` § Security researcher layer) and report validated issues even when no check ID applies. Researcher findings use the same G1–G5 bar and normal VULN/AUTH/IAC/LEAK IDs.

> **v4.15 note:** Record Phase −1 context in **agent working notes** and **Top Structural Risks** / optional **Attack Chain Analysis** in the user report. Legacy **Appendix G** references below remain valid for internal architect work.

---

## Phase −1: Application Context (before broad scanning)

Complete this **before** Phase 0 (Graphify recon) or in parallel with the first `graphify query`. Record answers in internal architect notes (and **Top Structural Risks** in user report). Legacy: Appendix G.

### Context checklist

| Area | Determine |
|------|-----------|
| **Language & runtime** | Node, Java, Python, Go, etc.; version pins |
| **Framework** | Express, Spring, Django, AngularJS, React, Jade, etc. |
| **Architecture** | Monolith, BFF, microservices, server-rendered + SPA hybrid |
| **Entry points** | HTTP routes, WebSockets, cron, CLI, webhooks, file uploads |
| **Trust boundaries** | Internet → edge → app → session store → DB → third-party APIs |
| **Authentication** | SSO, session cookies, JWT, API keys, HMAC, basic auth, gateway-only |
| **Authorization** | Role checks, object-level ACLs, seller vs admin vs customer scopes |
| **Sensitive assets** | Tokens, credentials, PII, payment/financial data, admin panels |

### User-controlled inputs (sources)

Map all attacker-influenceable data:

- Query parameters, path segments, headers, cookies, JSON/form body
- File uploads (name, content, MIME)
- WebSocket messages
- OAuth/callback parameters
- Data stored by users that other users read (stored XSS, second-order injection)

### Sensitive assets (what attackers want)

- Session identifiers, OAuth tokens, API keys
- Customer/merchant PII, reviews, order data
- Payment/wallet/refund flows
- Admin or internal-only functionality
- Infrastructure credentials (Vault, Redis, DB connection strings)

**Tools:** README, `AGENTS.md`, `docs/architecture/`, `graphify query "routes auth middleware session"`, scoped reads of `routes/`, `middleware/`, `app.js`.

---

## Phase 2 (manual): Taint / Data-Flow Analysis

For every candidate (pattern hit, graphify hotspot, or auth gap):

1. **Identify SOURCE** — exact file:line:method; classify input type (HTTP param, header, upload, etc.).
2. **Trace propagation** — follow data across functions, files, services, API calls, DB queries.
3. **Identify SINK** — SQL/NoSQL exec, shell, file I/O, outbound HTTP (SSRF), template/HTML render, deserialize, LDAP, XPath, SSTI.
4. **Document controls** — validation, sanitization, encoding, authorization, framework defaults, WAF/gateway (note if out-of-app).
5. **Prove or disprove reachability** — `graphify path "<source>" "<sink>"` + narrow `Read` on path nodes only.

**Rule:** No FINDING without a documented source→sink path (or explicit AUTH/access-control gap with HTTP surface).

---

## Review Taxonomy (manual lens)

Use this checklist **in addition to** SAST manifests. Prioritize categories that match application context (Phase −1).

### Standards & logic

| Category | Focus |
|----------|--------|
| OWASP Top 10 | Broken access control, crypto failures, injection, insecure design, misconfiguration, vulnerable components, auth failures, integrity failures, logging/monitoring, SSRF |
| OWASP API Top 10 | Broken object level auth, broken auth, excessive data exposure, lack of resources/rate limits, broken function level auth, mass assignment, security misconfiguration, injection, improper assets management, unsafe consumption of APIs |
| Business logic | Workflow bypass, price/quantity manipulation, race conditions, state machine abuse |

### Authentication & session

- Hardcoded credentials, API keys, tokens, secrets (`secrets-patterns.md`)
- Weak password policy, missing/weak hashing (MD5/SHA1/plaintext)
- Weak session generation, insecure remember-me, auth bypass logic
- Weak or missing auth on sensitive routes (see `route_auth_audit.md`)
- Session fixation, predictable session IDs, timeout issues
- Missing secure / HttpOnly / SameSite cookie flags
- JWT weaknesses (alg none, weak secret, missing exp/aud validation)
- Credential stuffing enablers (no lockout / weak rate limits)

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §3, §13  
**Extended probes:** `extended-category-scans.md` §3, §13

### Authorization

- Missing authorization / role validation on sensitive handlers
- IDOR / BOLA (access object by changing ID without ownership check)
- Privilege escalation (role parameter, admin routes without panel auth)
- Mass assignment, missing ownership validation, forced browsing

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §4  
**Extended probes:** `extended-category-scans.md` §4

### Injection (trace source → sink for each)

- SQL, NoSQL, Command/OS command, LDAP, XPath, XML
- CRLF, header, email-header injection
- SSTI, expression-language (SpEL/OGNL/EL), log injection

**Manifests:** `injection-deep-scan.md`, `extended-category-scans.md` §1  
**Full taxonomy map:** `vulnerability-taxonomy-coverage.md` §1

### Client & web

- XSS: reflected, stored, DOM-based; HTML injection; JavaScript injection
- CSRF on state-changing operations
- Open redirect (`redirect=`, `next=`, `url=` params)
- CORS misconfiguration (overly permissive `Access-Control-Allow-Origin`)

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §2

### File & path

- Directory/path traversal, arbitrary file read/write
- Unrestricted file upload (type, size, path, executable content)
- File inclusion (LFI/RFI), symlink abuse, unsafe temp files

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §7  
**Extended probes:** `extended-category-scans.md` §7

### Server & protocol

- SSRF, open redirect, unsafe URL fetch handling
- XXE, XML entity expansion, parser misconfiguration
- Unsafe deserialization / RCE via deserialization chains
- Race conditions (TOCTOU), business logic flaws
- Debug mode, insecure defaults, disabled security controls
- Overly permissive CORS, missing security headers, weak TLS

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §8, §11–§15  
**Extended probes:** `extended-category-scans.md` §8–§15, §19 (framework-specific)

### Secrets & crypto

- Hardcoded secrets (see `secrets-patterns.md`)
- Weak algorithms (MD5, SHA1, DES), weak cipher modes (ECB)
- Static/predictable IV, predictable salt, hardcoded crypto keys
- Insecure RNG, improper certificate validation, custom crypto

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §5, §6  
**Extended probes:** `extended-category-scans.md` §5, §6

### Disclosure & abuse

- Stack traces / debug info to clients (see `frontend-stacktrace-leaks.md`)
- Sensitive data in logs or error responses
- Rate limiting gaps on auth/OTP/expensive endpoints

### API-specific

- Mass assignment, verbose errors, missing schema validation
- Shadow/admin endpoints not in public docs

### Mobile (if applicable)

- Hardcoded API endpoints, local storage of secrets, insecure WebView
- Certificate pinning gaps, unsafe IPC, weak local encryption

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §16 — **N/A** unless mobile tree in repo  
**Extended probes:** `extended-category-scans.md` §16

### Memory (native C/C++/Rust only)

- Buffer/heap/stack overflow, format strings, use-after-free — **N/A** for typical web stacks

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §9

### Cloud / IaC / supply chain

- Public buckets, excessive IAM, K8s/Docker misconfigs (`iac-misconfig-scan.md`)
- Dependency advisories, dependency confusion, unsafe package sources (`sca-dependency-audit.md` only in explicit SCA mode; otherwise residual)

**Taxonomy:** `vulnerability-taxonomy-coverage.md` §17–§18

### Framework-specific (conditional)

- Spring Boot, Node.js, PHP, Python, Java, .NET — run `extended-category-scans.md` §19 when stack detected

**Mapping:** Core internal checks + the **Completeness & Residual Risk Register** cover a baseline issue list. Manual **security-researcher review** adds **business logic**, **authz chains**, **cross-file flows**, and **domain-specific bugs** that patterns and check IDs miss — report these as first-class findings with `Discovery: Researcher`.

---

## Pre-Report Verification Gates (MANDATORY)

**Before** assigning VULN-NNN, AUTH-NNN, IAC-NNN, or LEAK-NNN, answer all five gates. If any gate fails → **FALSE POSITIVE** → Appendix A, not Detailed Findings. In explicit SCA mode, use `SCA-NNN` per `sca-dependency-audit.md`; do not turn advisory-only dependency issues into VULN findings.

| Gate | Question | PASS criterion |
|------|----------|----------------|
| **G1 — Attacker control** | Is there an actual attacker-controlled input (or missing auth on a reachable HTTP route)? | YES with file:line evidence |
| **G2 — Reachability** | Can the input realistically reach the dangerous sink (or unauthenticated handler execute)? | YES — `graphify path` or equivalent trace |
| **G3 — Protections** | Is there existing protection that blocks exploitation? | Judge against **`effective-controls-catalogue.md` §1** — cite the control's `file:line`; bypassable control = NOT effective |
| **G4 — Practical exploit** | Can it **practically** be exploited (not theoretical, not dev-only, not test-only)? | YES with concrete attack scenario; check **`effective-controls-catalogue.md` §2** preconditions |
| **G5 — Assumptions** | What assumptions are required (auth role, second victim, timing, internal network)? | Listed explicitly; minimal assumptions preferred |

**G3/G4 evidence rule:** an exclusion is valid only when you name the control (§1) or the unmet precondition (§2) **with a citation**. Unknown precondition → **Tentative**, not Appendix A.

### G3 / G4 hard gates (v4.33 — apply before every VULN/AUTH ID)

These **override** pattern severity and live `200` excitement. Cite `file:line` or the HTTP status+body.

| Fail this → Appendix A | Gate | Typical mis-report |
|------------------------|------|---------------------|
| Response/lookup binds to **session/token subject**, not attacker `userId`/`customerId` | **G3** IDOR-ADJ-01 | "IDOR because query has userId" |
| Live `200` with **empty** array/object and **no** foreign PII/PFI fields | **G4** for BOLA *data leak* | "Confirmed Critical IDOR" |
| Live `500`/`400` "required `sso_token` / parameter missing" | **G4** Confirmed-unauth | "Unauth because app error JSON" |
| Probe-safe `/health` `/status` `OK` with no secrets | **G4** AUTH-ADJ-03 | Standalone Critical AUTH |
| Dummy token **rejected** by SSO or next hop never uses the ID | **G4** EXPLOIT-ADJ-01 | "Invoice IDOR, dummy SSO accepted" |
| SSRF/LDAP from sink name only | **G3** SSRF-ADJ-01 / LDAP-ADJ-01 | Pattern-only VULN |

**Still a finding (do not Appendix-A):** missing auth on a **data or privileged** handler (even if today's probe returned `[]`) → **AUTH** Firm, not Confirmed BOLA. `200 []` proves the route ran **without** a session; it does **not** prove cross-user data.

**Confirmed BOLA / data-exfil** requires **one** of: (1) live body contains another user's fields, or (2) code trace shows attacker ID is the **query key** **and** that object is serialized in the response. Otherwise IDOR ≤ **Tentative**.

### Verdict rules

| Outcome | Action |
|---------|--------|
| All gates PASS | TRUE POSITIVE → Detailed Finding + **mandatory** Burp PoC if HTTP |
| G1 or G2 fails | FALSE POSITIVE → Appendix A |
| G3 effective protection | FALSE POSITIVE → Appendix A — cite control `file:line`; failed gate **G3** (+ adjudication ID e.g. SSRF-ADJ-01) |
| G4 fails (theoretical only) | FALSE POSITIVE → Appendix A; failed gate **G4**; note "speculative" |
| G5 requires many unlikely assumptions | Downgrade or exclude; document in Appendix A |
| Missing auth in code, live probe not run (user declined / no host) | AUTH-NNN per **`severity-calibration.md`** + **Not Verified** + **mandatory Burp PoC** — cover every unauth route as an **instance** under that AUTH (or merge under shared root-cause AUTH); not Appendix D–only |
| Unauthenticated `/health` (no secrets) | **Low** instance under shared AUTH (or Low AUTH if unique root cause) |
| Multiple files/endpoints, same root cause | **One finding ID** + `### Instances` with Source/Sink each — **`finding-instances.md`** |
| Missing auth, Burp/curl confirms 2xx / business body | Same severity rules — live success may set **Confidence: Confirmed**; **does not auto-upgrade severity** unless four factors justify it |

### Confidence labels (single canonical enum)

Use **`Confirmed` / `Firm` / `Tentative`** only — defined in `finding-confidence-validation.md`. The legacy High/Medium/Low confidence wording is **removed**; High/Medium/Low belong to **Severity** (`severity-calibration.md`). Never put a severity word in a confidence field.

| Confidence | Meaning | Where it goes |
|------------|---------|---------------|
| **Confirmed** | Live PoC succeeded, or unambiguous static proof with full source→sink | Detailed Findings |
| **Firm** | G1–G5 pass on strong static evidence, no live verification | Detailed Findings |
| **Tentative** | Plausible; a hop, control, or precondition is unproven | Detailed Findings **with `### Assumptions`**, or Appendix A with a named reason |

**Default posture:** report **precisely**, not sparsely. Every candidate ends as a Finding, a Tentative finding, or an Appendix A row **with a named failed gate** — never a silent drop (`finding-confidence-validation.md` fail-open policy). Resolve doubt by **reading the code and citing the control** (`effective-controls-catalogue.md`), not by omitting the candidate.

Precision comes from evidence: cite the neutralizing control (§1) or the unmet precondition (§2) of `effective-controls-catalogue.md` when excluding. An exclusion without cited evidence is a defect, exactly like an unproven finding.

---

## Integration with existing skill phases

| Skill phase | Manual review addition |
|-------------|------------------------|
| Phase −1 (this doc) | Context checklist → Appendix G |
| Phase 0 | Graphify queries informed by entry points & trust boundaries |
| Phase 1 / manifests | Hits are **candidates only** until gates pass |
| Phase 1f | Extended taxonomy scans (`extended-category-scans.md`) → Completeness & Residual Risk Register |
| Phase 1a | Auth audit = G1 for access control |
| Phase 2 | Mandatory taint trace per candidate → feeds **`### Data Flow Trace`** |
| Phase 3 | Apply **Pre-Report Verification Gates** + AI Validation Checklist |
| Phase 3b | Burp PoC for **every** HTTP TRUE POSITIVE + AUTH (live probe optional) |
| Phase 4 | Each finding: **`### Vulnerable Code Snippet`** + **`### Data Flow Trace`** + **`### Remediation`** (see `report-vulnerable-code-dataflow.md`) |
| Appendix A | All false positives with gate that failed |

---

## Appendix A exclusion template

When filtering a candidate, record:

```markdown
| Pattern | Location | Failed Gate | Exclusion Reason |
|---------|----------|-------------|------------------|
| SQL Injection | db.js:45 | G3 | Uses parameterized query via ORM |
| SSRF | fetch.js:12 | G4 | URL hardcoded; param not passed to fetch |
| SSRF | OutboundHttpClient.java:104 | **G3** | SSRF-ADJ-01: buildUrl() uses config base + pathSegment(domain); authority not attacker-controlled |
| LDAP | JsonPathUtils.java:60 | **G3** | LDAP-ADJ-01: JMESPath Expression.search on JsonNode; no LDAP sink in file or callee chain |
| XSS | template.jade:89 | G3 | Jade auto-escapes by default |
```

### Appendix A — forbidden exclusion reasons (MANDATORY)

The following exclusion reasons are **not allowed** because past reviews used them to silently drop real findings. Use only when **explicitly verified** with cited evidence:

| Forbidden reason (when unverified) | What you must do instead |
|--------------------------------------|--------------------------|
| "Relies on edge gateway / API gateway / WAF" | Cite the specific gateway manifest file:line (Kong/Apigee/NGINX/Spring Cloud Gateway/helm chart) showing the path is gated. **No gateway manifest in repo → cannot use this reason** — keep as Tentative/Not Verified, not Appendix A. |
| "Internal-only network" / "Not exposed to internet" | Cite the K8s `NetworkPolicy`, `Service.type=ClusterIP` with no Ingress, or VPC/SG rule. Pod-to-pod within the same cluster is **not** "internal" — service-mesh sidecars and other pods can hit it. |
| "Mutual TLS / service mesh authenticates" | Cite the mesh policy (Istio `PeerAuthentication`, Linkerd policy) showing `STRICT` mode for the namespace. |
| "Pre-prod / staging only" | Cite the deployment manifest showing the image/profile never ships to prod. A repo-only `dev` profile is **not** proof — `Dockerfile` may still bake it in (see prior Dockerfile-dev-profile finding). |
| "Test code only" | The file path must be under `**/test/**`, `**/tests/**`, or `src/test/`. A file named `*Test*.java` under `src/main/` is **production**. |
| "Annotation present on the class" | Open the interceptor and confirm a class-level annotation actually applies to the method in question (most custom Spring interceptors check **method** annotation only — see `per-method-auth-audit.md`). |
| "Other endpoints on the same controller are protected" | Per-method analysis required (see `per-method-auth-audit.md`) — peer protection is **not** transitive. |
| "Same DB password is dev/test" | Confirm the password value does not appear in any `application-{prod,pre-prod,uat,perf}*.{yml,properties}` profile. Reuse across environments is itself a finding. |
| "`restTemplate.exchange` / `fetch(` / `axios(` present → SSRF" | Run **SSRF-ADJ-01** (`precision-false-positive-adjudication.md`): trace who controls scheme/host/port. Config base + pathSegment/query only → Appendix A with cited builder. |
| "`.search(` method call → LDAP injection" | Run **LDAP-ADJ-01**: require LDAP imports (`LdapTemplate`, `InitialDirContext`, etc.). JMESPath `Expression.search`, Elasticsearch, Python `re.search` → Appendix A. |
| "Outbound call uses user-derived `domain` in URL → SSRF" | Distinguish **authority** vs **path segment**. `UriComponentsBuilder.fromHttpUrl(configBase).pathSegment(domain)` does not retarget host — Appendix A via **G3** (SSRF-ADJ-01). **G1 may still pass.** |
| "`.path()` with user input is safe like pathSegment" | **Forbidden.** `.path(userInput)` injects slashes/`..` — not an SSRF authority bypass but not a safe dynamic segment; do not Appendix A on SSRF authority grounds alone if `.path()` used |
| "200 empty JSON = Confirmed IDOR/BOLA" | **Forbidden.** Apply **IDOR-ADJ-01** + **AUTH-ADJ-02**. Empty body → AUTH (if no session) and/or Tentative IDOR, never Confirmed data-exfil. |
| "Query/header `userId` present = IDOR" | Trace whether that ID is the **repository key**. Token-bound response → Appendix A **G3** (IDOR-ADJ-01). |
| "Missing Spring Security = every route is Critical IDOR" | One AUTH finding with instances; IDOR only where object ID is used unsafely. Health/status → AUTH-ADJ-03. |

When in doubt → **do not move to Appendix A.** Keep as Tentative in Detailed Findings with explicit `### Assumptions` block listing what would have to be true for the finding to be a false positive. Reviewers will downgrade later; silent drops cannot be recovered.

---

## Senior reviewer notes (quality bar)

1. **One finding, one root cause** — do not duplicate the same bug as SQLi + injection + OG hit.
2. **Severity = f(Impact, Exploitability, Exposure, Complexity)** — use `severity-calibration.md`; not pattern severity alone. The shorthand **impact × exploitability × exposure** is retained but **Complexity** and **Step 1 caps** are explicit in the calibration doc.
3. **Compensating controls** — document gateway auth, WAF, network segmentation; adjust status/severity per AUTH rules and calibration downgrades **only when verified**.
4. **Test/dev code** — exclude unless deployed to production paths.
5. **Dependency advisories** — default code-only mode marks SCA residual. Explicit SCA mode uses `SCA-NNN`; promote to VULN only when there is first-party vulnerable usage with a normal source→sink trace.
6. **Prefer staging hosts** for Burp/curl; never localhost; **ask user before curl**.
7. **Evidence in report** — paste real source/sink code under **`### Vulnerable Code Snippet`**; never report without a documented data flow.

---

**See also:** `agent-execution.md` (per-check loop), `security-architect.md` (ARCH-*), `route_auth_audit.md` (AUTH-*), Phase 3 in `SKILL.md`.
