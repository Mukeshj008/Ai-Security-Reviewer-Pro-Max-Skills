# Severity Calibration (MANDATORY — before assigning Critical/High/Medium/Low)

**Purpose:** Severity must be **derived**, not guessed from pattern type or CWE name alone. Every finding gets a reproducible severity from four factors: **Impact**, **Exploitability**, **Exposure**, and **Complexity**.

**Relationship to other fields:**

| Field | Question it answers | Affects severity? |
|-------|---------------------|-------------------|
| **Confidence** (`finding-confidence-validation.md`) | How sure are we the flaw exists? (Confirmed / Firm / Tentative) | **Tentative only** → Medium max (uncertainty, not DAST) |
| **Verification / DAST status** | Did Burp/curl confirm live behavior? (`Verified in Burp` / `Not Verified` / …) | **No** — report separately; never downgrade severity because live probe was skipped or inconclusive |
| **Exploitable** (`report-finding-field-consistency.md`) | Can it be triggered in production? (Yes / No / Hardening) | **Yes** — via Exploitability factor |
| **Impact Assessment** (`report-impact-assessment.md`) | If triggered, what is harmed? (CIA + Business table) | **Yes** — Impact factor |
| **Severity** (this doc) | How urgent is remediation? (Critical / High / Medium / Low) | — |

**Do not conflate them:**
- A **Firm** finding can be **High** severity even when **Not Verified**.
- **Not Verified** means live DAST did not confirm — it does **not** mean Medium severity.
- **Verified in Burp/curl** may upgrade **Confidence** to Confirmed **only for the claimed effect** (empty `200` ≠ Confirmed BOLA — AUTH-ADJ-02); it does **not** automatically upgrade **Severity** (severity still follows the four factors).

---

## The four factors (score each before severity)

Rate each factor using the enums below. Record ratings in **`### Severity Rationale`** (mandatory in Detailed Findings).

### 1. Impact (I) — harm if exploited

Use the **highest** level from the finding's `### Impact Assessment` table (Confidentiality, Integrity, Availability, Authentication, Business Impact).

| Level | When |
|-------|------|
| **Severe** | RCE, full account takeover, mass PII/financial exposure, production secret harvest, pipeline/agent hijack with spend or code write |
| **High** | Sensitive single-tenant data, privileged workflow control (approve plans, trigger CI), auth bypass on state-changing routes |
| **Medium** | Limited data leak, DoS on non-critical path, misconfig with narrow blast radius |
| **Low** | Information useful to attackers but no direct compromise; dev ergonomics issues |
| **None** | No meaningful harm (usually Appendix A, not a finding) |

### 2. Exploitability (E) — can an attacker trigger it?

Align with **Exploitable** + G4, but rate trigger ease:

| Level | When |
|-------|------|
| **Trivial** | Single request; no auth; default deploy; PoC works as-is |
| **Practical** | Achievable with documented steps; may need known config (repo slug, branch name) |
| **Conditional** | Requires specific env (empty secret, DEBUG, feature flag) — maps to **Exploitable: Hardening** |
| **Impractical** | Theoretical only; G4 fails → Appendix A |

### 3. Exposure (X) — who can reach the attack surface?

| Level | When |
|-------|------|
| **Public** | Internet-facing URL, public webhook tunnel, `0.0.0.0` bind in prod Dockerfile/K8s Ingress |
| **Internal** | Cluster/VPN/corporate network; other pods/services can reach; staging with broad access |
| **Local** | `127.0.0.1` bind, developer `docker compose` only, not in production deploy path |
| **None** | Not deployed; test/mock code only |

**Evidence required:** cite Dockerfile, compose, Ingress, nginx/gateway config, or an auth middleware that runs before the handler. A path string is not evidence.

### Route exposure — decide this before Step 3 (v4.45)

Score **Exposure from how the route is reached**, not from the word in the path. Record the class in `### Severity Rationale`.

| Class | What you must have read | Exposure | Severity effect |
|-------|-------------------------|----------|-----------------|
| **external** | Edge config proxies this prefix with no `auth_basic`, `allow`/`deny`, or mTLS (for example `location /api/` → app). Or there is no edge config in the repo and the route itself has no auth middleware. | **Public** | High is allowed when Impact is High |
| **internal-named-but-proxied** | The path contains `/internal`, `/admin`, `/ops`, or `/seller`, but the only edge config forwards the parent prefix with no ACL. | **Public** | Do not downgrade because of the path name |
| **internal-gated** | Basic auth, mTLS, API key, or an IP allowlist is in the file and runs **before** the handler. | **Internal** | High max. Medium when the gate is real and the missing check is a second factor |
| **non-prod-only** | The handler returns 404 or skips the action unless a staging/preprod flag is set, and that flag is false in production config. | **Internal** | **Medium max** |
| **loopback** | Binds `127.0.0.1` and no proxy location points at it. | **Local** | **Medium max** (Step 1) |
| **needs-network-position** | TLS verification off, or a secret only useful to someone already on the network or in the log store. | not Public | **Medium max**. High only when the same bug also takes a user-controlled URL (SSRF) or the secret is a production credential in the repo (LEAK cap) |

Unknown deployment ACLs stay in the Residual Register. They do not lower a **Public** rating and they do not raise a **Local** one.

**Same bug, different exposure:** if one instance is external and another is internal-gated, severity follows the worst instance. Say which instance that is.

### 4. Complexity (C) — attacker effort beyond the PoC

| Level | When |
|-------|------|
| **Low** | Copy-paste PoC; no chaining; no timing |
| **Medium** | Needs repo-specific knowledge, multi-field payload, or guessing config |
| **High** | Multi-step chain, race, second victim, or repeated attempts |
| **Very high** | Insider, physical access, breaking crypto |

**Chaining note:** If exploit **requires** another finding (e.g., SSRF after AUTH bypass), rate Complexity on the **dependent** finding higher unless the chain is trivial (document in Attack Chain Analysis).

---

## Severity decision matrix (apply in order)

### Step 1 — Hard caps (never from DAST / Not Verified)

| Rule | Cap |
|------|-----|
| **Confidence: Tentative** | **Medium** max |
| **Exposure: Local** (compose/dev-only, not prod path) | **Medium** max for IAC/AUTH unless prod manifest proves otherwise |
| **Exploitable: Hardening** | **High** max (usually Medium) |
| **Exploitable: No** | Do not report — Appendix A |
| **Hardcoded credentials** (`LEAK-NNN`, `SAST-SECRET-01…12`, `SAST-OG-10`) | **Critical forbidden** — see **§ Hardcoded credentials severity cap** below |
| **Missing authentication** (`AUTH-NNN`) on **internal** route, **webhook**, or **cron/worker** trigger — see **§ Internal / webhook / cron missing-auth (v4.54)** | **Medium** default; **High/Critical forbidden** on that finding unless a **separate** public external route shares the same root cause (severity follows worst **external** instance) |
| **Quantum-only / HNDL / PQC migration** (no classical break today) — see **`quantum-crypto-out-of-scope.md`** | **Do not report** — Residual / Appendix A only |

**Forbidden cap:** `Not Verified`, `no Burp/curl`, `user declined curl`, `401 at gateway on probe`, `WAF blocked`, `no target host in code` — **none of these may lower severity**. They belong in **Verification Status** / **DAST Status** / **Confidence** only.

### Internal / webhook / cron missing-auth (MANDATORY — v4.54)

Apply when the finding is **missing or broken authentication** (no session/JWT/API key, fail-open verify, trust of unsigned body) on any of:

| Surface | How to recognize | Default severity |
|---------|------------------|------------------|
| **Internal route** | Path or gateway class **internal-gated**, **loopback**, **non-prod-only**; service mesh / cluster-only bind; `/internal`, `/admin` behind mTLS or IP allowlist with **no app-level auth** | **Medium** |
| **Webhook** | Inbound HTTP callback (`/webhook`, `/hooks`, Stripe/GitHub-style receivers, `@PostMapping("/webhooks/...")`) without HMAC/signature/token verification, or verify always passes | **Medium** |
| **Cron / worker / scheduler HTTP** | `@Scheduled`, Quartz/cron activation URL, queue consumer admin API, K8s `CronJob` wget/curl to app, Lambda/Step Functions HTTP trigger without auth | **Medium** |

**Rules:**

1. **Assign Medium** as the default severity for the AUTH finding on that surface (record in `### Severity Rationale`: *v4.54 internal/webhook/cron missing-auth default*).
2. **Do not assign High or Critical** for missing auth **only** on these surfaces — even when Impact narrative mentions pipeline or payment hooks. Split issues: unsigned webhook body → Medium AUTH; injection/RCE on same handler → separate `VULN-NNN` at normal severity.
3. **Exception — external public API:** If the **same** missing-auth pattern affects an **external** route (internet-facing, no edge gate), severity for that **instance** follows Steps 2–3 (may be High/Critical). Use `### Instances` when one controller mixes internal and public paths.
4. Document Exposure class in Rationale (`internal-gated`, `webhook`, `cron/worker`).

**See also:** `per-method-auth-audit.md`, `async-second-order-audit.md`, `express-auth-audit.md`.

### Post-quantum / harvest-now crypto (OUT OF SCOPE — v4.56)

**Do not create findings** for quantum-only, HNDL, or PQC-readiness issues. Full rules: **`quantum-crypto-out-of-scope.md`**.

**Classical crypto** (MD5/SHA-1 passwords, weak TLS versions, `none` JWT, hardcoded keys, misuse) — use the normal matrix above; may be High/Critical when Impact and Exposure warrant.

### Hardcoded credentials severity cap (MANDATORY — LEAK / SAST-SECRET)

**Never assign Critical** to findings whose primary issue is a **committed credential** (password, API key, token, private key, connection string with embedded password, Vault/cloud SM literal in config/source). Use **`LEAK-NNN`** (preferred) or existing secret IDs — not inflated to Critical because impact narrative mentions “production database” or “live Stripe key.”

| Situation | Max severity | Notes |
|-----------|--------------|--------|
| Credential in **production** deploy path (`application-prod*`, `config/production/**`, prod K8s/Helm values, `sk_live_`, prod JDBC URL to non-local host) | **High** | Rotate + vault/env; cite profile/manifest for Exposure |
| **Staging / preprod / QA** profile or shared non-prod host with real-shaped secret | **High** or **Medium** | **High** if same secret reused in prod or artifact ships to prod-like env; else **Medium** |
| **Local / dev-only** profile (`local`, `dev`, `docker-compose` not in prod path), or developer machine defaults | **Medium** | Step 1 **Exposure: Local** cap still applies |
| **Test fixtures** under `tests/`, `*Test*`, `__mocks__` with obvious dummy (`changeme`, `password123`, `YOUR_*_HERE`) | **Low** or Appendix A | Skip per `secrets-patterns.md` when clearly non-production |
| Pattern match only; cannot confirm prod path or real credential shape | **Medium** max (Tentative) | Confidence Tentative cap stacks |

**Impact note:** Secret exposure can rate **Impact: Severe** in `### Impact Assessment` (credential theft, DB access) — that does **not** override this cap. **Severity** for hardcoded secrets stays **High** or **Medium** per table above.

**Not covered by this cap:** injection/RCE, missing auth on routes, SSRF, **runtime** secret dump via actuator/env endpoint (`IAC-NNN` / misconfig) — those still use Steps 2–3 and may reach Critical when all Step 2 gates pass.

### Step 2 — Critical (all must be true)

Assign **Critical** only when **every** row passes:

| # | Requirement |
|---|-------------|
| 1 | **Impact** = Severe (Business Impact SEVERE or equivalent) |
| 2 | **Exploitability** = Trivial or Practical |
| 3 | **Exposure** = Public or Internal (with cited evidence) |
| 4 | **Complexity** = Low or Medium |
| 5 | **Confidence** = Confirmed **or** Firm with unambiguous static proof (full source→sink) |

**Typical Critical examples:** SQLi with Firm trace to DB dump on public route; fail-open webhook on public bind with Severe pipeline/agent hijack impact (Firm code proof — live probe optional).

**Not Critical (use LEAK + cap):** hardcoded DB password, API keys, JWT signing secrets, or Vault tokens in `application-*.properties` / source — **High** (prod path) or **Medium** (local/staging-only) per hardcoded-credentials cap.

**Not Critical by default:** low-impact misconfig; local-only compose Mongo; read-only `/health` without sensitive data.

**v4.35 — also not Critical by default:**

| Pattern | Max unless Step 2 **and** cited public/Ingress bind |
|---------|-----------------------------------------------------|
| Spring module with no `SecurityFilterChain` / no `spring-boot-starter-security` | **High** |
| `LEAK` / CWE-321 hardcoded AES/key in source (use LEAK + v4.34 cap) | **High** |
| Exposure rated **Local** in Severity Rationale | **Medium** (existing Step 1) |

### Step 3 — High

Assign **High** when Impact is **High or Severe** and Exploitability is **Practical or Trivial**, Exposure is **Public or Internal**, the route class is **external**, **internal-named-but-proxied**, or **internal-gated**, and Step 1 caps do not apply.

Do not assign High for **non-prod-only**, **loopback**, or **needs-network-position** (those are Medium max). A committed production credential stays High under the LEAK cap even when exploit needs repo access.

Common cases (including when **Not Verified**):
- Fail-open auth on state-changing webhook + Public exposure + Firm code proof
- Injection with complete source→sink on public route
- Optional signature bypass (`if sig and …`) + High impact route + Low complexity

### Step 4 — Medium

- Impact **Medium** with Practical exploitability
- **Exposure: Local** (Step 1 cap)
- **Exploitable: Hardening** / Conditional exploitability
- **Confidence: Tentative** (Step 1 cap)
- Gateway **may** block live probe — severity still from code + four factors if Firm

### Step 5 — Low

- Impact Low/Medium + Hardening + Local exposure
- Defense-in-depth gaps with effective compensating controls **verified** in repo
- Prefer Appendix A if G4 fails

### Step 6 — Adjustments (not DAST)

| Adjustment | Effect |
|------------|--------|
| Effective compensating control **verified** (cite manifest) | −1 severity band |
| Compensating control **assumed** not proven | No downgrade — note in Assumptions |
| Live PoC succeeded | May set **Confidence: Confirmed** — **do not auto-bump severity** unless four factors justify it |
| Chained trivial exploit | Rate each finding; mention chain separately |

---

## Category-specific rules

### AUTH-NNN (missing / broken authentication)

| Condition | Severity | Verification status (separate) |
|-----------|----------|------------------------------|
| High/Severe impact + Practical exploit + Public/Internal exposure + Firm | **High**–**Critical** (per Step 2–3) | `Not Verified` or `Verified in Burp` — **does not change severity** |
| Medium impact or Local exposure | **Medium** | Any verification status |
| Read-only `/health` / `/ready` / `/status` / liveness (no secrets, no PII) | **Low** AUTH-NNN — **still a finding** (never Appendix D–only); **AUTH-ADJ-03** — never standalone High/Critical | Any verification status |
| Unauth data route + live `200 []` / empty orders, no foreign fields | **AUTH Medium–High** by handler privilege (ops/refund/PNR vs catalog); **not** Critical BOLA | Verified reachability ≠ Confirmed data-exfil |

Mandatory **Burp PoC** for every AUTH finding regardless of severity or verification status.

### IDOR / BOLA (CWE-639)

| Condition | Severity / disposition |
|-----------|------------------------|
| Attacker ID is query key **and** response has foreign object fields (or live PII/PFI) | **High**–**Critical** per Steps 2–3 |
| Live `200 []` / empty collection, no victim fields | **Not Confirmed BOLA** — AUTH if unauth; IDOR **Tentative** (AUTH-ADJ-02) |
| Lookup+response bound to token subject; request `userId` unused | **Appendix A G3** IDOR-ADJ-01 — not a VULN |
| Dummy SSO / unused `order_id` / dead next hop | **Appendix A G4** EXPLOIT-ADJ-01 |

### VULN-NNN (injection, SSRF, XSS, etc.)

| Condition | Severity |
|-----------|----------|
| Firm source→sink + Public + Low complexity + High/Severe impact | **High**–**Critical** |
| SSRF with Practical chain | **High** on SSRF; rate AUTH separately by its four factors |

### IAC-NNN / LEAK-NNN

| Condition | Severity |
|-----------|----------|
| Prod Dockerfile/K8s exposes admin/actuator/secrets | **High**–**Critical** by Impact (misconfig — not LEAK cap) |
| `docker-compose.yml` local Mongo, no auth | **Medium** max (Exposure Local) |
| Container runs as root | **Medium** (amplifier) |
| Hardcoded secret in config/source (`LEAK-NNN`, SAST-SECRET) | **High** or **Medium** only — **never Critical** (hardcoded-credentials cap) |

---

## Mandatory report section: `### Severity Rationale`

Place **after** `### Impact Assessment`, **before** `### Assumptions`:

```markdown
### Severity Rationale

| Factor | Rating | Evidence |
|--------|--------|----------|
| Impact | High | Business Impact: unauthorized pipeline/Cursor agent control |
| Exploitability | Practical | Omit `X-Slack-Signature`; fail-open if secret unset |
| Exposure | Public (assumed) | Webhook bound `0.0.0.0:8765` in Dockerfile |
| Complexity | Low | Single POST, no chaining |
| **Severity** | **High** | Step 3: High impact + Practical + Public + Low complexity |
```

**Rules:**
1. **Severity** row must match the finding title `[SEVERITY]`.
2. If a Step 1 cap applied, state it explicitly (never cite Not Verified as a cap).
3. Checklist **Severity** must match; **Verification Status** / **DAST Status** are separate columns.

---

## Internal adjudication record (extend candidate ledger)

```
impact=..., exploitability=..., exposure=..., complexity=...,
severity=..., severity_cap=tentative|local-exposure|hardening|none,
confidence=..., verification_status=..., dast_status=..., rationale=one line
```

---

## Anti-patterns (do not do this)

| Anti-pattern | Why wrong | Fix |
|--------------|-----------|-----|
| Medium because Not Verified | Conflates DAST with severity | Calibrate four factors; Not Verified → Verification Status only |
| High/Critical only after Burp | Severity ≠ live proof | Firm static proof can justify High |
| Critical because "missing auth" | Ignores impact/exposure | Complete Severity Rationale |
| High/Critical for webhook/cron/internal missing auth only | v4.54 default is **Medium** | Medium + cite internal/webhook/cron table |
| Any finding for “RSA-2048 needs PQC someday” | Quantum-only risk | **Out of scope** → Appendix A / Residual only; separate classical issues |
| Critical for hardcoded AWS/DB/JWT in config | LEAK cap forbids Critical | **High** (prod) or **Medium** (local/staging); cite cap in Rationale |
| Severity = Confidence | Independent dimensions | Firm + Not Verified + High is valid |
| Downgrade because 401 on curl | Gateway may block probe; code may still be vulnerable | Not Verified + severity from code |
| Skip Severity Rationale | Not reproducible | Mandatory section |

---

## Reconciliation gate (before HTML `--strict`)

- [ ] `### Severity Rationale` present with four factors + Severity row
- [ ] Title `[SEVERITY]` matches Rationale + Checklist + Classification
- [ ] **No** severity chosen because of Not Verified / skipped curl / no host
- [ ] Step 1 caps honored (Tentative, Local, Hardening, **hardcoded-credentials**, **internal/webhook/cron AUTH**); **quantum-only crypto excluded**
- [ ] No **LEAK-NNN** / SAST-SECRET finding labeled **Critical**
- [ ] Verification Status / DAST Status populated separately from Severity

---

## Worked example (unsigned inbound webhook — v4.54)

| Factor | Rating |
|--------|--------|
| Issue | `AUTH-NNN` — POST `/webhooks/deploy` accepts body with no HMAC/signature check |
| Surface | **Webhook** (inbound callback) |
| Impact | High (could trigger deploy) if exploited |
| Exposure | Public URL |

**Wrong:** **High/Critical** because impact mentions pipeline control — v4.54 caps missing webhook auth at **Medium** default.  
**Wrong:** Medium because Not Verified — DAST does not set severity.  
**Correct:** **Medium** — missing authentication on webhook; cite v4.54 table. If the handler also has **command injection**, file a separate **VULN-NNN** at normal severity.

## Worked example (cron HTTP trigger without auth — v4.54)

| Factor | Rating |
|--------|--------|
| Issue | `AUTH-NNN` — `GET /internal/cron/run-backup` callable without token |
| Surface | **Internal route** + **cron** activation |

**Correct:** **Medium** — internal/cron missing-auth default. Exposure **Internal** supports the cap.

---

**See also:** `finding-confidence-validation.md`, `report-impact-assessment.md`, `report-finding-field-consistency.md`, `dast-verification-flow.md`, `finding-templates.md`.
