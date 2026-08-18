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

**Evidence required:** cite Dockerfile, compose, Ingress, README deploy instructions, or `[TARGET_HOST]` assumption in Assumptions.

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

**Forbidden cap:** `Not Verified`, `no Burp/curl`, `user declined curl`, `401 at gateway on probe`, `WAF blocked`, `no target host in code` — **none of these may lower severity**. They belong in **Verification Status** / **DAST Status** / **Confidence** only.

### Step 2 — Critical (all must be true)

Assign **Critical** only when **every** row passes:

| # | Requirement |
|---|-------------|
| 1 | **Impact** = Severe (Business Impact SEVERE or equivalent) |
| 2 | **Exploitability** = Trivial or Practical |
| 3 | **Exposure** = Public or Internal (with cited evidence) |
| 4 | **Complexity** = Low or Medium |
| 5 | **Confidence** = Confirmed **or** Firm with unambiguous static proof (full source→sink) |

**Typical Critical examples:** SQLi with Firm trace to DB dump on public route; hardcoded prod DB password in deploy artifact; fail-open webhook on public bind with Severe pipeline/agent hijack impact (Firm code proof — live probe optional).

**Not Critical by default:** low-impact misconfig; local-only compose Mongo; read-only `/health` without sensitive data.

### Step 3 — High

Assign **High** when Impact is **High or Severe** and Exploitability is **Practical or Trivial**, Exposure is **Public or Internal**, and Step 1 caps do not apply.

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
| Prod Dockerfile/K8s exposes admin/actuator/secrets | **High**–**Critical** by Impact |
| `docker-compose.yml` local Mongo, no auth | **Medium** max (Exposure Local) |
| Container runs as root | **Medium** (amplifier) |
| Hardcoded secret in **deployed** config | **Critical**–**High** per `secrets-patterns.md` |

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
| Severity = Confidence | Independent dimensions | Firm + Not Verified + High is valid |
| Downgrade because 401 on curl | Gateway may block probe; code may still be vulnerable | Not Verified + severity from code |
| Skip Severity Rationale | Not reproducible | Mandatory section |

---

## Reconciliation gate (before HTML `--strict`)

- [ ] `### Severity Rationale` present with four factors + Severity row
- [ ] Title `[SEVERITY]` matches Rationale + Checklist + Classification
- [ ] **No** severity chosen because of Not Verified / skipped curl / no host
- [ ] Step 1 caps honored (Tentative, Local, Hardening only)
- [ ] Verification Status / DAST Status populated separately from Severity

---

## Worked example (webhook fail-open — code-only, Not Verified)

| Factor | Rating |
|--------|--------|
| Impact | High (pipeline/agent control) |
| Exploitability | Practical (omit signature header) |
| Exposure | Public (Dockerfile `0.0.0.0:8765`) |
| Complexity | Low |
| Confidence | Firm |
| Verification status | Not Verified (no target host in code) |

**Wrong:** Medium because Not Verified  
**Wrong:** Critical because "auth bypass" pattern alone  
**Correct:** **High** — Step 3 (High impact + Practical + Public + Low complexity). DAST stays Not Verified; does not reduce severity.

---

**See also:** `finding-confidence-validation.md`, `report-impact-assessment.md`, `report-finding-field-consistency.md`, `dast-verification-flow.md`, `finding-templates.md`.
