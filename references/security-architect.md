# Security Architect & Researcher Lens (ARCH-*)

**Goal:** Supplement pattern matching with **threat modeling**, **trust boundaries**, and **attack-surface reasoning** — like a principal security architect reviewing a design.

This phase does **not** replace SAST/DAST. It **prioritizes** where to dig and **documents** systemic gaps in **Appendix G**.

---

## ARCH-01 — Attack surface enumeration

**Graphify queries:**

```bash
graphify query "public API routes webhooks callbacks file upload export download" --budget 1500
graphify query "admin internal cron worker queue consumer websocket grpc" --budget 1500
```

**Deliverable (Appendix G):**

| Surface | Entry points | Auth model | Data sensitivity |
|---------|--------------|------------|------------------|
| Public HTTP | `/api/...` | SSO / none | PII / financial |
| Internal | `/internal/...` | Basic / mTLS | ops |
| Async | Kafka/SQS consumer | message trust | varies |

---

## ARCH-02 — Trust boundary map

Identify boundaries where data crosses trust levels:

```
Internet → CDN/WAF → Ingress → App → Redis/DB → Third-party APIs
```

**rg helpers:**

```bash
rg -n "axios\.|fetch\(|http\.request|makeRequest" routes api lib
rg -n "redis|mongoose|sequelize|kafka|amqp" config loadApp app.js
```

**Flag:** missing validation at boundary (ARCH finding → link to SAST-OG-14 / route auth).

---

## ARCH-03 — STRIDE per critical component

For each component in ARCH-01 table, note primary STRIDE threats:

| Component | S | T | R | I | D | E |
|-----------|---|---|---|---|---|---|
| Login API | ✓ | | ✓ | | | |
| File upload | | ✓ | | ✓ | ✓ | |
| Payment callback | ✓ | ✓ | | ✓ | | ✓ |

**S**poofing **T**ampering **R**epudiation **I**nfo disclosure **D**enial **E**levation

Only document threats with **code evidence** or **confirmed Burp** result.

---

## ARCH-04 — Sensitive data flow (PII/secrets)

```bash
graphify query "password token ssn card pan email phone session cookie encrypt" --budget 1500
rg -n "customer_id|order_id|pan|card|ssn|aadhaar|phone|email" routes api --glob "!*test*"
```

Map: **collect → store → log → transmit → display**. Flag logging/display without redaction.

---

## ARCH-05 — Security control gap analysis

Compare implemented controls vs **OWASP ASVS L1** expectations:

| Control | Expected | Observed | Gap |
|---------|----------|----------|-----|
| Session fixation protection | regenerate on login | ? | |
| CSRF on state-changing routes | token middleware | ? | |
| Security headers | helmet/CSP | ? | |
| Dependency pinning | lockfile + audit | ? | |
| Secrets management | vault/env, not code | ? | |

Fill from code reads — cite file:line for "Observed".

---

## ARCH-06 — CVE threat intelligence (researcher)

When `npm audit` or CVE-DEPS finds issues:

1. Read advisory: attack vector, affected versions, fixed version.
2. Search codebase for **vulnerable API surface** (not just package name).
3. Check **CISA KEV** / public exploit availability for Critical items.
4. Prioritize: **KEV + reachable** → P0 in remediation.

**Do not** report CVE without reachability pass (see `cve-exploitability.md`).

---

## ARCH-07 — IaC blast radius

For each IAC-FINDING, document:

- **Exposure:** internet / VPC / internal
- **Lateral movement:** can compromise lead to DB/secrets?
- **Multi-tenant risk:** shared cluster/namespace?

Links to `iac-misconfig-scan.md` findings.

---

## Appendix E rows

| ID | Description |
|----|-------------|
| ARCH-01 | Attack surface enumeration |
| ARCH-02 | Trust boundary map |
| ARCH-03 | STRIDE threat table |
| ARCH-04 | Sensitive data flow map |
| ARCH-05 | Security control gap (ASVS) |
| ARCH-06 | CVE threat intel + KEV prioritization |
| ARCH-07 | IaC blast radius analysis |

**Status:** `PASS` (documented, no gaps) | `FINDING` (gap linked to VULN/CVE/IAC) | `PARTIAL` | `N/A` (trivial repo)

---

## Appendix G — Security Architecture Assessment (MANDATORY)

Include in every report after Appendix F:

```markdown
## Appendix G: Security Architecture Assessment

### Attack Surface Summary
[Table from ARCH-01]

### Trust Boundaries
[Diagram or bullet flow from ARCH-02]

### Top Structural Risks
1. [Risk] — Evidence — Linked findings (VULN/CVE/IAC/AUTH)

### Control Maturity
| Domain | Maturity (1-5) | Notes |
|--------|----------------|-------|
| Authentication | | |
| Authorization | | |
| Input validation | | |
| Cryptography | | |
| Logging/monitoring | | |
| Supply chain | | |
| Infrastructure | | |

### Researcher Notes
[CVE prioritization, novel attack chains, defense-in-depth recommendations]
```
