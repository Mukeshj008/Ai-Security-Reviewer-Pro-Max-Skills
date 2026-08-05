# Impact Assessment (MANDATORY per finding)

Every **Detailed Finding** must include `### Impact Assessment` with a **CIA + Business** table. Generic one-liners are **invalid** — they produce weak HTML and fail the completion gate.

---

## Required table (exact columns)

```markdown
### Impact Assessment

| Impact Category | Level | Description |
|-----------------|-------|-------------|
| Confidentiality | HIGH / MEDIUM / LOW / NONE | What data or secrets can be exposed — name the asset |
| Integrity | HIGH / MEDIUM / LOW / NONE | What can be modified, injected, or poisoned |
| Availability | HIGH / MEDIUM / LOW / NONE | DoS, shutdown, resource exhaustion |
| Authentication | HIGH / MEDIUM / LOW / NONE | Auth bypass, session abuse, token replay |
| Business Impact | SEVERE / HIGH / MEDIUM / LOW | Concrete outcome for this app (PII, payments, ops) |
```

**Rules:**
1. **Level** must be one of: `HIGH`, `MEDIUM`, `LOW`, `NONE`, or `SEVERE` (Business Impact only).
2. **Description** must name **this finding's** asset, route, or config — not a category template.
3. Fill **every row**; use `NONE` with a one-line reason when not applicable.
4. Do **not** duplicate the Classification table or Master Register row here.

---

## Category-specific guidance

### Missing authentication (AUTH / VULN)

| Row | Write about |
|-----|-------------|
| Confidentiality | Exact data returned without auth — classify **PII / PHI / PFI / None** (field names) |
| Integrity | Whether the route is read-only or can mutate state |
| Authentication | Application-layer auth missing; note gateway/WAF if live test inconclusive |
| Business Impact | Fraud, compliance (PCI/GDPR/HIPAA), customer trust, SLA |

### IDOR / BOLA (VULN)

| Row | Write about |
|-----|-------------|
| Confidentiality | Cross-user object access — mandatory **PII / PHI / PFI / None** labels + named fields (see `idor-bola-audit.md` Step 1b) |
| Integrity | Whether the IDOR allows create/update/delete of another tenant's object |
| Authentication | Session/token present but ownership check missing (horizontal/vertical) |
| Business Impact | Privacy breach, payment/health compliance, mass enumeration risk |

**Bad:** `IDOR on GET /orders/{id}.`  
**Good:** `Authenticated user B can read user A's order via `/v1/orders/{id}` (no ownership filter). Response includes **PII** (name, email, phone) and **PFI** (masked PAN last4, amount, payout account id).`

**Bad:** `Missing authentication — unauthenticated access to GET /foo.`  
**Good:** `Unauthenticated callers can read live catalog DB rows (`/v1/test` verified on staging) including product metadata used for storefront merchandising.`

### Information disclosure / debug leaks (VULN-LEAK)

| Row | Write about |
|-----|-------------|
| Confidentiality | Stack traces, internal paths, partner API payloads, env hints |
| Integrity | Usually NONE unless leak enables follow-on attack |
| Availability | Usually NONE |
| Authentication | Whether leak requires auth or is on public route |
| Business Impact | Aids targeted exploits; partner/integration exposure |

**Bad:** `Information disclosure via logs or error responses.`  
**Good:** `debug_panel=true returns RequestAnalyzerDTO with external client request/response bodies when DEBUG logging is enabled, exposing integration contracts and filtered view logic.`

### JWT / session / crypto gaps

| Row | Write about |
|-----|-------------|
| Confidentiality | What the token gates access to |
| Integrity | Forged or replayed actions |
| Authentication | Expired/revoked token acceptance, missing `exp`/`aud` |
| Business Impact | Account takeover, merchant impersonation |

**Bad:** `JWT validation gap.`  
**Good:** `Expired HS256 merchant tokens remain valid indefinitely; captured Authorization headers grant ongoing access to V2 decorator flows for p4b/gg_app clients.`

### IaC / actuator / infrastructure (IAC)

| Row | Write about |
|-----|-------------|
| Confidentiality | JMX/Jolokia, env, heap dumps, metrics |
| Integrity | Config changes, shutdown, deployment hooks |
| Availability | Shutdown endpoint, health abuse, resource drain |
| Authentication | `management.security.enabled=false`, network exposure |
| Business Impact | Full service outage, lateral movement, secret harvest |

**Bad:** `Infrastructure misconfiguration — expanded blast radius.`  
**Good:** `Production enables actuator shutdown on port 8778 with management security disabled; an actor on the management network can terminate the JVM and cause storefront outage.`

### SCA / CVE (reachable only)

| Row | Write about |
|-----|-------------|
| All rows | Tie to **advisory exploit scenario** + **your reachability proof** (HTTP entry → vulnerable API) |
| Business Impact | RCE, SSRF, deserialization — per CVE class |

---

## Exploitable vs Impact vs Severity

| Field | Purpose |
|-------|---------|
| **Exploitable** (Classification + Register) | Can an attacker **trigger** the flaw in production? `Yes` / `No` / `Hardening` only |
| **Impact Assessment** | **If triggered**, what is harmed? (CIA + business) — feeds **Impact** factor |
| **Severity Rationale** | **How urgent?** Derived from Impact + Exploitability + Exposure + Complexity (`severity-calibration.md`) |

**Mapping:**
- Preconditions (DEBUG on, internal network only) → **Exploitable: Hardening**; Impact still describes harm **when** preconditions met; Severity usually **Medium** (Exposure/Exploitability caps).
- Theoretical / filtered by gates → Appendix A, not a finding.
- Live verified AUTH → **Exploitable: Yes**; Severity from four factors (not auto-High).
- **Not Verified** → document in Verification Status; **do not** lower Severity because of it.

---

## Consistency gate (before HTML)

For each finding ID:

1. `### Impact Assessment` table present (5 rows minimum).
2. No generic fallback phrases (see `report-finding-field-consistency.md`).
3. Highest Impact **Level** should align with **Severity Rationale → Impact** row (Critical/High finding should not be all LOW/NONE without Step 1 cap noted in Severity Rationale).
4. **`### Severity Rationale`** present per `severity-calibration.md`.

```bash
# Every finding has Impact Assessment
MD="${MD:-$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)_security_report.md}"
FIND=$(rg -c "^## \[(CRITICAL|HIGH|MEDIUM|LOW)\]" "$MD" | awk -F: '{s+=$2} END {print s+0}')
IMP=$(rg -c "^### Impact Assessment" "$MD" | awk -F: '{s+=$2} END {print s+0}')
# FIND must equal IMP
```

---

## HTML note

The generator renders `### Impact Assessment` as the **Impact** panel. It does **not** synthesize CIA tables — missing sections show a placeholder. Write the full table in markdown.
