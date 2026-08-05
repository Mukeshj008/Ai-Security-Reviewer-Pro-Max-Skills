# DAST Verification Flow (MANDATORY — v4.23)

**Purpose:** unify Burp MCP, curl fallback, user consent, and **mandatory crafted Burp requests** in every HTTP finding — even when live verification never runs.

Read this file when executing Phase 7 (DAST). Companion refs: `burp-host-discovery.md`, `curl-dast-fallback.md`, `burp_poc_templates.md`, `finding-templates.md`.

---

## Golden rules

1. **Craft the Burp request first** — before any live probe attempt.
2. **Every HTTP-exploitable finding** (`AUTH-NNN`, `VULN-NNN` with a route) **must** include `### Burp Suite PoC` with a complete raw HTTP/1.1 request — **even when Burp MCP is unavailable, curl is skipped, user denies probes, or no target host exists**.
3. **Never probe `localhost` / `127.0.0.1`**.
4. **curl requires explicit user permission** — do not run network probes silently.
5. Non-HTTP findings (`LEAK-NNN` config secrets, `IAC-NNN`) → `Burp PoC: N/A — not HTTP-exploitable`.

---

## Decision tree (execute in order)

```
For each HTTP finding (AUTH / VULN with route):
│
├─ 1. CRAFT Burp PoC (mandatory — always)
│     Use burp_poc_templates.md + code-derived host/path/method/body
│     Placeholders: [TARGET_HOST], [SSO_TOKEN], [API_KEY]
│     If no host in code → use [TARGET_HOST] placeholder + note in PoC table
│
├─ 2. Discover hosts (rg per burp-host-discovery.md)
│
├─ 3. Is Burp MCP (user-burp send_http1_request) available?
│     ├─ YES → run Burp probe using crafted request
│     │         Record: Verified in Burp / Not Verified (+ reason)
│     │
│     └─ NO → go to step 4
│
├─ 4. External host in code? (not localhost)
│     ├─ NO → Live status = Not Verified (no target host in code)
│     │        Burp PoC still published with [TARGET_HOST] placeholder
│     │
│     └─ YES → go to step 5
│
├─ 5. ASK USER PERMISSION for curl (mandatory — do not skip)
│     Present:
│       - finding ID + route
│       - proposed host (staging preferred)
│       - exact curl command (read-only)
│       - safety note (no destructive payloads)
│     Use AskQuestion or a direct message with Approve / Deny / Skip all
│
│     ├─ USER APPROVES → run curl in Shell (required_permissions: network)
│     │                  Record: Verified in curl / Not Verified (+ reason)
│     │                  Add ### Live Verification (curl) table to finding
│     │
│     └─ USER DENIES or SKIPS → Live status = Not Verified (live probe skipped — user declined)
│                               Burp PoC still mandatory in finding
│
└─ 6. Update checklist: DAST Status, Verification Status, PoC column
```

---

## User permission prompt (template)

When Burp MCP is absent and a code-derived external host exists, **stop and ask** before the first `curl`:

```markdown
Live verification: Burp MCP is not available. I can verify **[N] HTTP findings** against
**[staging-host.example.com]** using read-only curl probes (no destructive payloads).

Proposed first probe:
`curl -sS -w "%{http_code}" "https://[HOST]/[PATH]"`

- Approve curl verification for staging host
- Deny — code-review only (Burp PoC will still be included in each finding)
- Skip all live probes this session
```

**Rules for the ask:**
- One approval can cover all probes in the session **only if** the user explicitly agrees to batch verification.
- If the user says nothing / changes topic, treat as **Deny** — do not run curl.
- If the user rejects a single Burp MCP call, offer curl as fallback in the same turn (with permission ask).
- Re-ask if the target host changes (e.g. prod vs staging).

---

## Finding sections (required per HTTP finding)

| Section | When required |
|---------|---------------|
| `### Burp Suite PoC` | **Always** for HTTP AUTH/VULN — Verified or Not Verified |
| `### Live Verification (Burp MCP)` | Burp probe executed |
| `### Live Verification (curl)` | User approved and curl executed |
| `Burp PoC: N/A` | LEAK/IAC/non-HTTP only |

### Burp PoC table (include even when Not Verified)

```markdown
### Burp Suite PoC (MANDATORY — paste into Burp Repeater)

```http
GET /api/v1/example HTTP/1.1
Host: staging.example.com
User-Agent: Mozilla/5.0 (Security-Review)
Accept: application/json
Connection: close

```

| Field | Value |
|-------|-------|
| **Target host** | `staging.example.com` (from `application-staging.yml`) or `[TARGET_HOST]` |
| **Prerequisites** | None — unauthenticated probe |
| **Expected confirmation** | HTTP 200 + business JSON |
| **Live status** | Not Verified (Burp MCP unavailable; user declined curl) |
| **Manual retest** | Paste request into Burp Repeater → send without Authorization |
```

---

## DAST backend reporting

| Situation | Report `DAST Backend` | Appendix C tool column |
|-----------|-------------------------|------------------------|
| Burp probes run | `Burp MCP` | `Burp MCP` |
| Burp absent, curl run | `curl (Burp MCP not present)` | `curl (terminal)` |
| Burp absent, user declined curl | `None — live probe skipped (user declined)` | `Not run — Burp PoC only` |
| No external host | `None — no target host in code` | `Not run — Burp PoC with placeholder host` |

**FAIL gate (unchanged):** Burp absent + host exists + user approved curl + curl **never run** → Phase 7 incomplete.

**NOT a fail:** Burp absent + user declined curl → Phase 7 = `PASS (Burp PoC crafted; live probe skipped — user declined)` when every HTTP finding has a Burp PoC block.

---

## Checklist / verification interaction

**Severity is independent of live verification** (`severity-calibration.md`). DAST sets **Verification Status** and may upgrade **Confidence** — not Severity.

| Live result | Verification Status | Confidence (typical) |
|-------------|---------------------|----------------------|
| Verified in Burp | Verified in Burp | Confirmed |
| Verified in curl | Verified in curl | Confirmed |
| Not Verified (user declined) | Not Verified (live probe skipped) | Firm (if static proof strong) |
| Not Verified (no host) | Not Verified (no target host in code) | Firm / Tentative |
| Not Verified (gateway/WAF) | Not Verified (auth at gateway) | Firm — severity still from four factors |

**PoC column** in Security Verification Checklist must always reference the Burp request (e.g. `Burp PoC §1 — GET /v1/kafka/stop`) — never leave empty for HTTP findings.
