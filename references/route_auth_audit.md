# Route Authentication Audit

Systematic detection of **unauthenticated or weakly authenticated HTTP endpoints**. Sink-oriented scans (SQLi, XSS) miss these — this phase is **mandatory** on every review.

---

## Why This Matters

Routes without SSO, Basic Auth, API keys, or HMAC can expose PII, allow state changes (cancel/refund), or bypass business controls. Code review alone cannot confirm reachability past WAF/gateway — **Burp MCP** closes that gap when available.

---

## Phase 1a: Enumerate Routes (code)

### Step 1 — Locate route files

| Framework | Typical paths |
|-----------|---------------|
| Express (this repo) | `src/routes/**/index.js` |
| Spring | `*Controller.java`, `@RequestMapping` |
| Flask/Django | `urls.py`, `views.py`, `@app.route` |
| FastAPI | `router.get/post`, `APIRouter` |

Use Graphify first:

```bash
graphify query "router.get router.post routes endpoints middleware" --budget 1500
graphify query "authentication verifySsoToken basicAuth authorize middleware guards" --budget 1500
```

Fallback (no graph): scoped Grep on `src/routes/**` for `router\.(get|post|put|patch|delete)\(`.

### Step 2 — Auth middleware signatures

Flag a route as **candidate unauthenticated** when its handler chain lacks **all** of:

| Pattern | Examples (Express / Node) |
|---------|---------------------------|
| SSO / session | `verifySsoToken`, `AuthHandler.verifySsoToken`, `Handler.verifySsoToken`, `authenticate`, `requireAuth`, `isAuthenticated` |
| Basic / internal | `basicAuth`, `basic_auth`, `voucherBasicAuth` |
| API key / HMAC | `validateApiKey`, `verifyHmac`, `checkSignature`, `internalAuth` |
| Role / permission | `authorize`, `checkRole`, `requireAdmin` |

### Step 3 — Weak auth & bypass flags

Also flag as **weak auth** (still report):

| Signal | Location | Risk |
|--------|----------|------|
| `isSeller=true` skips SSO | preprocessor / auth handler | Auth bypass param |
| `login_not_required` set | handler sets `req.login_not_required` | Intentional public — verify impact |
| `req.customer_id = req.query.customer_id` | preprocessor | IDOR / impersonation |
| Route registered **before** `router.use(basicAuth)` | internal router | Internal API exposed |
| Auth only in preparer, skippable on error path | handler chain | Logic bypass |
| Dev/staging auth using config creds in prod path | `config.dev.auth` | Credential leak surface |

### Step 4 — Record each candidate

For every route missing auth middleware, record:

```
Method | Path | Router file:line | Auth present | Bypass notes | Sensitive? (PII/state-change/read-only)
```

**Sensitive impact** (for remediation priority, not severity — severity follows verification rules below):

- **Critical impact**: PII read, cancel/refund, payment, crypto, admin DB query
- **High impact**: order details, user data, state change
- **Medium impact**: public read metadata, notifications
- **Low impact**: health, static config, metrics

---

## Phase 1b: Burp MCP Verification (when MCP available)

### Detect Burp MCP

1. List MCP tools under `user-burp` (or project-configured Burp server name).
2. If `send_http1_request` is available → **run live verification**.
3. If absent → skip to Phase 1c; all candidates stay **Medium / Not Verified**.

### Verification request rules

1. **Discover host from code first** — follow **`references/burp-host-discovery.md`** and run `bash scripts/discover_burp_hosts.sh .`
2. **Never use localhost** — do not probe `localhost`, `127.0.0.1`, `0.0.0.0`, or `::1`
3. **Skip if no host** — if `burp_hosts.txt` has no external host → **Not Verified (no target host in code)**; do not guess
4. **No auth headers** — omit `Cookie`, `Authorization`, `X-SSO-Token`, `X-User-Id`, Basic Auth
5. **Minimal valid params** — placeholders from docs/config (`order_id`, `item_id`) or dummy values
6. **Prefer staging** — host from `config-staging.js` / `config-dev.js` over production
7. **Read-only first** — GET before POST; no destructive actions on production without approval
8. **One request per endpoint** — sufficient for auth check

### Call pattern (Cursor MCP)

```
CallMcpTool:
  server: user-burp
  toolName: send_http1_request
  arguments:
    content: |
      GET /api/v1/order/details?order_id=123 HTTP/1.1
      Host: staging.example.com
      User-Agent: Mozilla/5.0 (Security-Review)
      Accept: application/json
      Connection: close

    targetHostname: staging.example.com
    targetPort: 443
    usesHttps: true
```

Read tool schema from MCP descriptors before calling.

### Verdict matrix

| HTTP result (no auth) | Status | Severity |
|----------------------|--------|----------|
| **2xx** + app JSON/HTML/business body (not login page) | **Verified in Burp** | **High** |
| **2xx** but empty/error schema only | Verified in Burp (limited) | High |
| **401 / 403** + auth error body | Not Verified (gateway enforces auth) | Medium — note "auth at edge" |
| **403** WAF / block page | Not Verified (WAF blocked) | Medium |
| **302** → login | Not Verified (redirect to auth) | Medium |
| **4xx** validation (missing param) but no auth challenge | **Verified in Burp** (partial) | High — endpoint reachable without auth; params needed |
| Burp MCP unavailable / timeout / error | Not Verified | Medium |
| **No external host in code** | **Not Verified (no target host in code)** | Medium |
| **Only localhost in code** | **Not Verified (no target host in code)** | Medium |
| Code-only, user declined live test | Not Verified | Medium |

**Verified in Burp** means: an unauthenticated caller can reach the application handler (even if business validation fails). **Not Verified** means: code suggests missing auth but live test did not confirm, or MCP was not used.

### Document in finding

```markdown
### Live Verification (Burp MCP)

| Field | Value |
|-------|-------|
| MCP server | user-burp |
| Host | staging.example.com |
| HTTP status | 200 |
| Auth headers sent | None |
| Response indicator | JSON with order_id / PII field names |
| **Status** | Verified in Burp |
| **Severity** | High |
```

Or when not verified:

```markdown
| **Status** | Not Verified |
| **Severity** | Medium |
| **Reason** | Burp MCP not configured / returned 401 / not live-tested |
```

---

## Phase 1c: Promote to findings

Each unauthenticated route → finding **AUTH-NNN** (separate ID series from VULN-NNN).

### Do NOT duplicate

If the same route already has a VULN finding (e.g. XSS on `/order/details`), reference it in AUTH finding as related — one primary finding per issue type.

### Merge with injection findings

Unauthenticated **+** SQLi on same route: keep both AUTH (access) and VULN (injection); AUTH severity follows verification rules above.

---

## Appendix D table (mandatory in report)

```markdown
## Appendix D: Unauthenticated Endpoint Inventory

| ID | Method | Path | Router | Code auth | Burp status | Severity | Impact |
|----|--------|------|--------|-----------|-------------|----------|--------|
| AUTH-001 | GET | /order/details | routes/api/index.js:520 | None | Verified in Burp | High | PII read |
| AUTH-002 | GET | /refund/details | routes/api/index.js:530 | None | Not Verified | Medium | PII read |
```

---

## Express-specific checklist (example — adapt to target repo)

```
src/routes/**/index.js          — enumerate router.get/post chains for auth middleware
src/routes/**/internal/index.js — routes registered BEFORE basicAuth are exposed
src/handlers/**/auth*.js        — verifySsoToken / session validation implementation
src/handlers/**/preprocessor/** — conditional auth skips (query flags, login_not_required)
```

Grep helpers (scoped to routes only):

```bash
# Routes without verifySsoToken in same line (manual review each hit)
rg "router\.(get|post)\(" src/routes/ 
```

Every `router.get/post` line must be read for full middleware chain — chains span multiple handlers on one line.
