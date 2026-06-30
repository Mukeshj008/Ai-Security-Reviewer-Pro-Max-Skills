# DAST Scan Manifest (Burp MCP or terminal curl)

Live probing via **`user-burp`** MCP `send_http1_request` **when present**. When Burp MCP is **absent**, **do not install Burp** — run **`curl` in terminal** per **`curl-dast-fallback.md`**. **Never** use `localhost` / `127.0.0.1`.

**Prerequisite:** Discover hosts with `rg` per **`burp-host-discovery.md`** (agent only — no script).

If no external host → all DAST rows in Appendix E = `SKIP` with note `Not Verified (no target host in code)`.

---

## DAST-HOST-01 — Host discovery

```bash
# Agent: rg per burp-host-discovery.md Step 1
```

Record hosts in Appendix C and Appendix F.

---

## DAST-AUTH-PROBE — Unauthenticated endpoint verification

For each route in **Appendix D** (missing application-layer auth):

1. If Burp MCP available: read tool schema → `send_http1_request` without auth.
2. If Burp MCP absent: **run curl in Shell** (see `curl-dast-fallback.md`) — same request shape, no auth headers.
3. Use first host from code discovery (staging preferred over production).

**Verdict matrix** (see `route_auth_audit.md`):

| Response | Burp status | AUTH severity |
|----------|-------------|---------------|
| 2xx + business body | Verified in Burp | High |
| 401/403 auth challenge | Not Verified | Medium |
| WAF 403 only | Not Verified (WAF) | Medium |
| Connection error | Not Verified | Medium |

Record each probe in **Appendix C**.

---

## DAST-INJ-PROBE — Injection smoke tests

Only for **TRUE POSITIVE** candidates with HTTP surface. Read-only probes first.

| Class | Method | Payload location | Example payload |
|-------|--------|------------------|-----------------|
| XSS | GET | query `q`, `search` | `"><img src=x onerror=alert(1)>` |
| SQLi | GET | numeric/string param | `' OR '1'='1'--` |
| CMD | POST multipart | `filename` | `; id` |
| XXE | POST | XML body | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` |
| SSRF | POST JSON | `url` field | `http://169.254.169.254/` |

**Safety:** staging host only; no destructive DELETE/DROP; label `read-only` in finding.

---

## Appendix E rows

| ID | Description |
|----|-------------|
| DAST-HOST-01 | Host discovery from code |
| DAST-AUTH-PROBE | Unauthenticated route probes (count in Notes) |
| DAST-INJ-PROBE | Injection PoC verification (per VULN with HTTP surface) |

---

## Burp MCP unavailable (mandatory curl)

1. **Do not install** Burp Suite or MCP extension.
2. **Run curl in terminal** per **`curl-dast-fallback.md`** for **every** AUTH candidate when external host exists.
3. Install `curl` only if command not found (`dependency-install-policy.md`).

Document in report:

- Appendix F: Phase 1b = `PASS (curl — Burp MCP not present)` when probes executed
- Appendix C: tool column = `curl (terminal)`; status = `Verified in curl` when 2xx unauth
- All AUTH findings: upgrade to **High / Verified in curl** when curl confirms; else **Medium / Not Verified**

**FAIL gate:** Burp absent + host in code + curl never run → Phase 1b incomplete; re-run review.
