# DAST Scan Manifest (Burp MCP, user-approved curl, or Burp PoC only)

Live probing via **`user-burp`** MCP `send_http1_request` **when present**. When Burp MCP is **absent or rejected**, **ask user permission** before **`curl` in terminal** per **`curl-dast-fallback.md`** and **`dast-verification-flow.md`**. **Never** use `localhost` / `127.0.0.1`.

**Always:** craft `### Burp Suite PoC` in each HTTP finding **before** any live probe — mandatory even when both Burp and curl are skipped.

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

0. **Craft `### Burp Suite PoC`** in the finding (mandatory — always).
1. If Burp MCP available: read tool schema → `send_http1_request` without auth.
2. If Burp MCP absent/rejected: **ask user permission** → if approved, run curl in Shell (see `curl-dast-fallback.md`).
3. If user declines curl: mark `Not Verified (live probe skipped — user declined)` — **Burp PoC still in finding**.
4. Use first host from code discovery (staging preferred over production).

**Verdict matrix** (verification status only — see `route_auth_audit.md`):

| Response | Burp status |
|----------|-------------|
| 2xx + business body | Verified in Burp |
| 401/403 auth challenge | Not Verified |
| WAF 403 only | Not Verified (WAF) |
| Connection error | Not Verified |

**Severity:** `severity-calibration.md` — not derived from this table.

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

## Burp MCP unavailable (curl with user permission, or Burp PoC only)

1. **Do not install** Burp Suite or MCP extension.
2. **Ask user permission** before any curl probe when external host exists (`dast-verification-flow.md`).
3. If **approved** → run curl in terminal per **`curl-dast-fallback.md`** for AUTH + HTTP VULN candidates.
4. If **declined** → no curl; every HTTP finding still has `### Burp Suite PoC`; Appendix C notes `Not run — Burp PoC only`.
5. Install `curl` only if command not found (`dependency-install-policy.md`) **and** user approved probes.

Document in report:

- Appendix F: Phase 7 = `PASS (curl — user approved)` OR `PASS (Burp PoC crafted; live probe skipped — user declined)`
- Appendix C: tool column = `curl (terminal)` / `Burp MCP` / `Not run — Burp PoC only`
- All AUTH findings: set **Verification Status** from Burp/curl; assign **Severity** via `severity-calibration.md` (Not Verified does not cap severity)

**FAIL gate:** Burp absent + host in code + user **approved** curl + curl never run → Phase 7 incomplete.
