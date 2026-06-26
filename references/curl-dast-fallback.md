# curl DAST Fallback (when Burp MCP unavailable)

Use when **`user-burp`** MCP is not configured or `send_http1_request` fails. Same host rules as Burp — **never** probe `localhost` / `127.0.0.1`.

---

## When to use

| Condition | Action |
|-----------|--------|
| Burp MCP available | Prefer `send_http1_request` (Phase 1b primary) |
| Burp MCP missing / error | Run **curl** probes per this doc |
| No external host in code | Skip live probes — `Not Verified (no target host in code)` |
| Production host only | Staging preferred; prod only with read-only probes + user approval |

---

## Host discovery

Same as **`burp-host-discovery.md`** — run `rg` on `config/`, `routes/`, `.env.example`. Record host in Appendix C.

**Default target:** first `*-staging.*` host from code (e.g. `app-staging.example.com`).

---

## curl command template

```bash
# GET — no auth (AUTH probe)
curl -sS -o /tmp/sec_body.txt -w "%{http_code}" \
  --max-time 15 \
  -H "User-Agent: Mozilla/5.0 (Security-Review)" \
  -H "Accept: application/json" \
  "https://[HOST]/[PATH]"

# Inspect
head -c 500 /tmp/sec_body.txt
```

```bash
# POST JSON — SSRF / OAuth probe (use session cookie if required)
curl -sS -o /tmp/sec_body.txt -w "%{http_code}" \
  --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Security-Review)" \
  -d '{"targetUrl":"https://example.com","payload":{}}' \
  "https://[HOST]/api/oauth/callback"
```

**Flags:**
- `-sS` — silent but show errors
- `--max-time 15` — avoid hangs
- `-w "%{http_code}"` — capture status for Appendix C
- `-L` — follow redirects **only** when documenting redirect behavior (note final URL)
- **Never** send destructive payloads

---

## Verdict matrix (same as Burp)

| curl result | Burp status column | AUTH severity |
|-------------|-------------------|---------------|
| 2xx + business JSON/body | **Verified in curl** (treat as Verified in Burp) | **High** |
| 401/403 auth error body | Not Verified (auth at gateway) | Medium |
| 302 → `/login` only | Not Verified (auth at gateway) | Medium |
| 403 from WAF/ELB | Not Verified (WAF blocked) | Medium |
| Timeout / connection refused | Not Verified | Medium |

In findings, write: `Live Verification (curl)` with status code and body snippet (first 200 chars).

---

## Appendix C documentation

| Finding ID | Host | Tool | HTTP | Status |
|------------|------|------|------|--------|
| AUTH-003 | app-staging.example.com | curl | 200 | Verified in curl |
| VULN-001 | app-staging.example.com | curl | 302 | Not Verified (gateway) |

**Appendix F:** Phase 1b = `PASS (curl fallback)` when Burp skipped.

---

## Report wording

In **Burp Suite PoC** sections, add when curl used:

```markdown
### Live Verification (curl — Burp MCP unavailable)

| Field | Value |
|-------|-------|
| Command | `curl -sS -w "%{http_code}" "https://app-staging.example.com/api/health"` |
| HTTP status | 200 |
| Response snippet | `{"status":"ok"}` |
| **Status** | **Verified in curl** |
```

For HTML/Burp PoC blocks, still include raw HTTP request (copy-paste for Repeater); note curl was used for live confirmation.

---

## Safety

- Staging/dev hosts only unless user approves production
- Read-only GET/HEAD first
- No auth bypass exploitation beyond confirming missing auth
- Redact secrets from logged curl output in report
