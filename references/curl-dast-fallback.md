# curl DAST Fallback (MANDATORY when Burp MCP unavailable — user permission required)

When **`user-burp`** MCP is **not** configured, `send_http1_request` fails, or the user rejects Burp MCP probes:

1. **Do not install Burp Suite** or Burp MCP — per `dependency-install-policy.md`
2. **Ask the user for permission** before running **any** `curl` command — see **`dast-verification-flow.md`** § User permission prompt. **Never run curl silently.**
3. If user **approves** → run `curl` in the terminal (Shell tool) — the **only** permitted HTTP verification tool when Burp is absent
4. If user **denies** → skip live probes; status = `Not Verified (live probe skipped — user declined)` — **still include `### Burp Suite PoC`** in every HTTP finding
5. **Do not** substitute Playwright, Firefox DevTools MCP, Python `requests`, `wget`, or custom scripts for DAST verification
6. Apply the **same verdict matrix** as Burp; record **Verified in curl** (treat as **Verified in Burp** for severity)

Same host rules as Burp — **never** probe `localhost` / `127.0.0.1`.

**Canonical flow:** `references/dast-verification-flow.md`

---

## When to use

| Condition | Action |
|-----------|--------|
| Burp MCP available | **Burp MCP only** — `send_http1_request` (Phase 7 primary) |
| Burp MCP missing / error / user rejected | **Ask user permission** → if approved, run **curl only** in terminal |
| User declines curl | **No live probe** — `Not Verified (live probe skipped — user declined)`; **mandatory Burp PoC** in finding |
| Burp absent, curl attempted (user approved) | No other HTTP tool may be used for verification |
| `curl` missing | Install per `dependency-install-policy.md`, then run probes (after user approval) |
| No external host in code | Skip live probes — `Not Verified (no target host in code)`; Burp PoC with `[TARGET_HOST]` |

**Never** mark Phase 7 incomplete solely because Burp MCP is absent **if** user declined curl **and** every HTTP finding has a crafted `### Burp Suite PoC`.

**FAIL gate:** Burp absent + host in code + user **approved** curl + curl never run → Phase 7 incomplete; re-run review.

---

## User permission gate (mandatory — before first curl)

**Do not run curl until the user explicitly approves.** Use `AskQuestion` or a direct message:

```markdown
Burp MCP is unavailable. I can verify [N] HTTP findings against **[HOST]** with read-only curl.

Example: `curl -sS -w "%{http_code}" "https://[HOST]/[PATH]"`

Approve curl verification? (Deny = code review + Burp PoC only in report)
```

| User response | Action |
|---------------|--------|
| Approve (single or batch) | Run curl probes; log commands in findings + Appendix C |
| Deny / Skip | No curl; `Not Verified (live probe skipped — user declined)`; **Burp PoC still in each finding** |
| No response / topic change | Treat as **Deny** |

Re-ask if switching hosts (staging → prod) or if probe class changes (AUTH → injection).

---

## Execution requirement (when user approves curl)

For **each** row in Appendix D when host exists:

1. Build the curl command from the finding's Burp PoC (same URL, method, headers minus auth)
2. **Run it** via Shell with `required_permissions: ["network"]` (or `all` if sandbox blocks HTTPS)
3. Capture HTTP status (`-w "%{http_code}"`) and first ~500 bytes of body
4. Apply verdict matrix → update finding severity/status and Appendix C

```bash
# Example — run in project terminal (replace HOST/PATH)
curl -sS -o /tmp/sec_body.txt -w "\nHTTP_CODE:%{http_code}\n" \
  --max-time 15 \
  -H "User-Agent: Mozilla/5.0 (Security-Review)" \
  -H "Accept: application/json" \
  "https://[HOST]/[PATH]"
head -c 500 /tmp/sec_body.txt
```

Log the **exact command** in the finding's `### Live Verification (curl)` table and Appendix C.

---

## Host discovery

Same as **`burp-host-discovery.md`** — run `rg` on `config/`, `routes/`, `.env.example`. Record host in Appendix C.

**Default target:** first `*-staging.*` host from code (e.g. `app-staging.example.com`).

---

## curl command templates

```bash
# GET — no auth (AUTH probe)
curl -sS -o /tmp/sec_body.txt -w "\nHTTP_CODE:%{http_code}\n" \
  --max-time 15 \
  -H "User-Agent: Mozilla/5.0 (Security-Review)" \
  -H "Accept: application/json" \
  "https://[HOST]/[PATH]?[QUERY]"

head -c 500 /tmp/sec_body.txt
```

```bash
# POST JSON — lead/API probe
curl -sS -o /tmp/sec_body.txt -w "\nHTTP_CODE:%{http_code}\n" \
  --max-time 15 \
  -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Security-Review)" \
  -d '{"field":"test"}' \
  "https://[HOST]/api/v1/[PATH]"

head -c 500 /tmp/sec_body.txt
```

**Flags:**
- `-sS` — silent but show errors
- `--max-time 15` — avoid hangs
- `-w "\nHTTP_CODE:%{http_code}\n"` — capture status for Appendix C
- `-L` — follow redirects **only** when documenting redirect behavior (note final URL)
- **Never** send destructive payloads

---

## Verdict matrix (verification status only)

| curl result | Status column |
|-------------|---------------|
| 2xx + business JSON/body | **Verified in curl** (= Verified in Burp) |
| 4xx validation without auth challenge | **Verified in curl** (partial) |
| 401/403 auth error body | Not Verified (auth at gateway) |
| 302 → `/login` only | Not Verified (auth at gateway) |
| 403 from WAF/ELB | Not Verified (WAF blocked) |
| Timeout / connection refused **after curl run** | Not Verified |
| Burp absent, curl **not run** (host exists) | **FAIL** — re-run review |

**Severity:** assign via `severity-calibration.md` — **not** from this table.

In findings, write: `### Live Verification (curl)` with command, status code, and body snippet (first 200 chars).

---

## Appendix C documentation

| Finding ID | Host | Tool | HTTP | Status |
|------------|------|------|------|--------|
| AUTH-003 | app-staging.example.com | curl (terminal) | 200 | Verified in curl |
| AUTH-004 | business.example.com | curl (terminal) | 403 | Not Verified (WAF) |

**Appendix F:** Phase 1b = `PASS (curl — Burp MCP not present)` when all candidates probed via terminal.

---

## Report wording

**Header:** `DAST Backend: curl (Burp MCP not present)` when Burp skipped and user-approved curl executed.

**Header:** `DAST Backend: None — live probe skipped (user declined); Burp PoC crafted` when user declined curl.

In findings, **always** include `### Burp Suite PoC` first. Add curl table only when curl actually ran:

```markdown
### Live Verification (curl — Burp MCP not present)

| Field | Value |
|-------|-------|
| Tool | Terminal curl (Shell) |
| Command | `curl -sS -w "%{http_code}" "https://app-staging.example.com/api/health"` |
| HTTP status | 200 |
| Response snippet | `{"status":"ok"}` |
| **Status** | **Verified in curl** |
| **Severity** | **High** |
```

Still include raw HTTP request block for manual Burp Repeater retest — **even when curl was not run**.

---

## HTTP-exploitable VULN probes (mandatory when host exists)

When a **VULN-NNN** has an HTTP surface (injection, SSRF, XSS reflection), run **read-only** curl probes in addition to AUTH candidates. Same host rules — never localhost.

| Class | Probe | Safe payload | Confirm if |
|-------|-------|--------------|------------|
| SQLi | GET param | `' OR '1'='1'--` (read-only) | SQL error in body / extra rows / timing |
| XSS | GET param | `<script>alert(1)</script>` or `"><img src=x onerror=1>` | Reflection unencoded in body |
| SSRF | URL param | `https://[BURP_COLLABORATOR_OR_CONTROLLED_CANARY]/ssrf-test` | OOB callback / controlled canary hit / timing |
| Path traversal | file param | `../../../etc/passwd` | `root:` in body |
| IDOR | ID param | Adjacent ID (e.g. `id=2` vs `id=1`) | Foreign object in 200 body |

Log each probe in **Appendix C** with Finding ID, command, HTTP status, body snippet (≤200 chars). Update Verification Checklist **DAST Status** and **Verification Status** per verdict matrix.

**Sensitive/destructive payloads forbidden** — no DROP, DELETE, state-changing injection, cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`) or internal admin hosts in automated probes unless the user explicitly approves that target and environment.

---

## Safety

- Staging/dev hosts only unless user approves production
- Read-only GET/HEAD first; POST only when route requires it
- No auth bypass exploitation beyond confirming missing auth
- Redact secrets from logged curl output in report
- Redact tokens/cookies/passwords in PoC blocks unless placeholders are used
