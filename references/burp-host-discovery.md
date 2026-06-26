# Burp MCP Host Discovery (MANDATORY before any live probe)

**Never use `localhost`, `127.0.0.1`, `0.0.0.0`, or `::1` for Burp verification.**

Consumer health/metrics on loopback are **not live-DAST targets** unless the codebase exposes a **real external hostname** for the same service.

---

## Step 1 — Discover hosts from code (required)

```bash
# Config files (primary source)
rg -n "https?://[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z]{2,}" src/configs/ --glob "config-*.js"
rg -n "baseUrl|baseURL|apiUrl|apiHost|host:\s*['\"]|HOST\s*[:=]" src/configs/
rg -n "\.internal\.|\.amazonaws\.com|staging\.|dev\." src/configs/ -i

# Routes / downstream callers
rg -n "https?://[a-zA-Z0-9][-a-zA-Z0-9._]*" src/ --glob "!node_modules" | head -80

# Env examples (names only — do not use secret values)
rg -n "HOST|BASE_URL|API_URL" .env.example .env.sample 2>/dev/null || true
```

**Agent:** Run the `rg` commands above directly. Do **not** use `discover_burp_hosts.sh`.

Graphify (optional):

```bash
graphify query "config API URL host baseUrl downstream HTTP endpoint" --budget 1500
```

---

## Step 2 — Build target table

| Host | Source file:line | Environment | Use for |
|------|------------------|-------------|---------|
| staging.example.com | config-staging.js:42 | staging | DAST / AUTH |
| api.example.com | axios baseURL | production | **skip unless user approves** |

**Preference order:** `staging` / `dev` / `preprod` config → user-provided host → production (read-only, user approval).

---

## Step 3 — Burp probe rules

| Rule | Action |
|------|--------|
| Host found in code | `send_http1_request` with that **Host** header |
| No host in code | **Skip Burp** — status `Not Verified (no target host in code)` |
| Only localhost in code | **Skip Burp** — same status; note in Appendix C |
| Multiple hosts | Probe staging first; document each in Appendix C |

### Forbidden targets

```
localhost
127.0.0.1
0.0.0.0
::1
host.docker.internal   (unless user explicitly requests)
```

### MCP call template

```http
GET /health HTTP/1.1
Host: [HOST_FROM_CONFIG]
User-Agent: Mozilla/5.0 (Security-Review)
Accept: application/json
Connection: close

```

Set `targetHostname`, `targetPort`, `usesHttps` from discovered URL (443 for https).

**Fallback:** If Burp MCP unavailable, use **`curl-dast-fallback.md`** with the same Host header and paths.

---

## Step 4 — Document in report

**Appendix C** must include:

| Finding ID | Host source | Host used | Skipped reason |
|------------|-------------|-----------|----------------|
| AUTH-001 | config-staging.js:12 | staging.example.com | — |
| AUTH-002 | none | — | No external host in code |

**Never mark "Verified in Burp"** if probe used localhost or host was guessed.
