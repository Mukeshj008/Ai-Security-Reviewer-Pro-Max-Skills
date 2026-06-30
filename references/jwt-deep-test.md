# JWT Deep Testing (additive)

**When:** JWT/Bearer auth detected (`Authorization: Bearer`, `JWTUtils`, `jjwt`, `nimbus-jose-jwt`, `jsonwebtoken`).

**Extends:** `extended-category-scans.md` §3.8, `curl-dast-fallback.md`, `burp_poc_templates.md`.

---

## Static checks (rg + Read)

```bash
rg -n "JWT|jjwt|nimbus|parseClaims|setSigningKey|verify|Algorithm\.NONE|none" \
  --glob "**/*.{java,js,ts,py,go}"
rg -n "exp|expiration|nbf|aud|iss" --glob "**/*JWT*" --glob "**/*Token*"
```

| Pattern | Risk |
|---------|------|
| No `exp` validation | Token never expires → VULN |
| `Algorithm.NONE` / accept unsigned | Forgery |
| HS256 with public key as secret | Key confusion |
| Hardcoded `secret` / `JWT_SECRET` | SAST-SECRET + VULN |

---

## DAST probes (read-only / non-destructive)

Decode token at [jwt.io](https://jwt.io) logic manually — **do not** paste production secrets in reports; use `[REDACTED]`.

### 1. Expired token

```bash
# Use token captured from login; if no exp in code, note "exp claim absent" (static finding)
curl -sS -w "\nHTTP:%{http_code}\n" --max-time 15 \
  -H "Authorization: Bearer [EXPIRED_OR_MODIFIED_TOKEN]" \
  "https://[HOST]/v1/[PROTECTED_PATH]"
```

### 2. Algorithm none (only if library/version suggests vulnerability)

Craft header `{"alg":"none","typ":"JWT"}` + payload with victim `sub` — **staging only**. If 200 on protected route → Critical.

### 3. Signature strip / tampered claims

Change `sub` or `role` in payload, re-sign only if weak secret found in code — otherwise document **Not Verified (cannot re-sign without secret)**.

### 4. Empty / malformed token

```bash
curl -sS -w "\nHTTP:%{http_code}\n" -H "Authorization: Bearer invalid" \
  "https://[HOST]/v1/[PROTECTED_PATH]"
```

Expect **401** — if **200**, missing auth validation.

---

## Report

| Result | Finding |
|--------|---------|
| Static: no exp check | VULN-NNN, Code confirmed |
| DAST: expired token accepted | VULN-NNN High, Verified in curl |
| DAST: none alg accepted | VULN-NNN Critical |

Include **`### Assumptions`** (gateway validates JWT, staging mirrors prod).

Appendix C: exact curl + HTTP code.
