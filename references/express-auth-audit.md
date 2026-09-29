# Express Auth Audit (MANDATORY when Express/Koa/Fastify detected)

**Purpose:** catch route-table bugs that per-controller annotation audits miss. Run after `multi-module-enumeration.md` Step 2 lists every `app.` / `router.` file.

**v4.35** — dogfood: glob vs later `app.post`, `next('route')` skipping `apiAuth`, named `restricted` that is `next()`, `TestSSO` literals, `X-Forwarded-Host` as API-key skip.

Partner **inbound** callbacks: outbound `VerifyKey` / HMAC on a **client** request is **not** G3 for the public `POST /callback` route. Require inbound verify in middleware or handler (`AUTH` webhook class).

---

## Mandatory `rg` (run in every Node HTTP module)

Exclude `node_modules`, `docs/dist`, `coverage`, `test/fixtures` unless the same pattern exists under `src/` / `routes/` / `middleware/`.

```bash
# 1. Prefix middleware vs concrete routes (glob miss)
rg -n "app\.all\(|router\.all\(|app\.use\(['\"]/" --glob '*.{js,ts}' -g '!**/node_modules/**'

# 2. next('route') skips remaining middleware on the CURRENT layer
rg -n "next\(\s*['\"]route['\"]\s*\)" --glob '*.{js,ts}' -g '!**/node_modules/**'

# 3. Named access-control that is a no-op
rg -n "restricted\s*:|function restricted" --glob '*.{js,ts}' -g '!**/node_modules/**'

# 4. Debug / test identity bypass
rg -n "TestSSO|TestWallet|skipAuth|authSkip|sso_token_enc\s*===\s*['\"]Test" --glob '*.{js,ts}' -g '!**/node_modules/**'

# 5. Host header as authentication
rg -n "x-forwarded-host|X-Forwarded-Host|req\.headers\.host" --glob '*auth*.{js,ts}' -g '!**/node_modules/**'
rg -n "x-forwarded-host|X-Forwarded-Host" --glob '**/middleware/**/*.{js,ts}' -g '!**/node_modules/**'

# 6. Fail-open oauth (missing token continues)
rg -n "return next\(\)\s*;" --glob '**/oauth*.js' -g '!**/node_modules/**'
rg -n "if\s*\(\s*!.*sso_token" --glob '**/middleware/**/*.{js,ts}' -g '!**/node_modules/**'

# 7. Partner callbacks / webhooks
rg -n "callback|/webhook" --glob '**/routes/**/*.{js,ts}' -g '!**/node_modules/**'
```

Every hit is a **ledger candidate**. Terminal status: Finding, Tentative, or Appendix A with **AUTH-ADJ-*** / G3 `file:line`. Silent drop forbidden.

---

## Check 1 — `app.all('/v*/internal*')` does not cover `/v1/foo`

Express `*` in `app.all` only matches that **path pattern**. A later `app.post('/v1/refresh_pod_data', handler)` **never** runs that `app.all` stack.

**Action:** List every `app.(get|post|put|patch|delete)` path in the same `app` file (and mounted routers). If the path does **not** match the `app.all` glob, classify as **Unauthenticated** unless that route has its own auth middleware.

---

## Check 2 — `next('route')`

In Express, `next('route')` **skips remaining middleware on the current route** and jumps to the **next matching route**. If `CstPanelAuth` calls `next('route')` inside `app.all('/v*/internal*', A, B, C)`, **B and C never run** for that request.

**Keep AUTH** (admin ACL bypass) when B/C were `apiAuth` / `authorizeAdmin` / HMAC.

**G3** only if the *next* matching route has equivalent auth (cite `file:line`).

---

## Check 3 — No-op named middleware

If `restricted` / `authenticate` / `requireAuth` body is only `return next()`, every route listing that name is **unauthenticated**. Merge one AUTH + instances (`finding-instances.md`).

---

## Check 4 — Literal test identities

`sso_token_enc === 'TestSSO'` (or body) that sets `req.user_detail` is **AUTH** (bypass). Not Appendix A because the string says "test" — production builds still ship it unless `NODE_ENV` **and** a dead-code path are proven.

---

## Check 5 — Host / `X-Forwarded-Host` as API key skip

Comparing `req.headers['x-forwarded-host'] || req.headers.host` to a trusted hostname **without** stripping at a cited ingress is **AUTH bypass** (CWE-290). G3 only if a **repo** gateway config overwrites `X-Forwarded-Host` (cite file:line). "mTLS on that host" with no cert check in app code is **not** G3.

---

## Check 6 — Inbound webhook HMAC

| Pattern | Verdict |
|---------|---------|
| Route `POST .../callback` with no signature/HMAC/mTLS middleware | **AUTH** |
| Handler forwards body to another service with `VerifyKey` | Still AUTH on the **inbound** route |
| HMAC compare of raw body vs header, constant-time | G3 if cited |

---

## Ledger close

Hits with no Finding and no Appendix A row → review incomplete (model-proof gate **Express AUTH rg**).
