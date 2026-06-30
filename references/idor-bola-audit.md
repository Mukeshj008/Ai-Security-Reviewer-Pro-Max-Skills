# IDOR / BOLA Systematic Audit (additive)

**When:** Any API with object IDs (`userId`, `orderId`, `accountId`, path `{id}`, query params). Run after route auth audit (Phase 6) and before final report.

**Does not replace:** `extended-category-scans.md` §4.3, `route_auth_audit.md`, or single-parameter curl in `curl-dast-fallback.md` — **extends** them.

---

## Step 1 — Object reference map

Enumerate endpoints that read/write resources by ID:

```bash
rg -n "@(Get|Post|Put|Patch|Delete)Mapping|@(RequestParam|PathVariable).*[Ii]d" \
  --glob "**/*Controller*.java" --glob "**/*controller*"
rg -n "router\.(get|post|put|patch|delete).*[:/].*id|req\.(params|query)\.(user|order|customer)" \
  routes api src
```

Build a table (internal or Appendix C supplement):

| Method | Path | ID param | Auth middleware | Ownership check in handler? |
|--------|------|----------|-----------------|----------------------------|
| GET | /v1/orders/{id} | path | JWT | ? |

Flag **missing ownership validation** (SAST-OG-12) for manual trace.

---

## Step 2 — Dual-session / cross-user probe (DAST)

When **two** test identities exist (or staging allows registration):

1. **Session A** — create or fetch object `ID_A` (order, profile, wallet).
2. **Session B** — request same endpoint with `ID_A` using B's cookie/token only.

```bash
# Session B attempts to read A's resource (read-only)
curl -sS -w "\nHTTP:%{http_code}\n" --max-time 15 \
  -H "Authorization: Bearer [TOKEN_B]" \
  -H "Accept: application/json" \
  "https://[HOST]/v1/orders/[ID_A]"
```

| Result | Verdict | Finding |
|--------|---------|---------|
| 200 + A's data in body | **BOLA confirmed** | VULN-NNN High |
| 403/404 | Likely protected | Appendix A or hardening note |
| 401 | Auth required — retest with valid B token | — |

If only one session available: document **Not Verified (single session)** and rely on code trace (G2 ≥3 hops).

---

## Step 3 — Horizontal vs vertical

| Test | Action |
|------|--------|
| **Horizontal** | User A → User B's object ID |
| **Vertical** | User → admin-only path (`/admin`, `/internal`, `role=admin` param) |
| **Mass assignment** | POST body adds `role`, `isAdmin`, `customer_id` — see extended §4 |

---

## Step 4 — Report

- **VULN-NNN** with Classification Source = route param, Sink = DB/query without ownership filter.
- Appendix C row: dual-session curl command + HTTP status.
- Burp PoC: two requests (Step 1 obtain ID → Step 2 cross-user GET).

**Dedup:** If missing auth is root cause, follow `report-output-spec.md` AUTH vs VULN rules.
