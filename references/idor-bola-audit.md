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

| Method | Path | ID param | Auth middleware | Ownership check in handler? | Data sensitivity (PII/PHI/PFI/None) |
|--------|------|----------|-----------------|-------------------------------|------------------------------------|
| GET | /v1/orders/{id} | path | JWT | ? | PII + PFI |

Flag **missing ownership validation** (SAST-OG-12) for manual trace.

---

## Step 1b — Data sensitivity (PII / PHI / PFI) — mandatory for every IDOR candidate

For **every** object-ID endpoint, classify what a successful cross-user (or unauth) read/write would expose. Use one or more labels; cite response fields or model attributes as evidence.

| Label | Meaning | Typical fields / assets |
|-------|---------|-------------------------|
| **PII** | Personally Identifiable Information | name, email, phone, address, DOB, government ID (Aadhaar/SSN/passport), device/customer identifiers tied to a person |
| **PHI** | Protected Health Information | diagnoses, prescriptions, lab results, medical record IDs, insurance/member health IDs, clinical notes |
| **PFI** | Personally Financial Information | PAN/card number, CVV, bank/account numbers, balances, statements, payment tokens, KYC financial docs, wallet/ledger |
| **None** | Non-sensitive / public metadata | catalog SKUs, public content IDs, non-personal feature flags |

**Rules:**
1. Label from **code + response shape** (DTO, serializer, SQL select, GraphQL type) — not guesswork.
2. Multiple labels allowed (e.g. order details → **PII + PFI**).
3. **None** only when the object cannot reasonably contain personal, health, or financial data.
4. Record sensitivity on the object map **and** in the finding Impact Assessment / Severity Rationale.
5. Severity calibration: mass **PII/PHI/PFI** cross-tenant exposure → raise **Impact** (often Severe/High); **None** alone does not inflate severity.

```bash
# Help locate sensitive fields on ID-keyed handlers / models
rg -n -i "email|phone|mobile|aadhaar|aadhar|ssn|dob|address|pan|cvv|card|iban|account.?no|balance|diagnosis|prescription|medical|patient|health" \
  --glob "*.{js,ts,py,java,kt,go}" -g '!node_modules/**' -g '!**/test/**'
```

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
| 200 + **A's fields** in body (name, PNR, order lines, …) | **BOLA confirmed** | VULN-NNN (calibrate with PII/PHI/PFI) |
| 200 + **empty** `[]` / `{orders:[]}` / no object fields | **Not Confirmed BOLA** | AUTH if unauthenticated (Firm); IDOR **Tentative** until victim ID or query-key proof — **IDOR-ADJ-01 / AUTH-ADJ-02** |
| 200 + **B's own** data while requesting A's ID | **Token-bound** | Appendix A **G3** IDOR-ADJ-01 |
| 403/404 | Likely protected | Appendix A or hardening note |
| 401 | Auth required — retest with valid B token | — |
| 500 missing `sso_token` / required param | Auth or schema gate | Not Confirmed unauth IDOR |

When confirmed, note which **PII/PHI/PFI** fields appeared in B's response (redact values in the report; keep field names).

If only one session available: document **Not Verified (single session)** and rely on code trace (G2 ≥3 hops) + sensitivity from models/DTOs.

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
- **Data sensitivity:** state `PII` / `PHI` / `PFI` / `None` (comma-separated if multiple) in Impact Assessment Confidentiality + Business Impact rows.
- Appendix C row: dual-session curl command + HTTP status + sensitivity labels observed.
- Burp PoC: two requests (Step 1 obtain ID → Step 2 cross-user GET).

**Dedup:** If missing auth is root cause, follow `report-output-spec.md` AUTH vs VULN rules.
