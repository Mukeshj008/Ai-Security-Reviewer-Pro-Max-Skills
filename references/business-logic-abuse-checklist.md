# Business Logic & Abuse-Case Checklist (additive — fintech / commerce)

**When:** E-commerce, payments, wallet, loyalty, catalog, storefront, marketplace repos. Run in **Phase −1** context + **Phase 9** manual validation.

**Does not replace** G1–G5 or SAST manifests — adds structured manual review where patterns fail.

---

## Abuse-case matrix (review each — PASS / FINDING / N/A)

| ID | Abuse case | What to look for | Typical sink |
|----|------------|------------------|--------------|
| BUS-01 | **Price / amount tampering** | Client-supplied `amount`, `price`, `discount` trusted server-side | Payment handler |
| BUS-02 | **Quantity / inventory negative** | `-1` qty, integer overflow, race on stock decrement | Order/cart service |
| BUS-03 | **Coupon / promo stacking** | Multiple codes, expired code, reuse after burn | Promo engine |
| BUS-04 | **Payment status bypass** | Skip callback; mark paid without gateway confirm | Webhook handler |
| BUS-05 | **Refund / chargeback abuse** | Double refund, refund > paid, idempotent replay | Refund API |
| BUS-06 | **Wallet / balance manipulation** | Transfer without debit, concurrent double-spend | Ledger service |
| BUS-07 | **IDOR on orders/accounts** | Cross-user order/wallet read-write | See `idor-bola-audit.md` |
| BUS-08 | **Workflow skip** | Jump state machine (SHIPPED without PAID) | State transition |
| BUS-09 | **Rate limit / OTP brute force** | No lockout on OTP/login/payment PIN | Auth endpoints |
| BUS-10 | **Test/debug in prod** | `/test`, `debug=true`, mock payment flags | Controllers, filters |

```bash
rg -n "amount|price|discount|quantity|refund|wallet|coupon|promo|debug_panel|/test" \
  src --glob "!*test*" | head -80
```

---

## G1–G5 for business logic

- **G1:** Can attacker control workflow input (JSON field, header, replay)?
- **G2:** Trace to state change or financial sink without server validation?
- **G3:** Idempotency keys, server-side price lookup, signed callbacks?
- **G4:** Exploitable on staging/production path (not test-only)?
- **G5:** Assumptions (e.g. "payment gateway always called first") — list in `### Assumptions`

---

## User report (optional section)

Add after **Top Structural Risks** when commerce/fintech detected:

```markdown
### Business Logic Review Summary

| ID | Status | Finding ref | Notes |
|----|--------|-------------|-------|
| BUS-01 | PASS | — | Server recalculates price from catalog |
| BUS-10 | FINDING | VULN-004 | TestController in prod profile |
```

Full matrix stays internal if space limited — summary table is enough.

---

## Platform checklist link

Maps to **TAX-LOGIC** in `platform-coverage-checklist.md` and **SAST-BUS-01** in coverage matrix.
