# Large Repository Playbook (additive)

**When:** Files Analyzed > 500 OR LOC > 100k OR monorepo with many unrelated modules.

**Does not reduce** required checks — prioritizes **order** and **depth** to fit context limits.

---

## Phase 0 — Triage

1. Read README, ARCHITECTURE.md, `pom.xml` / package.json roots.
2. Identify **production entrypoints** only (exclude `test/`, `scripts/`, `docs/` unless user scope includes them).
3. Record scope decision in Appendix F.

---

## Priority surfaces (review first)

| Priority | Surface |
|----------|---------|
| P0 | Public HTTP controllers, auth filters, payment/order paths |
| P1 | Config (`application*.properties`, env), Dockerfile, CI |
| P2 | Shared libs used by P0 handlers |
| P3 | Admin/internal routes, batch jobs — **AUTH inventory still mandatory** (v4.35) |

---

## Sampling rule

- **109 checks:** still run all **applicable** checks on P0+P1 files; mark N/A for irrelevant stacks (mobile, GraphQL).
- **Deep trace:** full G1–G5 on top 15 manifest hits by severity, not every rg match.
- **graphify query** budget: 1500–2000 per query, max 3 queries before scoped rg.

### v4.35 — P3 / skipped HTTP modules are Residual, not "later"

Large-repo **order** does **not** waive `multi-module-enumeration.md` Step 2.

| Allowed | Forbidden |
|---------|-----------|
| Deep G1–G5 only on P0/P1 **after** a **shallow AUTH walk** of **every** HTTP module (route files + auth middleware `rg` from `express-auth-audit.md` / `per-method-auth-audit.md`) | Walking 5 of 27 services then writing `Checks executed: 109` |
| Listing an HTTP module as **Residual — AUTH not walked** in Completeness Register **and** Scan Attestation `### HTTP module walk` | Silent skip of `*-admin-*`, `*-automation*`, `*-transactions*` because they are "P3" |
| Shallow = enumerate methods + auth chain; one AUTH or Residual row | Claiming Appendix D is complete for the monorepo |

Admin/internal (P3) is where fail-open tokens, unauth `register` / `onboard-admin`, and Go `IsAuthorisedRequest` bugs live. **Shallow AUTH is required; deep injection traces may wait.**

---

## Report honesty

```markdown
**Scope note:** Deep manual trace on P0/P1 paths (N files). Pattern scan covered M files per scan-scope-metrics.md.
**HTTP modules enumerated:** X. **AUTH-walked:** Y. **Residual (not walked):** [list or none].
```

`Checks executed` (MX-COV) must **not** be `109` unless Y == X **or** every skipped HTTP module is named Residual. Fake 109 after a 5-app slice is an attestation defect (`scan-attestation-summary.md` v4.35).

**Session memory (v4.35.1):** After each HTTP module walk, rewrite `.security-review/scan-session-memory.md` (`scan-session-memory.md`). Next session Reads it first — Residual list is the work queue. Do not re-triage P0 from README when memory is fresh.

**Weak model (v4.35.2):** Follow `weak-model-parity.md` — one HTTP module, parity AUTH `rg`. Depth may wait; AUTH Residual may not.

Do not claim line-by-line review of entire monorepo unless performed.

---

## Stop conditions

Hand off when: checklist complete, P0 surfaces reviewed, attestation summary filled, `--strict` HTML passes.
