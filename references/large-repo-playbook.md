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
| P3 | Admin/internal routes, batch jobs |

---

## Sampling rule

- **109 checks:** still run all **applicable** checks on P0+P1 files; mark N/A for irrelevant stacks (mobile, GraphQL).
- **Deep trace:** full G1–G5 on top 15 manifest hits by severity, not every rg match.
- **graphify query** budget: 1500–2000 per query, max 3 queries before scoped rg.

---

## Report honesty

```markdown
**Scope note:** Deep manual trace on P0/P1 paths (N files). Pattern scan covered M files per scan-scope-metrics.md.
```

Do not claim line-by-line review of entire monorepo unless performed.

---

## Stop conditions

Hand off when: checklist complete, P0 surfaces reviewed, attestation summary filled, `--strict` HTML passes.
