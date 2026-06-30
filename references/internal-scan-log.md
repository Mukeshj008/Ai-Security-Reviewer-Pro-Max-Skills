# Internal Scan Log (agent-only — not in user report)

Replaces **Appendix E** in `security_report.md`. Execute all 109 checks; record results here during the review session. Summarize layers in the user report's collapsible scan-layer toggle only.

**Template source:** `report-coverage-matrix.md`  
**Execution:** `agent-execution.md` per-check loop

---

## Where to record

Choose one (never commit to repo unless user asks):

1. **Agent working notes** in the session (preferred)
2. **Optional file** `.security-review/internal-scan-log.md` (gitignored) in the project under review
3. **Collapsed toggle** in user report — layer summary only (PASS/FINDING counts), not 109 rows

---

## Layer summary (copy into user report toggle)

After completing checks, aggregate:

```markdown
<details>
<summary>Scan layer checklist (109 internal checks) — click to expand</summary>

| Layer | Checks | PASS | FINDING | N/A | Notes |
|-------|--------|------|---------|-----|-------|
| SAST (OG) | 29 | X | X | X | — |
| SAST (LEAK) | 8 | X | X | X | — |
| SAST (SECRET) | 11 | X | X | X | — |
| SAST (INJ) | 5 | X | X | X | — |
| SAST (EXT) | 7 | X | X | X | — |
| CVE reachability | 14 | — | — | 14 | **N/A — code-only mode (v4.16+)** |
| IaC (source) | 21 | X | X | X | — |
| ARCH | 7 | X | X | 0 | internal — no Appendix G |
| DAST | 3 | X | X | X | — |
| GRAPH | 3 | X | X | X | — |
| DEPS + SCA (OSV) | 6 | — | — | 6 | **N/A — code-only mode (v4.16+)** |
| **Total** | **109** | X | X | 20+ | MX-COV reconciles; SCA/CVE/DEPS = Residual |

</details>
```

**MX-COV** Executed column in `## Scan Matrices Executed` must match **Total** checks run (not necessarily 109 if stack N/A).

---

## Per-check row format (internal worksheet)

For each check ID from `report-coverage-matrix.md`:

| Field | Value |
|-------|-------|
| Check ID | e.g. SAST-OG-06 |
| Status | PASS / FINDING / N/A / SKIP / FAIL (SCA/CVE/DEPS = N/A in code-only mode) |
| Finding Ref | VULN-001, AUTH-002, IAC-001, LEAK-001, or — (**no CVE-/SCA- IDs in code-only mode**) |
| Confidence | Confirmed / Firm / Tentative (`finding-confidence-validation.md`) |
| Discovery | Checklist / Researcher |
| Match Count | N hits from rg |
| Notes | Manifest section, failed gate, filtered reason |

---

## Completion gate

Before writing `security_report.md`:

- [ ] Every applicable check ID has a Status (no PENDING)
- [ ] Every FINDING row links to a Verification Checklist ID or Appendix A filter
- [ ] Layer summary totals reconcile with MX-COV
- [ ] Appendix F Phase 1 logs internal scan completion

**Do not** paste 109 rows into the user report.

---

## Scan Attestation Summary (user-facing — v4.15)

Copy the short accountability block from **`scan-attestation-summary.md`** into the user report after Scan Matrices Executed. This **adds** proof of execution without Appendix E bloat.
