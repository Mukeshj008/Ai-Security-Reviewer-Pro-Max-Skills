# Baseline & Delta Report (additive — re-scans)

**When:** Prior `security_report.md` or checklist exists in repo from earlier review.

---

## Step 1 — Locate baseline

```bash
ls -la security_report.md docs/security/security_report.md .security-review/baseline.json 2>/dev/null
```

---

## Step 2 — Compare finding IDs

| Status | Meaning |
|--------|---------|
| **New** | ID in current report, not in baseline |
| **Fixed** | In baseline, absent from current checklist |
| **Open** | In both |
| **Regressed** | Was Fixed, reappeared |

---

## User report section (optional)

```markdown
## Delta Since Last Review

**Baseline:** security_report.md @ 2026-05-01 (commit abc1234)

| ID | Status | Severity | Notes |
|----|--------|----------|-------|
| VULN-001 | Open | High | Unauth /v1/test |
| VULN-005 | New | Medium | JWT missing exp |
| AUTH-002 | Fixed | — | Removed from Appendix D |

**Risk score delta:** 62 → 48 (−14) per `risk-score-rubric.md`
```

---

## Optional baseline file

Save for next run (user-approved):

```json
{
  "date": "2026-06-26",
  "finding_ids": ["VULN-001", "VULN-002", "IAC-001"],
  "risk_score": 62
}
```

Path: `.security-review/baseline.json` (gitignore recommended).

**Does not replace** full report — adds trend visibility only.
