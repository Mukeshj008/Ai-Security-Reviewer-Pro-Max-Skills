# Risk Score Rubric (additive — reproducible Executive Summary metric)

**Purpose:** Define **Risk Score: X/100** in Executive Summary so scores are comparable across runs. **Adds** structure; existing severity distribution tables **remain**.

---

## Formula (0–100, higher = worse)

```
Risk Score = min(100, round(
  Critical × 25 +
  High     × 15 +
  Medium   × 8  +
  Low      × 3  +
  Hardening× 2  (Exploitable=Hardening rows in checklist)
))
```

| Band | Score | Label |
|------|-------|-------|
| 75–100 | Critical risk |
| 50–74 | High risk |
| 25–49 | Medium risk |
| 0–24 | Low risk |

---

## Adjustments (document in Executive Summary if applied)

| Adjustment | Points | When |
|------------|--------|------|
| +10 | Any **KEV** reachable CVE | `kev-prioritization.md` |
| +5 | Verified unauth **PII** (curl/Burp High) | AUTH/VULN verified |
| −5 | All Critical/High remediated since baseline | `baseline-delta-report.md` |

---

## Report template

```markdown
### Risk Score: 62/100 — HIGH

**Method:** rubric v4.15 (Critical×25 + High×15 + Medium×8 + Low×3 + Hardening×2; cap 100)
**Counts:** Critical 0 · High 3 · Medium 2 · Low 0 · Hardening 2
**Adjustments:** none
```

Agents **must** show counts used — do not invent scores without arithmetic.
