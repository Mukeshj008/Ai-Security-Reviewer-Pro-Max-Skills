# Finding Field Consistency (MANDATORY)

All findings must use **identical canonical values** across:
1. **Security Verification Checklist** row  
2. **`### Classification`** table  
3. **Detailed finding** banner (HTML)

Mismatch or non-enumerated values break the register and confuse readers.

---

## Canonical enums

| Field | Allowed values only | Notes |
|-------|---------------------|-------|
| **Severity** | `Critical`, `High`, `Medium`, `Low`, `Info` | Title `[SEVERITY]` must match Classification |
| **AI Verdict** | `TRUE POSITIVE`, `FALSE POSITIVE`, `FILTERED` | Optional ✅ prefix in prose; table = plain enum |
| **Exploitable** | **`Yes`**, **`No`**, **`Hardening`** | **Never** Conditional, Partial, Depends, Yes (note) |
| **PoC** | `Yes`, `N/A` | Burp/curl available vs not HTTP-exploitable |
| **Status** | Short phrase | e.g. `Verified in curl`, `Code confirmed`, `Not Verified (no target host in code)` |
| **Source (full path)** | `` `repo/relative/path.ext:line` `` | Same string in Register + Classification |
| **Sink (full path)** | `` `repo/relative/path.ext:line` `` or `—` | Same string in Register + Classification |

---

## Exploitable decision tree

```
Can attacker trigger flaw in production without unlikely preconditions?
├─ YES → Exploitable: Yes
├─ NO (confirmed issue but blocked / unreachable) → Exploitable: No
└─ Requires specific config, DEBUG, internal network, or ops access
   → Exploitable: Hardening
      (document preconditions in Description + Impact, NOT in Exploitable cell)
```

| Do not write | Write instead | Put detail in |
|--------------|---------------|---------------|
| `Conditional` | `Hardening` or `No` | Status / Description |
| `Yes (expired token replay)` | `Yes` | Description / Impact Authentication row |
| `Partial` | `No` or `Hardening` | Appendix A if not reportable |
| `Depends on WAF` | `Yes` if app-layer missing; Severity per DAST rules | Live Verification |

---

## Cross-table sync checklist

Before Phase 5 (HTML export), for **each** finding ID:

- [ ] Register **Severity** = Classification **Severity** = `## [SEVERITY]` title
- [ ] Register **Exploitable** = Classification **Exploitable** (exact enum)
- [ ] Register **Source/Sink** = Classification **Source (full path)** / **Sink (full path)**
- [ ] Register **AI Verdict** = Classification **AI Verdict**
- [ ] **Impact Assessment** present (`report-impact-assessment.md`)
- [ ] No bare filenames (`TestController.java:42` → full path under `src/main/java/...`)

```bash
# Exploitable must be exactly Yes, No, or Hardening
rg "Exploitable.*\|" security_report.md | rg -v "\| Yes \||\| No \||\| Hardening \|"
# Non-zero hits → fix before HTML
```

---

## AI Verdict vs Exploitable

| AI Verdict | Exploitable typical |
|------------|---------------------|
| TRUE POSITIVE | Yes or Hardening |
| TRUE POSITIVE (hardening gap) | Hardening |
| FALSE POSITIVE / FILTERED | Do not appear in Register (Appendix A only) |

**CVE-NNN:** Classification uses `AI Verdict: EXPLOITABLE (reachable)`; Register **Exploitable: Yes**.

---

## Status vs Severity (AUTH)

| Live test | Severity | Status |
|-----------|----------|--------|
| Verified unauthenticated 2xx | High | `Verified in Burp` / `Verified in curl` |
| Code only or 401 at gateway | Medium | `Not Verified` + reason |
| No host in code | Medium | `Not Verified (no target host in code)` |

Severity in **Classification** for AUTH findings should match this rule (not duplicated in Exploitable).

---

## Generator behavior (v4.11+)

- HTML **normalizes** Exploitable pills (`Conditional` → Hardening display).
- **Warnings** on non-canonical Exploitable or Register ↔ Classification mismatch.
- Generic **Impact** fallbacks log stderr — add real `### Impact Assessment` tables.

---

## Related docs

- `report-unified-findings-table.md` — register columns  
- `report-impact-assessment.md` — CIA table templates  
- `report-finding-completeness.md` — section checklist  
