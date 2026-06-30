# CISA KEV Prioritization (additive — SCA / remediation)

**Extends** `security-architect.md` ARCH-06 and `osv-sca-scan.md` — does not change Critical/High exploitable-only SCA summary rule.

---

## When to run

For each **Critical/High** OSV advisory (exploitable or not), query whether CVE is in [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

```bash
# Agent: fetch KEV JSON (curl + network)
curl -sS "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  -o /tmp/cisa-kev.json

# Match CVE IDs from OSV results
python3 - <<'PY'
import json, sys
kev = json.load(open("/tmp/cisa-kev.json"))
ids = {v["cveID"] for v in kev.get("vulnerabilities", [])}
for cve in sys.argv[1:]:
    print(cve, "KEV" if cve in ids else "-")
PY CVE-2024-XXXXX
```

---

## SCA table — add column (when advisories exist)

```markdown
| ID | Severity | CVE / OSV ID | Package@Version | CVSS | KEV | Reachability | Import file:line |
|----|----------|--------------|-----------------|------|-----|--------------|------------------|
| CVE-001 | High | CVE-2024-XXXXX | log4j@2.14.1 | 10.0 | **Yes** | reachable | Foo.java:12 |
```

**KEV values:** `Yes` / `No` / `N/A` (not C/H)

---

## Remediation Priority

KEV + reachable exploitable → **Immediate (24h)** even at High (not only Critical).

```markdown
### Immediate (Critical/High/KEV) - Fix within 24 hours
1. **CVE-001** - KEV-listed log4j — upgrade to [fixed_version]
```

---

## Non-exploitable KEV

If KEV but **not reachable** → **SCA Packages Filtered Out** with reason + note: *"KEV-listed — monitor for new imports."*
