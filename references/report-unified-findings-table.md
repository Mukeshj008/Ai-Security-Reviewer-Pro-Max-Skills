# Unified Findings Table — DEPRECATED alias

**Use instead:** `report-findings-verification-register.md` + `report-output-spec.md`

---

## Canonical section name

```markdown
## Security Verification Checklist
```

Legacy names accepted by HTML parser: `Security Findings Verification Register`, `Master Findings Register`.

---

## Required columns (v4.14)

| Column | Required values |
|--------|-----------------|
| **ID** | `VULN-001`, `AUTH-001`, `CVE-001`, `IAC-001` |
| **Severity** | Critical / High / Medium / Low / Info |
| **Category** | Short class name |
| **Source (full path)** | `path/from/repo/root/file.ext:line` |
| **Sink (full path)** | `path/from/repo/root/file.ext:line` |
| **Exploitable** | `Yes` / `No` / `Hardening` only |
| **AI Verdict** | `TRUE POSITIVE` / `FILTERED` |
| **Verification Status** | Code confirmed / Verified in Burp / Verified in curl / Not Verified / … |
| **DAST Status** | Verified in Burp / Verified in curl / Not Verified / N/A / … |
| **PoC** | Yes / N/A |

OWASP/SANS may appear in **Detailed Findings** Classification blocks — not required in checklist columns.

---

## Path rules

1. Repo-root-relative full paths with line numbers.
2. Classification Source/Sink **must match** checklist row for that ID.
3. See AUTH/VULN dedup in `report-output-spec.md`.

---

## Completion gate

```bash
MD="${MD:-$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)_security_report.md}"
rg -c '^## \[(CRITICAL|HIGH|MEDIUM|LOW)\]' "$MD"   # findings
rg -c '^\| (VULN|AUTH|IAC|LEAK|SCA)-' "$MD"       # checklist rows (approx; SCA only in explicit mode)
```

HTML export with `--strict` fails on missing Classification Source/Sink.
