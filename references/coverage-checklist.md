# Master Coverage Checklist — OpenGrep-aligned SAST

**Mandatory:** Complete every `SAST-OG-*` row in **Appendix E** of `security_report.md`.

Status: `PASS` | `FINDING` | `FAIL` | `N/A` | `SKIP`

Source taxonomy: [opengrep-vulnerability-index.md](opengrep-vulnerability-index.md) (from [opengrep/opengrep-rules](https://github.com/opengrep/opengrep-rules) `vulnerability_class` metadata).

| ID | OpenGrep `vulnerability_class` | Manifest | Tool |
|----|-------------------------------|----------|------|
| SAST-OG-01 | Active Debug Code | `sast_scan_manifest.md` §01 | rg |
| SAST-OG-02 | Code Injection | `sast_scan_manifest.md` §02 | rg |
| SAST-OG-03 | Command Injection | `sast_scan_manifest.md` §03 | rg |
| SAST-OG-04 | Cookie Security | `sast_scan_manifest.md` §04 | rg + Read |
| SAST-OG-05 | Cross-Site Request Forgery (CSRF) | `sast_scan_manifest.md` §05 | rg + Read |
| SAST-OG-06 | Cross-Site-Scripting (XSS) | `sast_scan_manifest.md` §06 | rg |
| SAST-OG-07 | Cryptographic Issues | `sast_scan_manifest.md` §07 | rg |
| SAST-OG-08 | Dangerous Method or Function | `sast_scan_manifest.md` §08 | rg |
| SAST-OG-09 | Denial-of-Service (DoS) | `sast_scan_manifest.md` §09 + `additional_vulns.md` | rg |
| SAST-OG-10 | Hard-coded Secrets | `sast_scan_manifest.md` §10 | rg |
| SAST-OG-11 | Improper Authentication | `route_auth_audit.md` | graphify + Read |
| SAST-OG-12 | Improper Authorization | `sast_scan_manifest.md` §12 | rg |
| SAST-OG-13 | Improper Encoding | `sast_scan_manifest.md` §13 | rg |
| SAST-OG-14 | Improper Validation | `sast_scan_manifest.md` §14 | rg + Read |
| SAST-OG-15 | Insecure Deserialization | `sast_scan_manifest.md` §15 | rg |
| SAST-OG-16 | Insecure Hashing Algorithm | `sast_scan_manifest.md` §16 | rg |
| SAST-OG-17 | Insufficient Logging | `sast_scan_manifest.md` §17 | rg |
| SAST-OG-18 | LDAP Injection | `sast_scan_manifest.md` §18 | rg |
| SAST-OG-19 | Mass Assignment | `sast_scan_manifest.md` §19 | rg |
| SAST-OG-20 | Memory Issues | `sast_scan_manifest.md` §20 | rg |
| SAST-OG-21 | Mishandled Sensitive Information | `sast_scan_manifest.md` §21 | rg |
| SAST-OG-22 | Open Redirect | `sast_scan_manifest.md` §22 | rg |
| SAST-OG-23 | Other Security | `sast_scan_manifest.md` §23 | rg |
| SAST-OG-24 | Path Traversal | `sast_scan_manifest.md` §24 | rg |
| SAST-OG-25 | SQL Injection | `sast_scan_manifest.md` §25 | rg + graphify path |
| SAST-OG-26 | Server-Side Request Forgery (SSRF) | `sast_scan_manifest.md` §26 | rg + graphify path |
| SAST-OG-27 | XML Injection | `sast_scan_manifest.md` §27 | rg |
| SAST-OG-28 | XPath Injection | `sast_scan_manifest.md` §28 | rg |
| SAST-BUS-01 | Message bus trust boundary | `sast_scan_manifest.md` bus § | rg + Read |
| SAST-LEAK-01…08 | Frontend/API stack trace leaks | `frontend-stacktrace-leaks.md` | rg |
| SAST-SECRET-01…11 | Hardcoded secrets (full catalog) | `secrets-patterns.md` | rg |
| SAST-INJ-XSS | XSS (reflected/stored/DOM) | `injection-deep-scan.md` | rg + graphify path |
| SAST-INJ-RCE | Remote Code Execution | `injection-deep-scan.md` | rg + graphify path |
| SAST-INJ-CMD | Command Injection | `injection-deep-scan.md` | rg + graphify path |
| SAST-INJ-XXE | XML External Entity | `injection-deep-scan.md` | rg |
| SAST-INJ-XML | XML Injection | `injection-deep-scan.md` | rg |
| DAST-HOST | Burp host from code (no localhost) | `burp-host-discovery.md` | discover_burp_hosts.sh |

Deterministic runner: `bash scripts/run_sast_scan.sh .`  
Burp hosts: `bash scripts/discover_burp_hosts.sh .`

**Do not run OpenGrep/Semgrep** as part of this skill — agent + rg only.
