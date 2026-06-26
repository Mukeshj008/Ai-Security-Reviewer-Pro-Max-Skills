# Master Coverage Checklist — OpenGrep-aligned SAST + Full Review

**Mandatory:** Complete every row in **Appendix E** and **Appendix F** of `security_report.md`.

**Full template:** [report-coverage-matrix.md](report-coverage-matrix.md)  
**How to execute:** [agent-execution.md](agent-execution.md) — **you** run manifest `rg` / `graphify` commands; **no scan scripts**.

Status (Appendix E): `PASS` | `FINDING` | `FAIL` | `N/A` | `SKIP`  
Status (Appendix F): `PASS` | `FAIL` | `SKIP` | `PARTIAL`

---

## Quick inventory (109 checks)

| ID range | Count | Manifest |
|----------|-------|----------|
| SAST-OG-01 … SAST-OG-28 | 28 | `sast_scan_manifest.md` |
| SAST-BUS-01 | 1 | `sast_scan_manifest.md` bus § |
| SAST-LEAK-01 … 08 | 8 | `frontend-stacktrace-leaks.md` |
| SAST-SECRET-01 … 11 | 11 | `secrets-patterns.md` |
| SAST-INJ-XSS, RCE, CMD, XXE, XML | 5 | `injection-deep-scan.md` |
| SAST-EXT-01 … 07 | 7 | `additional_vulns.md` |
| CVE-DEPS/REACH/CODE | 14 | `cve-exploitability.md` |
| IAC-DOCKER/K8S/TF/NGINX/CI | 21 | `iac-misconfig-scan.md` |
| ARCH-01 … 07 | 7 | `security-architect.md` + Appendix G |
| DAST-HOST-01, DAST-AUTH-PROBE, DAST-INJ-PROBE | 3 | `dast_scan_manifest.md` |
| DEPS-01 | 1 | `npm audit` (agent-run) |
| GRAPH-01, 02, 03 | 3 | `graphify_security.md` |

---

## SAST-OG (OpenGrep `vulnerability_class`)

| ID | OpenGrep `vulnerability_class` | Manifest | Agent tool |
|----|--------------------------------|----------|------------|
| SAST-OG-01 | Active Debug Code | `sast_scan_manifest.md` §01 | rg |
| SAST-OG-02 | Code Injection | §02 | rg + graphify path |
| SAST-OG-03 | Command Injection | §03 | rg + graphify path |
| SAST-OG-04 | Cookie Security | §04 | rg + Read |
| SAST-OG-05 | Cross-Site Request Forgery (CSRF) | §05 | rg + Read |
| SAST-OG-06 | Cross-Site-Scripting (XSS) | §06 | rg + graphify path |
| SAST-OG-07 | Cryptographic Issues | §07 | rg |
| SAST-OG-08 | Dangerous Method or Function | §08 | rg |
| SAST-OG-09 | Denial-of-Service (DoS) | §09 + `additional_vulns.md` | rg |
| SAST-OG-10 | Hard-coded Secrets | §10 | rg |
| SAST-OG-11 | Improper Authentication | `route_auth_audit.md` | graphify + Read + Burp |
| SAST-OG-12 | Improper Authorization | §12 | rg |
| SAST-OG-13 | Improper Encoding | §13 | rg |
| SAST-OG-14 | Improper Validation | §14 | rg + Read |
| SAST-OG-15 | Insecure Deserialization | §15 | rg + graphify path |
| SAST-OG-16 | Insecure Hashing Algorithm | §16 | rg |
| SAST-OG-17 | Insufficient Logging | §17 | rg |
| SAST-OG-18 | LDAP Injection | §18 | rg |
| SAST-OG-19 | Mass Assignment | §19 | rg |
| SAST-OG-20 | Memory Issues | §20 | rg |
| SAST-OG-21 | Mishandled Sensitive Information | §21 | rg |
| SAST-OG-22 | Open Redirect | §22 | rg + graphify path |
| SAST-OG-23 | Other Security | §23 | rg |
| SAST-OG-24 | Path Traversal | §24 | rg + graphify path |
| SAST-OG-25 | SQL Injection | §25 | rg + graphify path |
| SAST-OG-26 | Server-Side Request Forgery (SSRF) | §26 | rg + graphify path |
| SAST-OG-27 | XML Injection | §27 | rg |
| SAST-OG-28 | XPath Injection | §28 | rg |
| SAST-BUS-01 | Message bus trust boundary | bus § | rg + Read |

## SAST-LEAK, SECRET, INJ, EXT, CVE, IAC, ARCH

See [report-coverage-matrix.md](report-coverage-matrix.md) sections E.2–E.10.

## DAST, DEPS, GRAPH

See [report-coverage-matrix.md](report-coverage-matrix.md) sections E.6–E.7 and [dast_scan_manifest.md](dast_scan_manifest.md).

**Do not run OpenGrep/Semgrep** or skill scan scripts — agent + `rg` + graphify only.

**Completion gate:** No `PENDING` rows in Appendix E/F/G before handoff.
