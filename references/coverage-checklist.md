# Master Coverage Checklist — OpenGrep-aligned SAST + Full Review

**Mandatory:** Execute every check in **`report-coverage-matrix.md`** (109 checks). Record results in **`internal-scan-log.md`** — **not** Appendix E in the user report.

**Report contract:** `report-output-spec.md`  
**How to execute:** `agent-execution.md` — you run manifest `rg` / `graphify`; **no scan scripts**.

Status (internal log): `PASS` | `FINDING` | `FAIL` | `N/A` | `SKIP`  
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
| ARCH-01 … 07 | 7 | `security-architect.md` (internal — Top 3 risks in user report) |
| DAST-HOST-01, DAST-AUTH-PROBE, DAST-INJ-PROBE | 3 | `dast_scan_manifest.md` |
| DEPS-01 | 1 | `npm audit` (agent-run) |
| GRAPH-01, 02, 03 | 3 | `graphify_security.md` |

---

## User report attestation (layer summary only)

After internal log is complete, copy aggregated counts into the **Security Verification Checklist** collapsible toggle per `internal-scan-log.md`. MX-COV in `## Scan Matrices Executed` must match.

**Do not** emit Appendix E, Appendix G, or Appendix I in `security_report.md`.

---

## SAST-OG (OpenGrep `vulnerability_class`)

See **`report-coverage-matrix.md`** for the full 109-row template and manifest cross-links.

Completion gate: no PENDING rows in internal log at handoff; every FINDING links to a checklist ID or Appendix A filter.
