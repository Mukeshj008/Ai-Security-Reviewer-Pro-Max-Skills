# Changelog

All notable changes to **AI Security Reviewer Pro Max Skills** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [4.4] — 2026-06-26

### Added

- **Mandatory `### Vulnerable Code Snippet`** per finding — real source + sink code copied from the target repo (not paraphrased).
- **Mandatory `### Data Flow Trace`** per finding — full ASCII taint path or step table plus simplified flow diagram.
- **`references/report-vulnerable-code-dataflow.md`** — templates, rules, and completion gate (findings = snippets = traces = remediations).
- **HTML report panels** — `generate_html_report.py` renders dedicated **Vulnerable Code** and **Data Flow Trace** sections; warns when sections are missing.
- **Completion gate** in `report-finding-completeness.md` — count of finding headers must match snippet, trace, and remediation sections before HTML export.

### Changed

- **`SKILL.md`** — bumped to v4.4; finding templates (VULN, AUTH, CVE, IAC) now require snippet + trace; workflow step 11 explicitly lists all three mandatory sections.
- **`references/agent-execution.md`** — pre-HTML gate includes snippet and trace counts.
- **`references/manual-code-review.md`** — Phase 4 report generation requires vulnerable code and data-flow documentation.
- **`scripts/generate_html_report.py`** — parses and styles new sections; improved finding panel layout.
- **SSRF example** in SKILL.md generalized (`routes/catalog-proxy.js` / `/fetchResource`) — no engagement-specific filenames.

### Unchanged from v4.3

- 109-check Appendix E matrix + Appendix H taxonomy attestation (19 domain groups).
- Senior manual review with pre-report gates G1–G5.
- Mandatory `### Remediation` with BEFORE/AFTER code (v4.2).
- curl DAST fallback when Burp MCP unavailable (v4.2).
- Agent-only execution model — no scan scripts for analysis (v4.0).

---

## [4.3] — 2026-06-23

### Added

- **Full vulnerability taxonomy** — `vulnerability-taxonomy-coverage.md` maps all issue classes to check IDs.
- **Extended category scans** — `extended-category-scans.md` supplemental `rg` for Partial taxonomy rows.
- **Appendix H attestation** — 19 domain groups (TAX-INJ … TAX-FW) mandatory in every report.
- **Expanded injection manifest** — NoSQL, CRLF, header, SSTI, EL, log injection in `injection-deep-scan.md`.

---

## [4.2] — 2026-06-22

### Added

- **Mandatory `### Remediation`** per finding with BEFORE/AFTER code blocks.
- **`references/curl-dast-fallback.md`** — live verification when Burp MCP is unavailable.
- **`references/report-finding-completeness.md`** — finding completeness gate before HTML export.

### Changed

- HTML generator improved Remediation Priority inference as fallback.

---

## [4.1] — 2026-06-21

### Added

- **Senior manual code review** — `manual-code-review.md` with context-first analysis.
- **Pre-report gates G1–G5** — mandatory before any VULN/AUTH/CVE/IAC finding.
- **Phase −1** — application context before broad scanning; feeds Appendix G.

---

## [4.0] — 2026-06-20

### Changed

- **Agent-only execution** — manifests are cookbooks; agent runs `rg`, `graphify`, `npm audit`, Burp MCP directly.
- Scan scripts deprecated for agents (CI-only).
- **`graphify path`** mandatory for injection/CVE/SSRF reachability proof.

---

## [3.9] — 2026-06-18

### Added

- Exploitable CVE analysis (CVE-NNN with import + reachability proof).
- IaC misconfiguration scan (IAC-NNN — Docker, K8s, Terraform, Nginx, CI).
- Security architect lens (ARCH-01…07 + Appendix G).
- 109-check Appendix E matrix.

---

## [3.8] — 2026-06-15

### Added

- Full Appendix E/F coverage matrices in every report.
- Complete SAST manifest runner coverage (LEAK, SECRET, EXT checks).
- DAST manifest for Burp probe rules.

---

## [3.7] — 2026-06-12

### Added

- Frontend stack trace leak checks (SAST-LEAK-01…08).
- Full secrets catalog (SAST-SECRET-01…11).
- Deep injection scan manifest.
- Code-derived Burp host discovery rules.

---

## [3.6] — 2026-06-10

### Added

- Unauthenticated endpoint audit (AUTH-NNN).
- Burp MCP live verification.
- Burp Suite PoC templates per finding.
- HTML report export via `generate_html_report.py`.
- Graphify-first discovery workflow.
- Checkmarx-style natural language descriptions and full stack traces.
