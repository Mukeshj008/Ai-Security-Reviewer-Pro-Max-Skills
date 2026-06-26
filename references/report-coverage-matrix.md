# Report Coverage Matrix — Appendix E & F (MANDATORY)

Every security review **must** include **Appendix E** (all checks) and **Appendix F** (phase execution log) in `security_report.md`.

**Generate Appendix E:** Copy the 109-row table from this file into `security_report.md`. **You** run each check per [agent-execution.md](agent-execution.md) — no scripts.

Every security review **must** include **Appendix E**, **Appendix F**, and **Appendix G** in `security_report.md`.

---

## Status values (Appendix E)

| Status | Meaning |
|--------|---------|
| `PASS` | Check executed; no validated issue |
| `FINDING` | Check executed; issue confirmed → link `VULN-NNN`, `AUTH-NNN`, `CVE-NNN`, or `IAC-NNN` |
| `FAIL` | Check could not complete (tool error, missing graph) |
| `N/A` | Not applicable to this stack (document reason in Notes) |
| `SKIP` | Intentionally skipped (user declined graphify, no Burp host, etc.) |

**Completion gate:** All rows must be non-empty before `generate_html_report.py`. Counts in Executive Summary must match Appendix E.

---

## Appendix E — Full Check Inventory

### E.1 OpenGrep-aligned SAST (`SAST-OG-*`)

| Check ID | Category | Tool | Manifest |
|----------|----------|------|----------|
| SAST-OG-01 | Active Debug Code | rg | `sast_scan_manifest.md` §01 |
| SAST-OG-02 | Code Injection | rg + graphify path | §02 |
| SAST-OG-03 | Command Injection | rg + graphify path | §03 |
| SAST-OG-04 | Cookie Security | rg + Read | §04 |
| SAST-OG-05 | Cross-Site Request Forgery (CSRF) | rg + Read | §05 |
| SAST-OG-06 | Cross-Site-Scripting (XSS) | rg + graphify path | §06 |
| SAST-OG-07 | Cryptographic Issues | rg | §07 |
| SAST-OG-08 | Dangerous Method or Function | rg | §08 |
| SAST-OG-09 | Denial-of-Service (DoS) | rg | §09 + `additional_vulns.md` |
| SAST-OG-10 | Hard-coded Secrets | rg | §10 |
| SAST-OG-11 | Improper Authentication | route auth audit + Burp | `route_auth_audit.md` |
| SAST-OG-12 | Improper Authorization | rg + Read | §12 |
| SAST-OG-13 | Improper Encoding | rg | §13 |
| SAST-OG-14 | Improper Validation | rg + Read | §14 |
| SAST-OG-15 | Insecure Deserialization | rg + graphify path | §15 |
| SAST-OG-16 | Insecure Hashing Algorithm | rg | §16 |
| SAST-OG-17 | Insufficient Logging | rg | §17 |
| SAST-OG-18 | LDAP Injection | rg | §18 |
| SAST-OG-19 | Mass Assignment | rg | §19 |
| SAST-OG-20 | Memory Issues | rg | §20 |
| SAST-OG-21 | Mishandled Sensitive Information | rg | §21 |
| SAST-OG-22 | Open Redirect | rg + graphify path | §22 |
| SAST-OG-23 | Other Security | rg | §23 |
| SAST-OG-24 | Path Traversal | rg + graphify path | §24 |
| SAST-OG-25 | SQL Injection | rg + graphify path | §25 |
| SAST-OG-26 | Server-Side Request Forgery (SSRF) | rg + graphify path | §26 |
| SAST-OG-27 | XML Injection / XXE | rg | §27 |
| SAST-OG-28 | XPath Injection | rg | §28 |
| SAST-BUS-01 | Message Bus Trust Boundary | rg + Read | `sast_scan_manifest.md` bus § |

### E.2 Stack trace / error disclosure (`SAST-LEAK-*`)

| Check ID | Category | Tool | Manifest |
|----------|----------|------|----------|
| SAST-LEAK-01 | Node/Express error in response | rg + AI validate | `frontend-stacktrace-leaks.md` §01 |
| SAST-LEAK-02 | Stack trace fields explicitly | rg | §02 |
| SAST-LEAK-03 | GraphQL / API verbose errors | rg | §03 |
| SAST-LEAK-04 | Template / SSR error pages | rg | §04 |
| SAST-LEAK-05 | React / Vue / Angular client leaks | rg | §05 |
| SAST-LEAK-06 | Browser global error handlers | rg | §06 |
| SAST-LEAK-07 | Sensitive fields in error payloads | rg | §07 |
| SAST-LEAK-08 | Debug / verbose flags to frontend | rg | §08 |

### E.3 Hardcoded secrets catalog (`SAST-SECRET-*`)

| Check ID | Category | Tool | Manifest |
|----------|----------|------|----------|
| SAST-SECRET-01 | Cloud & infra keys | rg | `secrets-patterns.md` §01 |
| SAST-SECRET-02 | Git / package / CI tokens | rg | §02 |
| SAST-SECRET-03 | Payment & messaging SaaS | rg | §03 |
| SAST-SECRET-04 | Database & cache URIs with credentials | rg | §04 |
| SAST-SECRET-05 | Private keys & certificates | rg | §05 |
| SAST-SECRET-06 | JWT / session / HMAC / API keys | rg | §06 |
| SAST-SECRET-07 | Password literals | rg | §07 |
| SAST-SECRET-08 | OAuth / OIDC client secrets | rg | §08 |
| SAST-SECRET-09 | Env fallback to hardcoded | rg | §09 |
| SAST-SECRET-10 | Base64 / hex encoded secrets (heuristic) | rg + manual | §10 |
| SAST-SECRET-11 | Kafka / RMQ / third-party inline creds | rg | §11 |

### E.4 Deep injection (`SAST-INJ-*`)

| Check ID | Category | Tool | Manifest |
|----------|----------|------|----------|
| SAST-INJ-XSS | Cross-Site Scripting (reflected/stored/DOM) | rg + graphify path | `injection-deep-scan.md` |
| SAST-INJ-RCE | Remote Code Execution | rg + graphify path | same |
| SAST-INJ-CMD | Command Injection | rg + graphify path | same |
| SAST-INJ-XXE | XML External Entity | rg | same |
| SAST-INJ-XML | XML Injection (non-XXE) | rg | same |

### E.5 Extended classes (`SAST-EXT-*`)

| Check ID | Category | Tool | Manifest |
|----------|----------|------|----------|
| SAST-EXT-01 | Trust Boundary Violation (session from request) | rg + Read | `additional_vulns.md` §2 |
| SAST-EXT-02 | HTTP Request Smuggling (proxy config) | Read config | §3 |
| SAST-EXT-03 | JNDI Injection / Log4Shell | rg | §4 |
| SAST-EXT-04 | Session Fixation | rg + Read | §5 |
| SAST-EXT-05 | ReDoS | rg | §6 + SAST-OG-09 |
| SAST-EXT-06 | XML Bomb (Billion Laughs) | rg | §6 |
| SAST-EXT-07 | Zip Bomb | rg | §6 |

### E.6 DAST & dependencies

| Check ID | Category | Tool | Manifest |
|----------|----------|------|----------|
| DAST-HOST-01 | Code-derived Burp host discovery | agent `rg` | `burp-host-discovery.md` |
| DAST-AUTH-PROBE | Unauthenticated endpoint probes | Burp MCP | `route_auth_audit.md` + `dast_scan_manifest.md` |
| DAST-INJ-PROBE | Injection payloads on HTTP surface | Burp MCP | `dast_scan_manifest.md` |
| DEPS-01 | Dependency vulnerability audit | `npm audit` (agent-run) | lockfile + audit output |

### E.7 Graphify recon

| Check ID | Category | Tool | Manifest |
|----------|----------|------|----------|
| GRAPH-01 | Attack surface mapping | `graphify query` | `graphify_security.md` |
| GRAPH-02 | Vulnerability hotspot discovery | `graphify query` | same |
| GRAPH-03 | Source→sink path traces | `graphify path` | per FINDING candidate |

### E.8 Exploitable CVE reachability (`CVE-*`)

See `cve-exploitability.md` — **CVE-DEPS-01…03**, **CVE-REACH-01…03**, **CVE-CODE-01…08** (14 checks).

### E.9 IaC misconfigurations (`IAC-*`)

See `iac-misconfig-scan.md` — **IAC-DOCKER/K8S/TF/NGINX/CI** (21 checks).

### E.10 Security architect (`ARCH-*`)

See `security-architect.md` — **ARCH-01…07** + mandatory **Appendix G**.

---

## Appendix G — Security Architecture Assessment (MANDATORY)

Template in `security-architect.md`. Linked from ARCH-* rows in Appendix E.

---

## Appendix E — Report table template

Paste into `security_report.md` — **you** fill all rows per `agent-execution.md` (no `generate_coverage_appendix.py`):

```markdown
## Appendix E: Security Check Coverage Matrix (MANDATORY)

| Check ID | Layer | Category | Tool | Status | Finding Ref | Match Count | Notes |
|----------|-------|----------|------|--------|-------------|-------------|-------|
| SAST-OG-01 | SAST | Active Debug Code | rg | PASS | — | 0 | |
| SAST-OG-02 | SAST | Code Injection | rg + graphify | PASS | — | 0 | |
| ... | ... | ... | ... | ... | ... | ... | |
| SAST-LEAK-01 | SAST | Error in HTTP response | rg | PASS | — | 0 | |
| ... | ... | ... | ... | ... | ... | ... | |
| DAST-HOST-01 | Burp host discovery | `rg` per burp-host-discovery.md | script | SKIP | — | — | No external host in code |
| GRAPH-01 | Recon | Attack surface | graphify | PASS | — | — | 3 queries run |
```

### Coverage summary block (required above the table)

```markdown
### Checks Performed Summary

| Metric | Value |
|--------|-------|
| Total checks defined | 109 |
| Checks executed (PASS + FINDING) | X |
| Findings (FINDING) | X |
| Not applicable (N/A) | X |
| Skipped (SKIP) | X |
| Failed to run (FAIL) | X |
| Coverage rate | X% |
```

---

## Appendix F — Review Phase Execution Log (MANDATORY)

Documents **what ran**, not just outcomes. One row per workflow step.

```markdown
## Appendix F: Review Phase Execution Log

| Phase | Step | Command / Tool | Status | Artifact | Notes |
|-------|------|----------------|--------|----------|-------|
| 0 | Burp host discovery | `rg` per burp-host-discovery.md | PASS | Appendix C | |
| 1 | SAST manifests | `rg` per sast_scan_manifest + refs | PASS | Appendix E | |
| 1c | CVE + graphify path | cve-exploitability.md | PASS | CVE-NNN | |
| 1d | IaC `rg` | iac-misconfig-scan.md | PASS | IAC-NNN | |
| 1e | Architect review | security-architect.md | PASS | Appendix G | |
| 1a | Route auth audit | `route_auth_audit.md` | PASS | Appendix D | N routes |
| 1b | Burp AUTH probes | `send_http1_request` | SKIP | Appendix C | No Burp MCP |
| 2 | Data-flow traces | `graphify path` | PASS | — | M paths |
| 3 | AI validation | agent checklist | PASS | — | X true positives |
| 4 | Markdown report | `security_report.md` | PASS | this file | |
| 5 | HTML export (optional) | `generate_html_report.py` | PASS | `security_report.html` | formatting only |
```

**Status for Appendix F:** `PASS` | `FAIL` | `SKIP` | `PARTIAL`

---

## Agent workflow (coverage)

See **`agent-execution.md`**. Summary:

1. For each of **109** checks: run manifest `rg` / `graphify` / `npm audit` **yourself**.
2. On hits: `graphify path` + AI validate before FINDING.
3. Record each row in Appendix E as you go (no scripts, no `PENDING` at end).
4. Log phases in Appendix F; complete Appendix G after ARCH review.
5. Executive Summary counts must match Appendix E.
