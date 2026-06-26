# AI Security Reviewer Pro Max Skills

Enterprise-grade **Cursor Agent Skill** for application security reviews — agent-native SAST + DAST with AI-validated findings, Checkmarx-style reports, Burp/curl live verification, and HTML export.

**Version:** 4.4

## What it does

- **Graphify-first discovery** — knowledge-graph queries before broad file reads
- **Agent-native SAST** — 750+ pattern signatures across 85+ vulnerability classes
- **109-check coverage matrix** (Appendix E) + **full taxonomy attestation** (Appendix H)
- **Senior manual review** — taint analysis, OWASP/API taxonomy, pre-report gates G1–G5
- **Vulnerable code + data flow** — real source/sink snippets and full taint traces per finding
- **Deep injection scans** — SQL, NoSQL, XSS, RCE, CMD, XXE, XML, CRLF, SSTI, log injection
- **Extended category scans** — auth, crypto, file handling, API, framework-specific (Spring, Node, PHP, Python, Java, .NET)
- **Secrets & stack-trace leaks** — cloud keys, JWT, passwords, error disclosure
- **Unauthenticated endpoint audit** — route auth inventory with AUTH-NNN findings
- **CVE exploitability** — Critical/High deps only when import + reachability proven
- **IaC misconfiguration** — Docker, K8s, Terraform, Nginx, CI/CD
- **Burp MCP + curl fallback** — live DAST on code-derived hosts (never localhost)
- **Mandatory remediation** — every finding includes BEFORE/AFTER fix snippets
- **HTML report export** — styled `security_report.html` with Vulnerable Code and Data Flow panels

## Install in Cursor

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.cursor/skills/ai-security-reviewer
```

Or symlink:

```bash
ln -sf "$(pwd)/Ai-Security-Reviewer-Pro-Max-Skills" ~/.cursor/skills/ai-security-reviewer
```

Restart Cursor, then attach the skill or invoke:

```
Review this code for security vulnerabilities
```

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| [Graphify](https://pypi.org/project/graphifyy/) | Code knowledge graph | `pipx install graphifyy` |
| [ripgrep](https://github.com/BurntSushi/ripgrep) | Static pattern scans | `brew install ripgrep` |
| Burp MCP (optional) | Live DAST verification | Burp Suite + Cursor MCP |

Build the project graph before scanning (in Cursor: `/graphify .`, or AST-only):

```bash
unset OLLAMA_BASE_URL
graphify extract routes api lib middleware --no-cluster
```

## Repository structure

```
├── SKILL.md                              # Main skill instructions (Cursor reads this)
├── README.md                             # This file
├── CHANGELOG.md                          # Version history
├── references/
│   ├── agent-execution.md                # Agent-only rules (no scan scripts)
│   ├── manual-code-review.md             # Senior review + G1–G5 gates
│   ├── sast_scan_manifest.md             # SAST-OG-01…28
│   ├── injection-deep-scan.md            # XSS, RCE, CMD, XXE, NoSQL, SSTI, …
│   ├── extended-category-scans.md        # Supplemental rg for taxonomy gaps
│   ├── vulnerability-taxonomy-coverage.md
│   ├── report-vulnerable-code-dataflow.md # Snippet + trace templates (v4.4)
│   ├── secrets-patterns.md
│   ├── frontend-stacktrace-leaks.md
│   ├── route_auth_audit.md
│   ├── cve-exploitability.md
│   ├── iac-misconfig-scan.md
│   ├── security-architect.md
│   ├── report-coverage-matrix.md         # 109 Appendix E rows
│   ├── report-finding-completeness.md
│   ├── curl-dast-fallback.md
│   ├── skill-privacy.md
│   ├── burp-host-discovery.md
│   ├── burp_poc_templates.md
│   └── …
└── scripts/
    ├── generate_html_report.py           # Markdown → HTML (formatting only)
    └── README.md                         # Scripts = optional CI only, not for agents
```

## Usage examples

```
# Standard security review
Review this code for security vulnerabilities

# Full audit with HTML report + taxonomy coverage
Run comprehensive security audit and generate security_report.html

# Focused scans
Check for SQL injection and XSS in the API controllers
Check for information disclosure and stack trace exposure
```

## Workflow overview (v4.4)

1. **Phase −1** — Application context (trust boundaries, auth, assets)
2. **Graphify recon** — attack surface queries (`budget 1500`)
3. **SAST manifests** — agent runs `rg` per reference files (not shell scripts)
4. **Extended taxonomy** — `extended-category-scans.md` → Appendix H
5. **CVE + IaC + architect** — exploitable deps, infra misconfigs, STRIDE
6. **Route auth audit** — unauthenticated endpoints → AUTH-NNN
7. **Data-flow traces** — `graphify path` source → sink; mandatory snippet per finding
8. **AI validation** — G1–G5 gates; true positives only
9. **Burp / curl verify** — code-derived staging hosts only
10. **Report** — `security_report.md` (Vulnerable Code + Data Flow + Remediation per finding) → `security_report.html`

## Agent execution model

**You are the scanner.** The skill provides directions — the Cursor agent runs `rg`, `graphify`, `npm audit`, and Burp MCP directly. Do **not** rely on bundled scan scripts for analysis (`run_sast_scan.sh`, etc. are CI-only).

## Privacy

Before sharing or publishing this skill, run checks in `references/skill-privacy.md`. Do not commit real scan reports, client hosts, or credentials.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

Use responsibly — only scan systems you are authorized to test.

## Author

[Mukeshj008](https://github.com/Mukeshj008)
