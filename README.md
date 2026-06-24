# AI Security Reviewer Pro Max Skills

Enterprise-grade **Cursor Agent Skill** for application security reviews — SAST + DAST with AI-validated findings, Checkmarx-style reports, and Burp Suite PoCs.

**Version:** 3.7

## Features

- **Graphify-first discovery** — knowledge-graph queries before broad file reads
- **Agent-native SAST** — 750+ pattern signatures across 85+ vulnerability classes
- **Deep injection scans** — XSS, RCE, command injection, XXE, XML injection
- **Full secrets catalog** — cloud keys, JWT, passwords, OAuth, env fallbacks
- **Stack trace leak detection** — errors/stacks exposed to browser/API
- **Unauthenticated endpoint audit** — route auth inventory with AUTH-NNN findings
- **Burp MCP live verification** — code-derived hosts only (never localhost)
- **AI validation** — true positives only, with full source→sink traces
- **HTML report export** — styled `security_report.html` deliverable

## Install in Cursor

Copy this skill into your Cursor skills directory:

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.cursor/skills/ai-security-reviewer
```

Or symlink:

```bash
ln -s "$(pwd)/Ai-Security-Reviewer-Pro-Max-Skills" ~/.cursor/skills/ai-security-reviewer
```

Restart Cursor, then invoke:

```
Review this code for security vulnerabilities
```

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| [Graphify](https://pypi.org/project/graphifyy/) | Code knowledge graph | `pipx install graphifyy` |
| Burp MCP (optional) | Live DAST verification | Burp Suite + Cursor MCP |
| `rg` (ripgrep) | Static pattern scans | `brew install ripgrep` |

Build the project graph before scanning:

```bash
graphify extract . --no-cluster
# or in Cursor: /graphify .
```

## Repository Structure

```
├── SKILL.md                          # Main skill instructions (Cursor reads this)
├── references/                       # SAST manifests, patterns, Burp templates
│   ├── sast_scan_manifest.md
│   ├── secrets-patterns.md
│   ├── injection-deep-scan.md
│   ├── frontend-stacktrace-leaks.md
│   ├── route_auth_audit.md
│   ├── burp_poc_templates.md
│   └── ...
└── scripts/
    ├── run_sast_scan.sh              # Deterministic rg runner
    ├── discover_burp_hosts.sh        # Extract Burp targets from code
    └── generate_html_report.py       # Markdown → HTML report
```

## Usage Examples

```
# Standard security review
Review this code for security vulnerabilities

# Full audit with HTML report
Run comprehensive security audit and generate security_report.html

# Focused scans
Check for SQL injection and XSS in the API controllers
Check for information disclosure and stack trace exposure
```

## Workflow Overview

1. **Graphify recon** — map attack surface with scoped queries
2. **SAST** — `run_sast_scan.sh` + manifest-driven pattern checks
3. **Route auth audit** — enumerate unauthenticated endpoints
4. **Data flow tracing** — `graphify path` source → sink
5. **AI validation** — confirm true positives only
6. **Burp verification** — live probes on code-derived hosts (optional)
7. **Report** — `security_report.md` → `security_report.html`

## License

See repository license. Use responsibly — only scan systems you are authorized to test.

## Author

[Mukeshj008](https://github.com/Mukeshj008)
