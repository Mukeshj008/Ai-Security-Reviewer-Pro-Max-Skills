# AI Security Reviewer Pro Max Skills

**Version 4.4** — Agent-native security review skill for **Cursor** and **Claude**.

Enterprise SAST + DAST with AI-validated findings, Checkmarx-style reports, vulnerable code snippets, data-flow traces, and HTML export.

**Repo:** https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills

---

## What it does

- Agent-native static analysis — 750+ patterns, 85+ vulnerability classes, 109-check matrix
- Senior manual review — taint analysis, OWASP/API taxonomy, pre-report gates G1–G5
- Every finding includes **Vulnerable Code Snippet**, **Data Flow Trace**, and **Remediation** (BEFORE/AFTER)
- Unauthenticated endpoint audit (AUTH-NNN) + exploitable CVE + IaC misconfig scans
- Live verification via **Burp MCP** — falls back to **curl** automatically if Burp is unavailable
- **Graphify** optional — speeds up discovery when installed; works without it using `rg` + targeted reads
- Delivers `security_report.md` + styled `security_report.html`

---

## Install

### Cursor

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.cursor/skills/ai-security-reviewer
```

Restart Cursor → attach skill or type:

```
Review this code for security vulnerabilities
```

### Claude (Claude Code / Claude Desktop skills)

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.claude/skills/ai-security-reviewer
```

Or symlink:

```bash
ln -sf "$(pwd)/Ai-Security-Reviewer-Pro-Max-Skills" ~/.claude/skills/ai-security-reviewer
```

Point Claude at `SKILL.md` as the skill entry file. Same prompts work in both IDEs.

### Project-local (either IDE)

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git .claude/skills/ai-security-reviewer
# or
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git .cursor/skills/ai-security-reviewer
```

---

## Optional enhancements

| Tool | Role | If missing |
|------|------|------------|
| **Graphify** | Faster attack-surface mapping & source→sink paths | Agent uses `rg` + narrow file reads |
| **Burp MCP** | Live DAST on code-derived hosts | Agent uses **curl** (`references/curl-dast-fallback.md`) |
| **ripgrep (`rg`)** | Pattern scans | Use IDE/agent grep — slower but works |

No external service is required to run a full review.

---

## Usage

```
Review this code for security vulnerabilities

Run comprehensive security audit and generate security_report.html

Check for SQL injection and XSS in the API controllers

Check for information disclosure and stack trace exposure
```

---

## Workflow (short)

1. Application context → trust boundaries, auth, assets
2. Static scans (`rg` per manifest files in `references/`)
3. CVE + IaC + route auth audit
4. Data-flow trace + AI validation (G1–G5 gates)
5. Live verify — Burp MCP or curl fallback
6. Report — `security_report.md` → `security_report.html`

**Agent model:** The AI agent is the scanner. Manifests are cookbooks — do not run bundled scan scripts for analysis.

---

## Key files

| File | Purpose |
|------|---------|
| `SKILL.md` | Main skill instructions (entry point) |
| `references/` | SAST manifests, taxonomy, DAST rules, report templates |
| `scripts/generate_html_report.py` | Markdown → HTML (formatting only) |
| `CHANGELOG.md` | Version history |

---

## Privacy

Before sharing this skill publicly, run checks in `references/skill-privacy.md`. Do not commit scan reports, client hosts, or credentials.

---

## Author

[Mukeshj008](https://github.com/Mukeshj008) — use responsibly; only scan systems you are authorized to test.
