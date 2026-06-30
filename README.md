# AI Security Reviewer Pro Max Skills

> **Works with Cursor and Claude** — same skill, same prompts, same reports.

**Version 4.4** | Agent-native SAST + DAST | Checkmarx-style findings | HTML export

**Repo:** https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills

---

## Description

**AI Security Reviewer** is a Cursor and Claude agent skill that turns your AI coding assistant into a senior application security engineer. Instead of running a separate scanner, the agent **is** the scanner — it reads your codebase, traces tainted data from source to sink, validates findings with AI, and produces enterprise-grade security reports.

**What you get:**
- `security_report.md` + styled `security_report.html` with every finding documented
- Real **vulnerable code snippets** copied from your repo (not generic examples)
- Full **data-flow traces** showing how attacker input reaches the dangerous sink
- **Remediation** with BEFORE/AFTER code fixes for each issue
- Burp/curl-ready PoC requests for live-verifiable findings

**What it covers:**
- Injection (SQL, NoSQL, XSS, RCE, CMD, XXE, SSTI, CRLF, log injection)
- Authentication & authorization (missing auth routes, IDOR, session flaws)
- Secrets leakage, stack-trace disclosure, crypto weaknesses
- IaC misconfigs from source (Docker, K8s, Terraform, Nginx, CI/CD)
- Standards completeness sweep: OWASP Top 10 2021 · OWASP API Top 10 2023 · CWE Top 25 2024 · OWASP ASVS 5.0 · OWASP LLM Top 10 2025
- Completeness & Residual Risk Register so nothing is silently missed

> **Code-only mode (v4.16+):** third-party dependency/CVE scanning (OSV, npm audit, Maven SCA, trivy) is **disabled** — those classes are reported as **Residual — not assessed**, not as PASS. See `CHANGELOG.md` for the authoritative per-version behavior (operative spec is `SKILL.md`, currently v4.18).

**How it works:** The agent follows manifests in `references/` — running pattern scans, manual taint analysis, pre-report gates (G1–G5), and optional live verification. Burp MCP is used when available; otherwise it falls back to curl. Graphify speeds up discovery but is not required.

**Best for:** Developers and security teams who want Checkmarx-quality findings inside Cursor or Claude — without installing Semgrep, Burp plugins, or a separate SAST pipeline.

---

## Supported AI agents

| Platform | Install path | How to use |
|----------|--------------|------------|
| **Cursor** | `~/.cursor/skills/ai-security-reviewer` | Attach skill or paste prompt in chat |
| **Claude Code** | `~/.claude/skills/ai-security-reviewer` | Skill auto-loads from skills folder |
| **Claude Desktop** | `~/.claude/skills/ai-security-reviewer` | Enable skill in project settings |
| **Claude (project)** | `.claude/skills/ai-security-reviewer` | Per-repo skill in project root |

This is **not Cursor-only**. Any Claude or Cursor agent that can read `SKILL.md`, run shell commands, and write files can run a full security review.

---

## What it does

- Agent-native static analysis — 750+ patterns, 85+ vulnerability classes, 109-check matrix
- Senior manual review — taint analysis, OWASP/API taxonomy, pre-report gates G1–G5
- Every finding includes **Vulnerable Code Snippet**, **Data Flow Trace**, and **Remediation** (BEFORE/AFTER)
- Unauthenticated endpoint audit (AUTH-NNN) + exploitable CVE + IaC misconfig scans
- Live verification via **Burp MCP** — falls back to **curl** if Burp is not available
- **Graphify** optional — faster discovery when installed; works without it using `rg` + reads
- Delivers `security_report.md` + styled `security_report.html`

---

## Install

### Option A — Cursor

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.cursor/skills/ai-security-reviewer
```

Restart Cursor → attach skill or type: `Review this code for security vulnerabilities`

### Option B — Claude

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.claude/skills/ai-security-reviewer
```

Restart Claude → skill loads from `SKILL.md`. Same prompts as Cursor.

**Symlink (either platform):**

```bash
ln -sf "$(pwd)/Ai-Security-Reviewer-Pro-Max-Skills" ~/.claude/skills/ai-security-reviewer   # Claude
ln -sf "$(pwd)/Ai-Security-Reviewer-Pro-Max-Skills" ~/.cursor/skills/ai-security-reviewer   # Cursor
```

---

## Optional enhancements

| Tool | Role | If missing |
|------|------|------------|
| **Graphify** | Faster attack-surface mapping & source→sink paths | Agent uses `rg` + narrow file reads |
| **Burp MCP** | Live DAST on code-derived hosts | Agent uses **curl** (`references/curl-dast-fallback.md`) |
| **ripgrep (`rg`)** | Pattern scans | Use agent grep — slower but works |

No external service is required to run a full review.

---

## Usage (Cursor or Claude)

```
Review this code for security vulnerabilities

Run comprehensive security audit and generate security_report.html

Check for SQL injection and XSS in the API controllers
```

---

## Workflow

1. Application context → trust boundaries, auth, assets
2. Static scans (`rg` per manifest files in `references/`)
3. CVE + IaC + route auth audit
4. Data-flow trace + AI validation (G1–G5 gates)
5. Live verify — Burp MCP or curl fallback
6. Report — `security_report.md` → `security_report.html`

The AI agent is the scanner. Manifests are cookbooks — do not run bundled scan scripts for analysis.

---

## Key files

| File | Purpose |
|------|---------|
| `SKILL.md` | Main skill instructions (entry point for Cursor & Claude) |
| `references/` | SAST manifests, taxonomy, DAST rules, report templates |
| `scripts/generate_html_report.py` | Markdown → HTML (formatting only) |
| `CHANGELOG.md` | Version history |

---

## Author

[Mukeshj008](https://github.com/Mukeshj008) — use responsibly; only scan systems you are authorized to test.
