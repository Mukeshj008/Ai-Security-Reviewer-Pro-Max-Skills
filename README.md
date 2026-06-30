# AI Security Reviewer Pro Max Skills

> **Works with Cursor and Claude** — same skill, same prompts, same reports.

**Version 4.21** | Agent-native SAST + DAST | Checkmarx-style findings | HTML export

**Repo:** https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills

---

## Description

**AI Security Reviewer** is a Cursor and Claude agent skill that turns your AI coding assistant into a senior application security engineer. Instead of running a separate scanner, the agent **is** the scanner — it reads your codebase, traces tainted data from source to sink, validates findings with AI, and produces enterprise-grade security reports.

**What you get:**
- `<repo>_security_report.md` + styled `<repo>_security_report.html` (repo slug derived automatically from the workspace folder)
- Real **vulnerable code snippets** copied from your repo (not generic examples)
- Full **data-flow traces** showing how attacker input reaches the dangerous sink
- **Remediation** with BEFORE/AFTER code fixes for each issue
- Burp/curl-ready PoC requests for live-verifiable findings
- **Scan Attestation Summary**, **Completeness & Residual Risk Register**, and **Confidence** per finding

**What it covers:**
- Injection (SQL, NoSQL, XSS, RCE, CMD, XXE, SSTI, CRLF, log injection)
- Authentication & authorization (missing auth routes, IDOR/BOLA, session flaws, per-method auth gaps)
- Secrets leakage, stack-trace disclosure, crypto weaknesses, JWT/CORS misconfigs
- IaC misconfigs from source (Docker, K8s, Terraform, Nginx, CI/CD)
- Standards completeness sweep: OWASP Top 10 2021 · OWASP API Top 10 2023 · CWE Top 25 2024 · OWASP ASVS 5.0 · OWASP LLM Top 10 2025
- **Security-researcher pass** — issues outside the 109-check matrix, validated with the same G1–G5 bar

> **Code-only mode (v4.16+):** third-party dependency/CVE scanning (OSV, npm audit, Maven SCA, trivy) is **disabled** — those classes are reported as **Residual — not assessed**, not as PASS. Operative spec is `SKILL.md` (currently **v4.21**). See `CHANGELOG.md` for per-version behavior.

**How it works:** The agent follows manifests in `references/` — running pattern scans, manual taint analysis, pre-report gates (G1–G5), confidence adjudication, and optional live verification. Burp MCP is used when available; otherwise it falls back to **curl only**. Graphify speeds up discovery but is not required.

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
- **Scope completeness (v4.19+)** — every module, every config profile, every Dockerfile, per-endpoint-method auth audit
- Senior manual review — taint analysis, OWASP/API taxonomy, pre-report gates G1–G5
- **Two-stage confidence validation (v4.18+)** — Confirmed / Firm / Tentative; fail-open (never silently drop uncertain candidates)
- Every finding includes **Vulnerable Code Snippet**, **Data Flow Trace**, and **Remediation** (BEFORE/AFTER)
- Unauthenticated endpoint audit (AUTH-NNN) + IaC misconfig scans + researcher-discovered issues
- Live verification via **Burp MCP** — falls back to **curl** if Burp is not available
- **Graphify** optional — faster discovery when installed; works without it using `rg` + reads
- Delivers `<repo>_security_report.md` + `<repo>_security_report.html` via `derive_report_name.py`

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
2. Module & profile enumeration (every module, every `application-*.yml`)
3. Static scans (`rg` per manifest files in `references/`)
4. IaC + route auth + per-method auth audit + researcher pass
5. Data-flow trace + AI validation (G1–G5 gates) + confidence adjudication
6. Live verify — Burp MCP or curl fallback
7. Report — derive repo slug → `<repo>_security_report.md` → `<repo>_security_report.html`

The AI agent is the scanner. Manifests are cookbooks — do not run bundled scan scripts for analysis.

**Report naming (v4.20):**

```bash
REPO=$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)
MD="${REPO}_security_report.md"
HTML="${REPO}_security_report.html"
```

Example: workspace `acmeteam-oauth-user-mgmt-service-48e5b67f7489` → `oauth-user-mgmt-service_security_report.md`

---

## Key files

| File | Purpose |
|------|---------|
| `SKILL.md` | Main skill instructions (entry point for Cursor & Claude) |
| `references/` | SAST manifests, taxonomy, DAST rules, report templates |
| `references/report-naming-convention.md` | Mandatory `<repo>_security_report.*` filename spec |
| `scripts/derive_report_name.py` | Derive clean repo slug from workspace folder |
| `scripts/generate_html_report.py` | Markdown → HTML (formatting only) |
| `scripts/push_to_github.sh` | Push skill updates to this repo (requires `GITHUB_TOKEN`) |
| `CHANGELOG.md` | Version history |

---

## Author

[Mukeshj008](https://github.com/Mukeshj008) — use responsibly; only scan systems you are authorized to test.
