# AI Security Reviewer Pro Max Skills

Cursor and Claude agent skill. The agent is the scanner: it reads your code, traces source to sink, and writes a security report. No Semgrep, Burp plugin, or separate SAST pipeline.

**Version 4.35.3**

**GitHub:** https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills  
**Docs:** https://mukeshj008.github.io/Ai-Security-Reviewer-Pro-Max-Skills/

Search: `AI Security Reviewer Pro Max Skills` · `Mukeshj008 Ai-Security-Reviewer-Pro-Max-Skills`

---

## What you get

`<repo>_security_report.md` and `.html`. Each finding has a root-cause title, description, **affected API list** (method, path, auth), real code snippet, data-flow trace, concrete impact, remediation, and one Burp request for the worst HTTP instance. Confidence is Confirmed, Firm, or Tentative. Live curl runs only after you approve it.

Default mode is **code-only**. Dependency CVE tools (OSV, npm audit, trivy) are not run; those classes are **Residual — not assessed**.

## What it looks for

Injection, missing auth, IDOR/BOLA, JWT/session flaws, secrets in source, TLS and crypto misuse, CORS, open redirects, Docker/K8s/Terraform misconfig, and issues outside the 109-check list (same G1–G5 bar). Express gets a dedicated auth audit (glob vs later routes, `next('route')`, no-op middleware, test SSO, Host-header key skip, inbound webhooks). A Spring module with no `SecurityFilterChain` is one AUTH finding plus instances, High unless a public bind is cited. Hardcoded secrets are never Critical.

Same root cause is **one finding** with an instances table, not a new ID per path.

## How a review runs

1. Read `.security-review/scan-session-memory.md` in the target repo if it exists, and resume Residual modules.
2. Enumerate HTTP modules. Deep-trace P0; every other HTTP module is AUTH-walked or named Residual. Do not claim 109 checks after a partial slice.
3. Pattern `rg`, then G1–G5. Empty `200` is not confirmed BOLA. An empty header that falls back to a config token is AUTH.
4. Write the report. HTML drops scanner metadata, the verification checklist, the 109-check toggle, and Appendices B/C/D/F (those repeat the findings). Markdown keeps them for the agent.

Small or cheap models should follow `references/weak-model-parity.md`: one HTTP module per turn.

## Install

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.cursor/skills/ai-security-reviewer
# Claude: ~/.claude/skills/ai-security-reviewer
```

Restart the app, attach the skill, and ask: `Review this code for security vulnerabilities`.

Optional: Graphify for call paths, Burp MCP for live requests, ripgrep for faster pattern scans. The review still runs with file reads and grep.

## Prompts

```
Review this code for security vulnerabilities
```

```
Follow references/weak-model-parity.md
Resume .security-review/scan-session-memory.md
One HTTP module this turn. Do not re-enumerate. Do not claim 109.
```

Report name:

```bash
python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py
```

A workspace folder like `acmeteam-oauth-user-mgmt-service-48e5b67f7489` becomes `oauth-user-mgmt-service_security_report.md`.

## Layout

| Path | Role |
|------|------|
| `SKILL.md` | Entry instructions |
| `references/` | Manifests, gates, templates |
| `references/finding-templates.md` | Description, endpoints, impact, remediation |
| `references/express-auth-audit.md` | Express route-table auth |
| `references/weak-model-parity.md` | Small-model AUTH loop |
| `references/scan-session-memory.md` | Resume file in the scanned repo |
| `scripts/generate_html_report.py` | Markdown to HTML (`--strict`) |
| `CHANGELOG.md` | Version history |

Full behavior is `SKILL.md`. History is `CHANGELOG.md`.

## Author

[Mukeshj008](https://github.com/Mukeshj008) — scan only systems you are authorized to test.
