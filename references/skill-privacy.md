# Skill Privacy & Data Hygiene

This skill must **never** contain real credentials, user paths, or org-specific production data.

## Forbidden in skill files

| Category | Examples |
|----------|----------|
| Real API keys / tokens | `AKIA…`, `ghp_…`, `sk_live_…`, JWT literals |
| Passwords | Any non-placeholder password string |
| Private keys / PEM files | `-----BEGIN PRIVATE KEY-----` with real body |
| Real internal hosts | Company staging/prod URLs from a specific engagement |
| User paths | `/Users/<username>/…`, `/home/<user>/…`, machine-specific absolute paths |
| Personal identifiers | Real names, emails, employee IDs in examples |
| `.env` contents | Copied secrets from projects |
| Security report outputs | `security_report.md` with real finding data from a client repo |
| Engagement-specific code | Project route names, internal middleware, or hosts from a past scan |

## Allowed (safe)

- **Detection regexes** (e.g. `AKIA[0-9A-Z]{16}`) — pattern only, not real keys
- **Generic placeholders** — `[TARGET_HOST]`, `staging.example.com`, `[ORDER_ID]`, `[PROJECT_NAME]`
- **Fictional vulnerable examples** — `admin123` in "vulnerable code" snippets (educational only)
- **Public documentation URLs** — OWASP, CWE links
- **Generic middleware names** — `verifyAuth`, `requireRole` (not copied from one client's codebase)
- **Portable skill paths** — `~/.cursor/skills/ai-security-reviewer/` (Cursor install convention, no username)

## Before publishing or sharing the skill

Run from the skill root (replace `SKILL_ROOT` with your install path):

```bash
SKILL_ROOT="${SKILL_ROOT:-$HOME/.cursor/skills/ai-security-reviewer}"

# Real secrets (should return no matches except regex examples in patterns.md)
rg -n "AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|sk_live_|BEGIN (RSA |OPENSSH )?PRIVATE KEY" \
  "$SKILL_ROOT"

# User-specific / engagement-specific leakage (customize YOUR_* before sharing)
rg -n "YOUR_ORG_DOMAIN|YOUR_STAGING_HOST|YOUR_USERNAME|/Users/[a-z]|/home/[a-z]" \
  "$SKILL_ROOT" -i
```

Both should return **no real matches**. Regex examples in `patterns.md` and fictional snippets in `additional_vulns.md` are OK.

### What to replace if found

| Found | Replace with |
|-------|----------------|
| Real staging/prod hostname | `app-staging.example.com` |
| Username in path | `[SKILL_ROOT]` or `$HOME/.cursor/skills/...` |
| Client project routes/files | Generic `routes/api/index.js`, `/api/orders/:id` |
| Scan finding IDs with real file paths | Fictional `UserController.java`, `index.js` |

## Runtime outputs (not stored in skill)

These are written to **project repos** during scans — do not commit to the skill or publish:

- `security_report.md` / `.html` / `.pdf`
- `sast_scan_results.txt`
- `burp_hosts.txt`
- `graphify-out/` from scanned projects

Add to project `.gitignore` if needed.

## Agent note

When generating reports, use **code-derived hosts** from the **current** repo only. Never paste hosts, paths, or findings from a previous engagement into skill files or cross-project templates.
