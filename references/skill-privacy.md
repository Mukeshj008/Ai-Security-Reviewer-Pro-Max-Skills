# Skill Privacy & Data Hygiene

This skill must **never** contain real credentials or org-specific production data.

## Forbidden in skill files

| Category | Examples |
|----------|----------|
| Real API keys / tokens | `AKIA…`, `ghp_…`, `sk_live_…`, JWT literals |
| Passwords | Any non-placeholder password string |
| Private keys / PEM files | `-----BEGIN PRIVATE KEY-----` with real body |
| Real internal hosts | Company staging/prod URLs from a specific engagement |
| User paths | `/Users/<username>/…` |
| `.env` contents | Copied secrets from projects |
| Security report outputs | `security_report.md` with real finding data |

## Allowed (safe)

- **Detection regexes** (e.g. `AKIA[0-9A-Z]{16}`) — pattern only, not real keys
- **Generic placeholders** — `[TARGET_HOST]`, `staging.example.com`, `[ORDER_ID]`
- **Fictional vulnerable examples** — `admin123` in "vulnerable code" snippets
- **Public documentation URLs** — OWASP, CWE links

## Before publishing or sharing the skill

```bash
rg -n "AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|sk_live_|BEGIN (RSA |OPENSSH )?PRIVATE KEY" \
  ~/.cursor/skills/ai-security-reviewer/

rg -n "org-domain|travel-dev|mukeshchaudhari|/Users/" \
  ~/.cursor/skills/ai-security-reviewer/ -i
```

Both should return **no real matches** (regex examples in patterns.md are OK).

## Runtime outputs (not stored in skill)

These are written to **project repos** during scans — do not commit:

- `security_report.md` / `.html` / `.pdf`
- `sast_scan_results.txt`
- `burp_hosts.txt`

Add to project `.gitignore` if needed.
