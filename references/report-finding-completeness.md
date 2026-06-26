# Report Finding Completeness (MANDATORY)

Every **Detailed Findings** entry (VULN, AUTH, CVE, IAC, LEAK) **must** include the sections below before handoff. Abbreviated table-only or bullet-only write-ups are **invalid** — they produce empty Remediation panels in HTML.

---

## Required sections (every finding)

| Section | Required | Notes |
|---------|----------|-------|
| `### Classification` | Yes | Type, CWE, OWASP, severity, AI verdict |
| `### Location Summary` | Yes | File, method, route, source/sink lines |
| `### Description` | Yes | Checkmarx-style natural language (see SKILL.md) |
| `### Data Flow Trace` | Yes for taint findings | Source → sink; skip for pure IaC if N/A |
| `### Burp Suite PoC` or `### Live Verification` | Yes for HTTP | Write `Burp PoC: N/A — [reason]` for non-HTTP |
| `### Impact Assessment` | Yes | Table or bullets — CIA / business impact |
| **`### Remediation`** | **Yes — never omit** | See templates below |

**Completion gate (Phase 4):** Before `generate_html_report.py`, grep the report:

```bash
rg -n "^## \[(CRITICAL|HIGH|MEDIUM|LOW)\]" security_report.md | wc -l   # N findings
rg -n "^### Remediation" security_report.md | wc -l                      # must equal N
```

If counts differ → add missing `### Remediation` blocks before HTML export.

---

## Remediation section templates

### Code / route findings (VULN, most AUTH)

**Minimum:** prose fix + **BEFORE** / **AFTER** code snippets.

```markdown
### Remediation

#### Recommended Fix

**BEFORE (Vulnerable):**
```javascript
// file.js — lines X–Y
// vulnerable code
```

**AFTER (Secure):**
```javascript
// file.js — fixed pattern
```

#### Defense in Depth

1. Add `user.checkLoginStatus` to route chain
2. Allowlist outbound hosts in shared helper
```

### AUTH-only (missing middleware)

```markdown
### Remediation

Add middleware to match neighboring protected routes:

```javascript
app.get('/path', user.checkLoginStatus, aclClient.userinit, handler, error);
```

Document if intentionally public; enforce rate limiting + minimal response schema.
```

### IaC (IAC-NNN)

```markdown
### Remediation

**BEFORE:**
```nginx
more_set_headers X-Frame-Options "ALLOW-FROM *.example.com";
```

**AFTER:**
```nginx
add_header Content-Security-Policy "frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
```
```

### CVE (CVE-NNN)

```markdown
### Remediation

1. Upgrade `package@fixed_version`
2. `npm ci` and regenerate lockfile
3. Re-run CVE reachability checks
```

### When remediation is in prose only

Do **not** bury fix advice in Description or table rows. Move it under **`### Remediation`** even if one paragraph.

---

## Anti-patterns (cause empty HTML Remediation panel)

| Anti-pattern | Example | Fix |
|--------------|---------|-----|
| Table-only finding | `\| Route \| POST /addmoney \|` with fix in last table cell | Add full `### Remediation` |
| Fix in Description | "Validate req.body.url against allowlist" in Description only | Duplicate under Remediation + code |
| Missing ### header | `Build URLs server-side...` as plain paragraph | Prefix `### Remediation` |
| AUTH block without Remediation | AUTH-002 metrics section ends after Impact | Add Remediation with nginx/middleware fix |

---

## HTML export

`generate_html_report.py` reads **`### Remediation`** first. It may infer short fixes from preamble heuristics — **do not rely on inference**. Always write explicit sections.

---

## Live verification cross-reference

Findings with HTTP surface must document verification in **Burp Suite PoC** or **Live Verification (Burp MCP / curl)** — see `curl-dast-fallback.md` when Burp MCP unavailable.
