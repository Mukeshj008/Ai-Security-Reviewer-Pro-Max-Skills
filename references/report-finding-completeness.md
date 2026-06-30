# Report Finding Completeness (MANDATORY)

Every **Detailed Findings** entry (VULN, AUTH, CVE, IAC, LEAK) **must** include the sections below before handoff. Abbreviated table-only or bullet-only write-ups are **invalid** — they produce empty Remediation panels in HTML.

---

## Required sections (every finding)

| Section | Required | Notes |
|---------|----------|-------|
| `### Classification` | Yes | **Severity**, **AI Verdict**, **Exploitable**, Type, CWE, OWASP, **Source (full path)**, **Sink (full path)** |
| `### Location & Data Flow` or `### Location Summary` | Yes | Full repo-relative paths with line numbers |
| `### Description` | Yes | Checkmarx-style natural language (see SKILL.md) |
| **`### Assumptions`** | **Yes (v4.15)** | G5 gate — table or bullets; see `finding-templates.md` |
| **`### Vulnerable Code Snippet`** | **Yes** | Real code from repo — source + sink lines; see `report-vulnerable-code-dataflow.md` |
| **`### Data Flow Trace`** | **Yes** | Full source → sink ASCII box + simplified flow; not optional for taint findings |
| `### Burp Suite PoC` or `### Live Verification` | Yes for HTTP | **AUTH-NNN:** PoC **mandatory even when Not Verified** (Medium); write `Burp PoC: N/A — [reason]` only for non-HTTP |
| `Secret Type` in Classification | Yes for secrets | Per `secret-type-labels.md` — e.g. GitHub PAT, AWS key, RabbitMQ password |
| `### Impact Assessment` | Yes | **CIA + Business table** — per `report-impact-assessment.md`; no generic one-liners |
| **`### Remediation`** | **Yes — never omit** | See templates below |

**Completion gate (Phase 4):** Before `generate_html_report.py`, grep the report:

```bash
FINDINGS=$(rg -c "^## \[(CRITICAL|HIGH|MEDIUM|LOW)\]" security_report.md | awk -F: '{s+=$2} END {print s+0}')
REM=$(rg -c "^### Remediation" security_report.md | awk -F: '{s+=$2} END {print s+0}')
VC=$(rg -c "^### Vulnerable Code Snippet" security_report.md | awk -F: '{s+=$2} END {print s+0}')
DF=$(rg -c "^### Data Flow Trace" security_report.md | awk -F: '{s+=$2} END {print s+0}')
AS=$(rg -c "^### Assumptions" security_report.md | awk -F: '{s+=$2} END {print s+0}')
# FINDINGS must equal REM, VC, DF, and AS
# Exploitable enum check — see report-finding-field-consistency.md
rg "^\| \*\*Exploitable\*\*" security_report.md | rg -v "\| Yes \||\| No \||\| Hardening \|"
```

If any count differs → add missing sections before HTML export. See **`report-vulnerable-code-dataflow.md`** for snippet and trace templates.

---

## Master Findings Register (legacy — use Verification Register)

**Superseded by `## Security Findings Verification Register`** in v4.12. If both exist, HTML uses the Verification Register.

One row per finding — see **`references/report-findings-verification-register.md`**.

| ID | Severity | Category | Source (full path) | Sink (full path) | Exploitable | AI Verdict | Verification Status | DAST Status | PoC |

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

### SCA / CVE dependency (CVE-NNN in SCA section)

Must appear in **`## Software Composition Analysis (SCA)`** summary table **and** include full snippet + trace + upgrade remediation. Unreachable OSV/npm hits → **SCA Packages Filtered Out** table only — not a FINDING.

### AUTH-only (missing middleware)

**Burp PoC required** whether Verified or Not Verified. Not Verified → Severity Medium; include manual test PoC.

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
| Code only in Description | Vulnerable `request(url)` inline in Description | Move to `### Vulnerable Code Snippet` |
| Placeholder data flow | `[Full stack trace as shown above]` | Paste actual ASCII trace from SKILL.md |
| Missing ### header | `Build URLs server-side...` as plain paragraph | Prefix `### Remediation` |
| AUTH block without Remediation | AUTH-002 metrics section ends after Impact | Add Remediation with nginx/middleware fix |

---

## HTML export

`generate_html_report.py` reads **`### Vulnerable Code Snippet`**, **`### Data Flow Trace`**, and **`### Remediation`** as dedicated panels. Do not bury snippet or trace only in Description.

---

## Live verification cross-reference

Findings with HTTP surface must document verification in **Burp Suite PoC** or **Live Verification (Burp MCP / curl)** — see `curl-dast-fallback.md` when Burp MCP unavailable.
