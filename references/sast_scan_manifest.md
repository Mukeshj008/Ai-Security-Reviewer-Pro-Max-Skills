# SAST Scan Manifest (MANDATORY)

**You (the agent)** run each section's `rg` commands below — do **not** use `run_sast_scan.sh`.  
Taxonomy aligned with [OpenGrep `vulnerability_class`](opengrep-vulnerability-index.md) names.

Replace `[SRC]` with `src` or your source root. Exclude: `node_modules`, `test`, `tests`, `.foundry`.

---

## SAST-OG-01 — Active Debug Code

```bash
rg -n "debug\s*:\s*true|DEBUG\s*=\s*true|app\.run\([^)]*debug\s*=\s*True" [SRC]
rg -n "NODE_ENV\s*[=!]==?\s*['\"]development['\"]" [SRC]
```

---

## SAST-OG-02 — Code Injection

```bash
rg -n "eval\s*\(|new Function\s*\(|vm\.runInNewContext|vm\.runInThisContext" [SRC]
rg -n "setTimeout\s*\(\s*['\"\`]|setInterval\s*\(\s*['\"\`]" [SRC]
```

---

## SAST-OG-03 — Command Injection

```bash
rg -n "exec\(|execSync|spawn\(|spawnSync|child_process" [SRC]
rg -n "shell\s*:\s*true|shell\s*:\s*['\"]/" [SRC]
rg -n "git clone|spawn\([^)]*clone" [SRC]
```

---

## SAST-OG-04 — Cookie Security

```bash
rg -n "setCookie|res\.cookie\(|cookie\s*:" [SRC]
rg -n "secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*false|sameSite\s*:\s*none" [SRC]
rg -n "session\(\{|cookie:\s*\{" [SRC] -A3
```

Flag: cookies set without `secure: true`, `httpOnly: true`, `sameSite: 'strict'|'lax'`.

---

## SAST-OG-05 — Cross-Site Request Forgery (CSRF)

```bash
rg -n "method-override|methodOverride|X-HTTP-Method-Override|_method" [SRC]
rg -n "router\.(post|put|patch|delete)\(" [SRC]
```

Flag: state-changing routes + `method-override` middleware without CSRF token middleware (`csurf`, `csrf`, `doubleCsrf`).

---

## SAST-OG-06 — Cross-Site-Scripting (XSS)

```bash
rg -n "innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html" [SRC]
rg -n "mustache\.escape\s*=\s*function\s*\(\)\s*\{\s*return" [SRC]
rg -n '\.render\([^)]*\+|`\s*<[^`]*\$\{' [SRC]
rg -n "javascript:|href\s*=\s*\{|dangerouslySetInnerHTML" [SRC]
```

---

## SAST-OG-07 — Cryptographic Issues

```bash
rg -n "md5|sha1|DES|ECB|RC4|createCipher\(" [SRC]
rg -n "crypto\.pseudoRandomBytes|Math\.random\(\)" [SRC]
rg -n "new WebSocket\s*\(\s*['\"]ws://" [SRC]
rg -n "rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED" [SRC]
rg -n "jsonwebtoken\.sign\([^)]*algorithm\s*:\s*['\"]none" [SRC]
```

---

## SAST-OG-08 — Dangerous Method or Function

```bash
rg -n "require\(['\"]child_process['\"]\)|require\(['\"]vm['\"]\)" [SRC]
rg -n "\.exec\(|\.execSync\(|\.spawn\(" [SRC]
rg -n "puppeteer\.|playwright\.|page\.goto\([^)]*req\.|page\.evaluate\(" [SRC]
```

---

## SAST-OG-09 — Denial-of-Service (DoS)

```bash
rg -n "RegExp\([^)]*\+|new RegExp\(req\.|\.match\(/.*\(\.\+\)\+" [SRC]
rg -n "findAll\(\)|\.query\([^)]*LIMIT\s*-\s*1" [SRC]
rg -n "while\s*\(true\)|for\s*\(\s*;\s*;\s*\)" [SRC]
```

See `additional_vulns.md` for ReDoS, XML bomb, zip bomb.

---

## SAST-OG-10 — Hard-coded Secrets

```bash
rg -n "AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36}|sk_live_|password\s*[:=]\s*['\"][^'\"]{8,}" [SRC]
rg -n "jwt\.sign\([^)]*['\"][A-Za-z0-9+/=]{16,}['\"]|secretOrKey\s*:\s*['\"]" [SRC]
rg -n "-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----" [SRC]
```

---

## SAST-OG-11 — Improper Authentication

See `route_auth_audit.md` (mandatory). Flag routes missing SSO/Basic/HMAC/API-key middleware.

---

## SAST-OG-12 — Improper Authorization

```bash
rg -n "isAdmin|role\s*===|req\.user\.role|authorize\(" [SRC]
rg -n "login_not_required|isSeller|skipAuth" [SRC]
```

---

## SAST-OG-13 — Improper Encoding

```bash
rg -n "res\.send\([^)]*req\.|res\.write\([^)]*req\." [SRC]
rg -n "unquoted|{{{.*}}}|&\{.*\}" [SRC]
rg -n "encodeURI\(|encodeURIComponent\(|escape\(" [SRC]
```

Flag: user input in HTML/URL contexts without contextual encoding.

---

## SAST-OG-14 — Improper Validation

```bash
rg -n "JSON\.parse\(message\.|consumer\.run|channel\.consume" [SRC]
rg -n "req\.body|req\.query|req\.params" [SRC] --glob "*validator*"
rg -n "joi\.|yup\.|zod\.|express-validator" [SRC]
```

Flag: message bus / HTTP handlers without schema validation on untrusted input.

---

## SAST-OG-15 — Insecure Deserialization

```bash
rg -n "pickle\.loads|yaml\.load\(|unserialize|node-serialize" [SRC]
rg -n "JSON\.parse\([^)]*\)\s*;?\s*$" [SRC]
```

---

## SAST-OG-16 — Insecure Hashing Algorithm

```bash
rg -n "createHash\(['\"]md5|createHash\(['\"]sha1|bcrypt\.compareSync\([^,]+,\s*[^)]*\+)" [SRC]
```

---

## SAST-OG-17 — Insufficient Logging

```bash
rg -n "catch\s*\([^)]*\)\s*\{\s*\}|catch\s*\([^)]*\)\s*\{\s*//" [SRC]
rg -n "logger\.(info|error).*(password|token|secret|ssn)" [SRC]
```

---

## SAST-OG-18 — LDAP Injection

```bash
rg -n "ldap\.|createClient\(|search\([^)]*\+|filter\s*=\s*['\"].*\+.*['\"]" [SRC]
```

---

## SAST-OG-19 — Mass Assignment

```bash
rg -n "Object\.assign\([^)]*req\.(body|query)|\.\.(create|update)\(req\.body\)" [SRC]
rg -n "__proto__|constructor\.prototype|lodash\.(set|merge|defaultsDeep)\(" [SRC]
```

---

## SAST-OG-20 — Memory Issues

```bash
rg -n "Buffer\.(read|write)(UInt|Int|Float|Double).*true\)|noAssert\s*:\s*true" [SRC]
rg -n "allocUnsafe\(|new Buffer\(" [SRC]
```

---

## SAST-OG-21 — Mishandled Sensitive Information

```bash
rg -n "err\.stack|error\.stack|res\.json\(\s*err\s*\)" [SRC]
rg -n "logger\.(info|error|debug).*(customer_id|order_id|phone|email|password)" [SRC]
rg -n "console\.(log|info|debug)\(" [SRC]
```

---

## SAST-OG-22 — Open Redirect

```bash
rg -n "redirect\([^)]*req\.(query|body|params)|res\.redirect\([^)]*\+|location\.href\s*=" [SRC]
```

---

## SAST-OG-23 — Other Security

```bash
rg -n "bypassSecurityTrust|trustAsHtml|ng-bind-html|sanitize\s*:\s*false" [SRC]
rg -n "cors\(\s*\)|Access-Control-Allow-Origin.*\*" [SRC]
rg -n "helmet\(\)|app\.disable\(['\"]x-powered-by" [SRC]
```

---

## SAST-OG-24 — Path Traversal

```bash
rg -n "path\.join\([^)]*req\.|readFile\([^)]*req\.|sendFile\([^)]*req\." [SRC]
rg -n "\.\./|fs\.(read|write|unlink)\([^)]*\+.*req\." [SRC]
```

---

## SAST-OG-25 — SQL Injection

```bash
rg -n "\.query\(`|\.query\(['\"].*\+|sequelize\.query\(['\"].*\+|where\s*:\s*literal\(" [SRC]
rg -n "\$\{.*\}.*SELECT|SELECT.*\$\{" [SRC]
```

---

## SAST-OG-26 — Server-Side Request Forgery (SSRF)

```bash
rg -n "axios\(|require\(['\"]request['\"]\)|fetch\(|http\.get\(|https\.get\(" [SRC]
rg -n "url:\s*(req\.|data\.|message\.|params\.)" [SRC]
```

---

## SAST-OG-27 — XML Injection / XXE

```bash
rg -n "xml2json|libxmljs|DOMParser|parseXml|fast-xml-parser" [SRC]
rg -n "DOCTYPE|ENTITY|expat" [SRC]
```

---

## SAST-OG-28 — XPath Injection

```bash
rg -n "xpath\.|selectNodes\(|evaluate\([^)]*\+|xpath\s*=\s*['\"].*\+.*['\"]" [SRC]
```

---

## Message bus (consumer repos — extends Improper Validation)

```bash
rg -n "JSON\.parse\(message\.|eachMessage|consumer\.run" [SRC]
rg -n "makeRequest\(|axios\.(get|post|put)" [SRC] --glob "**/kafka/**"
```

---

## Completion gate

Every `SAST-OG-01` … `SAST-OG-28` row must appear in **Appendix E** with PASS / FINDING / FAIL / N/A.

Also complete:
- **`references/frontend-stacktrace-leaks.md`** — SAST-LEAK-01…08
- **`references/secrets-patterns.md`** — SAST-SECRET-01…11
- **`references/injection-deep-scan.md`** — SAST-INJ-XSS, RCE, CMD, XXE, XML
