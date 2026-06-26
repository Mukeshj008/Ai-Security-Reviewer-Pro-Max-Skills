# Extended Category Scans (Supplemental `rg` Probes)

Run **after** core manifests (`sast_scan_manifest.md`, `injection-deep-scan.md`, etc.) for taxonomy rows marked **Partial** in `vulnerability-taxonomy-coverage.md`.

**Rules:** Same as agent-execution — you run each `rg`; on hits → `graphify path` → G1–G5 → VULN-NNN if TRUE POSITIVE.

Exclude: `node_modules`, `vendor`, `dist`, `build`, `.git`, `coverage`, `test/fixtures` (unless test mirrors prod pattern).

---

## §1 Injection extensions

### §1.2 NoSQL Injection

```bash
rg -n "\$where|\$regex|\$gt|\$ne|\$or|findOne\s*\(|find\s*\(|aggregate\s*\(|collection\.(find|update|delete)" --glob "*.{js,ts,jsx,tsx,py,php,java}" -g '!node_modules/**' -g '!**/test/**'
rg -n "mongoose\.(find|findOne|update|aggregate)|Model\.find\(|\.where\s*\(" --glob "*.{js,ts}" -g '!node_modules/**'
rg -n "JSON\.parse\s*\(.*req\.|eval\s*\(.*req\.|new Function\s*\(.*req\." --glob "*.{js,ts}" -g '!node_modules/**'
```

**Sinks:** Mongo query objects built from `req.body` / `req.query` without schema validation.

### §1.7 CRLF Injection

```bash
rg -n "res\.(setHeader|writeHead|end)\s*\(.*req\.|res\.redirect\s*\(.*req\.|Location.*\+.*req\.|setHeader\s*\(\s*['\"]Location" --glob "*.{js,ts,py,java,php}" -g '!node_modules/**'
rg -n "\\r\\n|%0d%0a|%0a|%0d" --glob "*.{js,ts,py}" -g '!node_modules/**' -g '!**/test/**'
```

### §1.8 Header Injection

```bash
rg -n "setHeader\s*\(\s*['\"][^'\"]+['\"]\s*,\s*.*req\.(headers|query|body|params)" --glob "*.{js,ts}" -g '!node_modules/**'
rg -n "response\.addHeader|addHeader\s*\(.*request\." --glob "*.{java,php}" -g '!node_modules/**'
```

### §1.9 Email Header Injection

```bash
rg -n "nodemailer|sendmail|smtp|mail\(|MailMessage|MimeMessage|setSubject\s*\(.*req\.|setTo\s*\(.*req\.|setFrom\s*\(.*req\." --glob "*.{js,ts,py,java,php}" -g '!node_modules/**'
rg -n "headers\s*:\s*\{.*req\.|Cc:|Bcc:|Reply-To" --glob "*.{js,ts}" -g '!node_modules/**'
```

### §1.10 Template Injection (SSTI)

```bash
rg -n "renderString|render\s*\(.*req\.|compile\s*\(.*req\.|ejs\.render|pug\.render|handlebars\.compile|mustache\.render|nunjucks\.render|jinja2\.Template|render_template_string" --glob "*.{js,ts,py,jinja,j2,html}" -g '!node_modules/**'
rg -n "\{\{.*req\.|\$\{.*req\.|<%.*req\." --glob "*.{js,ts,html,jade,pug,ejs}" -g '!node_modules/**'
```

### §1.11 Expression Language Injection

```bash
rg -n "SpelExpressionParser|StandardEvaluationContext|parseExpression\s*\(|OGNL|javax\.el\.|UnifiedEL|spring\.expression" --glob "*.{java,xml}" -g '!node_modules/**'
rg -n "vm\.runInNewContext|vm\.runInContext|new Function\s*\(" --glob "*.{js,ts}" -g '!node_modules/**'
```

### §1.12 Log Injection / Log Forging

```bash
rg -n "console\.(log|info|warn|error)\s*\(.*req\.(body|query|params|headers)|logger\.(info|warn|error|debug)\s*\(.*req\." --glob "*.{js,ts,py,java}" -g '!node_modules/**'
rg -n "log\.(info|warn|error)\(.*\+.*request\.|logging\.(info|warning).*%s.*req\." --glob "*.{py,java}" -g '!node_modules/**'
```

---

## §2 XSS extensions

### §2.4 DOM XSS (static heuristics)

```bash
rg -n "document\.(write|writeln)|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|eval\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]|location\s*=|location\.href\s*=" --glob "*.{js,jsx,ts,tsx}" -g '!node_modules/**' -g '!**/test/**'
rg -n "\$\(.*\)\.html\s*\(|dangerouslySetInnerHTML|ng-bind-html|v-html" --glob "*.{js,jsx,ts,tsx,vue}" -g '!node_modules/**'
rg -n "window\.location\.(search|hash)|URLSearchParams|document\.URL|location\.hash" --glob "*.{js,jsx,ts,tsx}" -g '!node_modules/**'
```

Trace: user-controlled URL fragment/search → DOM sink without encoding.

### §2.5 JavaScript Injection

```bash
rg -n "eval\s*\(|new Function\s*\(|setTimeout\s*\([^,]+req\.|setInterval\s*\([^,]+req\.|vm\.runIn" --glob "*.{js,ts}" -g '!node_modules/**'
rg -n "<script[^>]*>.*\+.*req\.|javascript:.*req\." --glob "*.{js,jade,pug,ejs,html}" -g '!node_modules/**'
```

---

## §3 Authentication extensions

### §3.5 Weak password policy

```bash
rg -n "password.*length|minLength|passwordPolicy|validatePassword|password.*regex|password.*match\s*\(" --glob "*.{js,ts,py,java,php}" -g '!node_modules/**'
rg -n "password.*===|password\s*==\s*['\"]|if\s*\(\s*password\s*\)" --glob "*.{js,ts}" -g '!node_modules/**' -g '!**/test/**'
```

**Manual:** Read login/register handlers — check min length, complexity, breach list, rate limit.

### §3.6 Weak session generation

```bash
rg -n "Math\.random\s*\(\s*\).*session|uuid\.v1\s*\(|Date\.now\s*\(\s*\).*session|sessionId\s*=.*\+|token\s*=.*Math\.random" --glob "*.{js,ts,py}" -g '!node_modules/**'
rg -n "session\.id\s*=|genRandomString|randomBytes" --glob "*.{js,ts}" -g '!node_modules/**'
```

### §3.7 Insecure remember-me

```bash
rg -n "rememberMe|remember_me|persistentLogin|stayLoggedIn|longLivedToken|remember.*cookie" --glob "*.{js,ts,java,php}" -g '!node_modules/**'
rg -n "maxAge:\s*31536000|expires.*365|permanent:\s*true" --glob "*.{js,ts}" -g '!node_modules/**'
```

Read: token stored in cookie without rotation/signature/user binding.

### §3.8 Missing / weak password hashing

```bash
rg -n "md5\s*\(.*password|sha1\s*\(.*password|createHash\s*\(\s*['\"]md5|createHash\s*\(\s*['\"]sha1|password.*===|compareSync\s*\(.*plain" --glob "*.{js,ts,py,php,java}" -g '!node_modules/**'
rg -n "bcrypt|scrypt|argon2|pbkdf2" --glob "*.{js,ts,py,php,java}" -g '!node_modules/**'
```

Missing bcrypt/argon2 near password write = candidate FINDING.

### §3.10 Authentication bypass logic

```bash
rg -n "login_not_required|skipAuth|bypassAuth|isAdmin\s*=\s*true|role\s*=\s*['\"]admin|req\.session\.(role|admin)\s*=" --glob "*.{js,ts}" -g '!node_modules/**'
rg -n "if\s*\(\s*!.*password|return\s+true.*auth|authenticate\s*\(\s*\)\s*\{|verify.*\|\|\s*true" --glob "*.{js,ts,py}" -g '!node_modules/**'
```

---

## §4 Authorization extensions

### §4.2 Missing role validation

```bash
rg -n "isAdmin|isSeller|hasRole|checkRole|authorize|requireRole|req\.session\.(role|userType)" --glob "*.{js,ts,py,java}" -g '!node_modules/**'
rg -n "router\.(get|post|put|delete|patch)\s*\([^)]+(?!verifySso|auth|Auth)" --glob "routes/**/*.{js,ts}" -g '!node_modules/**'
```

Cross-check with `route_auth_audit.md`.

### §4.3 BOLA / IDOR patterns

```bash
rg -n "req\.(params|query|body)\.(id|userId|orderId|merchantId|sellerId|accountId)" --glob "*.{js,ts,py,java}" -g '!node_modules/**' -g '!**/test/**'
rg -n "findById\s*\(.*req\.|getUser\s*\(.*req\.|WHERE.*req\." --glob "*.{js,ts,py,java}" -g '!node_modules/**'
```

**Mandatory:** `graphify path` from param → DB/API fetch; verify ownership check in handler.

### §4.4 Privilege escalation

```bash
rg -n "req\.body\.(role|isAdmin|permissions|privileges|userType)|Object\.assign\s*\(.*req\.body|spread.*req\.body|\.\.\.req\.body" --glob "*.{js,ts,py}" -g '!node_modules/**'
rg -n "session\.(role|admin)\s*=.*req\.|setAttribute\s*\(\s*['\"]role" --glob "*.{js,ts,java}" -g '!node_modules/**'
```

---

## §5 Cryptography extensions

### §5.3 Static / predictable IV

```bash
rg -n "createCipheriv\s*\([^,]+,\s*[^,]+,\s*['\"][^'\"]{1,32}['\"]|iv\s*:\s*Buffer\.alloc\(0\)|iv\s*=\s*['\"][0]+|new Uint8Array\s*\(\s*16\s*\)" --glob "*.{js,ts,py,java}" -g '!node_modules/**'
rg -n "AES.*ECB|mode:\s*['\"]ecb['\"]" --glob "*.{js,ts,py,java}" -g '!node_modules/**'
```

### §5.5 Predictable salt

```bash
rg -n "salt\s*=\s*['\"]|fixedSalt|STATIC_SALT|salt:\s*['\"][^'\"]+['\"]" --glob "*.{js,ts,py,java}" -g '!node_modules/**'
```

### §5.7 Insecure RNG

```bash
rg -n "Math\.random\s*\(\s*\).*(token|key|secret|session|TOKEN|KEY|SECRET|IV|salt|nonce)" --glob "*.{js,ts,py}" -g '!node_modules/**' -i
rg -n "random\.random\s*\(|rand\s*\(\s*\)|java\.util\.Random\s*\(\s*\)" --glob "*.{py,java}" -g '!node_modules/**'
```

---

## §6 Sensitive data extensions

### §6.8 Sensitive data in URLs

```bash
rg -n "res\.redirect\s*\(.*(token|password|secret|apiKey|session)|Location.*\?.*(token|password|key)=" --glob "*.{js,ts,py,java}" -g '!node_modules/**'
rg -n "window\.location.*(token|password|secret)|href=.*password=" --glob "*.{js,jsx,html}" -g '!node_modules/**'
```

### §6.9 Client-side secrets

```bash
rg -n "(apiKey|api_key|secret|password|token|privateKey)\s*[:=]\s*['\"][^'\"]{8,}" --glob "public/**/*.{js,jsx,ts,tsx,html}" -g '!node_modules/**'
rg -n "process\.env\.(SECRET|KEY|TOKEN|PASSWORD)" --glob "public/**/*.{js,jsx}" -g '!node_modules/**'
```

---

## §7 Path / file handling extensions

### §7.2 Arbitrary file read

```bash
rg -n "readFile(Sync)?\s*\(.*req\.|createReadStream\s*\(.*req\.|fs\.read\s*\(.*req\.|sendFile\s*\(.*req\." --glob "*.{js,ts,py,java,php}" -g '!node_modules/**'
rg -n "path\.join\s*\(.*req\.|path\.resolve\s*\(.*req\." --glob "*.{js,ts}" -g '!node_modules/**'
```

### §7.3 Arbitrary file write

```bash
rg -n "writeFile(Sync)?\s*\(.*req\.|createWriteStream\s*\(.*req\.|fs\.appendFile\s*\(.*req\." --glob "*.{js,ts,py,java,php}" -g '!node_modules/**'
```

### §7.4 Unsafe file upload

```bash
rg -n "multer|busboy|formidable|upload\.|multipart|req\.files|fileFilter|destination\s*:" --glob "*.{js,ts,py,php}" -g '!node_modules/**'
rg -n "\.originalname|\.filename|mimetype|file\.name" --glob "*.{js,ts,py,php}" -g '!node_modules/**'
```

Read: extension whitelist, path traversal on filename, executable MIME, size limits.

### §7.5 File inclusion (PHP / Java)

```bash
rg -n "include\s*\(\s*\$|require\s*\(\s*\$|include_once\s*\(\s*\$_|readResource\s*\(.*req\." --glob "*.{php,java,jsp}" -g '!node_modules/**'
```

### §7.6 Symlink abuse

```bash
rg -n "fs\.symlink|followSymlinks|preservePaths|extractAllTo|unzip|adm-zip|tar\.extract" --glob "*.{js,ts,py}" -g '!node_modules/**'
```

### §7.7 Unsafe temp files

```bash
rg -n "tmp\.file|mkstemp|tempnam|os\.tmpnam|/tmp/.*req\.|writeFileSync\s*\(\s*['\"]/tmp" --glob "*.{js,ts,py,java,php}" -g '!node_modules/**'
```

---

## §8 Deserialization extensions

### §8.2 Framework-specific unsafe deserialize

```bash
rg -n "pickle\.loads|yaml\.load\s*\(|unserialize\s*\(|ObjectInputStream|readObject\s*\(|JSON\.parse\s*\(.*req\.|deserialize\s*\(.*req\." --glob "*.{js,ts,py,php,java}" -g '!node_modules/**'
rg -n "node-serialize|serialize-javascript|flatted\.parse|bson\.deserialize" --glob "*.{js,ts}" -g '!node_modules/**'
```

---

## §9 Memory (native code only)

Run only if repo contains `.c`, `.cpp`, `.h`, `.rs`, or native `binding.gyp` / `node-addon-api`:

```bash
rg -n "strcpy|strcat|sprintf|gets\s*\(|scanf\s*\(\s*[^,]+,\s*[^\"]" --glob "*.{c,cpp,h}" 
rg -n "malloc\s*\(.*\*.*req|memcpy\s*\(.*req\.|buffer overflow" --glob "*.{c,cpp,rs}" 
```

For Node-only projects → Appendix H **TAX-MEM** = **N/A**.

---

## §10 API security extensions

### §10.5 Missing rate limiting

```bash
rg -n "rateLimit|rate-limit|express-rate-limit|slowDown|throttle|TooManyRequests|429" --glob "*.{js,ts,py,java}" -g '!node_modules/**'
rg -n "router\.(post|put|delete|patch)\s*\(\s*['\"]/(login|auth|register|otp|reset|password)" --glob "routes/**/*.{js,ts}" -g '!node_modules/**'
```

If login/OTP routes exist without rate-limit middleware → document as **Medium** architectural gap (manual G4).

---

## §13 Session extensions

### §13.2 Predictable session IDs

```bash
rg -n "sessionId\s*=|genid|uid\s*\(|uuid\.v1|increment|session\.id\s*=" --glob "*.{js,ts,py}" -g '!node_modules/**'
```

### §13.3 Session timeout

```bash
rg -n "cookie:\s*\{[^}]*maxAge|rolling:\s*false|resave:\s*true|saveUninitialized:\s*true|session\.maxAge|expiresIn" --glob "*.{js,ts}" -g '!node_modules/**'
```

---

## §14 Configuration extensions

### §14.2 Insecure defaults

```bash
rg -n "trust proxy|trustProxy|X-Forwarded-For|secure:\s*false|httpOnly:\s*false|sameSite:\s*false|csrf.*false|helmet\s*\(\s*\{\s*contentSecurityPolicy:\s*false" --glob "*.{js,ts}" -g '!node_modules/**'
```

### §14.7 Missing security headers

```bash
rg -n "helmet|contentSecurityPolicy|X-Frame-Options|Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy" --glob "*.{js,ts,py}" -g '!node_modules/**'
rg -n "add_header\s+(X-Frame|Strict-Transport|Content-Security)" --glob "**/*.{conf,nginx}" 
```

If app is internet-facing and no helmet/nginx headers → IAC or CONFIG finding.

---

## §15 Concurrency / logic (manual + heuristics)

### §15.1 TOCTOU / race heuristics

```bash
rg -n "fs\.existsSync.*writeFile|if\s*\(.*exists.*\).*(unlink|write|delete)|check-then-act" --glob "*.{js,ts,py}" -g '!node_modules/**'
rg -n "SELECT.*FOR UPDATE|transaction|beginTransaction|mutex|lock\s*\(" --glob "*.{js,ts,py,java}" -g '!node_modules/**'
```

Most business logic flaws require **manual** review per `manual-code-review.md` SAST-BUS-01.

---

## §16 Mobile (conditional)

Run if `android/`, `ios/`, `*.apk`, `ReactNative`, or `capacitor` present:

```bash
rg -n "AsyncStorage\.setItem.*(token|password|secret)|localStorage\.setItem.*(token|password)" --glob "*.{js,jsx,ts,tsx,java,kt,swift}" 
rg -n "WebView|setJavaScriptEnabled\s*\(\s*true|loadUrl\s*\(.*javascript:" --glob "*.{java,kt,swift,m,jsx,tsx}" 
rg -n "http://|cleartextTrafficPermitted|NSAllowsArbitraryLoads" --glob "**/*.{xml,plist,gradle}" 
```

---

## §18 Supply chain extensions

### §18.4 Dependency confusion

```bash
rg -n "\"[^\"]+\"\s*:\s*\"(file:|http://|git\+http)" --glob "package.json"
rg -n "registry\.npmjs\.org|nexus|artifactory|@scope/" --glob "{package.json,.npmrc,yarn.lock,package-lock.json}" 
```

### §18.5 Unsafe package sources

```bash
rg -n "git\+|bitbucket:|github:.*#|resolved.*http://" --glob "package-lock.json" | head -50
rg -n "pip install.*--index-url|extra-index-url|trusted-host" --glob "{requirements.txt,pyproject.toml,Pipfile}" 
```

---

## §19 Framework-specific stacks

Detect stack from manifests, then run applicable subsection only.

### §19.1 Spring Boot (Java)

```bash
rg -n "actuator|/env|/heapdump|management\.endpoints|spring\.security\.csrf\.disable|@CrossOrigin\s*\(\s*\*|SpelExpressionParser|ObjectMapper.*enableDefaultTyping|readValue\s*\(.*HttpServletRequest" --glob "*.{java,xml,yml,yaml,properties}" -g '!node_modules/**'
rg -n "jwt\.decode|parseClaimsJws|setSigningKey\s*\(\s*['\"]|verify\s*\(\s*false" --glob "*.{java,kt}" -g '!node_modules/**'
```

### §19.2 Node.js

```bash
rg -n "eval\s*\(|new Function\s*\(|child_process\.(exec|execSync|spawn)\s*\([^)]*\+|require\s*\(\s*req\.|__proto__|constructor\.prototype" --glob "*.{js,ts}" -g '!node_modules/**'
rg -n "merge\s*\(|deepmerge|lodash\.merge|extend\s*\(\s*true.*req\.body" --glob "*.{js,ts}" -g '!node_modules/**'
```

### §19.3 PHP

```bash
rg -n "include\s*\(\s*\$_|require\s*\(\s*\$_|unserialize\s*\(\s*\$_|eval\s*\(\s*\$_|preg_replace\s*\(.*/e|create_function\s*\(" --glob "*.php" -g '!vendor/**'
```

### §19.4 Python

```bash
rg -n "pickle\.loads|yaml\.load\s*\([^)]*\)|subprocess\.(call|Popen|run)\([^)]*shell\s*=\s*True|eval\s*\(|exec\s*\(" --glob "*.py" -g '!venv/**' -g '!**/test/**'
```

### §19.5 Java (general)

```bash
rg -n "Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|Class\.forName\s*\(.*req\.|readObject\s*\(|ObjectInputStream|ScriptEngineManager|InitialContext\.lookup" --glob "*.{java,jsp}" -g '!node_modules/**'
```

### §19.6 .NET

```bash
rg -n "BinaryFormatter|LosFormatter|ObjectStateFormatter|JavaScriptSerializer|ViewState|validateRequest\s*=\s*false|Request\.ValidateInput\s*\(\s*false" --glob "*.{cs,cshtml,vb}" 
rg -n "TypeNameHandling\.All|JsonConvert\.DeserializeObject.*Type" --glob "*.cs" 
```

---

## Completion

After running applicable sections:

1. Record hits in working notes with file:line.
2. Update **Appendix H** domain rows (PASS / FINDING / N/A).
3. Link supplemental FINDINGs to taxonomy row in finding **Classification** table (`Taxonomy: §1.2 NoSQL Injection`).
