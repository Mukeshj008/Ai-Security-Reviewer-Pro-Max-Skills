# Effective Controls & Exploitability Preconditions (MANDATORY — precision layer)

**Purpose:** cut false positives **without** silently dropping real bugs. This is the evidence base for **G3 (protections)** and **G4 (practical exploit)** in `manual-code-review.md`.

Two questions, per candidate:

1. **Is a control present that genuinely neutralizes this CWE?** → §1 Effective control catalogue
2. **Are the runtime preconditions for exploitation actually met?** → §2 Exploitability preconditions

**Rules of use:**

- A control counts **only when you read it and it is on the actual path** — cite `file:line`. "The framework probably escapes" is not evidence.
- A control that is **bypassable as written** (blocklist, regex on user input, escaping the wrong context) is **not** effective → keep the finding.
- Preconditions **not met** → Appendix A with the named precondition. Preconditions **unknown** → **Tentative**, never a silent drop (`finding-confidence-validation.md` fail-open).
- **Never** use this file to downgrade missing authentication/authorization. Absent authz has no compensating "control" inside the same app.

---

## §1 Effective control catalogue (what actually neutralizes each class)

### SQL / NoSQL injection (CWE-89, CWE-943)

| Effective (→ Appendix A with citation) | NOT effective (→ keep finding) |
|----------------------------------------|--------------------------------|
| `PreparedStatement` + `setX()` bound params | String concat / `String.format` / `+` into SQL, even "validated" |
| JPA/Hibernate named params `:id`, Criteria API, Spring Data derived queries | `@Query` with `"… " + param`, `createQuery(concat)`, `nativeQuery` concat |
| Django ORM `filter()`, Rails ActiveRecord hash conditions, Sequelize `where:{}`, GORM `Where("x = ?", v)` | `.raw()`, `extra()`, `find_by_sql`, `sequelize.query(tpl)`, `Raw(fmt.Sprintf)` |
| MongoDB driver with typed value, `$eq` on scalar | `JSON.parse(req.body)` straight into query (operator injection `{$ne:…}`) |
| Value is a **parsed integer/enum** before concat (`Integer.parseInt`, enum lookup) — cite the parse | Length checks, quote-stripping, `replace("'","")`, blocklists |
| Identifier from a **fixed allowlist map** (sort column lookup table) | Identifier interpolation "sanitized" by regex |

### Command injection (CWE-78)

**Effective:** argv-array exec with no shell (`ProcessBuilder(list)`, `execFile`, `subprocess.run([...], shell=False)`, `exec.Command(bin, args...)`) **and** binary not attacker-chosen. Fixed-allowlist argument values.
**Not effective:** `shell=True`, `Runtime.exec(String)`, `sh -c`, `exec()` with concatenation, quoting/escaping helpers, blocklisting `;`/`&&` (bypass via `$()`, newline, glob, argument injection like `--output=`).

### XSS (CWE-79)

| Effective | NOT effective |
|-----------|---------------|
| Framework auto-escaping in **HTML text context**: React `{value}`, Angular interpolation, Vue `{{ }}`, Thymeleaf `th:text`, Jinja2 autoescape on, ERB `<%= %>` with Rails, Go `html/template` | `th:utext`, `\|safe`, `raw()`, `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `bypassSecurityTrustHtml`, Go `text/template` for HTML |
| DOMPurify / OWASP Java Encoder **for the matching context** | HTML-escaping a value used inside a **JS string, URL, or attribute** — wrong-context escaping is a finding |
| `textContent` / `setAttribute` on non-URL attrs | `href`/`src` from user input without scheme allowlist (`javascript:`) |
| Response is non-HTML **and** `X-Content-Type-Options: nosniff` (see §2) | JSON response without nosniff reflected into a browser-rendered context |

### Path traversal / arbitrary file access (CWE-22)

**Effective:** canonicalize then confine — `Path.of(base).resolve(in).normalize().startsWith(base)`, `filepath.Clean` + prefix check, `os.path.realpath` + `commonpath` check; or filename taken from a **generated ID**, never from user text.
**Not effective:** stripping `../` once, `replace("..","")`, `basename()` alone when the value is later joined to a user-controlled dir, extension allowlist alone (traversal is in the path, not the extension).

### SSRF (CWE-918)

**Effective:** host allowlist checked **after** DNS resolution against resolved IPs, with redirects disabled or re-validated per hop; or fixed base URL where only a **path segment** (no scheme/host, `..` rejected) is user-controlled; egress proxy with deny-by-default.

**Java Spring — effective (cite builder):**
- `@Value` / config property as sole authority + `UriComponentsBuilder.fromHttpUrl(base).pathSegment(userPart)` or `.queryParam(name, value)`
- `configBase + FIXED_ENDPOINT_CONSTANT` where endpoint constant is not user-derived
- `WebClient` with `.baseUrl(config)` and relative URI templates only

**NOT effective:** blocklisting `localhost`/`169.254.169.254` (bypass: decimal/hex IP, `[::]`, DNS rebinding, redirect chain, `0.0.0.0`), scheme check alone, allowlist checked on the **pre-redirect** URL only, **`restTemplate.exchange(url)` hit without authority trace**, string concat `base + "/" + userInput` without segment encoding, **`UriComponentsBuilder.path(userControlled)`** (use **`pathSegment()`** only for dynamic segments), **Spring Cloud Feign `@Url` with user-controlled full URL**, config base URL **writable by attacker** via admin/API.

**Mandatory adjudication:** `precision-false-positive-adjudication.md` **SSRF-ADJ-01** before any CWE-918 finding.

**G1 + G3:** attacker may control a path segment (G1 passes) while config-fixed authority excludes SSRF (G3 → Appendix A) — normal outcome.

### LDAP injection (CWE-90)

**Effective:** LDAP filter/DN built with bound parameters or framework APIs that escape/filter metacharacters; fixed filter template with validated scalar substitution.

**NOT effective:** "No LDAP in deployment" without reading code; assuming any `.search()` call is LDAP.

**Mandatory adjudication:** `precision-false-positive-adjudication.md` **LDAP-ADJ-01** — require LDAP imports/context; JMESPath `Expression.search`, Elasticsearch `.search`, Python `re.search` are **not** LDAP sinks.

### Deserialization (CWE-502)

**Effective:** JSON/protobuf into a **fixed DTO** with polymorphism disabled; `ObjectInputFilter`/allowlist on `ObjectInputStream`; `yaml.safe_load`; `TypeNameHandling.None`.
**Not effective:** "we only deserialize our own data" without integrity check; `enableDefaultTyping`/`@JsonTypeInfo` on untrusted input; `pickle`, `Marshal.load`, `BinaryFormatter` under any wrapper; classpath-gadget arguments ("no gadget present" is a snapshot, not a control).

### XXE / XML external entities (CWE-611, CWE-776)

| Effective (→ Appendix A with citation) | NOT effective (→ keep finding) |
|----------------------------------------|--------------------------------|
| `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` | **Unmarshalling into a typed DTO / JAXB class** — binding constrains object mapping, **not** the parser's entity resolution |
| `XMLConstants.FEATURE_SECURE_PROCESSING` = true, or `ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` = `""` | Schema/XSD validation alone |
| `XMLInputFactory.SUPPORT_DTD` = false; `IS_SUPPORTING_EXTERNAL_ENTITIES` = false | A well-formedness or `startsWith("<")` pre-check |
| JAXB fed from a **hardened** `XMLStreamReader`/`SAXSource` you constructed | `Unmarshaller.unmarshal(Reader/String/InputStream)` — JAXB builds a **default, entity-resolving** parser |
| Parser library that is secure-by-default **in the pinned version** — cite it | "The XML comes from our partner/bank, so it's trusted" when the channel is not authenticated |

**Trust-boundary rule:** a third-party **response** body is attacker-controlled whenever the transport is unauthenticated — trust-all `TrustStrategy`, `NoopHostnameVerifier`, cleartext HTTP, or a compromisable proxy. Verify the client's TLS configuration before calling a response "trusted"; if TLS validation is disabled anywhere on that client, treat every parsed response field as attacker-controlled and chain the two findings (`attack-chain-narrative.md`).

**Anti-pattern to reject explicitly:** "typed unmarshal, so XXE is residual/low". Type safety and entity expansion are orthogonal. Downgrade only with cited **parser-level** hardening.

### CSRF (CWE-352)

**Effective:** framework CSRF token validated on state-changing methods; **or** the endpoint authenticates *only* via `Authorization: Bearer`/custom header (not ambient cookies) — cite the auth filter; `SameSite=Strict/Lax` for non-GET **plus** no cookie-auth cross-site flow.
**Not effective:** `SameSite=None`, `csrf().disable()` on cookie-authenticated routes, Referer checks that accept missing/empty Referer, GET endpoints that mutate state.

### Open redirect / deep-link destination (CWE-601)

**Effective:** exact host+path allowlist, or relative-path-only enforcement rejecting `//evil`, `\evil`, `https:`, encoded variants.
**Not effective:** `startsWith("/")` alone (`//evil.com` is protocol-relative), `contains(ourDomain)` (`evil.com?x=ourDomain`), suffix check (`ourdomain.evil.com`).

### Secrets in source (CWE-798)

**Effective:** value is a placeholder/env reference (`${VAR}`, `changeme`, `<REDACTED>`, obvious test fixture); credential provably rotated/revoked (user-confirmed).
**Not effective:** "it's only dev/staging" when the same value appears in a prod profile, or the file is baked into an image; "it's in .gitignore now" when it remains in git history (see `git-history-secrets-scan.md`).

### Crypto (CWE-327/329/338/916)

**Effective:** AES-GCM/ChaCha20-Poly1305 with per-message random nonce; bcrypt/argon2id/scrypt/PBKDF2 (adequate cost) for passwords; `SecureRandom`/`crypto.randomBytes`/`secrets` for tokens; **constant-time** comparison for MACs.
**Not effective:** ECB, fixed/derived-from-key IV, MD5/SHA-1 for signatures or passwords, unsalted SHA-256 for passwords, `Math.random`/`java.util.Random`/`rand()` for tokens/OTP/session IDs, `==`/`String.equals`/`memcmp` on MACs (see §3 `SIG-01`).

### Spring Boot actuator exposure (CWE-1188/200)

| Effective (→ Appendix A with citation) | NOT effective (→ keep finding on **sensitive** endpoints) |
|----------------------------------------|-----------------------------------------------------------|
| Only `health`/`info` exposed **and** `health.show-details: never` (or when-authorized) **and** no custom secret contributors | Blanket "actuator is bad" finding when **only** probe-safe endpoints are exposed |
| Sensitive endpoints require auth (`hasRole('ACTUATOR')`, separate management port + mTLS, Spring Security on `/actuator/env` etc.) — cite filter chain | `/actuator/health` unauthenticated alone — **Low** AUTH instance at most, not High VULN |
| Gateway/mesh blocks sensitive paths **and** app config does not expose them (`include: health` only) | `include: "*"` or explicit `env,heapdump,…` with `permitAll` — finding lists **sensitive** endpoints only |

See **`actuator-sensitive-endpoints-audit.md`** for the sensitive vs probe-safe taxonomy.

### Missing authentication / authorization (CWE-306/862/639)

**No in-app compensating control exists.** Only these are acceptable, each with cited manifest evidence, and they change **severity/verification status only — not the finding's existence**: gateway route policy (`route_auth_audit.md`), mesh `STRICT` mTLS, `NetworkPolicy` denying ingress. See the forbidden-exclusion table in `manual-code-review.md`.

**IDOR exception (G3):** attacker-supplied `userId`/`customerId` that is **ignored** after SSO, with lookup+response bound to token subject — **Appendix A IDOR-ADJ-01**. Missing auth on that same route is still AUTH if SSO is not required.

### IDOR / BOLA (CWE-639) — effective vs not

| Effective (→ Appendix A G3, IDOR-ADJ-01) | NOT effective (→ keep IDOR or AUTH) |
|------------------------------------------|-------------------------------------|
| Query uses `SecurityContext` / SSO `userId` only; request ID unused or equality-checked then discarded | Query uses request `customerId`/`pnr`/`order_id` with no ownership check |
| UUID never disclosed **and** no list endpoint leaks IDs — **does not** delete missing-authz; **may** cap severity | `200 []` on a guessed ID — **not** a control; AUTH may still stand |
| Gateway requires service identity **and** cited in repo | "Ops will only call this internally" with no NetworkPolicy |

---

## §2 Exploitability preconditions (G4 — check before Critical/High)

Ask whether the condition holds. **Met** → proceed. **Not met** → Appendix A naming the precondition. **Unknown** → Tentative.

| Class | Precondition that must hold | Common reason it fails (→ FP) |
|-------|------------------------------|-------------------------------|
| Reflected/stored XSS | Value reaches a **browser-rendered HTML/JS context** | Pure JSON API, `Content-Type: application/json` + `nosniff`, consumed only by a native mobile client |
| CSRF | Auth is **ambient** (cookie/basic) and cross-site sendable | Bearer-header-only API; custom required header |
| SSRF | Attacker controls **destination authority** (scheme/host/port) **or** can force client redirect to arbitrary URL without per-hop re-validation | **Authority config/constant-only**; user input only in **`pathSegment` / `queryParam`** on fixed base (`SSRF-ADJ-01` → Appendix A **G3**) |
| SSRF (blind) | Process can egress, and response/error is observable or side-effecting | Fully egress-blocked worker with no observable effect — downgrade severity, don't delete silently |
| SSRF (redirect chain) | Trusted backend open-redirect + client follows redirects | Fixed authority + no user URL — **Tentative/Low** (SSRF-ADJ-01-F), not Appendix A |
| SQLi | Sink executes against a live DB on a reachable route | Migration/CLI/dead code not wired to any route |
| Path traversal | Process has read/write rights outside the base dir | Fully chrooted/read-only FS with base == mount root |
| Deserialization RCE | Attacker controls the serialized bytes **before** any integrity check | Payload is HMAC-verified with a secret not in the repo |
| IDOR/BOLA **data leak** | Attacker ID is the **object query key** **and** response includes that object's fields (or live foreign PII/PFI) | Request ID unused / token-bound response (**IDOR-ADJ-01** → Appendix A **G3**); live `200 []` with no foreign fields (**AUTH-ADJ-02** → not Confirmed BOLA) |
| IDOR/BOLA | Object IDs are guessable/enumerable **or** leaked elsewhere | 128-bit random IDs never disclosed — still report **AUTH** if authz is absent; **do not** Confirmed-BOLA without (A) or live foreign data |
| Unauthenticated **sensitive** handler | Handler returns or mutates PII/PFI/privileged state without a session | `/status`/`/health` OK only (**AUTH-ADJ-03**); `500` missing SSO header (not Confirmed) |
| Dummy credential | Forged token is accepted **as a subject** and authorizes the sink | Token ignored / SSO client 401 / next hop unused `order_id` (**EXPLOIT-ADJ-01**) |
| Race/TOCTOU | Two requests can interleave on shared state | Single-writer with DB unique constraint or `SELECT … FOR UPDATE` covering the invariant |
| ReDoS | Regex applied to attacker-length-controlled input | Input length-capped before the regex (cite the cap) |
| Log injection | Logs render in a viewer that interprets the payload, or feed a parser | Structured JSON logging that escapes newlines |
| Mobile exported IPC | Component reachable by another app (exported, no signature permission) | `exported="false"`, signature-level permission, or `android:permission` held only by the same signer |
| Cleartext HTTP | Traffic crosses a network an attacker can observe | `localhost`-only loopback call inside the same pod |

**Never** treat these as valid FP reasons: "needs a rooted device", "needs the user to install a malicious app" (that *is* the Android IPC threat model), "needs an authenticated account" (accounts are cheap), "requires a fast script".

---

## §3 Precision patterns for classes that are usually missed

### SIG-01 — Non-constant-time MAC / token comparison (auth bypass; near-zero FP rate)

```bash
rg -n -i "(signature|hmac|mac|digest|token|secret|otp|checksum)[^=\n]{0,40}(\.equals\(|==|!=)" --glob '*.{java,kt,go,js,ts,py,rb,cs,php}'
rg -n "hmac\.new\(|createHmac\(|Mac\.getInstance|hmac\.New\(" -A6 --glob '*.{java,kt,go,js,ts,py,rb,cs,php}'
```

**Effective:** `MessageDigest.isEqual`, `hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`, `ActiveSupport::SecurityUtils.secure_compare`.
**Finding:** `==` / `.equals` / `memcmp` on a MAC or webhook signature → **VULN**, CWE-208/CWE-347. Webhook signature compared this way = forgeable request; treat as High+ when it authenticates a payment/state-changing callback.

### SIG-02 — Signature verification skipped or attacker-selected

```bash
rg -n -i "verify\s*=\s*false|skipVerif|insecureSkip|validateSignature\s*\(\s*false|alg.*none|decode\([^)]*verify" --glob '*.{java,kt,go,js,ts,py,rb,cs}'
```

### SAML-01 — SAML assertion handling

```bash
rg -n -i "saml|Assertion|SAMLResponse|opensaml|python3-saml|ruby-saml|Sustainsys|onelogin" --glob '*.{java,kt,xml,py,rb,cs,js,ts,yml,properties}' | head -40
rg -n -i "validateSignature|wantAssertionsSigned|WantAssertionsSigned|signatureRequired|checkRecipient|checkDestination|allowedClockDrift|InResponseTo" --glob '*.{java,kt,xml,py,rb,cs,yml}'
```

**Findings:** assertions not required to be signed; signature validated on the Response but not the Assertion (or vice versa) → **XML signature wrapping**; missing `InResponseTo`/`Recipient`/`Destination`/`NotOnOrAfter` validation → replay; XML parsed with entity resolution on (chain to XXE); comment-truncation-vulnerable canonicalization in the SAML library's usage.

### OAUTH-01 — OAuth / OIDC flow handling

```bash
rg -n -i "response_type|redirect_uri|code_verifier|code_challenge|state\b|nonce|id_token|access_token|refresh_token|implicit" --glob '*.{java,kt,go,js,ts,py,rb,cs,yml,properties}' | head -60
```

**Findings:** `redirect_uri` matched by prefix/substring instead of exact registered URI; missing/unverified `state` (CSRF on the callback); public client without PKCE; `id_token` accepted without `iss`/`aud`/signature/`nonce` checks; tokens returned in the URL fragment or query (chain to `deeplink-audit.md`); refresh tokens without rotation/binding.

### CI-01 — CI/CD workflow injection (RCE on the build, code-findable)

```bash
rg -n "pull_request_target|workflow_run|issue_comment" --glob '.github/workflows/*.{yml,yaml}' -A15
rg -n '\$\{\{\s*github\.event\.(issue|pull_request|comment|head_commit|review)[^}]*\}\}' --glob '.github/workflows/*.{yml,yaml}'
rg -n "runs-on:\s*\[?\s*self-hosted|persist-credentials\s*:\s*true|actions/checkout@.*ref:\s*\$\{\{\s*github\.event\.pull_request\.head" --glob '.github/workflows/*.{yml,yaml}'
rg -n "uses:\s*[^@\n]+@(main|master|v?[0-9]+)\s*$" --glob '.github/workflows/*.{yml,yaml}'
rg -n -i "secrets\.|GITLAB_TOKEN|CI_JOB_TOKEN|when:\s*always|allow_failure" --glob '{.gitlab-ci.yml,Jenkinsfile,azure-pipelines.yml}'
```

**Findings:** `pull_request_target` (or `workflow_run`/`issue_comment`) that checks out **PR head code** or interpolates `github.event.*` text into `run:` → attacker-controlled shell in a context holding secrets → **VULN, High/Critical**; unpinned third-party actions on a secret-bearing workflow; self-hosted runner reachable from fork PRs. `IAC-NNN` is also acceptable — be consistent within the report.

### ARCHIVE-01 — ZipSlip / archive extraction

```bash
rg -n "ZipEntry|getNextEntry|ZipFile|TarArchiveEntry|extractall|tarfile\.open|unzipper|adm-zip|archive/zip|Rubyzip" -A6 --glob '*.{java,kt,go,js,ts,py,rb,cs}'
```

**Effective:** resolve each entry against the destination and reject escapes, plus entry-count/size caps (zip bomb).
**Not effective:** trusting `entry.getName()`, checking only the first path component.

### XXE-01 — Unhardened XML parsers (run whenever XML/SOAP is parsed)

```bash
rg -n "JAXBContext|createUnmarshaller|Unmarshaller|DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReader|SAXReader|XmlMapper" --glob '*.{java,kt}'
# Hardening must appear on the SAME factory/parser instance — empty output over a parsing codebase = finding
rg -n "disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES|setExpandEntityReferences" --glob '*.{java,kt}'
```

Then trace who supplies the XML (request body, upload, queue message, or a **third-party response over an unvalidated TLS client**) and apply the trust-boundary rule above.

### RAND-01 — Predictable security values

```bash
rg -n "Math\.random|new Random\(|java\.util\.Random|rand\(\)|mt_rand|random\.random|uuid1\(|Date\.now\(\)\s*\+|System\.currentTimeMillis\(\)\s*\+" -B2 -A2 --glob '*.{java,kt,go,js,ts,py,rb,cs,php}'
```

**Finding only when** the value becomes a token/OTP/session ID/password-reset/nonce/filename-for-secret — cite the use. Random for jitter, retry backoff, sampling, or test data → Appendix A.

### SSRF-ADJ-01 — Outbound HTTP authority (false-positive prevention; run on every SAST-OG-26 hit)

```bash
rg -n 'restTemplate\.(exchange|getForEntity|getForObject)|WebClient|HttpClient\.|fetch\(|axios\(|requests\.(get|post)\(' --glob '**/*.{java,kt,js,ts,py,go}'
rg -n '@Url\s|FeignClient|@RequestLine' --glob '**/*.{java,kt}'
# Mandatory Read: trace URL variable to authority source — do NOT report from rg alone; untraced → Tentative
rg -n 'buildUrl|UriComponentsBuilder|fromHttpUrl|fromUriString|new URL\(|URI\.create|@Value.*\.url' --glob '**/*.{java,kt,js,ts,py,go}'
```

**Appendix A (failed gate G3) when:** authority config/constant-only and not runtime-writable; user input in **`pathSegment`/`queryParam` only** (not `.path(userInput)`). **Finding when:** full user URL, Feign `@Url`, authority concat. **Tentative/Low when:** redirect chain (SSRF-ADJ-01-F). Full workflow: `precision-false-positive-adjudication.md`.

### LDAP-ADJ-01 — `.search()` namesake exclusion (false-positive prevention; run on every SAST-OG-18 hit)

```bash
rg -n 'io\.burt\.jmespath|Expression\.search|re\.search\(|elasticsearch.*\.search' --glob '**/*.{java,kt,py,js,ts}'
rg -n 'LdapTemplate|InitialDirContext|DirContext|ldapTemplate|LDAPConnection|ldap\.' --glob '**/*.{java,kt,js,ts,py,rb,cs}'
```

**Appendix A (failed gate G3 — wrong sink) when:** hit is JMESPath/ES/regex `.search` with no LDAP context in **file or callee chain**. **Finding when:** LDAP filter/DN built with concat from user input.

---

## §4 Reporting hooks

- Control cited and effective → **Appendix A** row: `Failed Gate: G3` + adjudication ID (e.g. `SSRF-ADJ-01`) + control `file:line`.
- Precondition unmet → **Appendix A** row: `Failed Gate: G4` + the named precondition from §2.
- **Do not label config-fixed-authority SSRF exclusions as G4** — that is G3 (effective control), not an exploitability precondition failure.
- Control present but bypassable → keep the finding; describe the bypass in `### Description` and note the partial control under `### Assumptions`.
- Findings from §3 use normal IDs (`VULN-NNN` / `IAC-NNN`) and `Discovery: Checklist`.
