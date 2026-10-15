# Taxonomy master checklist (v4.40)

One row per category. For every **active** language pack, the agent fills the register row for each category with files actually read. `§` = section name inside each `lang-packs/<pack>.md`.

Status values for the Completeness & Residual Risk Register: `Covered (files read: N)` · `Not applicable (no triggers: …)` · `Residual (why)` · `Out of scope (code-only mode)`.

| # | Category | Where the language-specific rules live | Cross-cutting reference | Default status if nothing found |
|---|----------|-----------------------------------------|-------------------------|-------------------------------|
| 1 | Injection (SQL, NoSQL, OS command, LDAP, XPath, EL/OGNL/SpEL, SSTI, code eval, header/CRLF, log injection) | § SQL/ORM, § NoSQL, § Command, § Code/EL/SSTI, Java § NoSQL/LDAP/XPath | `injection-deep-scan.md` | Covered only if every DB/exec/template call site in read files was judged |
| 2 | Authentication & session (login, MFA/OTP, reset, session fixation, cookie flags, remember-me) | § Auth/session/JWT | `jwt-deep-test.md`, `express-auth-audit.md`, `senior-researcher.md` (LOG rows for OTP/reset) | Residual if OTP/reset flows exist but weren't walked |
| 3 | Authorization (BOLA/IDOR, BFLA, mass assignment, missing per-method checks, tenant isolation) | § Auth (route-before-middleware, permission defaults), Python/Ruby/.NET mass-assignment rows | `idor-bola-audit.md`, `per-method-auth-audit.md`, `route_auth_audit.md` | Never PASS without route→auth table |
| 4 | XSS (reflected, stored, DOM, mXSS, template escaping) | § XSS & templates (server packs) + `frontend-browser.md` | `lang-packs/README.md` G0 + Step 4 boundaries | G0 must cite engine escaping default |
| 5 | SSRF (full, partial/path, blind, redirect-follow, DNS rebinding, cloud metadata) | § SSRF | `precision-false-positive-adjudication.md` SSRF-ADJ-01 | Partial-path SSRF reported as SSRF-adjacent, not full |
| 6 | File handling (path traversal, LFI/RFI, upload, Zip Slip, symlinks, temp files) | § Path/file/upload | — | |
| 7 | Deserialization | § Deserialization | — | |
| 8 | Cryptography (weak algorithms, ECB/static IV, randomness, timing compare, key handling) | § Crypto/randomness | — | |
| 9 | Secrets (hardcoded, fallback defaults, committed env/keys, CI secrets, bundle secrets) | § Crypto (hardcoded keys), `frontend-browser.md` § Secrets, `iac-ci.md` | `secrets-patterns.md`, `git-history-secrets-scan.md`, `secret-type-labels.md` | Configs must be **Read**, not only grepped |
| 10 | API security (OWASP API Top 10: BOLA, excessive data exposure, rate limits, unsafe consumption) | § Auth, § DoS (pagination/body limits) | `idor-bola-audit.md`, `protocol-scans-graphql-ws-grpc.md` | |
| 11 | Business logic (price/amount tampering, workflow skip, coupon/refund abuse, negative values) | `frontend-browser.md` § Client-side trust | `business-logic-abuse-checklist.md`, `senior-researcher.md` LOG-01…15 | Residual unless logic walk done per money-moving op |
| 12 | Race conditions / TOCTOU (double spend, check-then-act, missing locks/transactions) | Go § Race conditions, C/C++ § Command/file (TOCTOU) | `business-logic-abuse-checklist.md` | |
| 13 | Input validation (type confusion, qs arrays/objects, length/range, allow-lists) | § Sources (per-framework parsing quirks) | — | |
| 14 | Error handling (stack traces, debug mode, verbose errors, fail-open catch blocks) | § Logging/errors | `frontend-stacktrace-leaks.md` | |
| 15 | Logging & monitoring (PII/token logging, missing audit logs, log injection) | § Logging/errors | `skill-privacy.md` | |
| 16 | Security headers (CSP, HSTS, XFO, nosniff, Referrer-Policy) | § CSRF/CORS/headers; `iac-ci.md` § Web server config | — | G3: check proxy/CDN config before reporting absence |
| 17 | CORS (origin reflection, unanchored regex, null origin, credentials) | § CSRF/CORS/headers | — | |
| 18 | CSRF (cookie-auth state change, SameSite, token checks) | § CSRF/CORS/headers | — | Not applicable for pure bearer-header APIs (cite auth mechanism) |
| 19 | Path / URL handling (open redirect, URL parser confusion, path normalization differences) | § Redirect/header injection, `iac-ci.md` nginx alias rules | — | |
| 20 | HTTP-level (request smuggling, host-header poisoning, response splitting, method override) | § Redirect/header injection, Python § CSRF/CORS (host header) | — | Smuggling usually Residual (needs infra) |
| 21 | XML (XXE, entity expansion, XPath, XML signature wrapping) | § XML | — | |
| 22 | Cloud / Kubernetes | `iac-ci.md` § Kubernetes, § Terraform | `iac-misconfig-scan.md` | Not applicable if no manifests |
| 23 | Dependencies / supply chain | `iac-ci.md` § CI/CD supply-chain row | dedicated SCA scanner outside this skill | **Out of scope**; Residual register only |
| 24 | CI/CD | `iac-ci.md` § CI/CD pipelines | — | Not applicable if no pipeline files |
| 25 | Containers | `iac-ci.md` § Dockerfile, § docker-compose | `container-image-scan.md` (image scan only when requested) | |
| 26 | Memory safety / native | `c-cpp.md`, `rust.md` § Memory safety | — | Not applicable without native code |
| 27 | Mobile | — | `mobile-sast-audit.md`, `deeplink-audit.md` | Not applicable without mobile triggers |
| 28 | Protocol / auth-protocol (OAuth/OIDC flows, SAML, JWT alg confusion, WebSocket auth, gRPC reflection) | § Auth/session/JWT, Java § XML (SAML), Go § Auth (gRPC) | `jwt-deep-test.md`, `protocol-scans-graphql-ws-grpc.md` | |
| 29 | DoS (ReDoS, unbounded body/pagination, zip bombs, slowloris, panics) | § DoS | — | Note engine: Go/Rust `regex` are linear-time (ReDoS FP trap) |
| 30 | Privacy (PII in logs/URLs/responses, over-collection, retention, masking gaps) | § Logging/errors, `frontend-browser.md` § Secrets (PII in URLs) | `skill-privacy.md` | |

## How to use

1. After Step 1 of `lang-packs/README.md`, copy this table into the register with one status cell per active pack.
2. A row is `Covered` only when you name the files you read for it. Pattern zero-hits never count.
3. For categories with no language-specific section (27 mobile, 23 SCA), follow the cross-cutting reference or mark the documented default status.
