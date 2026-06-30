# Platform Security Checklist — Skill Coverage Map

Maps the **API / Web / Android / iOS / Cross-platform / Manual** checklist to ai-security-reviewer checks.  
Use for **agent attestation** (internal). **v4.15:** Optional **Appendix I** in user report still supported (HTML suppresses); prefer platform gaps noted in **Scan Attestation Summary** N/A rows.

**New deep-dive refs (v4.15):** `idor-bola-audit.md`, `jwt-deep-test.md`, `business-logic-abuse-checklist.md`, `mobile-sast-manifest.md`, `protocol-scans-graphql-ws-grpc.md`.

**Legend:** Full = automated in skill · Partial = supplemental rg / DAST sample · Manual = G1–G5 + human · Gap = not in skill yet · N/A = stack not present

---

## 1. API Security (SAST + DAST)

### Authentication

| Check | SAST | DAST | Skill coverage | Check IDs |
|-------|------|------|----------------|-----------|
| Hardcoded API keys | ✓ | — | **Full** | SAST-SECRET-06, SAST-OG-10 |
| Hardcoded JWT secrets | ✓ | — | **Full** | SAST-SECRET-08 |
| Weak JWT alg (None/HS256) | ✓ | — | **Partial** | extended §3.8 + manual decode |
| Missing token expiry | ✓ | — | **Partial** | manual-code-review |
| Weak password storage | ✓ | — | **Partial** | SAST-OG-16, extended §3.4 |
| Static service credentials | ✓ | — | **Full** | SAST-SECRET-07 |
| Credentials in source | ✓ | — | **Full** | SAST-SECRET-01…11 |
| Missing MFA | — | ✓ | **Manual** | route auth + manual |
| Insecure OAuth flow | ✓ | ✓ | **Partial** | SAST-OG-22, burp open redirect |
| Missing refresh token validation | ✓ | ✓ | **Partial** | manual + DAST-AUTH-PROBE |
| JWT tampering | — | ✓ | **Partial** | Burp PoC templates; not auto-fuzz all claims |
| Expired token acceptance | — | ✓ | **Partial** | DAST manual |
| Signature bypass | — | ✓ | **Gap** | Document Manual in Appendix I |
| Token replay | — | ✓ | **Partial** | manual |
| Session fixation | ✓ | ✓ | **Full** | SAST-EXT-04 |
| Brute force login | — | ✓ | **Manual** | DAST + manual |
| Weak password policy | — | ✓ | **Manual** | extended §3.5 |
| MFA bypass | — | ✓ | **Manual** | — |
| Password reset flaws | — | ✓ | **Manual** | — |
| Account enumeration | — | ✓ | **Partial** | DAST error diff manual |

### Authorization

| Check | SAST | DAST | Skill coverage | Check IDs |
|-------|------|------|----------------|-----------|
| Missing ownership validation | ✓ | ✓ | **Partial** | route_auth_audit, extended §4 IDOR |
| Missing RBAC | ✓ | ✓ | **Partial** | SAST-OG-12, route auth |
| Missing ABAC | ✓ | — | **Manual** | — |
| Insecure role comparison | ✓ | — | **Partial** | rg + manual |
| Client-side authz | ✓ | ✓ | **Partial** | SAST-OG-12 |
| BOLA/IDOR | — | ✓ | **Partial** | extended §4, Burp |
| BFLA | — | ✓ | **Partial** | route auth |
| Horizontal/vertical priv esc | — | ✓ | **Partial** | DAST manual |
| Forced browsing | — | ✓ | **Partial** | AUTH audit |
| Admin endpoint access | — | ✓ | **Partial** | Burp on discovered hosts |

### Input validation

| Check | SAST | DAST | Skill coverage |
|-------|------|------|----------------|
| SQLi / NoSQL / LDAP / XPath / OS cmd / CRLF / SSTI / XML / deserialization / ReDoS | ✓ | ✓ | **Full/Partial** | SAST-OG-03,18,25,28, INJ-*, extended §1 |

### Sensitive data

| Check | SAST | DAST | Skill coverage |
|-------|------|------|----------------|
| Logging secrets / hardcoded secrets / weak crypto / missing encryption | ✓ | — | **Full/Partial** | SAST-SECRET, SAST-OG-07, LEAK-* |
| Sensitive fields in response / PAN / JWT exposure / verbose errors / stack traces | — | ✓ | **Full/Partial** | SAST-LEAK-*, DAST manual |

### API-specific

| Check | SAST | DAST | Skill coverage |
|-------|------|------|----------------|
| Rate limiting logic | ✓ | ✓ | **Partial** | manual + DAST |
| API version validation | ✓ | — | **Gap** | Manual |
| Mass assignment / schema validation / pagination | ✓ | ✓ | **Partial** | SAST-OG-19, extended |
| GraphQL introspection/batching | — | ✓ | **Gap** | Manual when GraphQL present |
| Swagger/Actuator exposure | — | ✓ | **Partial** | iac + burp host discovery |

### SSRF

| Check | SAST | DAST | Skill coverage |
|-------|------|------|----------------|
| User-controlled URL fetch / missing allowlist | ✓ | ✓ | **Full/Partial** | SAST-OG-26, extended §7, Burp SSRF templates |

### Misconfiguration

| Check | SAST | DAST | Skill coverage |
|-------|------|------|----------------|
| Debug enabled / default creds / missing middleware | ✓ | ✓ | **Full/Partial** | SAST-OG-01, IAC-*, DAST headers |

---

## 2. Web Application

| Domain | Skill coverage | Notes |
|--------|----------------|-------|
| Auth (CSRF, session, brute force) | **Full/Partial** | SAST-OG-05, EXT-04, route auth |
| Authz / IDOR | **Partial** | extended §4 |
| Injection (XSS/SQLi/CMD/SSTI) | **Full** | INJ-*, OG-06,25,03 |
| File upload | **Partial** | extended §5 — run when upload handlers exist |
| Security headers (CSP, HSTS, XFO) | **Partial** | TAX-CONFIG, DAST header probe manual |
| Business logic | **Manual** | TAX-LOGIC — not reliable via SAST/DAST alone |

---

## 3. Android / 4. iOS

| Domain | Skill coverage | Notes |
|--------|----------------|-------|
| Storage / crypto / exported components / WebView / TLS | **N/A default** | Run when `android/` or `ios/` tree detected |
| TAX-MOBILE | **Partial** | extended-category-scans §19 mobile blocks |
| MITM / Frida / runtime | **Manual/DAST** | Not automated in agent skill |

**Gap:** No dedicated SAST-ANDROID-* / SAST-IOS-* manifest rows yet — use extended §19 + manual when mobile present.

---

## 5. Cross-platform (all apps)

| Check | Skill coverage | Check IDs |
|-------|----------------|-----------|
| Secrets scanning | **Full** | SAST-SECRET-01…11 |
| Dependency CVE / OSV | **Full** | SCA-OSV-01…05, CVE-* |
| IaC misconfig | **Full** | IAC-* |
| Container CVE | **Partial** | IAC-DOCKER when Dockerfile present |
| CI/CD secrets | **Partial** | IAC-CI-*, SAST-SECRET |
| Rate limiting / DoS / smuggling / cache poison / CORS / clickjacking | **Partial/Manual** | EXT-02 smuggling, TAX-CONFIG, DAST manual |

---

## 6. Manual-only (document in Appendix I)

Business logic, fraud, race conditions, payment bypass, OTP bypass, subscription abuse, authorization chaining, inventory abuse — **Manual** per TAX-LOGIC. Skill records PASS/FINDING after manual review, not automated rg alone.

---

## Appendix I template (add to reports)

| Checklist group | Items | Full | Partial | Manual | Gap | N/A (this repo) |
|-----------------|-------|------|---------|--------|-----|-----------------|
| API Auth | 19 | 6 | 8 | 4 | 1 | — |
| API Authz | 10 | 0 | 8 | 2 | 0 | — |
| Web Injection | 10 | 8 | 2 | 0 | 0 | varies |
| Android | 20+ | 0 | 0 | 0 | 0 | N/A static site |
| iOS | 15+ | 0 | 0 | 0 | 0 | N/A |
| Manual-only | 12 | — | — | 12 | 0 | documented |

Fill per project after Phase 1f + stack detection.
