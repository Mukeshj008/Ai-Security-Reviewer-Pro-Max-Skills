# Hardcoded Secrets — Full Pattern Catalog (SAST-SECRET)

Run **every** section with `rg` on `[SRC]`. Exclude `node_modules`, `test`, `tests`, `*.md`, `*.example` unless reviewing examples.

**Never report:** `process.env.*`, `YOUR_*_HERE`, `changeme`, `xxx`, test fixtures in `tests/` only.

---

## SAST-SECRET-01 — Cloud & infra keys

```bash
rg -n "AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}" [SRC]
rg -n "AIza[0-9A-Za-z\-_]{35}" [SRC]
rg -n "xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24}" [SRC]
rg -n "dop_v1_[a-f0-9]{64}|glpat-[A-Za-z0-9\-_]{20,}" [SRC]
```

---

## SAST-SECRET-02 — Git / package / CI tokens

```bash
rg -n "gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}" [SRC]
rg -n "npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc" [SRC]
rg -n "x-access-token:[A-Za-z0-9]{20,}" [SRC]
```

---

## SAST-SECRET-03 — Payment & messaging SaaS

```bash
rg -n "sk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|rk_live_" [SRC]
rg -n "SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}" [SRC]
rg -n "AC[a-f0-9]{32}|SK[0-9a-fA-F]{32}" [SRC]
rg -n "key-[0-9a-zA-Z]{32}|mailgun" [SRC]
```

---

## SAST-SECRET-04 — Database & cache URIs with credentials

```bash
rg -n "mongodb(\+srv)?://[^:]+:[^@]+@" [SRC]
rg -n "postgres(ql)?://[^:]+:[^@]+@" [SRC]
rg -n "mysql://[^:]+:[^@]+@" [SRC]
rg -n "redis://[^:]+:[^@]+@" [SRC]
rg -n "amqp://[^:]+:[^@]+@" [SRC]
```

---

## SAST-SECRET-05 — Private keys & certificates

```bash
rg -n "-----BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----" [SRC]
rg -n "-----BEGIN CERTIFICATE-----" [SRC]
rg -n "\.pem['\"]|\.p12['\"]|\.pfx['\"]" [SRC]
```

---

## SAST-SECRET-06 — JWT / session / HMAC / API keys (generic)

```bash
rg -n "(jwt|session|api|auth|hmac|signing)[_-]?(secret|key)\s*[:=]\s*['\"][^'\"]{8,}['\"]" [SRC] -i
rg -n "secretOrKey\s*:\s*['\"][^'\"]+['\"]|jwt\.sign\([^,]+,\s*['\"]" [SRC]
rg -n "Bearer\s+[A-Za-z0-9\-_.~+/]+=*" [SRC]
rg -n "Basic\s+[A-Za-z0-9+/=]{20,}" [SRC]
```

---

## SAST-SECRET-07 — Password literals

```bash
rg -n "password\s*[:=]\s*['\"][^'\"]{4,}['\"]" [SRC] -i
rg -n "passwd\s*[:=]|pwd\s*[:=]\s*['\"]" [SRC] -i
rg -n "credentials\s*[:=]\s*\{|username.*password" [SRC] -i
```

Skip: `password: process.env`, `password: ''`, form field names only.

---

## SAST-SECRET-08 — OAuth / OIDC client secrets

```bash
rg -n "client_secret\s*[:=]\s*['\"][^'\"]+['\"]" [SRC] -i
rg -n "client_id\s*[:=].*client_secret" [SRC] -i
rg -n "refresh_token\s*[:=]\s*['\"][^'\"]{10,}['\"]" [SRC] -i
```

---

## SAST-SECRET-09 — Env fallback to hardcoded (anti-pattern)

```bash
rg -n "process\.env\.\w+\s*\|\|\s*['\"][^'\"]{8,}['\"]" [SRC]
rg -n "getenv\([^)]+\)\s*\|\|\s*['\"][^'\"]+['\"]" [SRC]
rg -n "config\.\w+\s*\|\|\s*['\"](?!localhost)[^'\"]{8,}['\"]" [SRC]
```

**Flag:** Production code falling back to embedded secret when env missing.

---

## SAST-SECRET-10 — Base64 / hex encoded secrets (heuristic)

```bash
rg -n "(secret|key|token|password)\s*[:=]\s*['\"][A-Za-z0-9+/]{32,}={0,2}['\"]" [SRC] -i
rg -n "(secret|key|token)\s*[:=]\s*['\"][0-9a-fA-F]{32,}['\"]" [SRC] -i
```

Manual review — high false positive rate; decode and validate.

---

## SAST-SECRET-11 — Kafka / RMQ / third-party inline creds

```bash
rg -n "sasl\.(username|password)\s*[:=]\s*['\"]" [SRC]
rg -n "connectionString\s*[:=]\s*['\"][^'\"]+['\"]" [SRC]
rg -n "apiKey\s*[:=]\s*['\"][A-Za-z0-9]{16,}['\"]" [SRC] -i
```

---

## Reporting

- Map findings to **SAST-OG-10** / **DEPS-*** if dependency-related.
- Severity: **Critical** for live keys in `src/`; **Medium** for test-only if committed to main branch.
