# Secret Type Labels (SAST-SECRET reporting)

When reporting **hardcoded secrets** (VULN-NNN or SAST-OG-10), you **must** name the **secret type** in plain language — not generic "hardcoded credential".

---

## Mandatory Classification field

Every secret finding **must** include in `### Classification`:

| Attribute | Value |
|-----------|-------|
| **Secret Type** | **[specific label from table below]** |
| **Credential Role** | API key / password / connection string / private key / token |
| **Service / Vendor** | AWS, GitHub, RabbitMQ, MapMyIndia, etc. |

**Example:** `Secret Type: RabbitMQ password (AMQP connection string)` — not "hardcoded secret in config".

---

## Pattern → Secret Type label

Use the **first matching row** after `rg` hit. If vendor is obvious from variable name (`mapmyindia_api_key`, `STRAPI_JWT_SECRET`), use that label even without regex match.

### Cloud & infrastructure

| Pattern / context | Secret Type label |
|-------------------|-------------------|
| `AKIA[0-9A-Z]{16}` | AWS Access Key ID |
| `ASIA[0-9A-Z]{16}` | AWS temporary access key (STS) |
| `aws_secret_access_key`, `AWS_SECRET` | AWS Secret Access Key |
| `AIza[0-9A-Za-z\-_]{35}` | Google API key |
| `ya29\.[0-9A-Za-z\-_]+` | Google OAuth access token |
| `xox[baprs]-` | Slack bot/user token |
| `dop_v1_` | DigitalOcean personal access token |
| `glpat-` | GitLab personal access token |

### Git, CI, package registries

| Pattern / context | Secret Type label |
|-------------------|-------------------|
| `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | GitHub personal/oauth token |
| `github_pat_` | GitHub fine-grained PAT |
| `npm_` | npm access token |
| `pypi-` | PyPI API token |
| `x-access-token:` (git URL) | Git hosting access token (GitHub/GitLab/Bitbucket) |

### Payment & messaging

| Pattern / context | Secret Type label |
|-------------------|-------------------|
| `sk_live_`, `rk_live_` | Stripe live secret key |
| `sk_test_` | Stripe test secret key |
| `SG\.` | SendGrid API key |
| `AC` + 32 hex (Twilio SID context) | Twilio Account SID |
| `SK` + 32 hex (Twilio context) | Twilio API secret |
| `key-` + mailgun context | Mailgun API key |

### Databases & message brokers

| Pattern / context | Secret Type label |
|-------------------|-------------------|
| `mongodb(+srv)?://[^:]+:` | MongoDB connection password |
| `postgres(ql)?://[^:]+:` | PostgreSQL connection password |
| `mysql://[^:]+:` | MySQL connection password |
| `redis://[^:]+:` | Redis password |
| `amqp://[^:]+:` | **RabbitMQ password (AMQP connection string)** |
| `kafka.*sasl.password` | Kafka SASL password |
| `connection_string.*amqp` | RabbitMQ connection string |

### Crypto material

| Pattern / context | Secret Type label |
|-------------------|-------------------|
| `-----BEGIN RSA PRIVATE KEY-----` | RSA private key |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | OpenSSH private key |
| `-----BEGIN EC PRIVATE KEY-----` | EC private key |
| `-----BEGIN ENCRYPTED PRIVATE KEY-----` | Encrypted private key |
| `.pem`, `.p12`, `.pfx` path + inline material | TLS/SSL certificate or PKCS#12 bundle |

### Auth tokens (generic & OAuth)

| Pattern / context | Secret Type label |
|-------------------|-------------------|
| `client_secret` | OAuth client secret |
| `refresh_token` literal | OAuth refresh token |
| `jwt_secret`, `JWT_SECRET`, `secretOrKey` | JWT signing secret |
| `session_secret`, `cookie_secret` | Session/cookie signing secret |
| `hmac.*key`, `signing_key` | HMAC signing key |
| `Bearer [long token]` in source | Bearer API token (identify service from URL/host if possible) |
| `Basic [base64]` in source | HTTP Basic credentials |

### Application / partner APIs (name heuristics)

| Variable / comment / host context | Secret Type label |
|-----------------------------------|-------------------|
| `mapmyindia`, `mmi_`, `mappls` | MapMyIndia / Mappls API key |
| `strapi`, `STRAPI_` | Strapi API token or JWT secret |
| `irctc`, `IRCTC_` | IRCTC partner password/token |
| `agoda`, `AGODA_` | Agoda API key |
| `clevertap`, `CT_` | CleverTap account token |
| `newrelic`, `NR_` | New Relic license key |
| `sendbird`, `firebase`, `fcm` | Respective SaaS API key |
| `apiKey`, `api_key` + vendor comment | **[Vendor] API key** (state vendor) |

### Password literals

| Pattern / context | Secret Type label |
|-------------------|-------------------|
| `password: '...'` in config (non-env) | **Hardcoded application password** |
| `auth.pass`, `basicAuth` user+pass in config | HTTP Basic Auth password |
| `dev.auth.pass` in production config path | Internal ops Basic Auth password |

---

## Description template (secrets)

```
A **[Secret Type]** is hardcoded at line **N** of **[file]**. The value `[REDACTED_PREFIX]…` 
is embedded in **[connection string / config object / source code]** and used at runtime for 
**[authentication to SERVICE / signing / encryption]**. Anyone with repository or config access 
can extract this **[Secret Type]** and [impact: publish to bus / call API / decrypt data].
```

**Never** paste full secret in report — redact to first 4 chars + `…` + last 2 chars, or `[REDACTED]`.

---

## Finding example (classification excerpt)

```markdown
| Secret Type | RabbitMQ password (AMQP connection string) |
| Service / Vendor | RabbitMQ / cross-vertical bus (`bus-event-prod`) |
| Credential Role | Message broker authentication password |
```

---

## Appendix E linkage

Map to **SAST-SECRET-01…11** row that matched. In **Notes** column: `Secret Type: GitHub PAT`.
