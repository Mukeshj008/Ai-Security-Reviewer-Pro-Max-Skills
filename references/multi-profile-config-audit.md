# Multi-Profile Configuration Audit (MANDATORY)

**Purpose:** prevent the "I only read `application.yml`" silent miss. Production credentials, kafka SASL passwords, OAuth client secrets, and TLS keystore passwords frequently live **only** in environment-specific profile files. Sampling one profile is not enough.

**Trigger:** any of these file types is present in any module:

- `application.{yml,yaml,properties}`
- `application-*.{yml,yaml,properties}`
- `bootstrap*.{yml,yaml,properties}`
- `config/*.{yml,yaml,properties,env,toml,conf}`
- `.env`, `.env.*`
- `appsettings*.json` (ASP.NET)
- `settings*.py` (Django)
- `config*.{js,ts,json}` (Node)

---

## Step 1 — Enumerate every config file in every module

```bash
rg --files \
  -g 'application*.{yml,yaml,properties}' \
  -g 'bootstrap*.{yml,yaml,properties}' \
  -g 'appsettings*.json' \
  -g 'settings*.py' \
  -g '.env*' \
  -g '*.{conf,toml,ini}' \
  -g '!**/node_modules/**' -g '!**/build/**' -g '!**/target/**' \
  -g '!**/test/**' \
  .
```

Record the list in agent working notes as `config_files.txt`.

**Mandatory:** `wc -l config_files.txt` ≥ 1, and the audit must read **every** file in the list, not a subset.

---

## Step 2 — Per-file secret pattern scan

For each file in `config_files.txt`, run the catalog from `secrets-patterns.md` plus these profile-config-specific patterns:

```bash
# Database connection passwords (covers MySQL / Postgres / Mongo / Oracle / MSSQL)
rg -n 'password[:= ]+["'\'']?[^"$\s{][^\s"'\'']{2,}' <file> -i

# JDBC/MongoDB URIs with embedded creds
rg -n '(jdbc|mongodb(\+srv)?|postgres(ql)?|mysql|sqlserver|oracle):.*://[^/]*:[^@]+@' <file>

# OAuth / OIDC client secrets
rg -n 'client[_-]?secret[:= ]+["'\'']?[A-Za-z0-9\-_./+=]{8,}' <file> -i

# JWT / signing / HMAC secrets
rg -n '(jwt|signing|hmac|app|api|session)[_-]?(secret|key)[:= ]+["'\'']?[A-Za-z0-9\-_./+=]{8,}' <file> -i

# Kafka / RabbitMQ / RMQ creds
rg -n '(sasl|broker|kafka|rmq|rabbit).*?(password|user)[:= ]+["'\'']?[^"\s{]{2,}' <file> -i

# TLS keystore / truststore passwords
rg -n '(key|trust)-?store-?password[:= ]+["'\'']?[^"\s{]{2,}' <file> -i
rg -n 'ssl-key-?store-?password[:= ]+' <file> -i

# Cloud provider key/secrets
rg -n 'aws[_-]?(access|secret)[_-]?(key|id)[:= ]' <file> -i
rg -n '(azure|gcp|gcs|firebase)[_-]?(key|secret|token)[:= ]' <file> -i

# Internal admin tokens baked into config (HIGH risk — controllers may use them)
rg -n '(admin|service|internal)[_-]?(authorization|token|secret)[:= ]+["'\'']?[A-Za-z0-9\-_./+=]{8,}' <file> -i
```

**Skip patterns** (do not report):
- `password: ''`, `password: changeme`, `password: <SECRET>`, `password: ${...}`, `password: !env`, `password: process.env.X`
- Lines commented with `#`/`//`
- Files under `**/test/**`, `**/fixtures/**`

---

## Step 3 — Cross-profile diff (find secret reuse)

The same DB password reused across multiple environments is a separate **High** finding (compromise of any environment compromises all). Generate a quick diff:

```bash
rg -n 'password[:= ]' <config_files> | sort -u | awk -F: '{print $NF}' | sort | uniq -c | sort -rn | head
```

Any password value appearing in **≥2 profile files** = **High** finding `LEAK-NNN — Credential reuse across environments`.

---

## Step 4 — Map each secret to a finding row

Build a per-config-file table in agent notes, then merge into the LEAK-001 finding:

```markdown
| File | Line | Secret Type | Value (redacted) | Profile | Service |
|------|------|-------------|------------------|---------|---------|
| api/src/main/resources/application-uat.yml | 145 | OAuth client secret | ifUJTbL6...wub5 | uat | admin client |
| api/src/main/resources/application-pre-prod-write.yml | 649 | OAuth client secret | ifUJTbL6...wub5 | pre-prod | admin client (REUSED) |
| cache-consumer/src/main/resources/application.yml | 68 | MySQL password | 2XDsdN... | default | ums_dev DB |
| migration-service/src/main/resources/application-dev-local.yml | 16 | MySQL password | qnZC-CIF...K*RB | dev-local | cif DB |
```

This table is the **source of truth** for LEAK-001. The finding must cite each `file:line`, not just a representative sample.

---

## Step 5 — Completion gate

In the **Scan Attestation Summary**, publish:

```markdown
### Config / Profile Audit
| Total config files | N |
| Config files scanned | N |
| Files with hardcoded secrets | M |
| Distinct secret values | X |
| Cross-profile reused secrets | Y |
```

`generate_html_report.py --strict` should fail if `Config files scanned < Total config files`.

---

## Why this matters (lessons from past misses)

| Past miss | Cause | This step's prevention |
|-----------|-------|------------------------|
| Earlier scan flagged secrets only in `application-uat.yml`, missed the same passwords in `application-pre-prod-write.yml` and 6 other modules | Sampled one profile | Step 1 enumeration + Step 4 per-file table |
| `ssl-key-store-password` in keystore config never flagged | Pattern not in generic secrets catalog | Step 2 keystore-specific regex |
| `accountClosureProperties.authorization` (an admin Bearer token baked in YAML) never flagged → controller used it to bypass auth | "admin-token-in-config" pattern absent | Step 2 internal-admin-token regex + cross-reference with controller code |
| Per-environment credential reuse went unflagged | No cross-file diff | Step 3 |
