# Spring Boot Actuator — Sensitive Endpoints Audit (MANDATORY when actuator present)

**Purpose:** report **only sensitive** actuator/management endpoints — not every ops URL. `/actuator/health` for K8s probes and default `/info` are **not** standalone VULN/IAC findings unless they leak secrets (`show-details: always` + sensitive health contributors, or custom `info.*` properties).

**Trigger:**

```bash
rg -l "management\.endpoints|spring\.boot\.admin|/actuator" --glob '*.{yml,yaml,properties,java}' --glob '!**/target/**' . | head -20
```

If no actuator/management config → mark **N/A** in attestation.

---

## Step 1 — Read exposure configuration (mandatory)

Read the **effective** management config (base + active profiles):

```bash
rg -n "management\.|endpoints\.|endpoint\." --glob '**/application*.{yml,yaml,properties}' --glob '**/bootstrap*.{yml,yaml,properties}'
rg -n "include:|exclude:|base-path:|show-details:|show-components:" --glob '**/application*.{yml,yaml,properties}'
```

Record:

| Field | Value |
|-------|-------|
| `management.endpoints.web.exposure.include` | list or `*` |
| `management.endpoints.web.exposure.exclude` | if any |
| `management.endpoints.web.base-path` | default `/actuator` |
| `management.endpoint.health.show-details` | never / when-authorized / always |
| `management.server.port` | separate management port? |
| Spring Security on `/actuator/**` | permitAll / authenticated / disabled |

---

## Step 2 — Sensitive vs probe-safe taxonomy

### Sensitive — **FINDING when exposed without authentication**

| Endpoint | Risk | Typical impact |
|----------|------|----------------|
| `env` | **Critical** | Secrets, tokens, datasource URLs in environment |
| `configprops` | **High** | Bound `@ConfigurationProperties`, may include secrets |
| `heapdump` | **Critical** | Full memory dump — tokens/keys in heap |
| `threaddump` | **High** | Stack traces, internal paths |
| `shutdown` | **Critical** | Remote JVM shutdown |
| `loggers` (+ POST) | **High** | Log level change; may enable debug secret leakage |
| `beans` | **Medium** | Internal architecture, sometimes secrets in bean props |
| `mappings` | **Medium** | Full route map — aids auth bypass |
| `flyway` / `liquibase` | **Medium** | Schema/SQL exposure |
| `sessions` | **High** | Session IDs if session store exposed |
| `httptrace` / `httpexchanges` | **High** | Recent request headers/cookies |
| `jolokia` | **Critical** | JMX over HTTP — RCE class |
| `auditevents` | **Medium** | User/action metadata |
| `caches` / `scheduledtasks` / `quartz` | **Medium** | Ops intel |
| `sbom` | **Medium** | Dependency intel (not a substitute for SCA) |

When `include: "*"` (or `include: health,env,heapdump,…` lists any row above) **and** app/management security does not require auth → **VULN-NNN or IAC-NNN** listing **only the sensitive endpoints in scope**, not `/health`.

### Probe-safe — **no standalone VULN/IAC** (AUTH Low instance OK)

| Endpoint | When acceptable | Do not inflate |
|----------|-----------------|----------------|
| `health` | `show-details: never` or `when-authorized`; no custom secret contributors | K8s liveness/readiness — **Low** AUTH instance if `permitAll`, not High VULN |
| `info` | Default build/git info only; no custom secret `info.*` keys | Monitoring metadata |
| `prometheus` / `metrics` | Often scraped in-cluster; no auth on metrics port is common | **Medium** only if labels expose PII/secrets or endpoint is Internet-facing — else Appendix A or residual |

### Custom / legacy

```bash
rg -n "@Endpoint|@ReadOperation|@WriteOperation|WebEndpoint|@Controller.*actuator" --glob '*.{java,kt}'
```

Any custom actuator extension that returns secrets or allows state change → treat as **Sensitive**.

---

## Step 3 — Finding rules (precision)

| Config observed | Report |
|-----------------|--------|
| `include: "*"` without management auth | **FINDING** — title: *Sensitive Spring Actuator endpoints exposed*; **Instances** table lists each **sensitive** endpoint class (env, heapdump, …), **not** health/info |
| Explicit sensitive list (e.g. `env,heapdump`) | **FINDING** — one ID, instances per endpoint |
| `include: health` (or `health,info`) only | **No VULN/IAC** for actuator; optional **AUTH-NNN Inst** `/actuator/health` **Low** if permitAll |
| `include: health,prometheus,metrics` only | **No High VULN**; prometheus **Medium** only if Internet-facing or labels leak secrets — else Appendix A |
| Sensitive endpoints exposed **but** Spring Security requires `ROLE_ACTUATOR` / mTLS on management port | **Appendix A** — cite SecurityFilterChain / `management.server.port` + NetworkPolicy evidence |
| Gateway blocks `/actuator/env` but app exposes it | **Still FINDING** at app layer — gateway not in repo does not remove VULN (forbidden exclusion) |

**Forbidden finding titles:** "Actuator exposes all endpoints" without naming **which sensitive** endpoints matter. **Forbidden:** Critical/High severity driven solely by unauthenticated `/actuator/health`.

---

## Step 4 — AUTH vs VULN dedup

| Surface | ID | Notes |
|---------|-----|-------|
| Missing auth on **money/API routes** | AUTH-NNN | As today |
| Missing auth on **`/actuator/health` only** | AUTH-NNN **instance**, Severity **Low** | Does not create separate VULN |
| **Sensitive** actuator exposed (env, heapdump, …) | **VULN-NNN or IAC-NNN** | List sensitive endpoints in Description + Instances |
| Both `permitAll` + `include: *` | AUTH instances for API routes + **one VULN** for sensitive actuator set | Do **not** duplicate env/heapdump as both AUTH High and VULN |

Appendix D: for actuator, prefer **one row per sensitive endpoint** linked to VULN Inst, plus optional **Low** row for `/actuator/health` under AUTH.

---

## Step 5 — rg helpers

```bash
rg -n "exposure:\s*\n\s*include:\s*[\"']?\*" --glob '**/application*.{yml,yaml}'
rg -n "include:\s*.*\b(env|heapdump|shutdown|configprops|threaddump|loggers|beans|mappings|flyway|liquibase|sessions|jolokia)\b" --glob '**/application*.{yml,yaml,properties}'
rg -n "show-details:\s*(always|when_authorized|when-authorized)" --glob '**/application*.{yml,yaml,properties}'
rg -n "management\.server\.|endpoints\.web\.base-path|spring\.security.*actuator" --glob '**/*.{yml,yaml,properties,java}'
```

---

## Step 6 — Reporting template

```markdown
## [High] [VULN-NNN] Sensitive Spring Actuator endpoints exposed without authentication

**Classification:** CWE-1188 / CWE-200. `Discovery: Checklist`.

### Instances

| Inst | Endpoint | Config source | Sensitive because |
|------|----------|---------------|-------------------|
| 1 | `/actuator/env` | `application.yml:65 include: "*"` | Environment variables / secrets |
| 2 | `/actuator/heapdump` | same | Memory dump |
| … | … | … | … |

**Not in scope for this finding:** `/actuator/health` (probe-safe, `show-details: never`) — listed as AUTH-NNN Inst-N Low only.

### Burp Suite PoC
GET /actuator/env HTTP/1.1 …
```

---

## Attestation block

```markdown
### Actuator Sensitive Endpoints Audit
| Trigger matched | Yes / No |
| Exposure include | `*` / list / health-only |
| Sensitive endpoints in effective exposure | env, heapdump, … (list) |
| Probe-safe only | Yes → no VULN / No |
| FINDING ID | VULN-… / none |
| Health-only AUTH instance | AUTH-… Inst (Low) / N/A |
```
