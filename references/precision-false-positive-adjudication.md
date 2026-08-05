# Precision False-Positive Adjudication (MANDATORY — Stage 2)

**Purpose:** cut systematic false positives from pattern-only hits **without** silently dropping real bugs. Run **after** Stage 1 candidate generation, **before** assigning a VULN ID.

**Rule:** A hit on an HTTP client sink or a method named `.search()` is **never** sufficient alone for a finding. Apply the class-specific gate below and cite evidence in Appendix A or in `### Assumptions`.

**See also:** `effective-controls-catalogue.md` §1 (controls), §2 (preconditions), `finding-confidence-validation.md` (fail-open), `finding-instances.md` (merge same root cause).

---

## Universal Stage-2 gate (every outbound-HTTP / injection candidate)

Before reporting **any** candidate from `rg` alone:

1. **Read the sink ±40 lines** and the URL/query/body builder — **follow calls until the authority source is identified** (no arbitrary hop cap). If the builder is not reached, mark **Tentative** — never Appendix A without reading it.
2. **Answer authority question (SSRF):** Who controls **scheme + host + port** of the outbound request?
3. **Answer sink-type question (LDAP/XPath/etc.):** Is the sink actually the CWE class claimed, or a namesake API?
4. **Apply G3** — cite neutralizing control at `file:line` or prove absent.
5. **Apply G4** — name unmet/met preconditions from `effective-controls-catalogue.md` §2.
6. **Merge** same root cause → one finding ID with `### Instances` (`finding-instances.md`).

Forbidden: reporting because `restTemplate.exchange`, `fetch(`, `axios(`, or `.search(` appears without steps 1–5.

### G1 + G3 can both pass (normal for SSRF candidates)

Attacker input may influence a **path segment or query value** (G1 passes) while **G3 excludes** because authority is config-fixed. That is a valid **Appendix A via G3** — do not fail G1 with "input does not control URL."

---

## SSRF-ADJ-01 — Outbound HTTP authority analysis (CWE-918)

### Mandatory questions (all must be answered in trace notes)

| # | Question | If YES → |
|---|----------|----------|
| A | Does attacker input supply **scheme, host, or port** (full URL or authority)? | Proceed toward SSRF finding |
| B | Is authority **only** from config (`@Value`, env, properties), constant, or DI bean — **and that config is not writable by attackers** (no unauth admin/API mutating the property)? | **Appendix A (G3)** unless A is also true **or** config is runtime-writable by attacker |
| C | Is dynamic input limited to **path segment** or **query value** on a fixed base, built with **`.pathSegment()` / `.queryParam()`** (not `.path(userInput)`)? | **Appendix A (G3)** if safe encoder (below) |
| D | Is URL built via **string concat** of base + user text (not `pathSegment` / bound query)? | **Keep candidate** — concat can inject `@`, `#`, `//`, `%2f` |
| E | Does code call `URI.create(userInput)`, `new URL(userInput)`, `fromUriString(userInput)`, `RestTemplate.getForEntity(userUrl, …)`, or **Feign `@Url` on user input**? | **Keep candidate** |
| F | Fixed authority but **trusted backend returns 302/301 to attacker URL** and client follows redirects (default RestTemplate/WebClient)? | **Tentative or Low** — document redirect chain; not Appendix A unless redirects disabled/re-validated per hop |

### Effective patterns → Appendix A (cite builder `file:line`; failed gate **G3**)

| Pattern | Languages | Why safe (SSRF authority) |
|---------|-----------|---------------------------|
| `configBase + FIXED_ENDPOINT_CONSTANT` | Java, any | No user input in URL |
| `UriComponentsBuilder.fromHttpUrl(configBase).pathSegment(userPart)` | Java Spring | Encodes segment; cannot change host |
| `UriComponentsBuilder.fromHttpUrl(configBase).path("/fixed/").pathSegment(domain)` | Java Spring | Same — domain cannot become authority |
| `UriComponentsBuilder.fromHttpUrl(configBase).queryParam("id", sessionId)` | Java Spring | Query values cannot retarget host |
| `WebClient.builder().baseUrl(configBase).build().get().uri("/fixed/{id}", id)` | Java Spring | Template on fixed base |
| `HttpClient.newHttpClient()` + `URI.create(configBase + fixedPath)` where **fixedPath has no user concat** | Java 11+ | Authority fixed |
| `axios.create({ baseURL: process.env.API_BASE })` + relative path only | Node | baseURL from env |
| Post-DNS host allowlist with redirect re-validation per hop | Any | §1 SSRF effective control |

### NOT effective (keep finding)

| Pattern | Why |
|---------|-----|
| `baseUrl + "/" + domain` string concat | `evil.com@trusted/` or traversal |
| `UriComponentsBuilder.path(userControlled)` | Injects `/` and `..` into path — not equivalent to `pathSegment()`; may reach unintended paths (separate authz issue on trusted host) |
| Blocklist `localhost` / `169.254.169.254` only | Bypass via decimal IP, DNS rebinding |
| "Private subnet" as answer to auth/TLS questions | Network placement ≠ SSRF control |
| User URL passed to `RestTemplate.exchange(url, …)` | Classic SSRF |
| **Spring Cloud OpenFeign** `@GetMapping` + **`@Url String url`** (or dynamic URI param) with user-controlled `url` | Full URL under attacker control |
| Redirect following on client without per-hop re-validation | Open redirect on trusted server → SSRF chain → **Tentative/Low** (SSRF-ADJ-01-F) |

### Java Spring — mandatory follow-up when SAST-OG-26 hits

```bash
# Find outbound HTTP sinks (candidates only)
rg -n 'restTemplate\.(exchange|getForEntity|getForObject|postForEntity|execute)|WebClient|HttpClient\.|OkHttpClient|\.retrieve\(\)|@Url\s' --glob '**/*.{java,kt}'
rg -n 'FeignClient|@RequestLine|@GetMapping.*@Url|@PostMapping.*@Url' --glob '**/*.{java,kt}'

# For each hit: trace URL variable — do NOT report from this rg alone
rg -n 'buildUrl|UriComponentsBuilder|fromHttpUrl|fromUriString|new URL\(|URI\.create|@Value.*\.url|baseUrl|base\.url' --glob '**/*.{java,kt}' -B0 -A0
```

**Adjudication workflow:**

1. Identify the variable passed as URL to `exchange`/`getForEntity`/Feign `@Url`/etc.
2. Jump to its builder (`buildUrl`, private helper, inline) — trace until authority source found.
3. If builder uses **config field + pathSegment/queryParam only** (not `.path(userInput)`) → **Appendix A (SSRF-ADJ-01, failed gate G3)**.
4. If builder concatenates user input into host/authority or passes full user URL → **Finding**.
5. If authority fixed but redirects unvalidated → **Tentative/Low** (question F).
6. Multiple call sites sharing one safe `buildUrl()` → **one VULN ID, N instances**.

### Worked false positive (Spring RestTemplate + config base)

```
restTemplate.exchange(buildUrl(domain), …)   // sink
  → buildUrl reads service.executor.url (@Value)   // authority fixed (G3 control)
  → .pathSegment(domain) — NOT .path(domain)        // user cannot set host
G1: PASS (domain is attacker-influenced path segment)
G3: PASS — effective control (§1 SSRF fixed base + pathSegment)
Verdict: Appendix A — SSRF-ADJ-01, failed gate G3 (config-fixed authority; cite buildUrl file:line)
```

---

## LDAP-ADJ-01 — `.search()` and LDAP sink disambiguation (CWE-90)

### Problem

Broad `rg` patterns match **any** `.search(` call — JMESPath, Elasticsearch, Java streams, Python `re.search`, file search APIs — not LDAP.

### Mandatory LDAP sink evidence (require ≥1 in **file or callee chain** before CWE-90)

Trace ≤3 hops from the `.search(` call site into callees if needed.

```bash
# Real LDAP context (sink file or callee chain must use these)
rg -n 'javax\.naming|InitialDirContext|LdapContext|DirContext|SpringLdap|LdapTemplate|ldap\.|createClient\(.*ldap|UnboundId|LDAPConnection' --glob '**/*.{java,kt,js,ts,py,rb,cs}'
```

Plus **attacker-controlled data in LDAP filter/DN** with string concat/template — not bound parameters.

### Known false-positive APIs (Appendix A when no LDAP context in file **or callee chain**)

| API | Library | Actual operation |
|-----|---------|------------------|
| `Expression.search(inputNode)` | `io.burt.jmespath` | JSON query |
| `expression.search(json)` | JMESPath | JSON query |
| `index.search(query)` | Elasticsearch Java API | Search index |
| `re.search(pattern, text)` | Python | Regex |
| `Array.prototype.search` / `str.search()` | JS/Python | Built-in search |
| `client.search()` with ES transport | Elasticsearch | Not LDAP |

### Safer SAST-OG-18 candidate query

Use **LDAP context + dynamic filter** — not bare `.search(`:

```bash
rg -n 'LdapTemplate|InitialDirContext|DirContext|ldapTemplate|\.search\([^)]*(\+|String\.format|filter\s*=)' --glob '**/*.{java,kt,js,ts,py,rb,cs}'
rg -n 'filter\s*=\s*['\''"].*\+.*['\''"]|\(\&\(.*\+.*\)\)' --glob '**/*.{java,kt,js,ts,py,rb,cs}'
```

When hit is only `jmespath` / `Expression.search` / `re.search` with **no LDAP context in file or callee chain** → **Appendix A (LDAP-ADJ-01, failed gate G3 — wrong sink type)**.

---

## INJ-ADJ-01 — SQLi on ORM / prepared APIs

**Mandatory when:** SAST-OG-25 / SQL concat / `createNativeQuery` candidates.

Do not report SQLi when:

- JPA `@Query` with `:named` params + `@Param`
- `PreparedStatement` + `setString` / `setLong` on all placeholders
- Spring Data derived query methods
- Django ORM `filter(field=value)` with no raw SQL

**Keep finding:** `createNativeQuery("... "+ user)`, `@Query` with string concat, MyBatis `${}` (not `#{}`).

---

## DESER-ADJ-01 — JSON to typed DTO

**Mandatory when:** `readValue` / `parseObject` / `JSON.parse` candidates flagged as deserialization RCE.

`objectMapper.readValue(json, MyDto.class)` / `JSON.parseObject(json, MyDto.class)` is **not** Java deserialization RCE by itself.

**Keep finding:** `ObjectInputStream.readObject()`, `enableDefaultTyping`, `pickle.loads`, `yaml.load` (unsafe), XStream from untrusted XML.

---

## XXE-ADJ-01 — Typed JAXB/unmarshal alone

**Mandatory when:** XML parse / JAXB candidates.

See `effective-controls-catalogue.md` §1 XXE — typed unmarshal is **not** a control. Do not use DESER-ADJ-01 reasoning for XML.

---

## LOG-ADJ-01 — Structured logging / format strings

**Mandatory when:** SAST-OG-21 / logger secret-leak candidates.

`logger.info("user={}", userId)` is not a secret leak.

**Keep finding:** `logger.info("password=" + password)`, `String.format("Bearer %s", token)` in logs, curl debug with Authorization header.

---

## AUTH-ADJ-01 — Class-level annotation ≠ method protected

**Mandatory when:** route auth / `@PreAuthorize` / interceptor candidates.

Spring custom interceptors often check **method** annotations only. Do not Appendix-A an unauth method because `@PreAuthorize` exists on the **class**. Run `per-method-auth-audit.md`.

---

## Candidate ledger terminal statuses (precision)

| Outcome | When |
|---------|------|
| **Finding** | G1–G5 pass; authority/sink type confirmed |
| **Tentative** | Builder not fully traced; config trust unknown; redirect chain plausible (SSRF-ADJ-01-F) |
| **Appendix A** | G3 control present (cite `file:line`) **or** G4 precondition demonstrably unmet — **name the gate** (e.g. SSRF-ADJ-01, LDAP-ADJ-01) |
| **N/A** | No web/outbound surface in scope |

---

## Reporting hooks

- Tag checklist rows adjudicated with `[Adj: SSRF-ADJ-01]` in internal scan log Notes.
- Appendix A table must include **Failed Gate** column: `G3` / `G4` + adjudication ID (`SSRF-ADJ-01`, `LDAP-ADJ-01`, …).
- Scan Attestation Summary: `Precision adjudication: all *-ADJ-* gates applied (v4.32.1+)`.
- Do **not** publish "zero SSRF" — publish "N candidates adjudicated; M excluded per SSRF-ADJ-01 with cited builders".

---

## Final compliance (add to model-proof gate)

- [ ] Every SAST-OG-26 hit has documented **authority analysis** (who controls host/scheme/port).
- [ ] Every SAST-OG-18 hit has **LDAP sink confirmation in file or callee chain** or LDAP-ADJ-01 exclusion.
- [ ] **INJ/DESER/LOG/AUTH/XXE-ADJ-*** applied when matching SAST candidates exist.
- [ ] Same safe `buildUrl()` / base-URL helper merged into one finding with instances, not N duplicate VULN IDs.
- [ ] Builder not traced → **Tentative**, not Appendix A.
