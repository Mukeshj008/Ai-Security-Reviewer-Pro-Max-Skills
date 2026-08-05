# Per-Method Auth Audit (MANDATORY — not per-controller)

**Purpose:** prevent the "controller has `@ValidateAuthorization` somewhere, so all its endpoints look protected" silent miss. A single controller can mix authenticated v4 endpoints with unauthenticated v1/v2/v3 variants — counting annotations per **file** hides this.

**Rule:** every HTTP endpoint method must be evaluated **individually**, not by file-level annotation presence.

This reference supplements `route_auth_audit.md` with method-level granularity for **annotation-based frameworks** (Spring, Spring Security, Quarkus, ASP.NET, NestJS, FastAPI dependencies).

---

## Step 1 — Inventory every endpoint method (not file)

### Spring / Java

```bash
# List every endpoint method with its mapping and the line just above it
rg -n -B 6 '@(Get|Post|Put|Delete|Patch|Request)Mapping' --type java \
  | rg -v '^\s*\*'   # drop javadoc noise
```

Build a worksheet (one row per **method**):

```
| Controller file | Method name | HTTP method | Path | Auth annotations on method |
|-----------------|-------------|-------------|------|---------------------------|
| SignInOTPController.java | signinValidateOtp | POST | /signin/validateOtp | (none) |
| SignInOTPController.java | v4SigninValidateOtpSv1 | POST | /signin/validateOtp/sv1 | @ClientPermission |
| ... | ... | ... | ... | ... |
```

### Node / Express

```bash
rg -n 'router\.(get|post|put|delete|patch)\(' --type js --type ts
```

For each match, **read** ±3 lines to capture the entire middleware chain. Express middleware chains are positional — record each handler in the chain, not just the last one.

### Python / FastAPI / Flask

```bash
rg -n -B 4 '@(app|router)\.(get|post|put|delete|patch)\(|@app\.route' --type py
```

FastAPI dependencies appear in the function signature (`Depends(verify_token)`) — read the whole signature.

### ASP.NET

```bash
rg -n -B 6 '\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\]' --type cs
```

Look for `[Authorize]` and `[AllowAnonymous]` on the same method.

---

## Step 2 — Classify each method

For each row in the worksheet, mark `Auth status` as one of:

| Status | Criterion |
|--------|-----------|
| **Authenticated** | At least one effective auth/authz annotation directly on the method (or on the containing class **if** the class-level annotation actually fires for unannotated methods — read the interceptor to confirm) |
| **Auth via gateway (claimed)** | No annotation in code; relies on upstream gateway/edge populating `AUTH_STATUS`, `AUTH_DETAILS`, `X-Userinfo`, etc. → must be **verified**, not assumed (see Step 4) |
| **Inline soft check** | Reads a header inside method body (`if request.getHeader("X-Auth-Status").equals("OK")`) but does not call a verified auth library — **report as Tentative AUTH-NNN** |
| **Unauthenticated** | No annotation, no inline check |

---

## Step 3 — Apply method-level grouping rules

| Pattern | Action |
|---------|--------|
| Controller class has annotation **and** every method inherits → annotated by framework | OK (verify with framework docs) |
| Some methods annotated, others not (mixed) | **Each unannotated method is a separate AUTH-NNN candidate** — do not let the annotated peer mask it |
| `V1`/`V2`/`V3` variant unannotated, `V4_SV1` annotated | Highly suspicious — typical refactor leftover. **Report v1/v2/v3** as AUTH candidates |
| `*_INTERNAL`, `*Intenal`, `internal*` paths | Report as AUTH candidate **and** an architectural risk: internal-only routes mounted on the same servlet as public routes |
| Method named `forceX`, `adminX`, `resetX`, `flushX`, `reloadX` without annotation | High-risk admin operation — promote to **Critical** AUTH-NNN |

---

## Step 4 — "Trust the gateway" → must be **verified**, not assumed

Do **not** auto-dismiss unauthenticated handlers with "gateway in front of it" reasoning. The gap analysis showed that a single such blanket exclusion let 10+ real findings slip through.

You may only mark a finding as `Not Verified — gateway enforces auth` when **all** are true:

1. The repo contains an explicit ingress/gateway manifest that proves the route is gated (Kong/Apigee/NGINX/Spring Cloud Gateway YAML, `RouteDefinition`, helm chart) — **and** you cited its file:line.
2. The same gateway manifest does **not** route directly to the service pod IP or expose it on internal networks.
3. The gateway enforcement is for the **specific path** being audited (matching path pattern). A blanket "we have an edge" is not sufficient.

If any of the three is missing → keep the finding at **Medium / Tentative** with note `Live verification not possible; gateway protection unverified` — never drop.

---

## Step 5 — Java/Spring specific pitfalls

| Pitfall | Detection |
|---------|-----------|
| Custom annotation (e.g., `@ValidateAuthorization`) registered via `HandlerInterceptor.preHandle` that ONLY checks `getMethodAnnotation(X.class) != null` | Read the interceptor. If unannotated methods bypass the check, **all** unannotated handlers are unauth. Confirm: `rg "getMethodAnnotation\(\w+\.class\)\s*!=\s*null"` |
| `WebMvcConfigurer.addInterceptors` with `excludePathPatterns(...)` | Read every exclude. Any wildcard like `/**` or `/api/v1/**` is a red flag |
| `@PreAuthorize("permitAll")` vs `@PreAuthorize("hasRole(...)")` | List **every** `@PreAuthorize` and check if "permitAll" sneaks into sensitive paths |
| `HttpSecurity.authorizeRequests().antMatchers(...).permitAll()` | List every chain; flag overly permissive matchers |
| Controller method that **rewrites** caller's `Authorization` header from config (e.g., `headers.put("Authorization", props.getAdminToken())`) | Search: `rg "headers\.put\(.*[Aa]uthorization" --type java`. This is a **Critical** bypass — caller is silently granted admin privilege |

---

## Step 6 — Cover every unauthenticated method (instances under AUTH findings)

**Do not** invent a new AUTH-NNN for every method when they share one root cause. **Do** ensure every unauth method is visible for triage.

**v4.28:**

| Same root cause (e.g. global `permitAll`) | **One AUTH-NNN** + **`### Instances`** (one row per method; Source + Sink each) |
| Different root causes | Separate AUTH-NNNs |
| Checklist | One row per AUTH finding |
| Appendix D | One row per endpoint with `Finding` + `Inst` |

See **`finding-instances.md`**. `/health` without secrets → Low **instance**, still listed. **Forbidden:** Appendix D row without Finding ID.

**Spring Boot actuator (v4.32):** run **`actuator-sensitive-endpoints-audit.md`**. Sensitive endpoints (`/actuator/env`, `/actuator/heapdump`, …) → **VULN-NNN or IAC-NNN** with per-endpoint Instances — **not** a High AUTH instance on `/actuator/**`. Probe-safe `/actuator/health` (especially `show-details: never`) → AUTH **Low** instance only; does **not** create a separate actuator VULN.

```markdown
| Finding | Inst | Method | Path | Controller method | Code auth | Status | Severity | Impact |
|---------|------|--------|------|-------------------|-----------|--------|----------|--------|
| AUTH-001 | 1 | POST | /signin/validateOtp | SignInOTPController.signinValidateOtp:42 | None | Not Verified | Medium | Auth bypass — sign-in OTP |
| AUTH-001 | 2 | POST | /signin/validateOtp/v2 | SignInOTPController.v2SigninValidateOtp:58 | None | Not Verified | Medium | Auth bypass — sign-in OTP v2 |
| AUTH-001 | 3 | POST | /signin/validateOtp/v3 | SignInOTPController.v3SigninValidateOtp:74 | None | Not Verified | Medium | Auth bypass — sign-in OTP v3 |
| AUTH-002 | 1 | POST | /forceDebBreak | DeBBreakController.forceDebBreak:31 | None | Not Verified | **High** | Different root cause — admin force-break |
| AUTH-001 | 4 | GET | /actuator/health | (actuator) | None | Not Verified | Low | Health — same permitAll root cause |
```

\*Severity on the **finding** = worst instance (`severity-calibration.md`). Per-row Impact still documents each endpoint.

When Spring Security uses global `.anyRequest().permitAll()`, emit **one** AUTH for that filter chain with **instances for every mapped controller method** — do not emit N AUTH IDs.
---

## Step 7 — Completion gate in attestation

```markdown
### Per-Method Auth Audit
| Endpoint methods enumerated | N |
| Authenticated (annotation on method) | A |
| Authenticated (class-level annotation that actually fires) | B |
| Gateway-only (verified with manifest) | C |
| Inline soft check (tentative) | D |
| Unauthenticated | U  ← every entry covered by an AUTH finding **instance** |
| Distinct AUTH findings | F  ← checklist row count |
| `A + B + C + D + U` must equal `N` | (check) |
| `sum(instances across F) == U` | (v4.28 instance gate) |
```

If `A + B + C + D + U != N`, the audit is incomplete → `--strict` failure.

---

## Common silent-miss patterns this step prevents

| Past miss | Cause | This step's prevention |
|-----------|-------|------------------------|
| `SignInOTPController` v4 has `@ClientPermission`; v1/v2/v3 don't — earlier scan counted the class as "annotated" | Per-file annotation count | Step 1 worksheet, Step 3 mixed-controller rule |
| `UserChallengeController.revokeAccount` rewrote `Authorization` from config, bypassing auth entirely | No detection for header-override pattern | Step 5 last row |
| `IosLogoutConfigUpdateController.iosLogoutConfigDrmEnable` flips global flag, no auth, but earlier scan ignored the whole module | Module not enumerated | Combined with `multi-module-enumeration.md` Step 2 |
| `DeBBreakController.FORCE_DEB_BREAK` (admin) shared a class with annotated `DEB_BREAK` | Per-class counting masked the gap | Step 3 |
