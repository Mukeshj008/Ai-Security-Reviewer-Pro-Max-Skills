# Changelog

All notable changes to **AI Security Reviewer Pro Max Skills** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [4.32.1] — 2026-08-05

### Fixed — false-positive / exploitability gate precision (audit follow-up)

- **`precision-false-positive-adjudication.md`** — SSRF Appendix A exclusions now cite **failed gate G3** (not G4); trace until authority found (no hop cap; untraced → Tentative); **G1+G3 both-pass** documented; **`.path()` vs `.pathSegment()`**; **SSRF-ADJ-01-F** redirect chain → Tentative/Low; **runtime-writable config** on question B; **Feign `@Url`**; LDAP **callee chain**; all `*-ADJ-*` marked mandatory when matching candidates exist.
- **`effective-controls-catalogue.md` §2** — SSRF preconditions split into **authority control** (→ Appendix A G3), **blind egress**, and **redirect chain** rows.
- **`finding-confidence-validation.md`**, **`manual-code-review.md`**, **`agent-execution.md`**, **`model-proof-operating-contract.md`**, **`scan-attestation-summary.md`**, **`sast_scan_manifest.md`**, **`extended-category-scans.md` §19.1**, **`patterns.md`** — aligned with v4.32.1 gates.
- **`SKILL.md`** — v4.32.1; Phase 2a covers all `*-ADJ-*` gates.
- **Org-neutral examples** — removed engagement-specific repo/class names from CHANGELOG, precision adjudication, manual review, patterns, and deeplink audit.

### Why

Internal audit of v4.32 found G3/G4 mislabeling on config-base RestTemplate SSRF exclusions, missing §2 authority precondition, `.path()` false-negative risk, and incomplete coverage (Feign, redirects, runtime config).

## [4.32] — 2026-08-05

### Added — precision false-positive adjudication (SSRF + LDAP namesakes)

- **`references/precision-false-positive-adjudication.md`** — mandatory Stage-2 gates before CWE-918/CWE-90 findings:
  - **SSRF-ADJ-01** — authority analysis (who controls scheme/host/port); config-fixed base + `UriComponentsBuilder.pathSegment` / query params → Appendix A; merge safe `buildUrl()` call sites into one finding with instances.
  - **LDAP-ADJ-01** — disambiguate `.search()` (JMESPath `Expression.search`, Elasticsearch, Python `re.search`) from real LDAP sinks; require LDAP imports before CWE-90.
  - Additional gates: INJ-ADJ-01 (ORM/prepared), DESER-ADJ-01 (JSON DTO), LOG-ADJ-01, AUTH-ADJ-01.
- **`effective-controls-catalogue.md`** — expanded SSRF row with Java Spring safe patterns; new LDAP injection row; §3 **SSRF-ADJ-01** / **LDAP-ADJ-01** scan blocks.
- **`sast_scan_manifest.md`** — SAST-OG-26 and SAST-OG-18 rewritten with two-stage queries + mandatory adjudication pointers (removed bare `.search(` LDAP pattern).
- **`patterns.md`** — Java SSRF safe/unsafe examples; JMESPath vs LDAP distinction.
- **`manual-code-review.md`** — forbidden exclusion reasons for "HTTP client present → SSRF" and "`.search(` → LDAP"; worked Appendix A examples (Spring RestTemplate + JMESPath class).
- **`finding-confidence-validation.md`** — CWE-918 and CWE-90 micro-rubric addenda.
- **`model-proof-operating-contract.md`** + **`agent-execution.md`** — compliance gates for SSRF-ADJ-01 / LDAP-ADJ-01 on every hit.
- **`extended-category-scans.md` §19.1** — Spring RestTemplate/WebClient candidate + builder trace patterns.

### Why

Dogfooding on a Spring microservice (risk/rule engine) produced systematic false positives: ten `restTemplate.exchange(buildUrl(domain), …)` hits flagged as SSRF where `buildUrl()` fixed authority from config, and a JMESPath utility's `.search()` misclassified as LDAP. Pattern-only Stage-1 hits were reported without authority/sink-type analysis.

## [4.31.1] — 2026-08-04

### Added — XXE control row + XXE-01 pattern (found by dogfooding v4.31)

- **`effective-controls-catalogue.md`** — new **XXE / XML external entities** row in §1. Explicitly rejects the anti-pattern *"typed/JAXB unmarshal, so XXE is residual/low"*: type binding constrains object mapping, not parser entity resolution. `Unmarshaller.unmarshal(Reader|String|InputStream)` builds a default entity-resolving parser and is **not** a control.
- **Trust-boundary rule** — a third-party **response** is attacker-controlled whenever the transport is unauthenticated (trust-all `TrustStrategy`, `NoopHostnameVerifier`, cleartext HTTP, compromisable proxy). "It comes from the bank/partner" is not a control unless TLS validation is verified; chain the two findings instead.
- **§3 `XXE-01`** — parser inventory + hardening-flag scan (`disallow-doctype-decl`, `FEATURE_SECURE_PROCESSING`, `SUPPORT_DTD`, …); hardening must be on the same factory instance.

### Why

Re-running the review of a Spring/SOAP bank-integration service surfaced a **false negative in the prior baseline report**, which had PASSed injection with "JAXB XXE residual low (typed unmarshal)" while that same report proved the outbound TLS client used trust-all + `NoopHostnameVerifier` — making the parsed bank response attacker-controlled. v4.31's §1 had rows for deserialization but none for XXE, so the incorrect reasoning was not explicitly blocked.

## [4.31] — 2026-08-04

### Added — evidence-based false-positive control

- **`references/effective-controls-catalogue.md`** — §1 what genuinely neutralizes each class (bound params vs concat, framework auto-escaping vs `raw`/`utext`, canonicalize+confine vs strip-`../`, post-DNS allowlist vs blocklist, DTO deserialization vs default typing, header-auth vs cookie-auth for CSRF) with an explicit **NOT effective** column; §2 **exploitability preconditions** per class (e.g. JSON+nosniff response ⇒ no reflected XSS; Bearer-only auth ⇒ no CSRF) plus forbidden FP excuses ("needs rooted device", "needs an account"); §3 precision patterns; §4 reporting hooks.
- **§3 new pattern classes:** `SIG-01` non-constant-time MAC/webhook-signature comparison (auth bypass, near-zero FP), `SIG-02` skipped signature verification, `SAML-01` (unsigned assertion, signature wrapping, missing `InResponseTo`/`Recipient`/`Destination`), `OAUTH-01` (prefix-matched `redirect_uri`, missing `state`, no PKCE, unvalidated `id_token`), `CI-01` GitHub Actions workflow injection (`pull_request_target` + PR-head checkout / `github.event.*` in `run:`, unpinned actions, self-hosted runners), `ARCHIVE-01` ZipSlip/zip bomb, `RAND-01` predictable tokens/OTP.

### Added — missing language/stack packs

- **`extended-category-scans.md` §19.8–§19.12** — **Go** (Gin/Echo/Fiber, `text/template` XSS, `math/rand` tokens, `InsecureSkipVerify`, per-route middleware gaps), **Ruby/Rails** (`skip_before_action`, `html_safe`, `permit!`, `Marshal.load`), **Rust** (`unsafe`, `&format!` into query, `danger_accept_invalid_certs`), **C/C++** (format string, `strcpy`/`gets`, unchecked `memcpy`), and **Elixir/Phoenix, Scala/Play, Salesforce Apex, shell/entrypoint scripts**. Previously only Spring/Node/PHP/Python/Java/.NET/mobile had blocks.

### Fixed — internal contradictions that degraded precision

- **Single canonical confidence enum.** `manual-code-review.md` had a second High/Medium/Low confidence scale conflicting with `Confirmed`/`Firm`/`Tentative` used by the report spec, register, and internal log — a `--strict` field-consistency hazard. Legacy scale removed; High/Medium/Low now unambiguously means **Severity**.
- **Default posture reconciled.** "When in doubt, do not report" contradicted the mandatory fail-open policy; replaced with "report precisely, not sparsely" — exclusions require a cited control or unmet precondition, unknown preconditions stay Tentative.
- **G3/G4 now have an evidence base** instead of unaided judgement.

### Why

Skill audit found: no per-CWE control/precondition knowledge (largest false-positive source for LLM adjudication), several high-yield exploitable classes with zero patterns (constant-time MAC compare, SAML, CI workflow injection), five widely deployed languages with no sink patterns, and two contradictory internal rules.

## [4.30] — 2026-08-04

### Added — full static mobile SAST (ATS, exported IPC, on-device storage)

- **`references/mobile-sast-audit.md`** — mandatory when Android/iOS/RN/Flutter present: inventory manifests; exploitable exported **Activities / BroadcastReceivers / ContentProviders / Services**; PendingIntent; **ATS / cleartext / network_security_config**; sensitive data in prefs/DB/files/AsyncStorage; backup/debuggable chains; WebView; crypto; logs; permissions; RN/Flutter bridges. **Static only** — Frida/MITM = Residual.
- **`mobile-sast-manifest.md`** expanded to **MOB-01…26**; **`extended-category-scans.md` §19.7**; taxonomy §16 Full for static classes.
- Wired into SKILL (M1), model-proof, attestation, finding-templates (`### Mobile Component PoC`), platform-coverage, report-output-spec.

### Why

Bug-bounty and internal reviews need systematic static detection of mobile issues (ATS exceptions, exported components, plaintext tokens on device) without requiring dynamic instrumentation.

## [4.29] — 2026-08-04

### Added — deep-link / Universal Link / App Link session-theft audit

- **`references/deeplink-audit.md`** — mandatory when mobile or deeplink minting/handling is present: inventory handlers; session/OTP/token in URL; unvalidated `redirect`/`url`; custom-scheme hijack; App Links `autoVerify` / AASA gaps; backend BFF minting; G1–G5; severity bands; `### Mobile Deep Link PoC` (`adb` / `simctl`); attestation block.
- **MOB-09…11** in `mobile-sast-manifest.md`; **§6.8b** in `extended-category-scans.md`; **SAST-OG-22** expanded for deeplink triggers.
- Coverage routing in `model-proof-operating-contract.md`; taxonomy + ASVS V7/V10 / OWASP A07; finding-templates + scan-attestation deep-link gate.

### Why

Bug-bounty programs frequently report **deeplink stealing user session** when apps accept auth tokens in deep-link query params or navigate without allowlists — previously only partially covered via open-redirect / mobile Partial rows.

## [4.28] — 2026-08-04

### Added — multi-instance findings (no duplicate IDs)

- **`references/finding-instances.md`** — merge rule (same CWE + root cause + remediation → one finding); mandatory `### Instances` table with **per-instance Source and Sink**; AUTH/Appendix D Finding+Inst columns; secrets/TLS/CORS examples.
- **`report-finding-completeness.md`**, **`finding-templates.md`** — Instances section required when N>1.

### Changed — AUTH coverage without ID spam

- **`report-output-spec.md`**, **`route_auth_audit.md`**, **`per-method-auth-audit.md`**, **`model-proof-operating-contract.md`**, **`scan-attestation-summary.md`**, **`report-findings-verification-register.md`** — every unauthenticated endpoint still covered; same root cause → **one AUTH-NNN** with instances; completion gate = Appendix D rows == sum(instances), not finding count.
- **`SKILL.md`** — v4.28.

## [4.27] — 2026-08-04

### Added — Spring/Vault/TLS/CORS/Kafka/secret-log pattern pack

- **`secrets-patterns.md` SAST-SECRET-12** — HashiCorp Vault `hvs.*`, `spring.cloud.vault.token`, cloud SM literals.
- **`secret-type-labels.md`** — Vault / KMS secret type labels.
- **`sast_scan_manifest.md`** — Java `NoopHostnameVerifier` / `TrustStrategy`; format-string Bearer/password logging; Spring CORS `setAllowedOrigins(*)` + credentials; header trust (`uid`/`tenantId`); Jackson mass-assignment.
- **`extended-category-scans.md` §19.1** — expanded Spring Boot mandatory `rg` (TLS trust-all, CORS, Kafka `trusted.packages`, ddl-auto/H2/actuator, Vault HTTP, permitAll, secret logging, header impersonation).
- **`multi-profile-config-audit.md`** — Vault token + cleartext Vault URI patterns.

### Changed — every unauthenticated endpoint is an AUTH finding

- **`report-output-spec.md`**, **`route_auth_audit.md`**, **`per-method-auth-audit.md`**, **`severity-calibration.md`**, **`finding-templates.md`**, **`report-findings-verification-register.md`**, **`model-proof-operating-contract.md`**, **`scan-attestation-summary.md`** — Appendix D inventory-only paths removed; **AUTH-NNN 1:1** with checklist + Detailed Findings (including Low `/health`); missing-auth + sensitive data keeps AUTH (optional separate VULN only for distinct CWE); global `permitAll` still emits per-method AUTH findings.

## [4.26] — 2026-07-30

### Added — IDOR/BOLA PII / PHI / PFI sensitivity

- **`references/idor-bola-audit.md`** — Step 1b mandatory data-sensitivity labels (**PII** / **PHI** / **PFI** / **None**) on every object-ID candidate; object map + dual-session reporting carry labels.
- **`report-impact-assessment.md`** — IDOR/BOLA impact guidance requiring sensitivity labels.
- **`extended-category-scans.md` §4.3**, **`route_auth_audit.md`**, **`security-architect.md` ARCH-04** — aligned to the same taxonomy.

## [4.25] — 2026-07-21

### Changed — severity independent of verification status

- **`references/severity-calibration.md`** — removed Step 1 cap tying **Not Verified** / skipped DAST to Medium max; DAST sets Verification Status and may upgrade Confidence only; worked example now **High** + Not Verified.
- **`finding-confidence-validation.md`**, **`finding-templates.md`**, **`manual-code-review.md`**, **`report-finding-field-consistency.md`**, **`report-impact-assessment.md`**, **`model-proof-operating-contract.md`** — severity from four factors only.
- **`dast-verification-flow.md`**, **`curl-dast-fallback.md`**, **`dast_scan_manifest.md`**, **`burp_poc_templates.md`**, **`route_auth_audit.md`**, **`report-finding-completeness.md`** — verdict matrices are verification-status only; removed AUTH severity columns.
- **`SKILL.md`** — v4.25; Stage 2 adjudication explicitly separates severity from DAST.

### Why

Users reported that capping or defaulting to Medium when live probes were Not Verified understated real code-confirmed issues (e.g. fail-open webhooks with High impact). Severity should reflect impact and exploit conditions; verification status remains a separate, honest field.

## [4.24] — 2026-07-21

### Added — mandatory severity calibration (Impact × Exploitability × Exposure × Complexity)

- **`references/severity-calibration.md`** — canonical severity decision matrix: four factors, Step 1 caps (~~AUTH Not Verified → Medium max~~ **removed in v4.25**; Local exposure → Medium max for IAC), Critical gate, mandatory **`### Severity Rationale`**, anti-pattern table, worked webhook example.
- **C3** reference row in `SKILL.md` quick-start and reference stack.

### Changed

- **`SKILL.md`** — v4.24; Stage 2 adjudication + review sequence step **9a** include severity calibration; required finding sections add Severity Rationale.
- **`finding-confidence-validation.md`** — severity step after CWE rubric; extended candidate ledger fields.
- **`manual-code-review.md`** — AUTH verdict rules + senior notes link to calibration; forbid Critical on code-only missing auth.
- **`finding-templates.md`** — AUTH severity table expanded; points to calibration before DAST table.
- **`report-impact-assessment.md`** — Impact vs Severity vs Exploitable mapping; Severity Rationale gate.
- **`report-finding-field-consistency.md`** — severity derivation workflow; forbidden Critical inflation patterns.
- **`risk-score-rubric.md`** — severities must be calibrated before score aggregation.
- **`model-proof-operating-contract.md`** — compliance gate + finding format example.

### Why

Field reviews (including webhook fail-open hubs) assigned **Critical** from pattern type alone without accounting for exposure (local compose), verification status (Not Verified), or complexity (optional header bypass). Risk score then hit 100/100 from inflated severities. v4.24 separates **Confidence** from **Severity** and makes severity reproducible.

## [4.23] — 2026-07-13

### Added — DAST verification with user consent + mandatory Burp PoC

- **`references/dast-verification-flow.md`** — canonical Phase 7 decision tree: craft Burp PoC first → Burp MCP → **ask user permission** → curl only if approved → Burp PoC still mandatory when both skipped.
- **User permission gate for curl** — agents must not run network probes silently; explicit Approve/Deny/Skip before any `curl` (`curl-dast-fallback.md`, `SKILL.md`).

### Changed

- **`SKILL.md`** — v4.23; Burp/DAST section rewritten; quick-start reads `dast-verification-flow.md`; reference stack adds **D4**; Phase 7/10 sequence updated.
- **`curl-dast-fallback.md`** — curl is opt-in via user approval; user decline = `Not Verified (live probe skipped — user declined)` + mandatory Burp PoC.
- **`burp_poc_templates.md`** — rule #10: always include `Live status` in PoC metadata; PoC required when verification skipped.
- **`finding-templates.md`** — Burp PoC section strengthened; AUTH severity table adds user-declined row.
- **`dast_scan_manifest.md`**, **`agent-execution.md`**, **`model-proof-operating-contract.md`** — aligned with permission flow and PoC-always rule.
- **`scan-attestation-summary.md`**, **`report-findings-verification-register.md`**, **`report-output-spec.md`** — DAST backend enum + PoC column guidance.

### Why

Field reviews often skipped live verification when Burp MCP was unavailable or rejected, leaving findings without reproducible HTTP evidence. v4.23 ensures every HTTP finding ships a Burp Repeater-ready request while respecting user consent for outbound curl probes.

## [4.21] — 2026-06-30

### Changed — vendor-neutral examples

- Removed org-specific naming from docs, prefix blocklists, and examples; replaced with generic `acme` / `acmeteam` placeholders.
- CORS bypass example in `extended-category-scans.md` §14.8 now uses `evil-example.com` / `example.com`.
- Use `--extra-prefix` on `derive_report_name.py` to strip your organisation's folder prefixes.

## [4.20] — 2026-06-30

### Added — mandatory report-file naming convention

- **`references/report-naming-convention.md`** — single-source spec for the report filename. Derives a clean repo slug from the workspace folder by stripping a default blocklist of org/team prefixes (`acmeteam-`, `acme-`, `acmelabs-`, `acme-internal-`, `team-`, `org-`, `internal-`, `corp-`, `eng-`, `engineering-`, `infra-`, `platform-`, `dev-`, `prod-`, `staging-`, `qa-`, `uat-`, `gh-`, `github-`, `gitlab-`, `bitbucket-`, `bb-`, `customer-`, `client-`) and trailing tokens that match `[-_]?[0-9a-f]{6,40}` (git short-hash/SHA), `[-_]?\d{6,}` (timestamps/dates), `[-_]?v?\d+(\.\d+){1,3}` (semver), or `[-_]?(main|master|develop|release)`. Outputs `<repo>_security_report.md` / `<repo>_security_report.html` (and `<repo>_security_report_gap_analysis.md` / `_delta.md` when applicable). Includes a migration snippet that renames any pre-existing bare `security_report.*` on workspace entry.
- **`scripts/derive_report_name.py`** — reference implementation; CLI flags `--workdir`, `--project` (user override), `--extra-prefix` (additional org prefix), `--suffix`, `--ext`, `--print-debug`. Self-tested against 12 cases (`acmeteam-oauth-user-mgmt-service-48e5b67f7489` → `oauth-user-mgmt-service`, `acmeteam-acme-checkout-v1.4.2-3f9a1b2c-main` → `checkout`, `react_native_app` → `react-native-app`, etc.). Underscores in the source name are normalised to hyphens for filename consistency.
- **`SKILL.md`** Phase 4 — adds the derive + migrate + render snippet next to the `generate_html_report.py` invocation and a new **N1** mandatory row in the reference stack.
- **`references/report-output-spec.md`** — bumped to v4.20; new top-of-spec **Report filenames** section makes the convention canonical.
- **`references/agent-execution.md`** — new mandatory Phase 0b (derive slug, migrate legacy files) and updated HTML-export snippet that uses `$REPO`.
- **`scripts/generate_html_report.py`** — emits a stderr Recommendation when the input filename does not follow `*_security_report.md`; still accepts legacy filenames so the gate is non-breaking.

### Why

Field reviewers reported that running the skill against multiple workspaces under `~/Downloads/` produced a sprawl of identically-named `security_report.md` files; the renamed convention also makes Jira/Slack attachments self-identifying (e.g. `oauth-user-mgmt-service_security_report.md` vs. `wallet-service_security_report.md`).

## [4.19] — 2026-06-30

### Added — scope completeness (prevents the biggest class of silent misses observed in field reviews)

- **`multi-module-enumeration.md`** — mandatory Phase −1c for multi-module repos (Gradle/Maven/pnpm/Cargo/Go workspaces). Forces enumeration of **every** module's controllers, configs, and Dockerfiles before SAST. Prevents the "scan only the main `api/` module and ignore the 14 sibling modules" miss.
- **`multi-profile-config-audit.md`** — mandatory Phase −1d when configs exist. Requires reading **every** `application-*.{yml,properties}`/`appsettings*.json`/`.env*` profile, not a sample. Adds cross-profile credential-reuse diff and internal-admin-token regex (catches admin Bearer tokens baked into config and used by controllers to bypass auth).
- **`per-method-auth-audit.md`** — mandatory Phase 6a for annotation-based frameworks (Spring, ASP.NET, Quarkus, NestJS). Builds a per-endpoint-method worksheet so unauthenticated `v1`/`v2`/`v3` variants are not masked by their annotated `v4` peers in the same controller. Includes Spring-specific pitfalls (custom interceptor that only checks method-level annotation, header-override patterns).

### Added — new mandatory pattern classes in `extended-category-scans.md`

- **§3.11** — controller rewrites caller's `Authorization` header from server config (Critical AUTH bypass pattern).
- **§3.12** — JWT minted without `exp` claim (High; catches `Jwts.builder().compact()` and `JWT.create().sign()` without `setExpiration`/`withExpiresAt`, plus Node `jwt.sign` without `expiresIn`).
- **§6.10** — plaintext token / credential logging (`log.info("... Authorization: " + getHeader("Authorization"))`, accessToken values logged on delete).
- **§6.11** — full request `@RequestHeader Map<String,String>` / `@RequestBody` logging at INFO level (PII leak; was missed in 20+ controllers in past reviews).
- **§6.12** — sensitive field logging (password, OTP, PAN, Aadhaar, CVV, mobile, email).
- **§14.8** — CORS allow-list bypass via `endsWith()` / `contains()` / `startsWith()` (Critical when combined with `Allow-Credentials: true`).
- **§14.9** — overly permissive CORS allow-list (size + raw-IP + wildcard audit).

### Added — Appendix A discipline (`manual-code-review.md`)

- **Forbidden exclusion reasons** table — bans unverified "trust the gateway", "internal-only network", "mutual TLS", "test code only", "annotation on class", "other endpoints on same controller are protected", and "same DB password is dev/test" dismissals unless cited with explicit evidence (gateway manifest file:line, K8s `NetworkPolicy`, mesh policy, etc.). Default posture for uncertain cases: keep as Tentative in Detailed Findings, never silent-drop.

### Changed

- **`SKILL.md`** — bumped to v4.19; reference stack adds S1/S2/S3 mandatory rows; review sequence inserts Phase −1c, −1d, 6a; final-gate step references the forbidden-exclusion table.
- **`agent-execution.md`** — review-order list expanded with Phase −1c, −1d, 6a, and explicit "every module / every profile / every Dockerfile" scoping.
- **`route_auth_audit.md`** — header note pointing to per-method audit + module enumeration prerequisites.
- **`report-output-spec.md`** — Scan Attestation Summary must include `### Module & Profile Enumeration`, `### Config / Profile Audit`, and `### Per-Method Auth Audit` blocks when their triggers fire; `--strict` recommends these in stderr.

### Why (lessons from an enterprise OAuth UMS gap analysis, 2026-06-30)

A skill-free re-scan turned up 12 additional findings (5 Critical) that the v4.18 run missed. Root causes were structural, not pattern-coverage: module scope narrowed to one directory, profiles sampled instead of enumerated, per-controller annotation counting, blanket "trust the gateway" Appendix A dismissals, and 5 specific pattern classes the manifests did not cover. v4.19 addresses each cause directly.

## [4.18] — 2026-06-30

### Added

- **`standards-coverage-map.md`** — mandatory completeness sweep against OWASP Top 10 2021, OWASP API Security Top 10 2023, CWE Top 25 2024, OWASP ASVS 5.0 (17 chapters), and OWASP Top 10 for LLM Apps 2025.
- **Completeness & Residual Risk Register** — mandatory report section; every taxonomy area gets Covered / N/A / Residual. Dependency-CVE classes (A06, API10, ASVS V15, LLM03) recorded **Residual — not assessed** in code-only mode so nothing is silently missed.
- **`finding-confidence-validation.md`** — two-stage (wide-net + adjudication) model, CWE-specific micro-rubrics, **confidence levels** (Confirmed/Firm/Tentative), **fail-open policy** (never silently drop uncertain candidates), and known-active-CVE override guard. Based on current hybrid SAST+LLM verification research.
- **Confidence** + **Discovery** columns added to the Security Verification Checklist.
- **Scope & honesty statement** in `SKILL.md` — no "zero-miss/100%" claims; report what was assessed, at what confidence, and what is residual.

### Changed / fixed

- Reconciled `vulnerability-coverage-overview.md` and `internal-scan-log.md` with code-only mode (SCA/CVE/DEPS = N/A; ~89 active of 109 defined) — removes the prior contradiction that implied SCA was performed.
- Bumped canonical `report-output-spec.md` to v4.18; fixed lingering "v4.16" references in `SKILL.md`.

## [4.17] — 2026-06-28

### Added

- **Security-researcher discovery layer** — agent must hunt for issues outside the 109-check matrix; validate with G1–G5; report as first-class VULN/AUTH/IAC/LEAK with `Discovery: Researcher`.
- **DAST tool lock** — Burp MCP when present; **curl only** when Burp absent (no Playwright/requests/other HTTP clients for verification).

### Changed

- **`SKILL.md`**, **`agent-execution.md`**, **`manual-code-review.md`**, **`curl-dast-fallback.md`**, **`report-output-spec.md`**, **`scan-attestation-summary.md`** — researcher pass + Discovery column + curl-only fallback.

## [4.16] — 2026-06-28

### Changed

- **Code-only review mode** — third-party dependency scanning removed from workflow and report.
- **Out of scope:** OSV API, `npm audit`, Maven/Gradle SCA, trivy/grype, SBOM, KEV, CVE-NNN / SCA-NNN from advisory databases.
- **In scope unchanged:** SAST (`rg`/`Read`), DAST (Burp/curl), IaC misconfig from source files, auth/IDOR/JWT/business-logic review.
- **`report-output-spec.md`** — SCA section excluded; attestation notes code-only mode.
- **`agent-execution.md`** — removed npm/OSV/Maven from agent tool list.

## [4.15] — 2026-06-26

### Added (all additive — v4.14 behavior preserved)

- **`scan-attestation-summary.md`** — user-facing 109-check accountability (no full Appendix E).
- **`idor-bola-audit.md`** — systematic BOLA/IDOR + dual-session curl.
- **`jwt-deep-test.md`** — JWT static + DAST probes.
- **`business-logic-abuse-checklist.md`** — fintech/commerce abuse cases (BUS-01…10).
- **`protocol-scans-graphql-ws-grpc.md`** — when GraphQL/WebSocket/gRPC detected.
- **`git-history-secrets-scan.md`** — gitleaks/git-log historical secrets.
- **`container-image-scan.md`** — trivy/grype image CVE layer.
- **`kev-prioritization.md`** — CISA KEV column in SCA + remediation.
- **`risk-score-rubric.md`** — reproducible Executive Summary risk score.
- **`attack-chain-narrative.md`** — optional multi-finding kill chains.
- **`baseline-delta-report.md`** — delta vs prior report.
- **`sbom-export.md`** — optional CycloneDX SBOM.
- **`mobile-sast-manifest.md`** — MOB-01…08 when android/ios present.
- **`large-repo-playbook.md`** — triage for monorepos.

### Changed

- **`SKILL.md`** v4.15 — extended review sequence; all v4.14 steps retained.
- **`report-output-spec.md`** v4.15 — Scan Attestation mandatory; recommended additive sections table.
- **`generate_html_report.py`** — `--strict` also checks Assumptions + Remediation; attestation/rubric recommendations on stderr.
- Stale refs updated **additively** (v4.15 notes in coverage-overview, manual-code-review, security-architect, platform-checklist).

## [4.14] — 2026-06-26

### Added

- **`references/report-output-spec.md`** — single canonical report contract (sections, forbidden appendices, AUTH/VULN dedup, SCA footer).
- **`references/internal-scan-log.md`** — agent-only 109-check worksheet (replaces Appendix E in user report).
- **`references/finding-templates.md`** — VULN/AUTH/CVE/IAC formats extracted from SKILL.md.
- **`generate_html_report.py --strict`** — exit non-zero on missing Classification Source/Sink, field inconsistencies, or register backfill.

### Changed

- **`SKILL.md`** v4.14 — lean orchestration (~200 lines); points to `report-output-spec.md`; no duplicate templates/changelog.
- **`agent-execution.md`**, **`coverage-checklist.md`**, **`report-scan-matrices-agent.md`**, **`report-unified-findings-table.md`** — aligned with internal scan log + Security Verification Checklist (no Appendix E/G/I in user report).
- **`report-findings-verification-register.md`** — AUTH/VULN dedup rules; Top Structural Risks; strict HTML gate note.
- **`curl-dast-fallback.md`** — mandatory read-only VULN probes when host exists.
- **`osv-sca-scan.md`** — Moderate/Low advisories scanned count footer.
- **`generate_html_report.py`** — backfill emits stderr warnings; `--strict` fails before HTML write.

## [4.13] — 2026-06-26

### Changed

- **`generate_html_report.py`** — verification checklist auto-wrapped in `<details>` toggle; scan-layer checklist via markdown `<details>`; removed duplicate Source/Sink classification chips (banner only); finding card overflow fix; suppress Appendix G in HTML.
- **`SKILL.md`** v4.13 — Appendix G internal only; **Security Verification Checklist** with collapsible status tables.

## [4.12] — 2026-06-26

### Added

- **`references/report-findings-verification-register.md`** — user-facing findings list with Source, Sink, Verification Status, DAST Status; replaces Appendix E + Appendix I in reports.

### Changed

- **`SKILL.md`** v4.12 — 109 checks remain **internal agent workflow**; user report uses **Security Findings Verification Register** only (no 109-row matrix, no platform checklist appendix).
- **`generate_html_report.py`** — suppress Appendix E/I in HTML; mandatory Source/Sink banner on every finding card; compact verification table; backfill Source/Sink from register when Classification omits them.
- **`references/report-finding-completeness.md`** — Verification Register replaces Master Register as primary table.

### Removed (from user-facing report)

- **Appendix E** (109-check coverage matrix) — still executed by agent, not emitted in `security_report.md`.
- **Appendix I** (platform checklist attestation) — internal only.

## [4.11] — 2026-06-26

### Added

- **`references/report-impact-assessment.md`** — mandatory CIA + Business Impact table per finding; category-specific guidance; bans generic one-liners.
- **`references/report-finding-field-consistency.md`** — Exploitable enum (`Yes`/`No`/`Hardening` only); Register ↔ Classification sync gate.

### Changed

- **`generate_html_report.py`** — table scroll wrappers; master register column CSS; Exploitable normalization; Impact panel uses `### Impact Assessment` only (no generic fallback); Simplified Flow rendering; suppress duplicate Risk/Severity blocks; field consistency stderr warnings; footer v4.11.
- **`references/report-finding-completeness.md`** — Impact + Exploitable gates.
- **`references/report-html-design.md`** — v4.11 layout rules.
- **`SKILL.md`** v4.11 — new references in stack + completion gates.

## [4.10] — 2026-06-26

### Changed

- **`generate_html_report.py`** — **deduped Executive Summary**: each metric renders once (scope bar → risk → outcome KPIs → static framework strip). Suppresses duplicate `### Scan Metrics` and Coverage Overview summary tables in HTML.
- **`references/report-html-design.md`** — v4.10 layout rules; anti-pattern for repeated scope/KPI/strip/table.
- **`SKILL.md`** v4.10 — HTML dedup note in report-html-design reference.

## [4.9] — 2026-06-26

### Added

- **`references/vulnerability-coverage-overview.md`** — human-readable coverage stats: **109 checks**, **85+ classes**, **750+ patterns**, scan layers, report section template.
- **`references/scan-scope-metrics.md`** — mandatory **Files Analyzed** and **Lines of Code** counting commands and report fields.

### Changed

- **Removed Appendix H / MX-H taxonomy attestation** — coverage proven by Appendix E + **`## Vulnerability Coverage Overview`** section.
- **`generate_html_report.py`** — modern colourful HTML: gradient hero, scan-scope bar, coverage strip, coloured KPI cards, gradient table headers.
- **`SKILL.md`** v4.9 — scan scope phase (−1b), Coverage Overview in report, Phase 1f optional extended scans.
- **`agent-execution.md`**, **`report-scan-matrices-agent.md`**, **`report-html-design.md`** — aligned with v4.9 (MX-COV replaces MX-H).

### Removed

- Mandatory **Appendix H** (19 TAX-* domain groups) from report workflow.

## [4.8] — 2026-06-26

### Added

- **Mandatory terminal curl DAST** when Burp MCP absent — do not install Burp Suite; execute curl in Shell for every AUTH candidate.

### Changed

- **`generate_html_report.py`** — skip markdown header metadata after hero render (fixes duplicate Report ID / Scan Agent block in HTML).
- **`curl-dast-fallback.md`** — mandatory execution requirement, FAIL gate if curl not run when host exists.
- **`dependency-install-policy.md`** — Burp MCP exception (like Graphify); install curl only for DAST.
- **`SKILL.md`** v4.8 — Burp/curl DAST rule, Phase 1b completion gate, DAST Backend header values.
- **`route_auth_audit.md`**, **`dast_scan_manifest.md`**, **`agent-execution.md`**, **`report-scan-matrices-agent.md`** — aligned with terminal curl policy.

## [4.7] — 2026-06-26

### Added

- **`references/dependency-install-policy.md`** — mandatory install-first for scan CLIs (`npm`, `mvn`, `gradle`, `python3`, `curl`, `rg`); **Graphify explicitly excluded** from auto-install; manual `rg` + Read traces when graph absent.

### Changed

- **`SKILL.md`** v4.7 — Phase 0a tool bootstrap; Prerequisites table; Graphify optional; fallback without install.
- **`agent-execution.md`** — Phase 0a bootstrap; install before SKIP; manual reachability when no graphify.
- **`osv-sca-scan.md`** / **`maven-sca-scan.md`** — install Maven/npm before pom.xml-only fallback.
- **`report-scan-matrices-agent.md`** — Dependency bootstrap row in Scan Agent attribution table.

## [4.6] — 2026-06-26

### Added

- **`references/maven-sca-scan.md`** — Maven/Gradle SCA (`SCA-MAVEN-01…05`): `pom.xml` discovery, `mvn dependency:list`, OSV `Maven` ecosystem (`groupId:artifactId`), Java import reachability, exploitability.
- **`references/report-scan-matrices-agent.md`** — scan matrices inventory + Scan Agent / AI Validation Agent attribution in reports.
- **`references/report-unified-findings-table.md`** — Master Findings Register (one table, Severity · AI Verdict · Exploitable · full paths).
- **`references/platform-coverage-checklist.md`** — API/Web/Android/iOS checklist → Appendix I.
- **Appendix E rows** — `SCA-MAVEN-01…05` when Java build manifests present.

### Changed

- **`osv-sca-scan.md`** — Maven/Gradle inventory commands; OSV Maven query examples; links to `maven-sca-scan.md`.
- **`cve-exploitability.md`** — `CVE-REACH-04` Java/Maven import reachability.
- **`SKILL.md`** v4.6 — Master Findings Register, no charts, scan agent header, Maven SCA in Phase 1c.
- **`generate_html_report.py`** — IBM Plex Sans, verdict pills, master register styling; Scan Agent in hero.

## [4.5] — 2026-06-26

### Added

- **`references/osv-sca-scan.md`** — inventory all production third-party libraries; OSV API batch lookup; reachability + exploitability; dedicated **`## Software Composition Analysis (SCA)`** report section (**Critical/High exploitable only**).
- **`references/secret-type-labels.md`** — mandatory **Secret Type** labels (GitHub PAT, AWS Access Key, RabbitMQ password, MapMyIndia API key, Strapi token, etc.).
- **Supplemental Appendix E rows** — `SCA-OSV-01…05` (114 checks when OSV SCA runs).

### Changed

- **`SKILL.md`** v4.5 — Phase 1c expanded (OSV + npm audit); AUTH validate-all; mandatory Burp PoC for every AUTH-NNN including Not Verified/Medium; hardcoded secret finding format with Secret Type field.
- **`route_auth_audit.md`** — live test every AUTH candidate; mandatory PoC when Not Verified.
- **`cve-exploitability.md`** — OSV as primary advisory source; SCA section placement rules.
- **`secrets-patterns.md`** — reporting requires `secret-type-labels.md`.
- **`report-finding-completeness.md`** — AUTH PoC mandatory; SCA/CVE section rules; Secret Type in Classification.

## [4.4] — 2026-06-26

### Added

- **Mandatory `### Vulnerable Code Snippet`** per finding — real source + sink code copied from the target repo (not paraphrased).
- **Mandatory `### Data Flow Trace`** per finding — full ASCII taint path or step table plus simplified flow diagram.
- **`references/report-vulnerable-code-dataflow.md`** — templates, rules, and completion gate (findings = snippets = traces = remediations).
- **HTML report panels** — `generate_html_report.py` renders dedicated **Vulnerable Code** and **Data Flow Trace** sections; warns when sections are missing.
- **Completion gate** in `report-finding-completeness.md` — count of finding headers must match snippet, trace, and remediation sections before HTML export.

### Changed

- **`SKILL.md`** — bumped to v4.4; finding templates (VULN, AUTH, CVE, IAC) now require snippet + trace; workflow step 11 explicitly lists all three mandatory sections.
- **`references/agent-execution.md`** — pre-HTML gate includes snippet and trace counts.
- **`references/manual-code-review.md`** — Phase 4 report generation requires vulnerable code and data-flow documentation.
- **`scripts/generate_html_report.py`** — parses and styles new sections; improved finding panel layout.
- **SSRF example** in SKILL.md generalized (`routes/catalog-proxy.js` / `/fetchResource`) — no engagement-specific filenames.

### Unchanged from v4.3

- 109-check Appendix E matrix + Appendix H taxonomy attestation (19 domain groups).
- Senior manual review with pre-report gates G1–G5.
- Mandatory `### Remediation` with BEFORE/AFTER code (v4.2).
- curl DAST fallback when Burp MCP unavailable (v4.2).
- Agent-only execution model — no scan scripts for analysis (v4.0).

---

## [4.3] — 2026-06-23

### Added

- **Full vulnerability taxonomy** — `vulnerability-taxonomy-coverage.md` maps all issue classes to check IDs.
- **Extended category scans** — `extended-category-scans.md` supplemental `rg` for Partial taxonomy rows.
- **Appendix H attestation** — 19 domain groups (TAX-INJ … TAX-FW) mandatory in every report.
- **Expanded injection manifest** — NoSQL, CRLF, header, SSTI, EL, log injection in `injection-deep-scan.md`.

---

## [4.2] — 2026-06-22

### Added

- **Mandatory `### Remediation`** per finding with BEFORE/AFTER code blocks.
- **`references/curl-dast-fallback.md`** — live verification when Burp MCP is unavailable.
- **`references/report-finding-completeness.md`** — finding completeness gate before HTML export.

### Changed

- HTML generator improved Remediation Priority inference as fallback.

---

## [4.1] — 2026-06-21

### Added

- **Senior manual code review** — `manual-code-review.md` with context-first analysis.
- **Pre-report gates G1–G5** — mandatory before any VULN/AUTH/CVE/IAC finding.
- **Phase −1** — application context before broad scanning; feeds Appendix G.

---

## [4.0] — 2026-06-20

### Changed

- **Agent-only execution** — manifests are cookbooks; agent runs `rg`, `graphify`, `npm audit`, Burp MCP directly.
- Scan scripts deprecated for agents (CI-only).
- **`graphify path`** mandatory for injection/CVE/SSRF reachability proof.

---

## [3.9] — 2026-06-18

### Added

- Exploitable CVE analysis (CVE-NNN with import + reachability proof).
- IaC misconfiguration scan (IAC-NNN — Docker, K8s, Terraform, Nginx, CI).
- Security architect lens (ARCH-01…07 + Appendix G).
- 109-check Appendix E matrix.

---

## [3.8] — 2026-06-15

### Added

- Full Appendix E/F coverage matrices in every report.
- Complete SAST manifest runner coverage (LEAK, SECRET, EXT checks).
- DAST manifest for Burp probe rules.

---

## [3.7] — 2026-06-12

### Added

- Frontend stack trace leak checks (SAST-LEAK-01…08).
- Full secrets catalog (SAST-SECRET-01…11).
- Deep injection scan manifest.
- Code-derived Burp host discovery rules.

---

## [3.6] — 2026-06-10

### Added

- Unauthenticated endpoint audit (AUTH-NNN).
- Burp MCP live verification.
- Burp Suite PoC templates per finding.
- HTML report export via `generate_html_report.py`.
- Graphify-first discovery workflow.
- Checkmarx-style natural language descriptions and full stack traces.
