# Multi-Instance Findings (MANDATORY — v4.28)

**Purpose:** prevent duplicate finding IDs for the **same root cause**. One finding can cover many code locations; each location is an **instance** with its own Source and Sink.

---

## Dedup key (when to merge)

Merge candidates into **one finding ID** when **all** of the following match:

| Factor | Must match |
|--------|------------|
| CWE / vulnerability type | Same (e.g. CWE-798 Vault token, CWE-306 missing auth) |
| Root cause | Same control/config/pattern (e.g. global `permitAll`, same `TrustStrategy` helper, same `hvs.` secret class) |
| Remediation | Same fix family (one remediation section covers all instances) |

**Do not merge** when root causes differ — e.g. missing `@PreAuthorize` on route A vs broken JWT `alg=none` on route B → two AUTH/VULN findings.

---

## Forbidden

| Anti-pattern | Correct |
|--------------|---------|
| AUTH-001, AUTH-002, AUTH-003 for three routes all open due to one `permitAll()` | **AUTH-001** with Instance-1/2/3 |
| LEAK-001…006 for the same Vault token pattern in six `bootstrap-*.yml` files | **LEAK-001** with six instances |
| VULN-001 and VULN-002 for `NoopHostnameVerifier` in two methods of the same class/helper | **VULN-001** with two instances |
| Checklist row per file hit of identical secret type | One checklist row; instances listed in Detailed Finding |

---

## Required structure on every multi-instance finding

In **Detailed Findings**, after Classification (use primary/worst instance paths in the Source/Sink table fields for HTML compatibility), add:

```markdown
### Instances

| Instance | Source (full path) | Sink (full path) | Notes |
|----------|--------------------|------------------|-------|
| 1 | `src/.../SecurityConfig.java:29` | `BankTransactionController.processTransaction:47` | POST fund transfer |
| 2 | `src/.../SecurityConfig.java:29` | `BankTransactionController.confirmTransaction:74` | POST statusCheck |
| 3 | `src/.../SecurityConfig.java:29` | `MyController.traceEndpoint:11` | GET /trace |
```

Rules:

1. **Every instance** must have its own **Source (full path)** and **Sink (full path)** with `file:line`.
2. Primary Classification Source/Sink = **highest-severity instance** (or Instance 1 if equal).
3. Vulnerable Code Snippet: show root-cause snippet once; optionally add short per-instance sink snippets under `#### Instance N`.
4. Data Flow Trace: one shared root-cause hops table, then **per-instance** sink hop (or a column/section `Instance N → sink`).
5. Burp PoC: at least one PoC for the highest-impact instance; additional instance PoCs optional under `#### Instance N Burp PoC`.
6. Severity: calibrate on the **worst** instance (Impact/Exposure of the most sensitive endpoint or secret).

---

## AUTH / unauthenticated endpoints (reconciles v4.27)

| Rule | Detail |
|------|--------|
| Coverage | **Every** unauthenticated endpoint method must appear as an **instance** (or Appendix D row linked to an AUTH finding). Nothing inventory-only without a finding ID. |
| Finding count | Same root cause → **one AUTH-NNN** with N instances. Different root causes → separate AUTH-NNNs. |
| Appendix D | One **row per endpoint**; columns include `Finding ID` + `Instance` (e.g. AUTH-001 / 2). |
| Checklist | **One row per AUTH-NNN** (not per endpoint). Source/Sink = primary instance; note `Instances: N` in PoC or Category notes. |
| Completion gate | `Appendix D endpoint rows` == `sum of AUTH instance counts` (not AUTH finding count). |

Example Appendix D:

```markdown
| Finding | Inst | Method | Path | Controller method | Code auth | Status | Severity | Impact |
|---------|------|--------|------|-------------------|-----------|--------|----------|--------|
| AUTH-001 | 1 | POST | /v1/bank/{bank}/processTransaction | …:47 | None | Not Verified | Critical | PFI fund transfer |
| AUTH-001 | 2 | POST | /v1/bank/{bank}/statusCheck | …:74 | None | Not Verified | Critical | PFI status |
| AUTH-001 | 3 | GET | /v1/bank/supported-banks | …:104 | None | Not Verified | Low | inventory |
| AUTH-001 | 4 | GET | /trace | …:11 | None | Not Verified | Low | debug |
```

---

## Secrets / LEAK / TLS / CORS examples

| Root cause | Finding | Instances |
|------------|---------|-----------|
| `hvs.*` in all `bootstrap-*.yml` | LEAK-001 | One instance per file:line |
| Redis password only in `application-pt.yml` | LEAK-002 | Single instance |
| `NoopHostnameVerifier` in `createApiSpecificRestClient` and `createLocalRestClient` | VULN-00N | Two instances (same class OK) |
| CORS `*` + credentials in `corsConfigurationSource` and duplicate `corsFilter` bean | VULN-00N | Two instances |

---

## Checklist / register columns

For multi-instance findings, in Security Verification Checklist:

- **Source** / **Sink**: primary instance paths  
- Add note in PoC column or Category: `Instances: N`  
- Do **not** add N checklist rows for N instances

---

## Candidate ledger

When merging:

```text
id=LEAK-001, status=Finding, instances=6, evidence=bootstrap-{dev,qa,pt,stage,preprod,production}.yml
```

Never close six separate LEAK candidates for the same Vault-token pattern — merge before report.
