# Model-Proof Operating Contract

Purpose: make the review reliable across weaker/smaller models without loading every reference into context.

## Mandatory First 10 Minutes

1. Derive report slug (`derive_report_name.py`).
2. Enumerate repository shape:
   - modules/packages
   - HTTP controllers/routes
   - async entry points (queues, cron, workers, Lambda, Spark/EMR, CLI)
   - config/profile files
   - Docker/IaC files
3. Start an internal candidate ledger.
4. Read only the references needed for detected technologies.

## Candidate Ledger

Maintain internally until final report:

```text
id,temp_class,source,sink,path,status,evidence,next_action
```

Allowed final statuses:

- `Finding`
- `Tentative`
- `Appendix A`
- `N/A with reason`

Rule: no candidate may disappear silently. If a pattern hit is filtered, record the failed gate and the exact evidence.

## Token-Efficient Execution

- Prefer scoped `rg` searches over broad file reads.
- Read source/sink files only around relevant lines, then widen if the trace needs it.
- Do not paste full 109-check matrices into chat or report.
- Do not read legacy SCA/CVE references in code-only mode.
- Keep high-volume pattern results internal; user report gets validated findings, residuals, and concise coverage.

## Coverage Routing

| Detected surface | Must run |
|------------------|----------|
| Spring/Express/FastAPI/Django/etc. | route auth + per-method auth; every unauth method covered as AUTH **instance** (merge same root cause — `finding-instances.md`) |
| Object IDs in routes/body | IDOR/BOLA audit |
| JWT/Bearer auth | JWT deep test |
| Commerce/fintech/payments/KYC/PII | business logic checklist |
| **Deep links / App Links / Universal Links / `myapp://` / Linking.getInitialURL** | **`deeplink-audit.md`** (session-in-URL, unvalidated handlers) |
| **android/ or ios/ or AndroidManifest / Info.plist / RN / Flutter** | **`mobile-sast-audit.md`** + mobile-sast-manifest MOB-01…26 + deeplink-audit when links present |
| Queues/cron/workers/Lambda/Spark/EMR | async-second-order audit |
| Docker/K8s/Terraform/Helm | IaC source audit |
| package manifests + explicit SCA request | SCA dependency audit |

## Final Compliance Gate

Before final answer and before HTML export, verify:

- [ ] Every module/package in scope was included.
- [ ] Every config/profile file was read or explicitly marked inaccessible.
- [ ] Every Dockerfile/IaC file was read or N/A justified.
- [ ] Every endpoint method was audited individually when a web framework exists.
- [ ] **Every unauthenticated endpoint is covered** by an AUTH finding instance (Appendix D Finding+Inst); same root cause merged into one AUTH with `### Instances` — no duplicate finding IDs, no inventory-only rows.
- [ ] **Same root-cause hits are instances**, not repeated VULN/AUTH/LEAK IDs (`finding-instances.md`); each instance has Source + Sink.
- [ ] Async/second-order entry points were audited.
- [ ] **Deep-link audit run or N/A justified** (`deeplink-audit.md`) when mobile or deeplink minting/handling is present.
- [ ] **Mobile SAST (static) run or N/A justified** (`mobile-sast-audit.md`) when Android/iOS/RN/Flutter code present — ATS, exported IPC, on-device storage.
- [ ] **Every language present has its §19.x stack pack run** (Spring/Node/PHP/Python/Java/.NET/mobile/Go/Ruby/Rust/C-C++/Elixir/Scala/Apex/shell) or N/A justified.
- [ ] **Precision patterns run:** SIG-01…RAND-01, **SSRF-ADJ-01, LDAP-ADJ-01**, plus **INJ/DESER/LOG/AUTH/XXE-ADJ-*** when matching candidates exist — or N/A justified.
- [ ] **Every SAST-OG-26 hit has SSRF-ADJ-01 authority analysis**; builder untraced → **Tentative**, not Appendix A; SSRF exclusions cite **failed gate G3**.
- [ ] **Every SAST-OG-18 hit has LDAP-ADJ-01 sink confirmation** (file or callee chain) or Appendix A exclusion.
- [ ] **Every Appendix A exclusion cites** a control (`effective-controls-catalogue.md` §1) or an unmet precondition (§2); no bare "false positive".
- [ ] **IDOR/BOLA:** no Confirmed data-exfil from `200 []` or unused `userId` (IDOR-ADJ-01 / AUTH-ADJ-02); token-bound responses → Appendix A G3.
- [ ] **G4 hard fails applied** (EXPLOIT-ADJ-01, AUTH-ADJ-03 probe-safe) — health/status not standalone High/Critical.
- [ ] **Confidence uses `Confirmed`/`Firm`/`Tentative` only** — no High/Medium/Low in a confidence field.
- [ ] Candidate ledger is closed.
- [ ] Every finding has Source, Sink, Assumptions, Vulnerable Code, Data Flow, Impact, **Severity Rationale**, Remediation.
- [ ] Every finding **Severity** assigned via `severity-calibration.md` (not pattern-inflated Critical).
- [ ] Every HTTP finding has `### Burp Suite PoC` (even when live verification skipped).
- [ ] DAST: Burp MCP attempted when available; curl **only after user approval**; otherwise `Not Verified` + Burp PoC documented (`dast-verification-flow.md`).
- [ ] SCA is either completed in explicit SCA mode or marked Residual — not assessed.
- [ ] Secrets are redacted in report evidence.
- [ ] `<repo>_security_report.md` and `<repo>_security_report.html` generated with `--strict`.

## Strict Report Finding Format

Use this exact finding header so HTML parsing works:

```markdown
## [High] [VULN-001] Short title

**Classification:** CWE-89 SQL Injection. `Discovery: Checklist`.

| Field | Value |
|-------|-------|
| Source (full path) | `src/...:12` |
| Sink (full path) | `src/...:45` |
| Exploitable | Yes |

### Description
...

### Vulnerable Code Snippet
...

### Data Flow Trace
...

### Impact Assessment
...

### Severity Rationale
| Factor | Rating | Evidence |
| Impact | High | ... |
| Exploitability | Practical | ... |
| Exposure | Public (assumed) | ... |
| Complexity | Low | ... |
| **Severity** | **High** | Step 3: four-factor calibration (example — not Not Verified cap) |

### Assumptions
...

### Remediation
...
```
