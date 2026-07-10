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
| Spring/Express/FastAPI/Django/etc. | route auth + per-method auth |
| Object IDs in routes/body | IDOR/BOLA audit |
| JWT/Bearer auth | JWT deep test |
| Commerce/fintech/payments/KYC/PII | business logic checklist |
| Queues/cron/workers/Lambda/Spark/EMR | async-second-order audit |
| Docker/K8s/Terraform/Helm | IaC source audit |
| package manifests + explicit SCA request | SCA dependency audit |

## Final Compliance Gate

Before final answer and before HTML export, verify:

- [ ] Every module/package in scope was included.
- [ ] Every config/profile file was read or explicitly marked inaccessible.
- [ ] Every Dockerfile/IaC file was read or N/A justified.
- [ ] Every endpoint method was audited individually when a web framework exists.
- [ ] Async/second-order entry points were audited.
- [ ] Candidate ledger is closed.
- [ ] Every finding has Source, Sink, Assumptions, Vulnerable Code, Data Flow, Impact, Remediation.
- [ ] DAST was run via Burp MCP or curl when an external host exists; otherwise residual reason is documented.
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

### Assumptions
...

### Remediation
...
```
