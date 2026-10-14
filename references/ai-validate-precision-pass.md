# AI Validate precision pass (MANDATORY — Stage 2b)

**Purpose:** Apply the same **true-positive / false-positive discipline** used in production finding triage **before** any candidate becomes a **Detailed Finding** (`VULN-*`, `AUTH-*`, `IAC-*`, `LEAK-*`). Pattern hits, `rg` matches, and “looks scary” APIs are **not** findings until this pass completes.

**Relationship to other refs:**

| Ref | Role |
|-----|------|
| `finding-confidence-validation.md` | Two-stage recall vs precision; Confidence levels |
| `precision-false-positive-adjudication.md` | Class-specific ADJ rules (SSRF, XSS, XML/XXE, SQL, IDOR, vertical privilege, …) |
| `manual-code-review.md` | G0–G5 gate definitions |
| `effective-controls-catalogue.md` | G3/G4 evidence you must cite to exclude |

This file is the **commit-to-verdict** layer: one adjudication **per call site / per instance**, stored-taint rules, exploitability alignment, and proof requirements.

---

## When to run

Run **once per candidate** (or per instance when instances differ by line/path) **after** G0–G5 and precision ADJ rules, **before** assigning a finding ID.

**Order:** Stage 1 candidate → Read sink ± context → G0–G5 → ADJ-* rules → **this pass** → only then `Finding` in Detailed Findings.

---

## Per-site adjudication (no borrowed verdicts)

Each row in the ledger is **one rule + file + start_line** (or one HTTP method+path for AUTH).

| Forbidden | Why |
|-----------|-----|
| Marking line 120 FP because line 95’s `fetch()` is safe | Different call sites, different URL builders |
| One “SSRF” verdict for the whole file | Adjudicate every outbound-HTTP sink |
| Copying Appendix A reason from another module without reading **this** handler | Same pattern ≠ same control |

---

## Verdict enum (internal ledger → report)

| Verdict | Goes in user report |
|---------|---------------------|
| **True Positive** | **Detailed Findings** — Confidence **Firm** or **Confirmed** only if proof bar met |
| **False Positive** | **Appendix A** only — never Detailed Findings |
| **Hardening** | Detailed Findings at **Low** max, **Exploitable: Hardening**, G4 conditional |
| **Needs Manual Review** | **Tentative** in Detailed Findings **or** Appendix A with named missing module — **&lt;5%** of candidates |

**Fixed** applies when vulnerable code path was removed in this checkout (rare during greenfield scan).

---

## Proof bar (non-negotiable)

### True Positive (report as finding)

Require **all**:

1. **Source** — `file:line` + input class (HTTP param, header, upload, missing auth on route, …).
2. **Sink** — `file:line` + sink class matching the CWE.
3. **Data flow** — ≥3 hops **or** `graphify path`, **or** documented missing auth on a reachable route (AUTH).
4. **G1–G5 pass** — G3/G4 failures → **not** TP.
5. **Written rationale** — ≥3 sentences naming functions, parameters, and **why** controls are absent or bypassable.
6. **Actionable narrative (v4.55)** — before promotion, draft all three:
   - Description: 3–6 issue-specific sentences (actor, entry, missing control, flow, exploit result/preconditions).
   - Impact: 2–5 sentences naming concrete data/actions/resources and business harm.
   - Remediation: exact repo fix location + secure replacement pattern + all-instance coverage + regression test.

If these cannot be written from evidence already read, the candidate is not ready for Detailed Findings. Continue tracing; do not fill the report with generic CWE boilerplate.

**Stored / second-order (CRITICAL — before any FP):**

If the immediate source is DB/cache/queue/file/model field/header echo/broker payload:

- Do **not** FP solely because “data came from database.”
- Set `injection_order: stored`.
- Search **minimally** (1–3 files) for a **writer** of the same field/key from attacker-influenced input.
- Record `writer_evidence: path:line` and `preconditions` (e.g. `POST /api/comments body.content`).

| Stored situation | Verdict |
|------------------|---------|
| Writer proven + no encoding/allowlist on ingest | **TP**, exploitability **Conditionally Exploitable** |
| Writer proven + effective control on ingest (cite `file:line`) | **FP** → Appendix A |
| No writer + **strong** stored field name (`comment`, `bio`, `redirect_url`, `filename`, `template`, `body`, …) | **Needs Manual Review** / **Tentative** — **not** FP |
| No writer + clearly system field (`uuid`, `created_at`, enum code only) | **FP** allowed with evidence |

Strong stored hints: `comment`, `note`, `bio`, `profile_url`, `avatar_url`, `title`, `description`, `address`, `filename`, `redirect_url`, `callback`, `template`, `content`, `body`, `message`, `subject`, `payload`, `raw`.

### False Positive (Appendix A only)

Require **all**:

1. Cited **file exists** in checkout (missing file → not FP; do not invent “dead code” without open).
2. **Positive disproof** at **this line**: constant/fixed input, dead branch, unreachable path, effective sanitization/encoding/allowlist, framework guarantee, wrong CWE/sink type, or precision ADJ rule (cite `SSRF-ADJ-01`, `LDAP-ADJ-01`, `IDOR-ADJ-01`, …).
3. **G3 control cited** with `file:line` from `effective-controls-catalogue.md` §1 **or** §2 precondition **demonstrably unmet**.
4. **≥3 sentences** in Appendix A row — no “Sanitized.” / “Not exploitable.” without naming what was checked.

**Forbidden FP reasons:** “best practice”, “might be mitigated at gateway”, “probably validated elsewhere” without reading the validator.

### Needs Manual Review (last resort)

Use only when **all** are true:

- Opened source file **and** ≥2 related files on the path.
- Source→sink crosses a boundary you cannot trace.
- You **name** the missing file/function/module.

If you can write a 3-sentence technical explanation, **commit to TP or FP** instead.

---

## Exploitability must match verdict

| Verdict | Exploitability label |
|---------|----------------------|
| False Positive | **Not Exploitable** |
| True Positive (direct) | **Exploitable** or **Conditionally Exploitable** |
| True Positive (stored) | **Conditionally Exploitable** |
| Needs Manual Review | **Conditionally Exploitable** |
| Hardening | **Hardening** / conditional per `severity-calibration.md` |

Do not label every issue “Conditionally Exploitable” to avoid deciding.

---

## Severity after True Positive (v4.54)

When promoting a **TP** to Detailed Findings, apply `severity-calibration.md` **before** writing `### Severity Rationale`:

| TP class | Severity rule |
|----------|----------------|
| **AUTH** — missing/broken auth on **internal** route, **webhook**, or **cron/worker** trigger | **Medium** default; no High/Critical for auth-only on that surface |
| **Crypto** — weakness requires **quantum computer** / HNDL only (no classical break) | **Out of scope** → Appendix A; do not promote |
| All other TP | Four-factor matrix (Steps 1–3) |

Injection/RCE on the same handler as an unauthenticated webhook is a **separate** `VULN-NNN`, not folded into AUTH severity.

---

## Quantum / HNDL / PQC (out of scope — v4.56)

If the **only** issue is post-quantum readiness, harvest-now-decrypt-later, or “quantum-vulnerable” algorithms with **no classical exploit today** → **False Positive** / **Appendix A — QUANTUM-OUT-OF-SCOPE**. Do **not** keep as Tentative or Not Fixed. See **`quantum-crypto-out-of-scope.md`**.

## Tie-breakers (when unsure)

| Situation | Choose |
|-----------|--------|
| Attacker input **can** reach dangerous sink; no proven control | **TP** (Conditionally Exploitable if env-dependent) |
| Code present with **read** effective control | **FP** → Appendix A |
| Vulnerable code absent | **Fixed** (internal) or omit |
| IDOR/BOLA | Apply `IDOR-ADJ-01` / `precision-false-positive-adjudication.md` — session-bound lookup ≠ IDOR |
| Live `200` + empty body | Not Confirmed BOLA; may still be **Firm AUTH** if route lacks session |
| Authenticated low-role access to admin/privileged action | Apply `PRIV-ADJ-01` + `authorization-privilege-escalation-audit.md`; authentication alone is not authorization |
| XSS with sanitizer/framework escaping | Apply `XSS-ADJ-01`; prove exact browser context and sanitizer/encoder configuration |
| XML parser/construction | Apply `XXE-ADJ-01` / `XML-ADJ-01`; secure-processing alone is not complete hardening |

For IDOR/BOLA, classify data sensitivity in rationale: **PII**, **PHI**, **PFI**, or **None**.

---

## IDOR / AUTH false-positive traps (quick)

| Trap | Correct handling |
|------|------------------|
| Query has `userId` but server binds to session subject | **FP** (G3 IDOR-ADJ-01) |
| `200` + `[]` / `{}` with no foreign sensitive fields | Not Confirmed data exfil; do not rate Critical BOLA |
| `500` / missing required auth param | Not “unauthenticated success”; see AUTH-ADJ-02 |
| Empty header → config service token injected | **Keep AUTH** (AUTH-ADJ-04) |

---

## Internal adjudication record (per candidate)

Copy into ledger before promoting to Detailed Findings:

```
candidate_id, file, start_line, cwe,
verdict: TP|FP|Hardening|NMR,
injection_order: direct|stored,
writer_evidence, preconditions,
source, sink, data_flow (required for TP),
gates G0-G5, adj_rule (e.g. SSRF-ADJ-01),
exploitability, confidence (Confirmed|Firm|Tentative),
appendix_a_reason (required for FP)
```

---

## Report mapping

| Verdict | Detailed Findings | Appendix A | Checklist |
|---------|-------------------|------------|-----------|
| TP + Firm/Confirmed | Yes | No | Row with Confidence |
| TP + Tentative | Only with `### Assumptions` | Optional duplicate note | Tentative |
| FP | **No** | **Yes** — table row with ADJ/gate reason | Do not list as open finding |
| NMR | Tentative or Appendix A | If deferred | Tentative |

**Scan Attestation Summary** must include one line:

`Precision pass: N candidates adjudicated; M promoted to findings; K false positives in Appendix A; R tentative/NMR.`

---

## Optional machine appendix (agent-internal)

After adjudication, agents **may** append to `.security-review/adjudication-log.json` or a fenced block in internal notes (not required in user HTML):

```validation-json
{"candidates":[{"candidate_id":"","file":"","line":0,"verdict":"False Positive","source":"","sink":"","data_flow":"","injection_order":"direct","writer_evidence":"","exploitability":"Not Exploitable","gates":{"G1":true,"G2":true,"G3":false}}]}
```

User-facing handoff remains markdown + HTML per `report-output-spec.md`.
