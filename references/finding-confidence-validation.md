# Finding Confidence & Validation Model (MANDATORY)

Accuracy controls for **maximizing true positives while controlling false positives — without silently dropping real issues**. Based on current hybrid SAST+LLM verification research (two-stage adjudication, CWE-specific micro-rubrics, fail-open policy).

---

## Two-stage model (do not collapse the stages)

| Stage | Role | Tool |
|-------|------|------|
| **1. Candidate generation (wide net)** | Find *every* plausible candidate — favor recall | `rg` manifests + `graphify` + researcher pass |
| **2. Adjudication (precision)** | Confirm/reject each candidate with context | `Read` ±context + G1–G5 + CWE micro-rubric + DAST |

**Never** let Stage 2 reasoning prevent Stage 1 from *listing* a candidate. Recall happens first; precision is applied per-candidate, with evidence.

---

## Fail-open policy (critical — prevents silent misses)

When adjudication is **uncertain** (can't fully prove or disprove), you **must not** silently drop the candidate. Instead:

- Keep it as a finding at **Tentative** confidence, **or**
- Record it in **Appendix A** with the explicit reason it could not be confirmed and what evidence would resolve it.

A real vulnerability degraded to "no finding" with no trace is the worst outcome. Uncertainty → **surface it**, don't bury it.

**Exception — known-active CVE override:** Never suppress a candidate that matches a known-active exploited weakness pattern (e.g., Log4Shell-style JNDI lookup, deserialization gadget) just because it sits in a "utils/test" path. Flag for human review even if reachability is unproven.

---

## Confidence levels (attach to every finding)

| Confidence | Criteria | Typical Verification Status |
|------------|----------|-----------------------------|
| **Confirmed** | Live PoC succeeded **with the claimed effect** (foreign object fields, write side-effect, or auth bypass that yields a **subject**) **or** unambiguous static proof with full source→sink | Verified in Burp / curl / Code confirmed |

**Confirmed is not:** HTTP `200` + empty `[]`, `500` missing-param, health `OK`, or a query ID that code never uses (see **IDOR-ADJ-01**, **AUTH-ADJ-02**). Those may still support **Firm AUTH** (route ran without a session) but **not** Confirmed BOLA/data-exfil.
| **Firm** | Strong static evidence, G1–G5 pass, but no live verification (e.g., no reachable host) | Code confirmed / Not Verified |
| **Tentative** | Plausible but missing a hop, control unclear, or reachability unproven | Not Verified — needs follow-up |

- Report **Confirmed** and **Firm** in Detailed Findings.
- Report **Tentative** in Detailed Findings only with explicit `### Assumptions`; otherwise list in Appendix A.
- Add a **Confidence** column to the Security Verification Checklist.

---

## CWE-specific micro-rubric (per finding, before assigning an ID)

For the candidate's CWE, answer the rubric — generic reasoning underperforms CWE-targeted reasoning:

1. **Source** — exact attacker-controlled input (`file:line`)?
2. **Sink** — exact dangerous operation for *this* CWE (`file:line`)?
3. **Path** — does the data actually reach the sink (≥3 hops or graphify path)?
4. **Control** — is there encoding/validation/authz that neutralizes it? Judge with **`effective-controls-catalogue.md` §1** and cite `file:line`; a bypassable control is not a control.
5. **Exploit** — concrete attack input + expected effect; the class preconditions in **`effective-controls-catalogue.md` §2** must hold (unknown → Tentative).

If 1–3 or 5 cannot be answered → not Confirmed/Firm. Decide Tentative vs Appendix A per fail-open policy.

---

## Severity calibration (Stage 2 — after CWE rubric, before finding ID)

**Do not assign Critical/High/Medium/Low until `severity-calibration.md` is applied.**

1. Complete **`### Impact Assessment`** (CIA + Business) first — highest level feeds **Impact** factor.
2. Rate **Exploitability**, **Exposure**, **Complexity** per `severity-calibration.md`.
3. Apply **Step 1 caps** (Tentative → Medium max; Local exposure → Medium max for IAC; Hardening → High max). **Do not** cap severity for Not Verified / skipped DAST.
4. Assign **Severity** from the decision matrix; document in mandatory **`### Severity Rationale`** table.
5. Set **Verification Status** / **DAST Status** from Burp/curl (`dast-verification-flow.md`) — **independent** of severity.

**Independence:** Confidence = certainty the bug exists. Severity = urgency from four factors. Verification Status = live DAST outcome. A **Firm** + **High** + **Not Verified** finding is valid.

---

## Structured adjudication record (internal, per candidate)

Keep a consistent record so results are reproducible:

```
candidate_id, cwe, source(file:line), sink(file:line), path_proven(yes/no/partial),
control_present(desc), exploit(desc), verdict(Confirmed|Firm|Tentative|FalsePositive),
confidence, impact(Severe|High|...), exploitability(Trivial|...), exposure(Public|...),
complexity(Low|...), severity(Critical|High|...), severity_cap(none|...),
verification_status, dast(Burp|curl|none), notes
```

---

## False-positive discipline (Appendix A)

Move to Appendix A only with a **named reason**, e.g.:
- Sink not reachable from any attacker source (path disproven)
- Effective framework/encoding control present (cite it — `effective-controls-catalogue.md` §1)
- Class precondition demonstrably unmet (name it — `effective-controls-catalogue.md` §2)
- **Precision gate passed** — cite `SSRF-ADJ-01`, `LDAP-ADJ-01`, etc. from `precision-false-positive-adjudication.md`
- Dev/test-only code, not built into deployable artifact
- Input is not attacker-controlled (internal constant)

### CWE-918 (SSRF) — mandatory micro-rubric addendum

Before Confirmed/Firm SSRF:
1. Trace URL to **authority** (scheme/host/port) — not merely "user input appears near HTTP call".
2. If authority is config/constant-only **and not runtime-writable by attacker** → **Appendix A (SSRF-ADJ-01, failed gate G3)** — G1 may still pass (path segment input).
3. Distinguish **`.pathSegment()`** (safe for SSRF authority) from **`.path(userInput)`** (not safe — keep candidate or separate path-abuse note).
4. Fixed authority + redirect chain → **Tentative/Low** (SSRF-ADJ-01-F), not Appendix A.
5. Merge multiple safe `buildUrl()` call sites → one finding with instances, not duplicate IDs.
6. Builder not traced → **Tentative**, not Appendix A (fail-open).

### CWE-639 (IDOR/BOLA) — mandatory micro-rubric addendum

Before Confirmed/Firm **IDOR data leak**:
1. Prove attacker ID is the **repository/query key** (`file:line`) **or** live body contains **another user's** fields.
2. Token/session bind + unused request ID → **Appendix A (IDOR-ADJ-01, G3)**.
3. Live `200 []` / empty orders → **AUTH** if no session required; IDOR **Tentative** until a real victim ID or query-key proof.
4. Do not label Confirmed BOLA from a dummy PNR/`customer_id=1` empty response.

### CWE-90 (LDAP) — mandatory micro-rubric addendum

Before Confirmed/Firm LDAP injection:
1. Confirm LDAP client imports/API in the **file or callee chain** (≤3 hops).
2. Confirm user input reaches **LDAP filter or DN string concat** — not JSON/JMESPath/regex `.search()`.
3. JMESPath `io.burt.jmespath.Expression.search` → **Appendix A (LDAP-ADJ-01, failed gate G3 — wrong sink type)**.

Never use a bare "false positive" with no reason — that is itself a defect. The forbidden-exclusion table in `manual-code-review.md` still applies: gateway/internal-network/staging claims need cited manifest evidence.

---

## Reconciliation gate

- Checklist **Confidence** values consistent with Verification Status enum.
- Every Tentative finding has `### Assumptions`.
- Fail-open honored: no candidate disappeared without either a finding row or an Appendix A reason.
- CVE-override candidates never silently suppressed.
