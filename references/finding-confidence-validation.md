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
| **Confirmed** | Live PoC succeeded (Burp/curl) **or** unambiguous static proof with full source→sink trace | Verified in Burp / curl / Code confirmed |
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
4. **Control** — is there encoding/validation/authz that neutralizes it? Is it effective?
5. **Exploit** — concrete attack input + expected effect.

If 1–3 or 5 cannot be answered → not Confirmed/Firm. Decide Tentative vs Appendix A per fail-open policy.

---

## Structured adjudication record (internal, per candidate)

Keep a consistent record so results are reproducible:

```
candidate_id, cwe, source(file:line), sink(file:line), path_proven(yes/no/partial),
control_present(desc), exploit(desc), verdict(Confirmed|Firm|Tentative|FalsePositive),
confidence, verification_status, dast(Burp|curl|none), notes
```

---

## False-positive discipline (Appendix A)

Move to Appendix A only with a **named reason**, e.g.:
- Sink not reachable from any attacker source (path disproven)
- Effective framework/encoding control present (cite it)
- Dev/test-only code, not built into deployable artifact
- Input is not attacker-controlled (internal constant)

Never use a bare "false positive" with no reason — that is itself a defect.

---

## Reconciliation gate

- Checklist **Confidence** values consistent with Verification Status enum.
- Every Tentative finding has `### Assumptions`.
- Fail-open honored: no candidate disappeared without either a finding row or an Appendix A reason.
- CVE-override candidates never silently suppressed.
