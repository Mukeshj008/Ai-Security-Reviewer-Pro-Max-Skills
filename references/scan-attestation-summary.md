# Scan Attestation Summary (user-facing — additive to v4.14)

**Purpose:** Prove the 109-check workflow ran **without** pasting the full Appendix E matrix into the user report. This section **adds** accountability; it does **not** replace the collapsible scan-layer toggle or internal scan log.

**Placement:** After **`## Scan Matrices Executed`**, before **Top Structural Risks** or **Security Verification Checklist**.

---

## Mandatory section heading

```markdown
## Scan Attestation Summary
```

---

## Required fields (short table)

| Field | Value |
|-------|-------|
| **Checks defined** | 109 (SCA/CVE/DEPS rows N/A in code-only mode) |
| **Checks executed** | N (must equal MX-COV Executed) |
| **PASS** | X |
| **FINDING** | Y (linked finding IDs) |
| **N/A** | Z (stack not present — list layers) |
| **SKIP/FAIL** | 0 at handoff (or explain in Notes) |
| **Internal log** | session notes / `.security-review/internal-scan-log.md` / layer toggle |
| **Researcher-discovered findings** | N (validated outside 109 matrix; `Discovery: Researcher`) |
| **DAST backend** | Burp MCP \| curl-only \| Not Verified (no host) |
| **Attestation** | All applicable 109 checks run + security-researcher pass completed; G1–G5 on every finding |

### Example

```markdown
## Scan Attestation Summary

| Field | Value |
|-------|-------|
| Checks defined | 109 |
| Checks executed | 109 |
| PASS | 102 |
| FINDING | 4 (VULN-001…004, IAC-001) |
| Researcher-discovered | 2 (VULN-003, AUTH-002 — `Discovery: Researcher`) |
| DAST backend | curl-only (Burp MCP unavailable) |
| N/A | 3 (GRAPH-*, mobile, GraphQL) |
| SKIP/FAIL | 0 |
| Internal log | agent session + layer toggle below |
| Attestation | 109 checks + researcher pass; G1–G5 on all findings |

**Finding-linked check IDs (sample):** SAST-OG-11 → VULN-001; IAC-ACTUATOR → IAC-001; VULN-003 → Researcher (interceptor exclude-mapping); SCA/CVE/DEPS → N/A (code-only mode).
```

---

## Completion gate

- [ ] `Checks executed` matches **MX-COV** row in Scan Matrices Executed
- [ ] Every FINDING links to a check ID **or** `Discovery: Researcher` with G1–G5 notes
- [ ] No `PENDING` in internal scan log
- [ ] Logged in **Appendix F** Phase 1 (SAST manifests) = PASS

**`--strict` HTML export:** warns if `## Scan Attestation Summary` is missing (does not fail export — additive recommendation). Missing attestation is logged to stderr.

---

## Relationship to legacy Appendix E

Agents may still use **`report-coverage-matrix.md`** as the full internal worksheet. **Appendix E in user report remains optional/legacy** — if present, HTML still suppresses it. Prefer this summary + toggle for new reports.
