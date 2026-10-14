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
| **Checks defined** | 109 (CVE/DEPS taxonomy rows N/A — not in skill scope, v4.46) |
| **Checks executed** | N (must equal MX-COV Executed) |
| **PASS** | X |
| **FINDING** | Y (linked finding IDs) |
| **N/A** | Z (stack not present — list layers) |
| **SKIP/FAIL** | 0 at handoff (or explain in Notes) |
| **Internal log** | session notes / `.security-review/internal-scan-log.md` / layer toggle; **walk resume:** `.security-review/scan-session-memory.md` |
| **Researcher-discovered findings** | N (validated outside 109 matrix; `Discovery: Researcher`) |
| **DAST backend** | Burp MCP \| curl (user approved) \| None — Burp PoC only (user declined / no host) |
| **HTTP findings with Burp PoC crafted** | N / N (must equal HTTP AUTH+VULN count) |
| **Deep-link audit** | Completed (`deeplink-audit.md`) \| N/A (no mobile/deeplink surfaces) — never silent skip when triggers match |
| **Mobile SAST (static)** | Completed (`mobile-sast-audit.md`) \| N/A (no mobile code) — ATS/exported IPC/storage reviewed; Frida/MITM Residual |
| **Precision adjudication (v4.35+)** | All `*-ADJ-*` including IDOR-ADJ-01 / PRIV-ADJ-01 / XSS-ADJ-01 / XXE-ADJ-01 / XML-ADJ-01 / AUTH-ADJ-02/03/**04** / EXPLOIT-ADJ-01; SSRF-ADJ-01: N (M excluded **G3**); empty-200 BOLA claims excluded or Tentative |
| **Authorization / privilege escalation** | Completed (`authorization-privilege-escalation-audit.md`): horizontal, vertical, cross-tenant, privileged-field candidates all dispositioned \| N/A (no authenticated/privileged surface) |
| **XML security audit** | Completed (`xml-security-audit.md`): XXE/entity, structural XML, XPath/XSLT, signature wrapping candidates dispositioned \| N/A (no XML/SOAP/SAML surface) |
| **AI Validate precision pass (v4.53+)** | `ai-validate-precision-pass.md`: *C* candidates; *F* findings; *K* FP → Appendix A only; *R* tentative/NMR (&lt;5% of *C*) |
| **Actuator sensitive endpoints audit** | Completed (`actuator-sensitive-endpoints-audit.md`) \| N/A (no Spring/management endpoints) — sensitive-only reporting; health/info probe-safe |
| **Attestation** | Applicable checks on **walked** HTTP modules + researcher pass; G1–G5 on every finding. Do **not** claim 109 executed unless `### HTTP module walk` Y==X or Residual lists every skipped HTTP module. |

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

**Finding-linked check IDs (sample):** SAST-OG-11 → VULN-001; IAC-ACTUATOR → IAC-001; VULN-003 → Researcher (interceptor exclude-mapping); CVE/DEPS → N/A (not in skill scope).
```

---

## Completion gate

- [ ] `Checks executed` matches **MX-COV** row in Scan Matrices Executed
- [ ] Every FINDING links to a check ID **or** `Discovery: Researcher` with G1–G5 notes
- [ ] No `PENDING` in internal scan log
- [ ] Logged in **Appendix F** Phase 1 (SAST manifests) = PASS
- [ ] **AUTH coverage gate:** Appendix D endpoint rows == sum of AUTH instance counts; checklist AUTH rows == distinct AUTH finding IDs; multi-instance findings include `### Instances` with per-instance Source/Sink (`finding-instances.md`)
- [ ] **No duplicate finding IDs** for the same CWE + root cause (secrets, TLS trust-all, CORS, Vault tokens, etc. → instances)
- [ ] **Precision adjudication:** SSRF/LDAP plus **IDOR-ADJ-01**, **PRIV-ADJ-01**, **XSS-ADJ-01**, **XXE-ADJ-01**, **XML-ADJ-01**; AUTH-ADJ-02/03/**04**; EXPLOIT-ADJ-01 (`precision-false-positive-adjudication.md`)
- [ ] **Authorization / privilege escalation:** authenticated apps have a completed principal/role/permission matrix covering horizontal, vertical, cross-tenant, and privileged-field paths
- [ ] **XML security:** when XML/SOAP/SAML triggers exist, `xml-security-audit.md` is completed; `FEATURE_SECURE_PROCESSING` alone is not accepted as complete XXE mitigation
- [ ] **HTTP module walk (v4.35):** table below present; `enumerated == walked` OR Residual names every skipped HTTP module; never `Checks executed: 109` after a partial slice
- [ ] **Session memory (v4.35.1, large repo):** `.security-review/scan-session-memory.md` exists and matches the HTTP module walk table
- [ ] **Mobile SAST (static)** completed or N/A justified (`mobile-sast-audit.md`) — exported components, ATS, on-device storage

### HTTP module walk (v4.35 — mandatory when 2+ HTTP modules)

```markdown
### HTTP module walk
| HTTP modules enumerated | N |
| HTTP modules AUTH-walked | M |
| Residual (AUTH not walked) | none \| `mod-a, mod-b` |
```

### Inventory coverage (v4.50 — mandatory)

```markdown
### Inventory coverage
| Metric | Read / walked | Enumerated | Gate |
|--------|----------------|------------|------|
| Code files (`must_read_files`) | R | M | R == M |
| Config profiles | K | C | K == C |
| HTTP modules (AUTH + logic) | H | N | H == N |
| `check_coverage_gate.py` | — | — | exit 0 |
```

- **`Review status: complete`** only when all Gate cells pass and the script exits 0.
- If any row is short: **`Review status: in_progress`** — do not say “scan complete” in chat or Executive Summary.

`--strict` fails if the report claims `Checks executed: 109` and this table is missing, or `M < N` with Residual `none` / empty.

**`--strict` HTML export:** warns if `## Scan Attestation Summary` is missing (does not fail export — additive recommendation). Missing attestation is logged to stderr.

---

## Relationship to legacy Appendix E

Agents may still use **`report-coverage-matrix.md`** as the full internal worksheet. **Appendix E in user report remains optional/legacy** — if present, HTML still suppresses it. Prefer this summary + toggle for new reports.
