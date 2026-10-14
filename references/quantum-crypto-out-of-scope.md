# Post-quantum / quantum-vulnerable crypto (OUT OF SCOPE — v4.56)

**Do not report** findings whose **only** weakness is resistance to a **cryptanalytically relevant quantum computer (CRQC)** or long-horizon **harvest-now-decrypt-later (HNDL)** policy. This skill assesses **classical** exploitability in the review window, not quantum migration roadmaps.

## Never assign `VULN-*` / `IAC-*` / `LEAK-*` for

| Pattern | Examples |
|---------|----------|
| PQC migration / hygiene | “Adopt ML-KEM / ML-DSA”, “enable TLS PQC hybrid”, “NIST PQC readiness” |
| Quantum-only key size | “RSA-2048 / P-256 vulnerable to Shor in theory”; “ECC not post-quantum” with **no classical break** |
| HNDL narrative only | “Adversary may store TLS ciphertext for future decryption”; “rotate before CRQC” without today’s break |
| Scanner rules | `quantum`, `post-quantum`, `PQC`, `HNDL`, `Shor`, `CRQC`, `quantum-safe`, `quantum-vulnerable` when impact is **future-only** |

## Still in scope (classical crypto — report normally)

- MD5/SHA-1 for passwords or signatures, DES/3DES, RC4, `none` JWT alg, TLS 1.0/1.1, weak PBKDF2, hardcoded keys, ECB misuse, missing MAC, homegrown crypto, **practically breakable** RSA/DH key sizes **today** (e.g. RSA-512, weak DH params).
- Misconfiguration that breaks confidentiality **now** (wrong cipher, verify off, static IV in active protocol).

## What to do instead

1. **Do not** add checklist rows or Detailed Findings for quantum-only issues.
2. **Appendix A** (optional): if a scanner flagged it, one line: *Quantum-only / HNDL — out of skill scope (v4.56); no classical exploit.*
3. **Completeness & Residual Risk Register**: one row — *Post-quantum / HNDL crypto migration — Residual (not in skill scope)*.
4. **G0 gate:** quantum-only candidate → **do not promote**; close ledger as `Appendix A — QUANTUM-OUT-OF-SCOPE`.

## Adjudication (AI Validate parity)

- Verdict: **False Positive** for triage tools when the **sole** rationale is quantum/HNDL/PQC.
- Do not use **Tentative** to keep quantum findings in the report.

**See also:** `severity-calibration.md` (classical caps unchanged), `SKILL.md` Out of scope.
