# Coverage complete gate (v4.52 — mandatory before “scan complete”)

**Purpose:** Separate two ideas agents often confuse:

| Term | Meaning |
|------|---------|
| **Inventory coverage 100%** | Every path in `must_read_files` (tests included) is in `.security-review/files-read.log` after a full-text batch. Required before **`status: complete`**. |
| **“Zero vulnerabilities”** | **Never claim.** Undecidable in general; not what “100%” means here. |

Load this file at the **start** of Phase D (report) and again **before** any user-facing “done / complete” message.

---

## When you may say “scan complete”

Only when **all** gates below pass **and** `python3 …/scripts/check_coverage_gate.py` exits **0**.

Forbidden until then (in chat, report title, Executive Summary, or HTML hero):

- “scan complete” · “review complete” · “security audit complete” · “full coverage” · “comprehensive review finished”
- `Review status: complete` in the report header
- `Checks executed: 109` (unless every gate passes)
- Delivering **final** `<repo>_security_report.html` as the **handoff** artifact (draft/progress snapshots are OK if clearly labeled `in_progress`)

**Allowed while gates fail:**

- Keep reading. The next tool call is another file, not a question to the user.
- `Review status: in_progress` only inside a draft you have not finished yet. Do not end the turn on a draft if production files remain.
- User explicitly says **`stop and ship partial`** → still `in_progress`; Residual Register must list **every** skipped production item

**Forbidden in the user-facing message, always:**

- “Say continue” / “type continue” / `CONTINUE` / `CONTINUE LARGE-REPO`
- Ending the turn because one module, one config batch, or the test suite is still unread

---

## Gate checklist (all must pass)

| # | Gate | Pass condition |
|---|------|----------------|
| G1 | **Every code file** | `files-read.log` contains every `must_read_files` path, tests included. The gate diffs the log. Typing `files_read: 333` does not pass. |
| G2 | **Configs** | `configs_read == configs_enumerated` (every profile in inventory config list **Read** once) |
| G3 | **HTTP modules + authorization** | `http_modules_walked == http_modules_enumerated` (per `per-method-auth-audit.md` + logic walk per module); authenticated apps have a completed horizontal/vertical authorization matrix (`idor-bola-audit.md` + `authorization-privilege-escalation-audit.md`) |
| G4 | **Ledger** | No candidate rows in `pending` (each → Finding, Tentative, or Appendix A with reason). Every **False Positive** is Appendix A only — zero FP rows in Detailed Findings (`ai-validate-precision-pass.md`) |
| G4b | **Precision pass** | Every Detailed Finding has adjudication verdict **True Positive** (or Hardening) with source, sink, and data flow; FP candidates counted in Scan Attestation precision line |
| G5 | **Taxonomy** | Completeness & Residual Risk Register published; only SCA/CVE rows may be “not in skill scope”; XML/SOAP/SAML surfaces have `XXE-ADJ-01` + `XML-ADJ-01` disposition |
| G6 | **Memory** | `.security-review/scan-session-memory.md` has `status: complete` and counters match inventory |
| G7 | **Report** | `generate_html_report.py --strict` succeeds **only after** G1–G6 |

Putting an unread **production** path in the Residual Register **does not** satisfy G1 and **does not** end the turn. Keep reading it. Unread tests are Appendix B, not a pause.

---

## Application vs integration (no P0-only “done”)

**Forbidden:** Finishing after a “P0 slice” (payments, webhooks only) while merchant APIs, UI, RBAC, channel admin, AI, or ads modules remain unwalked.

**Required:** HTTP module walk follows **inventory order** (or memory `next_http_module`) until `walked == enumerated`. Priority tables in `large-repo-playbook.md` only set **order**, not **stop early**.

---

## Session memory counters (mandatory updates)

After each config batch and each HTTP module, update `scan-session-memory.md`:

```yaml
status: in_progress   # only complete when check_coverage_gate.py exits 0
production_files_read: 0
production_must_read_count: 0    # copy from inventory.json
configs_read: 0
configs_enumerated: 0
http_modules_walked: 0
http_modules_enumerated: 0
next_http_module: services/...
```

When `files_read` increments, append paths to an internal log or rely on ordered walk — **do not** mark a file read without opening it in the editor/Read tool.

---

## User asked for “100% coverage”

Treat that as **production coverage 100%** (G1–G7), not “top findings only” and not “every test file.” Finish in this session. Do not ask the user to continue. When the gate script passes, hand off HTML + `status: complete`.
