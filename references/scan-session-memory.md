# Scan session memory (repo-local — resume after context compact)

**Purpose:** persist **inventory + walk progress** on disk in the **cloned workspace** so a new chat / compacted context does **not** re-enumerate the whole monorepo.

This is **not** Cursor product “Memories.” It is a file the agent **Reads first** and **rewrites after each HTTP module**.

**Path (canonical):** `.security-review/scan-session-memory.md` at the **workspace root** (the cloned repo).

**Companion (optional, gitignored):** `.security-review/internal-scan-log.md` — 109-check worksheet. Do **not** dump the 109 matrix into session memory.

---

## When (mandatory)

| Event | Action |
|-------|--------|
| Review start | `Read` this file **if it exists** — **before** `multi-module-enumeration.md` Step 1 |
| After each HTTP module AUTH-walked | Rewrite the file (inventory + Residual + next module) |
| Context near limit / user says stop | Flush memory **then** write/update `<repo>_security_report.md` |
| Review complete | Set `status: complete`; keep Residual `none` or named leftovers |

**Triggers for large repos:** Files > 500 or LOC > 100k or 2+ HTTP modules (`large-repo-playbook.md`). For tiny single-service repos the file is optional but still useful if the session may compact.

---

## Start-of-session (token save)

1. If `.security-review/scan-session-memory.md` exists:
   - **Do not** re-run whole-repo `find` / Step 1 inventory unless **stale** (below).
   - Resume at **`next_http_module`**.
   - Re-run AUTH `rg` **only** on Residual modules + modules in `git diff` vs `git_head`.
2. If the file is **missing:** run full enumeration, then **create** the file immediately (even before first finding).
3. Load skill references as usual; memory **does not** replace G1–G5 or `express-auth-audit.md`.

### Stale memory (must re-enumerate or re-walk)

Treat inventory as **stale** and re-run Step 1 + HTTP `rg` when **any**:

- `git_head` ≠ current `git rev-parse --short HEAD` **and** `git diff --name-only <old> HEAD` touches `**/routes/**`, `**/*Controller*`, `**/middleware/**`, `**/security/**`, `pom.xml`, `package.json`, or `application*.yml`
- `skill_version` major.minor **older** than current `SKILL.md` (e.g. memory `4.34` vs skill `4.35`) — keep module list; re-apply **new** AUTH probes (`express-auth-audit.md`, AUTH-ADJ-04, Spring Step 3b)
- User changed **scan scope** (include/exclude services)

If HEAD moved but diffs are docs-only: keep inventory; do not full-repo circle.

---

## Forbidden in this file

- Secret **values**, `.env` contents, private keys, Authorization headers
- Full `rg` dumps or whole source files
- Pasting the 109-check matrix
- Claiming `Checks executed: 109` here (that belongs in the **report** attestation)

Keep the file **under ~200 lines**. Prune old candidate rows; keep Residual names.

---

## Git

**Default:** add `.security-review/` to the **target repo** `.gitignore` (same as `internal-scan-log.md`). The file still **saves tokens** across compacted chats in **this clone**.

**Commit** a **redacted** copy only if the user wants resume on a **fresh clone** / another machine. Inventory paths and finding IDs are OK; snippets of credentials are not.

---

## Template (copy verbatim, then fill)

```markdown
# Scan session memory
skill_version: 4.35.2
status: in_progress   # in_progress | complete
git_head: <short SHA or unknown>
updated_at: <ISO-8601>
report_slug: <repo from derive_report_name.py>

## Scope
- Mode: code-only
- Include: <dirs or all>
- Exclude: node_modules, vendor, dist, test/fixtures

## HTTP module walk
enumerated: N
walked: M
residual: mod-a, mod-b
next_http_module: mod-c
walked_list:
- apps/services/foo (AUTH + express-auth-audit)
- apps/services/bar (AUTH shallow; injection Residual)

## Module inventory (do not re-ls unless stale)
| Module | HTTP | AUTH walked | Notes |
|--------|------|-------------|-------|
| apps/services/foo | yes | yes | glob app.all → AUTH-00x |
| apps/services/bar | yes | no | Residual |

## Manifests already run (names only)
- sast_scan_manifest (P0 modules only)
- express-auth-audit (walked_list only)
- secrets-patterns (whole repo)  # whole-repo once is OK to record

## Findings issued (IDs only + one line)
- AUTH-001: foo app.all glob vs /v1/refresh
- LEAK-001: …

## Candidates pending (path:line — no secret values)
- apps/services/baz/middleware/oauth.js:42 TestSSO

## Do not repeat
- multi-module Step 1 inventory (HEAD unchanged)
- whole-repo @RestController rg (HEAD unchanged)
```

---

## Resume checklist (new session)

- [ ] Read `.security-review/scan-session-memory.md`
- [ ] Compare `git_head` / skill_version (stale rules)
- [ ] Continue `next_http_module` — do **not** restart P0 from scratch
- [ ] Merge new findings into existing `<repo>_security_report.md` (same IDs; never reuse IDs for a different issue)
- [ ] Rewrite memory after the next module
- [ ] Attestation `### HTTP module walk` must match this file’s enumerated / walked / residual
