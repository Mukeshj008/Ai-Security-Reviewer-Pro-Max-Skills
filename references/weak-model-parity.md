# Weak-model loop (finish every module this session)

**Purpose:** keep a small model from claiming “done” after five P0 apps. Quality is **reading that module**, not finishing a regex pack.

**When:** large repos, cheap/fast models. Optional on a 1-service toy app.

**First** follow `exploration-first.md`: **Read whole-tree configs/secrets once**, then take one HTTP module.

Do **not** load the full 109-check sequence first. This card + session memory + reading the module’s filters and routes is the loop.

Quality is: **every HTTP module AUTH-walked or named Residual**, every real issue in that module is Finding / Tentative / Appendix A with `file:line`. Zero `rg` hits is not a pass.

---

## Why small models miss (do not repeat)

| Failure | What to do instead |
|---------|---------------------|
| Finish 5 P0 apps, claim 109, or stop and ask the user to continue | Walk every remaining HTTP module in this session; Residual is not a user prompt |
| Hunt only via `secrets-patterns.md` `rg` | **Read** `.properties` / yml / `.env` (unquoted values count) |
| Skip route table | **Read** middleware then every route file in **that** directory |
| Skip Java | **Read** filter chain / interceptors; empty `SecurityFilterChain` → Step 3b |
| “Config has a token” | Empty header → default secret is AUTH (AUTH-ADJ-04) |
| `200 []` = BOLA | Token-bind / empty body → IDOR-ADJ-01 |

---

## Loop (every HTTP module, this session)

1. `Read` `.security-review/scan-session-memory.md`. If missing: enumerate HTTP dirs **once**, **Read configs**, write memory.
2. Take **`next_http_module`**, then the next, until none remain.
3. **Explore that directory:** list files, Read security/middleware, Read controllers/routes, Read local application*.properties.
   - If the logical lane is active, apply **`senior-researcher.md` LOG-01…15** (IDOR, extra JSON fields, skip-state, webhook).
   - If the static lane is active, route direct sinks/secrets/single-file config findings through `scanner-static.md`.
4. Optional: run **Backup `rg` pack** below after the routes are open and only for the active lane.
5. Every issue → ledger. `Read` ±15 lines. G1–G5. No silent drop.
6. Rewrite memory. **Start the next module immediately.** Do not stop to ask the user to continue. Write the report after the last module.

`large-repo-runner.md` is the same rule for large repos: finish in this session. There is no CONTINUE handoff.

---

## Backup `rg` pack (optional; scope = current module)

Use only after you have Read the module. Copy if you are stuck:

Node:

```bash
rg -n "app\.all\(|router\.all\(|next\(\s*['\"]route['\"]\s*\)|TestSSO|TestWallet|skipAuth|X-Forwarded-Host|x-forwarded-host" --glob '*.{js,ts}'
rg -n "restricted\s*:|function restricted|/webhook|/callback" --glob '*.{js,ts}'
```

Java:

```bash
rg -n "SecurityFilterChain|permitAll|@RestController|@PreAuthorize" --glob '*.{java,kt}'
rg -n "password\s*[:=]|secret\s*[:=]|client-secret|vault\.secret" --glob '*.{java,kt,properties,yml,yaml}'
```

Then Read hits. If the logical lane is active and `@RestController` exists with no `SecurityFilterChain` in **this module** → `per-method-auth-audit.md` Step 3b. In static-only mode, record only handler-local missing auth.

---

## Hard stops (skill violation)

- User report with `Checks executed: 109` and Residual `none` while memory `walked` < `enumerated`
- Appendix A without control `file:line` or AUTH-ADJ / IDOR-ADJ id
- Skipping `*-admin*`, `*-panel*`, `gtfs*`, `notify*` because they are not P0
- LEAK/SECRET PASS while `configs_read` < enumerated config files

---

## After AUTH walk of a module

Deep injection/SSRF can wait only when the static lane is active (**Residual: injection not traced**). In logical-only mode, direct injection is `N/A — static lane not selected`. AUTH route reasoning and local config secrets follow the active lane routing in `scan-modes.md`.

Then: `severity-calibration.md`, `finding-instances.md`, `precision-false-positive-adjudication.md`.

---

## User prompt (paste)

```text
Follow ~/.cursor/skills/ai-security-reviewer/references/exploration-first.md
Then references/scan-modes.md and references/weak-model-parity.md
Resume .security-review/scan-session-memory.md
Read unread configs first. Walk every HTTP module this session. Hunt only the active lane(s); both if no mode was named.
Write the report before you stop. Do not ask the user to continue.
```
