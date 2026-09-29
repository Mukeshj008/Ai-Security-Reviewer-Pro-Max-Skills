# Weak-model parity (Mythos-class AUTH hunt without a frontier model)

**Purpose:** a **small** model finds the **same AUTH/fail-open/glob classes** a top model finds — by **running `rg` and filling Residual**, not by “being clever.”

**When:** **Always** on large repos. **Always** if the user asked for a cheaper/faster model. Optional on a 1-service toy app.

**Do not** load the full `SKILL.md` sequence first. This card + session memory + one stack audit (`express-auth-audit.md` **or** `per-method-auth-audit.md` Step 3b) is the loop.

Quality is **not** 109 rows. Quality is: **every HTTP module AUTH-walked or named Residual**, every probe **hit** is Finding / Tentative / Appendix A with `file:line`.

---

## Why small models miss (do not repeat)

| Failure | What a top model did | Forced substitute |
|---------|----------------------|-------------------|
| Finish 5 P0 apps, claim 109 | Walked IMS/OD/CST/GTFS/`TestSSO` | One module per turn; Residual list is the queue |
| Hunt secrets, skip route table | Glob `app.all` vs later `app.post` | `express-auth-audit.md` block **verbatim** in **that module path** |
| Skip Java | Empty `SecurityFilterChain` `rg` | Step 3b one AUTH + instances |
| “Config has a token” | Empty header → default secret | AUTH-ADJ-04 — keep AUTH |
| Outbound HMAC on client | Unauth inbound `/callback` | Inbound verify only is G3 |
| `200 []` = BOLA | Token-bind / empty body | IDOR-ADJ-01 / AUTH-ADJ-02 |

---

## Loop (one HTTP module per turn)

1. `Read` `.security-review/scan-session-memory.md`. If missing: enumerate HTTP dirs **once**, write memory, stop if context is already large.
2. Take **`next_http_module` only**. Set `working_directory` / `rg` path to **that directory**.
3. Run **Parity `rg` pack** below (Node and/or Java as present in **that dir**).
4. Every hit → ledger. `Read` ±15 lines. G1–G5. No silent drop.
5. Rewrite memory: move module to `walked_list` or keep Residual with reason.
6. **Stop.** Do not start the next module in the same turn if findings need writing. Flush report increment + memory.

**Forbidden:** whole-repo `rg` after inventory exists. **Forbidden:** writing the final report while Residual names modules you have not AUTH-probed.

---

## Parity `rg` pack (copy; scope = current module)

Node (if `package.json` / `*.js` routes in module):

```bash
rg -n "app\.all\(|router\.all\(|next\(\s*['\"]route['\"]\s*\)|TestSSO|TestWallet|skipAuth|X-Forwarded-Host|x-forwarded-host" --glob '*.{js,ts}'
rg -n "restricted\s*:|function restricted|/webhook|/callback" --glob '*.{js,ts}'
rg -n "if\s*\(.*==\s*['\"]['\"]|token\s*==\s*\"\"|access_token" --glob '*auth*.{js,ts}'
rg -n "onboard-admin|registerAdmin|/automation/" --glob '*.{js,ts}'
```

Then run the **full** block in `express-auth-audit.md` inside the same directory (do not skip because “already did a short pack”).

Java (if `pom.xml` / `*.java` in module):

```bash
rg -n "SecurityFilterChain|permitAll|@RestController|@PreAuthorize" --glob '*.{java,kt}'
rg -n "access_token|App_access_token|if\s*\(.*isEmpty|token\s*==\s*null" --glob '*.{java,kt}'
rg -n "IsAuthorisedRequest|onboard|automation" --glob '*.{java,kt}'
```

If `@RestController` hits and `SecurityFilterChain` is empty in **this module** → `per-method-auth-audit.md` Step 3b (one AUTH, **not** default Critical).

---

## Hard stops (treat as skill violation)

- User report with `Checks executed: 109` and Residual `none` while memory `walked` < `enumerated`
- Appendix A without control `file:line` or AUTH-ADJ / IDOR-ADJ id
- Merging “no Spring Security” into Critical without Ingress/public bind cite
- Skipping `*-admin*`, `*-panel*`, `gtfs*`, `notify*`, `ims*`, `order-details*` because they are not P0

---

## After AUTH walk of a module (quality floor)

Deep injection/SSRF can wait (**Residual: injection not traced**). AUTH probes **cannot** wait.

Then read only: `severity-calibration.md` (before severity), `finding-instances.md` (same root cause), `precision-false-positive-adjudication.md` (before dropping AUTH/IDOR).

---

## User prompt (paste when using a small model)

```text
Follow ~/.cursor/skills/ai-security-reviewer/references/weak-model-parity.md
Resume .security-review/scan-session-memory.md
One HTTP module this turn. Do not re-enumerate. Do not claim 109.
```
