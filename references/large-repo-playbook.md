# Large Repository Playbook (additive)

**When:** Files Analyzed > 500 OR LOC > 100k OR monorepo with many unrelated modules.

**Does not reduce** required exploration — only **order**. Follow `exploration-first.md`. Do not substitute a 109-row `rg` pass.

---

## Phase 0 — Triage

1. Read README, ARCHITECTURE.md, `pom.xml` / package.json roots.
2. List **every** HTTP module and **every** config/profile (including `.properties` / `.env`).
3. Identify production entrypoints. Still **Read** `scripts/` and test resources if they contain live-looking credentials — finding or Residual, not silent skip.
4. Record scope decision in Appendix F.

---

## Priority surfaces (review first)

| Priority | Surface |
|----------|---------|
| P0 | **All config/profile/secret files (Read)** + public HTTP + auth filters + payment/order |
| P1 | Dockerfile, CI |
| P2 | Shared libs used by P0 handlers |
| P3 | Admin/internal routes, batch jobs — **AUTH inventory still mandatory** (v4.35) |

---

## Sampling rule

- **Do not** treat “top 15 manifest hits” as the secret review. Secrets come from **reading configs**.
- Deep G1–G5 injection traces may wait on P3 after a **shallow AUTH walk** of every HTTP module.
- graphify query budget: 1500–2000 per query, max 3 queries.

### v4.35 — P3 / skipped HTTP modules are Residual, not "later"

| Allowed | Forbidden |
|---------|-----------|
| Deep G1–G5 only on P0/P1 **after** opening **every** HTTP module’s routes + auth | Walking 5 of 27 services then writing `Checks executed: 109` |
| Listing an HTTP module as **Residual — AUTH not walked** | Silent skip of `*-admin-*`, `*-automation*` |
| Unread configs as **Residual — LEAK/SECRET not read** | `LEAK/SECRET 12/12 PASS` after a P0 slice |

Admin/internal (P3) is where fail-open tokens live. **Shallow AUTH is required; deep injection traces may wait.**

---

## Report honesty

```markdown
**Scope note:** Explored by reading N config files and Y HTTP modules. Unread: [list].
**HTTP modules enumerated:** X. **AUTH-walked:** Y. **Residual (not walked):** [list or none].
**Configs enumerated / read:** M / K.
```

`Checks executed` must **not** be `109` unless Y == X **or** every skipped HTTP module is named Residual.

**Session memory (v4.35.1):** After each HTTP module walk, rewrite `.security-review/scan-session-memory.md`. Record `configs_read`.

**Large repo (v4.51):** one agent, `large-repo-runner.md`. Walk every production file and every route in the same session. No shard workers. No fake 109. Never ask the user to continue.

Do not claim line-by-line review of entire monorepo unless performed.

---

## Stop conditions

**Complete review:** every HTTP module walked, every config read, every production file read. Then `status: complete` and write the report. Unread tests are an appendix note, not a pause.

**Partial handoff:** only if the user said `stop and ship partial`. Do not invent that pause yourself. Never end a turn by asking the user to say continue.

Never hand off as complete after P0-only. See `large-repo-runner.md`.
