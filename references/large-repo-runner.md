# Large-repo runner (v4.47 — one agent, finish the repo)

**When:** 2+ HTTP modules, 15+ configs, >500 files, or ~100k LOC. **You** do the work. Do not spawn shard workers, Task subagents, or explore agents. Ignore `inventory.json` `parallel`.

`large-repo-playbook.md` is the honesty rules. This file is the loop.

Read every path in `inventory.json` → `must_read_files`, tests included. Do not sample. Do not skip a file because it is a test, large, unimported, or "P3".

Speed, without dropping files: do not call Read once per file. Run `scripts/next_read_batch.py`. It prints the next unread files **in full** (default 120KB per call; a bigger file is its own batch and is not cut). Judge every `===== FILE =====` block, then `--ack`, then run it again. Stop the loop only when it prints `BATCH_EMPTY`.

A file counts as read only when its full text was in a batch you looked at and then acked into `.security-review/files-read.log`. Key/cert paths in `secret_files_metadata_only` are recorded by name and type and are not opened.

`status: complete` is forbidden while any **production** path is unread, any config is unread, or any HTTP module is unwalked. Do not pause the review to wait for the user.

**Never ask the user to type `continue`.** Never print `CONTINUE LARGE-REPO`. Never end the turn after the first module, the first config batch, or because the file list is long. Keep reading until the report is written. **Never** tell the user the scan is **complete** until `check_coverage_gate.py` exits 0 (`coverage-complete-gate.md`). `stop and ship partial` exists only when the user explicitly says to stop (still not “complete”).

---

## Hard rules

| Must | Must not |
|------|----------|
| Run `enumerate_inventory.py` once per clone (or when memory stale) | Re-walk the whole tree every turn |
| Keep walking every config and every HTTP module in this same session until the report is written | Ask the user to say CONTINUE, or print CONTINUE LARGE-REPO |
| Update `scan-session-memory.md` after each module | Set `status: complete` while Residual HTTP or unread configs exist |
| HTML report only when Residual is empty, or the user says `stop and ship partial` (then `status: in_progress`) | Spawn subagents, Task workers, or shard scans |
| Run `next_read_batch.py` until `BATCH_EMPTY`, then AUTH-walk each HTTP module from those files | Skip a file, ack a batch you did not read, or call the scan complete with one path missing from `files-read.log` |

---

## Turn 0 — inventory (once)

```bash
python3 ~/.cursor/skills/ai-security-reviewer/scripts/enumerate_inventory.py
```

This writes `.security-review/inventory.json` (paths only) and creates `.security-review/scan-session-memory.md` if missing.

Then: `derive_report_name.py`. If memory already exists and is not stale, **skip** this script; resume `next_http_module` / `residual_unread`.

`enumerate_inventory.py` is **inventory**, not a SAST scanner. It is allowed. `run_sast_scan.sh` is still forbidden.

---

## Turn shape (repeat until Residual empty)

### A. Config batch (until `configs_read` == enumerated)

1. Open `inventory.json` → take the **next 8 unread** config paths.
2. **Read** them (unquoted `.properties` count). Ledger LEAK instances.
3. Update `read` / `residual_unread`.
4. If unread configs remain, start the next 8 immediately. Do not stop the session.

### B. HTTP + logic batch

Take `next_http_module` and **Read** it end-to-end: middleware, routes, handlers. Apply `weak-model-parity.md`, `senior-researcher.md` LOG-01…15, REACH-ADJ-01, and route exposure. Then take the next module. **No subagents.** A huge file's `read_ranges` in the inventory are line ranges **you** read, in order, until the file is done.

### C. Memory (after each module, not a place to stop)

1. Rewrite scan-session-memory (`walked++`, `next_http_module`, pending candidates).
2. Keep going while Residual is nonempty.
3. Write `<repo>_security_report.md` and the HTML when production files, configs, and HTTP modules are done (coverage gate exit 0), or when the user said `stop and ship partial`. While work remains, keep reading. Do not hand the user a "say continue" prompt.
4. There is no CONTINUE line. If you have not finished, the next action is another Read, not a message to the user.

---

## Session budget

| Resource | Cap |
|----------|-----|
| File reads | One `next_read_batch.py` call (~120KB of full files), then `--ack`, then the next call, same session, until `BATCH_EMPTY` |
| HTTP modules | Every module, from the batches, this session |
| New finding IDs | As many as validated; the rest stay in memory as pending |

Reading the file is not optional. A deep trace you could not finish is named in Residual after the file has been read. It is not a reason to skip the file.

---

## Completeness for large repos

**Complete** (`status: complete`) only when **all**:

- `files-read.log` contains every `must_read_files` path (tests included). `check_coverage_gate.py` diffs the log. A counter in the memory file is not enough
- `configs_read` == enumerated
- HTTP `walked` == `enumerated`
- Candidate ledger has no `pending` rows
- User did not freeze early
- No path was acked without its full text being in the batch output

**Partial ship** (`stop and ship partial`): HTML `--strict` may pass **if** Residual lists every skipped HTTP module **and** Checks executed is **not** 109. `validate_http_module_walk` fails fake 109 + empty Residual.

---

## User prompts

The user should not have to prompt again. First chat is the whole review:

```text
Follow exploration-first.md, senior-researcher.md, and large-repo-runner.md.
Run enumerate_inventory.py. Read every config. Walk every HTTP module and every
production file. Write the report in this session. Do not ask the user to continue.
```

The only user phrase that stops early is:

```text
stop and ship partial
```
