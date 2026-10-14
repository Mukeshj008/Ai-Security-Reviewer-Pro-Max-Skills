# Exploration-first review (v4.36 — primary loop)

**You are a senior AppSec engineer.** You find issues by **reading this repository**, not by executing a regex catalog.

Pattern files (`sast_scan_manifest.md`, `secrets-patterns.md`, stack `rg` packs) are **optional hints when you are stuck**. Zero regex hits is **not** coverage. A finished 109-row checklist is **not** coverage.

---

## Standing prompt (follow this every review)

```text
Explore this repository as a human AppSec reviewer would.

1. Map the system: every module, HTTP API, worker/cron/queue, CLI, mobile app,
   Dockerfile/K8s, and every config/profile (.properties, yml, env, json, pem).
2. Read the real files. Do not stop because a pattern list returned nothing.
3. Secrets: open every config and credential-looking file and look with your eyes.
   Java/Spring `key=value` with NO quotes still counts. vault.secret.id,
   datasource passwords, JWT signing secrets, API keys, private keys — all of them.
   Instance table must match what you actually saw, or Residual names unread files.
4. Auth: read middleware/filters AND every route in the current module. Walk methods.
5. Then hunt **logic** per `senior-researcher.md` LOG-01…15: IDOR, tenant mix-up,
   mass assignment, workflow skip, replay, race, client-trusted amounts/headers,
   webhook identity — by following the object and the state machine, not a CWE list.
6. On a large repo, keep reading the next file in `production_must_read_files` in this same
   session until that list is done. Secrets and config are read with the rest of that list — never skip a
   production file because “whole-repo rg is forbidden.” Never stop to ask the user to continue.
7. Every candidate becomes Finding, Tentative, or Appendix A with a reason.
   Unread production files are not allowed. Test files are not a stop condition; name unread tests in Appendix B.
   Do not silent-PASS a production file by putting it in Residual and ending the turn.
8. Do not claim Checks executed: 109 after a P0 slice.
9. **v4.51 — Do not say “scan complete”** until `check_coverage_gate.py` exits 0 (`coverage-complete-gate.md`). P0 webhook/payment slices are order, not stop. Application modules (campaigns, UI, RBAC, channels, ads, AI) must be walked like everything else. Do not print CONTINUE LARGE-REPO.
```

Copy the block into your working notes. Also follow **`senior-researcher.md`** (static + logical). Do not replace either with “run SAST-SECRET-01…12.”

---

## How to explore (tools)

Prefer **file listing + Read** over manifest `rg`.

| Goal | Do this |
|------|---------|
| Inventory | `Glob` / `find` for modules, `*Controller*`, `routes`, `application*.{yml,properties}`, `.env*`, `Dockerfile*`, workers |
| Secrets | **Read** each config/profile (unquoted properties included). List committed credentials. `secrets-patterns.md` only if you need a second pass |
| Auth | **Read** security filter / interceptor / `app.use` then **Read** route files in that module |
| Injection / SSRF | Trace user input from handler → client/query from the file, not from a sink regex |
| Logic / IDOR | Read the handler; change the object id in your head; find the ownership check |
| Stuck | Then use a scoped `rg` as a hint, still validate by reading |

**Forbidden excuses**

- “Pattern scan covered M files”
- “secrets-patterns whole repo already recorded” without a list of configs **Read**
- Skipping `.properties` / `.env` because scan-scope counted only `*.java` / `*.yml`
- Top-15 sampling as the only secret review
- Excluding `scripts/` or `src/test/resources` when they contain live-looking credentials — Residual or finding, not drop

---

## Secrets / config (mandatory, whole tree, once)

Before AUTH module walking:

1. Enumerate **every** `application*.{yml,yaml,properties}`, `bootstrap*`, `.env*`, `appsettings*.json`, `*vault*`, `*.pem`, `*.p12` (exclude `node_modules`, `vendor`, `dist`, `target`).
2. **Read** them. Unquoted `password=`, `secret=`, `token=`, `apiKey=`, `client-secret=` are in scope.
3. Record in session memory: `configs_read: N / M` and unread names as Residual **LEAK/SECRET not read**.
4. Same CWE-798 root cause → one LEAK with **instances**; instance count must not be a sample of hits you saw.

Scan-scope **must** count `*.properties` and `.env*` as analyzed files (`scan-scope-metrics.md`).

---

## Large repo / small model

Walk **every** HTTP module in this session (`weak-model-parity.md`, `large-repo-runner.md`). Do not stop after one module. Do not ask the user to type continue.

Does **not** waive:

- Whole-tree **config Read** at session start (this file)
- Residual names for unwalked HTTP modules
- Researcher-style reading inside the current module (not only the parity `rg` pack)

`rg` packs in `weak-model-parity.md` are **backup probes**, not the review.

---

## Subagents — forbidden

Do not spawn Task, explore, or shard workers. You own every Read, the ledger, G0–G5, flow walks, reachability, severity, and the report. On a large repo, `large-repo-runner.md` — keep going until every route file is read.

---

## When pattern files are OK

After exploration, if you have spare context, run hint `rg` from manifests to catch strings you might have missed. Hits still need Read + G1–G5. Hint `rg` never replaces unread configs or unwalked modules.
