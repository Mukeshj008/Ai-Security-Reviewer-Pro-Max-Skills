# Dependency Install Policy (MANDATORY)

When executing **ai-security-reviewer**, **install missing scan dependencies** before marking a check **SKIP** or **FAIL**. Do **not** skip SCA, audit, DAST (via curl), or report steps because a CLI is absent — install it first, then run the check.

**Exceptions — do not auto-install:**
- **Graphify** — use `rg` + manual traces
- **Burp MCP / Burp Suite** — use **terminal curl** for live verification

---

## Install-first rule

| If missing | Install (try in order) | Then run |
|------------|------------------------|----------|
| **npm** / **node** | `brew install node` (macOS) · `apt install nodejs npm` (Debian) · `winget install OpenJS.NodeJS.LTS` (Windows) | `npm audit`, lockfile parse, OSV npm inventory |
| **Maven (`mvn`)** | `brew install maven` · `apt install maven` · SDKMAN / project `./mvnw` | `mvn dependency:list`, SCA-MAVEN-02 |
| **Gradle** | use `./gradlew` if present · else `brew install gradle` | `./gradlew dependencies` |
| **Python 3** | `brew install python3` · `apt install python3` | `generate_html_report.py`, pip-audit if Python SCA |
| **curl** | usually preinstalled · `brew install curl` if needed | OSV API, DAST curl fallback |
| **rg** (ripgrep) | `brew install ripgrep` · `apt install ripgrep` | all SAST manifest `rg` blocks |
| **gitleaks** (optional v4.15) | `brew install gitleaks` · GitHub release binary | `git-history-secrets-scan.md` |
| **trivy** (optional v4.15) | `brew install trivy` · `apt install trivy` | `container-image-scan.md` |
| **gh** (PR tasks only) | `brew install gh` | user-requested PR workflow only |
| **Graphify** | **Do not install** — use fallback below | optional acceleration only |
| **Burp MCP / Burp Suite** | **Do not install** — use curl in terminal | mandatory DAST when host in code |

**Shell permissions:** Request `network` for package installs, OSV API, and **curl DAST probes**; request `all` only if sandbox blocks brew/apt or outbound HTTPS.

**After install:** Re-run the failed command. Mark Appendix E **FAIL** only if install fails after documented attempts; note error in Appendix F.

---

## Graphify exception (mandatory)

| Condition | Action |
|-----------|--------|
| `graphify` not found | **Do not** `pipx install graphifyy` unless user explicitly asks |
| No `graphify-out/graph.json` | Proceed with `rg` + Read; document reachability manually |
| User runs `/graphify .` | Use graph when available — not required for handoff |
| `graphify path` unavailable | Trace source→sink in report with file:line chain from `Read` |

**Appendix E:** `GRAPH-01…03` = **PASS** with note `manual trace (no graphify)` OR **SKIP** only when graph never built **and** manual trace completed for all FINDING candidates.

**Report header:** `Graph Backend: rg + manual trace (graphify not installed)` — not `graphify extract`.

---

## Burp MCP exception (mandatory)

| Condition | Action |
|-----------|--------|
| `user-burp` MCP missing | **Do not** install Burp Suite or MCP extension |
| External host in code | **Run `curl` in terminal** (Shell tool) for **each** AUTH candidate — `curl-dast-fallback.md` |
| `curl` not found | **Install curl** per install-first table, then run probes |
| No external host in code | Skip live DAST — `Not Verified (no target host in code)`; still include Burp PoC block |
| curl attempted, failed (timeout/refused) | **Not Verified** — document command + error in Appendix C |

**Appendix E:** `DAST-AUTH-PROBE` = **PASS** with `Verified in curl` when curl confirms; **FAIL** only if host exists and curl was never run.

**Report header:** `DAST Backend: curl (Burp MCP not present)` — not `Not run` when host exists and curl ran.

---

## Per-phase dependency requirements

| Phase | Required tools | Install if missing |
|-------|----------------|-------------------|
| SAST manifests | `rg` | yes |
| OSV SCA | `curl`, Python 3 (optional helper) | yes |
| npm SCA | `node`, `npm` when `package.json` | yes |
| Maven SCA | `mvn` or `./mvnw` when `pom.xml` | yes — prefer `./mvnw` |
| Gradle SCA | `./gradlew` or `gradle` | yes |
| Ruby SCA | parse `Gemfile.lock` + OSV (no extra CLI) | n/a |
| `npm audit` | `npm` | yes |
| HTML report | `python3` | yes |
| **DAST live verify** | Burp MCP **or** `curl` in terminal | **install curl only** — never install Burp |
| Graphify | optional | **never auto-install** |

---

## What you must NOT skip (after install attempt)

- **SCA-OSV-01…05** when lockfiles/manifests exist
- **SCA-MAVEN-01…05** when `pom.xml` / Gradle exists
- **DEPS-01 / npm audit** when `package.json` exists (add lockfile note if ENOLOCK)
- **generate_html_report.py** at handoff
- **Appendix E row execution** — use FAIL not SKIP when tool install fails

## What may still be SKIP (not install-related)

| Reason | Example |
|--------|---------|
| Stack N/A | TAX-MEM on pure JS site |
| No external Burp host | `burp-host-discovery.md` |
| Graphify absent | GRAPH-* with manual trace done |
| User declined live DAST | document in Appendix F |
| No `pom.xml` | SCA-MAVEN-* = N/A |
| Burp MCP absent | **not** a skip reason — run curl instead |

---

## Appendix F log template

| Phase | Step | Status | Notes |
|-------|------|--------|-------|
| 0 | Tool bootstrap | PASS | Installed node@20 via brew for npm audit |
| 0 | Tool bootstrap | PASS | Used ./mvnw (mvn not in PATH) |
| 0 | Graphify | SKIP | Policy: graphify not installed; manual rg traces |
| 1c | npm audit | PASS | After npm install |
| 1b | DAST (curl) | PASS | Burp MCP absent; curl run for N AUTH candidates |

---

## Completion gate

Before handoff, verify:

```bash
# No unjustified SKIP for missing npm/mvn/python when manifests exist
# Graphify SKIP allowed; npm audit SKIP when no package.json only
```

Report **Dependency Bootstrap** row in Scan Agent attribution table when any install was performed.
