# OSV Software Composition Analysis (SCA-OSV-*)

**Goal:** Enumerate **all third-party libraries** used by the application, fetch **CVE/advisory details from OSV**, prove **reachability and exploitability in application code**, and report **only Critical/High reachable exploitable** issues in a dedicated **SCA** report section.

**Philosophy:** `npm audit` alone is noisy. OSV is the **authoritative advisory source**; your job is reachability + exploitability filtering — same bar as `cve-exploitability.md`, stricter output rules for the SCA section.

**Agent-only:** You run inventory, OSV queries, `rg`, and reachability traces yourself. No scan scripts.

**Tool bootstrap:** If `node`, `npm`, `mvn`, `python3`, or `curl` is missing, **install per `dependency-install-policy.md`** before skipping SCA or `npm audit`. **Do not install Graphify.**

---

## When to run

- **Mandatory** on every review after lockfile discovery (Phase 1c, alongside `cve-exploitability.md`).
- Run **before** writing Detailed Findings — SCA section is populated from this phase only.

---

## Phase 1c-OSV: Full third-party library scan

### Step 1 — Inventory all production dependencies (SCA-OSV-01)

**Include:** direct `dependencies` + production `optionalDependencies` + **transitive** packages that ship in the runtime bundle (from lockfile).

**Exclude:** `devDependencies` unless the repo ships them to production (e.g. bundled CLI). Default: **production tree only**.

**Java/Maven/Gradle:** When `pom.xml` or `build.gradle(.kts)` exists, run **`maven-sca-scan.md`** (SCA-MAVEN-01…05) **in addition** to npm/Python steps below. OSV ecosystem = **`Maven`**, package name = **`groupId:artifactId`**.

```bash
# --- Maven / Gradle (SCA-MAVEN-01…02) — see maven-sca-scan.md ---
find . \( -name pom.xml -o -name build.gradle -o -name build.gradle.kts \) \
  -not -path '*/target/*' -not -path '*/.gradle/*' 2>/dev/null

# Preferred when mvn available — if `mvn: command not found`, try `./mvnw` then install Maven per dependency-install-policy.md
mvn -q -f pom.xml dependency:list -DincludeScope=runtime -DoutputFile=/tmp/maven-deps.txt 2>/dev/null
mvn -q -f pom.xml dependency:tree -DoutputType=text 2>/dev/null | head -400

# Fallback: parse pom.xml
rg -n "<dependency>" --glob "**/pom.xml" -A 6

# Gradle
./gradlew -q dependencies --configuration runtimeClasspath 2>/dev/null | head -300

# --- Node/npm ---
node -e "const p=require('./package.json'); console.log(Object.keys(p.dependencies||{}).sort().join('\n'))"

# Locked versions (npm v7+ lockfile)
node -e "
const lock=require('./package-lock.json');
const pkgs=lock.packages||{};
for (const [path, meta] of Object.entries(pkgs)) {
  if (!path || path==='' || !meta.version) continue;
  const name=path.replace(/^node_modules\\//,'').split('node_modules/').pop();
  if (name && !name.startsWith('@types/')) console.log(name+'@'+meta.version);
}
" 2>/dev/null | sort -u | head -500

# Python (if present)
# pip freeze 2>/dev/null || rg '^[a-zA-Z]' requirements.txt

# Ruby (if present)
# rg '^\s+spec\.' Gemfile.lock
```

Record: **package name**, **exact locked version**, **ecosystem** (`npm`, `PyPI`, **`Maven`** (`groupId:artifactId`), `Go`, `crates.io`, `RubyGems`).

**Maven naming for OSV:** `org.springframework:spring-core@5.3.39` → query `{"name":"org.springframework:spring-core","ecosystem":"Maven","version":"5.3.39"}`.

**Internal scan log:** `SCA-OSV-01` — Status PASS when inventory complete; Notes = count of unique packages.

---

### Step 2 — Query OSV for advisories (SCA-OSV-02)

Use **[OSV API](https://google.github.io/osv.dev/)** — not only `npm audit`.

**Single package:**
```bash
curl -sS -X POST 'https://api.osv.dev/v1/query' \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"express","ecosystem":"npm"},"version":"4.12.4"}'
```

**Batch (preferred — up to 1000 per request):**
```bash
# Build queries JSON from inventory, then:
curl -sS -X POST 'https://api.osv.dev/v1/querybatch' \
  -H 'Content-Type: application/json' \
  -d @/tmp/osv-queries.json
```

`queries.json` shape:
```json
{
  "queries": [
    {"package": {"name": "express", "ecosystem": "npm"}, "version": "4.12.4"},
    {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.21"},
    {"package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"}, "version": "2.17.1"}
  ]
}
```

**Parse each `vulns[]` entry:**
| Field | Use |
|-------|-----|
| `id` | OSV ID (e.g. `GHSA-xxxx`, `CVE-YYYY-NNNN`) |
| `summary` | Short title for report |
| `details` | Exploit context |
| `severity[]` / `database_specific` | Filter Critical/High |
| `affected[].ranges` | Confirm version in range |
| `aliases` | Map to CVE ID when present |

**Severity filter (SCA section only):**
- **Include:** CVSS ≥ 7.0, or OSV/database severity **HIGH** / **CRITICAL**
- **Exclude from SCA section:** Medium, Low, unspecified — note count in SCA summary table as "filtered out"

**Fallback:** If OSV returns empty but `npm audit` flags Critical/High for same package@version, use npm advisory + cross-check on [osv.dev](https://osv.dev) manually. Prefer OSV CVE ID when both exist.

**Internal scan log:** `SCA-OSV-02` — FINDING if any Critical/High advisories returned; Notes = advisory count before reachability filter.

---

### Step 3 — Reachability proof (SCA-OSV-03)

For **each** Critical/High OSV hit, prove the package is used in **application code** (not lockfile-only):

```bash
# --- Java / Maven (see maven-sca-scan.md SCA-MAVEN-04) ---
rg -n "import GROUP_ID\.|import static GROUP_ID\." --glob "**/*.{java,kt}" \
  --glob '!**/test/**' --glob '!**/*Test.java'

# --- Node/npm ---
# Replace PACKAGE with npm package name
rg -n "require\(['\"]PACKAGE['\"]\)|from ['\"]PACKAGE['\"]|import\(['\"]PACKAGE" \
  --glob '!node_modules' --glob '!test/**' --glob '!tests/**' .

# Scoped packages: escape @
rg -n "require\(['\"]@scope/PACKAGE['\"]\)" --glob '!node_modules' .
```

```bash
graphify query "require import PACKAGE dependency" --budget 1500
graphify path "router.get" "require('PACKAGE')"
graphify path "req.body" "VULNERABLE_API_FROM_ADVISORY"
```

**Reachability verdict:**

| Verdict | SCA section | Appendix A note |
|---------|-------------|-----------------|
| Import in `src/`, `app.js`, routes, handlers | Candidate for Step 4 | — |
| Lockfile only, zero app imports | **Exclude** | "OSV advisory present; not imported in app code" |
| devDependency only | **Exclude** | "Dev-only; not in production runtime" |
| Transitive — app calls wrapper that uses vuln API | **Include** if path proven | Document wrapper chain |

---

### Step 4 — Exploitability in this codebase (SCA-OSV-04)

Apply **`cve-exploitability.md`** AI checklist **plus** OSV-specific context:

```
┌─────────────────────────────────────────────────────────────────┐
│ OSV SCA EXPLOITABILITY CHECKLIST (mandatory)                    │
├─────────────────────────────────────────────────────────────────┤
│ 1. OSV/CVE ID + severity Critical/High confirmed                │
│ 2. Installed version in affected range (lockfile)               │
│ 3. Production dependency (not dev-only)                         │
│ 4. require/import in app code (rg + Read)                       │
│ 5. Vulnerable API/function from advisory used? (Read call sites) │
│ 6. graphify path: HTTP/cron/MQ → vulnerable call              │
│ 7. Attacker can trigger path without auth OR stolen creds enough│
│ 8. Compensating control blocks exploit → downgrade / exclude    │
├─────────────────────────────────────────────────────────────────┤
│ VERDICT: SCA_EXPLOITABLE | SCA_NOT_REACHABLE | SCA_NOT_APPLICABLE│
└─────────────────────────────────────────────────────────────────┘
```

**SCA_EXPLOITABLE only when:** steps 1–6 pass and G1–G5 from `manual-code-review.md` pass.

**Read advisory details:** Identify the **vulnerable function** (e.g. `ejs.render`, `jwt.verify` without algorithms, `qs.parse`). Grep for that symbol:

```bash
rg -n "VULNERABLE_METHOD|VULNERABLE_CLASS" --glob '!node_modules' src/ app.js
```

---

### Step 5 — Report in SCA section only (SCA-OSV-05)

**Finding ID:** Use **CVE-NNN** (same series as dependency CVEs) **inside** the SCA section, or **SCA-NNN** if you need a distinct ID — **prefer CVE-NNN** when a CVE alias exists.

**SCA section rules (strict):**
- **Only Critical and High** severities
- **Only SCA_EXPLOITABLE** verdict
- **No** unreachable lockfile-only advisories
- **No** Medium/Low in SCA section (may appear in appendix summary counts only)

Duplicate CVE already in Detailed Findings from `npm audit` path → **one finding**, cross-reference in both places or keep single canonical entry under SCA with link from summary table.

---

## SCA report section template (mandatory in `security_report.md`)

Place **after** Executive Summary / Findings Summary Table, **before** Detailed Findings (or immediately after Detailed Findings if you prefer CVE narrative there — **SCA summary table is mandatory either way**).

```markdown
## Software Composition Analysis (SCA)

**Source:** [OSV API](https://osv.dev) + lockfile inventory + code reachability  
**Scope:** Production third-party libraries only  
**Packages scanned:** N  
**OSV advisories (Critical/High):** M  
**Reachable + exploitable in code:** K  

### SCA Summary Table (Critical/High — exploitable only)

| ID | Severity | CVE / OSV ID | Package@Version | CVSS | **KEV** | Reachability | Import file:line | Exploit trigger |
|----|----------|--------------|-----------------|------|---------|--------------|------------------|-----------------|
| CVE-001 | High | CVE-2024-XXXXX | express@4.12.4 | 7.5 | No | All HTTP traffic | app.js:7 | Public HTTP request |
| CVE-002 | High | GHSA-xxxx | request@2.88.2 | 8.1 | Outbound HTTP | request.js:2 | Provider URL handling |

### SCA Packages Filtered Out (do not remediate from SCA alone)

| Package@Version | OSV ID | Severity | Reason excluded |
|-----------------|--------|----------|-----------------|
| minimist@1.2.5 | CVE-... | High | Not imported in application code |
| webpack@4.x | CVE-... | Critical | devDependency only |

### SCA Detailed Findings

[Each SCA_EXPLOITABLE item: full CVE-NNN format from SKILL.md — Vulnerable Code Snippet, Data Flow Trace, Remediation]

*Unreachable Critical/High OSV hits: N — see table above. No action required until package is imported or promoted to production.*

*Moderate/Low OSV advisories: M scanned — omitted from summary (Critical/High reachable exploitable only).*

*KEV column:* per `kev-prioritization.md` — query CISA catalog for each C/H CVE.
```

---

## Ecosystem mapping

| Lockfile / manifest | OSV ecosystem | Package name format |
|-------------------|---------------|---------------------|
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `npm` | `package-name` |
| `requirements.txt`, `Pipfile.lock`, `poetry.lock` | `PyPI` | `package-name` |
| **`pom.xml`**, **`build.gradle`**, `gradle.lockfile` | **`Maven`** | **`groupId:artifactId`** |
| `go.mod` | `Go` | `module/path` |
| `Cargo.lock` | `crates.io` | `crate-name` |
| `composer.lock` | `Packagist` | `vendor/package` |
| `Gemfile.lock` | `RubyGems` | `gem-name` |

**Full Maven/Gradle workflow:** `references/maven-sca-scan.md`

---

## Appendix E rows

| ID | Description |
|----|-------------|
| SCA-OSV-01 | Production dependency inventory from lockfile |
| SCA-OSV-02 | OSV querybatch / per-package CVE lookup |
| SCA-OSV-03 | Import reachability (`rg` + graphify) |
| SCA-OSV-04 | Vulnerable API exploitability in code paths |
| SCA-OSV-05 | SCA section written — Critical/High exploitable only |

---

## Integration with `cve-exploitability.md`

| Step | `npm audit` | OSV SCA |
|------|-------------|---------|
| Discovery | Fast local signal | Authoritative CVE IDs + aliases |
| Scope | npm only | Any ecosystem via lockfile |
| Output | Appendix E DEPS-01 | Dedicated **SCA** section |
| Finding bar | CVE-NNN if exploitable | Same bar — **stricter display** (CH only in SCA table) |

Run **both** `npm audit` (DEPS-01) and OSV batch (SCA-OSV-02). Reconcile duplicates; OSV CVE ID wins for report title.
