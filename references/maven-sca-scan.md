# Maven / Gradle SCA (SCA-MAVEN-*)

**Goal:** Inventory **all Java production dependencies** from Maven/Gradle manifests, query **OSV** (`ecosystem: Maven`), prove **import + call-site reachability** in `.java`/Kotlin code, and report **Critical/High exploitable only** in the SCA section.

**Agent-only:** You run discovery, `mvn`/`gradle` (when present), `rg`, `Read`, OSV batch, and `graphify path`. No scan scripts.

**Pairs with:** `osv-sca-scan.md` (SCA-OSV-01…05) · `cve-exploitability.md` (CVE-REACH-*) · `SKILL.md` Phase 1c

---

## When to run

| Condition | Action |
|-----------|--------|
| `pom.xml` or `**/pom.xml` present | **Mandatory** Maven SCA |
| `build.gradle` / `build.gradle.kts` present | **Mandatory** Gradle SCA (OSV ecosystem still `Maven`) |
| `gradle.lockfile` present | Prefer locked versions |
| Multi-module repo | Inventory **each module** + parent BOM imports |
| No Java tree | SCA-MAVEN-* → **N/A** in Appendix E |

---

## Phase 1 — Discover manifests (SCA-MAVEN-01)

```bash
# Find all Maven/Gradle roots (exclude build output)
find . \( -name pom.xml -o -name build.gradle -o -name build.gradle.kts \) \
  -not -path '*/target/*' -not -path '*/.gradle/*' 2>/dev/null

rg -l "<project|<dependencies>" --glob "**/pom.xml"
rg -l "implementation|api|compileOnly|runtimeOnly" --glob "**/build.gradle*"
```

Record in report **Dependency Manifests** table:

| Manifest | Present | OSV Scanned | Notes |
|----------|---------|-------------|-------|
| `pom.xml` | Yes/No | Yes/No | path to root or module |
| `pom.xml` (modules) | N | Yes | list module paths |
| `build.gradle(.kts)` | Yes/No | Yes | Gradle → Maven coords for OSV |
| `gradle.lockfile` | Yes/No | Yes | pinned versions |
| `maven-dependency-tree.txt` | optional | — | agent-generated artifact |

---

## Phase 2 — Inventory packages@version (SCA-MAVEN-02)

### Preferred: Maven CLI (when `pom.xml` present)

**Install order:** `./mvnw` → system `mvn` → install Maven per **`dependency-install-policy.md`**. Do **not** fall back to pom.xml-only parse until install attempts fail.

```bash
# Runtime + compile production deps (single module)
mvn -q -f pom.xml dependency:list \
  -DincludeScope=runtime \
  -DoutputFile=/tmp/maven-deps.txt 2>/dev/null

# Include compile scope (default for many Spring apps)
mvn -q -f pom.xml dependency:list \
  -DincludeScope=compile \
  -DoutputFile=/tmp/maven-deps.txt 2>/dev/null

# Full tree with versions (human-readable)
mvn -q -f pom.xml dependency:tree -DoutputType=text 2>/dev/null | head -400

# Multi-module reactor
mvn -q dependency:list -DincludeScope=runtime -DoutputFile=/tmp/maven-deps.txt 2>/dev/null
```

**Parse `dependency:list` lines:** `group:artifact:type:version:scope`  
→ OSV name: **`group:artifact`** · version: **4th field**

**Exclude from production inventory:** `test`, `provided` (unless shipped), `import` BOM-only rows (track BOM separately).

### Fallback: parse `pom.xml` (Maven install failed)

Use only after **`dependency-install-policy.md`** install attempts (including `./mvnw`) fail. Document **FAIL** reason in Appendix F.

```bash
# List dependency coordinates (Read full blocks for version resolution)
rg -n "<dependency>" --glob "**/pom.xml" -A 6

rg -n "<groupId>|<artifactId>|<version>|<scope>" --glob "**/pom.xml"

# Parent / BOM imports
rg -n "<parent>|<dependencyManagement>" --glob "**/pom.xml" -A 8

# Properties used for versions (${spring.version})
rg -n "<properties>" --glob "**/pom.xml" -A 30
```

**Version resolution order (manual):**
1. Explicit `<version>` on dependency
2. `${property}` from `<properties>` or parent POM
3. `<dependencyManagement>` / imported BOM
4. Parent POM `<parent><version>`

Read parent/BOM POMs when version is omitted — **never guess**; note `UNRESOLVED` in inventory if property chain unclear.

### Gradle projects

```bash
# When gradlew present
./gradlew -q dependencies --configuration runtimeClasspath 2>/dev/null | head -300
./gradlew -q dependencies --configuration compileClasspath 2>/dev/null | head -300

# Lockfile (Gradle 6.5+)
rg -n "name=|version=" gradle.lockfile 2>/dev/null
```

Map Gradle notation → OSV Maven name: `group:artifact` (strip `@version` suffix from tree output).

### Inventory output format (working table)

| groupId:artifactId | Version | Scope | Source | Module |
|--------------------|---------|-------|--------|--------|
| org.springframework:spring-web | 5.3.39 | compile | pom.xml | api-module |
| com.fasterxml.jackson.core:jackson-databind | 2.15.2 | compile | transitive | via spring-boot |

**Appendix E:** `SCA-OSV-01` Notes = total unique `group:artifact@version` across all modules.

---

## Phase 3 — OSV querybatch (SCA-MAVEN-03)

OSV ecosystem: **`Maven`**  
Package name: **`groupId:artifactId`** (colon-separated, no version in name)

```bash
# Build queries.json — example entries
# {"package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"}, "version": "2.14.1"}
# {"package": {"name": "org.springframework:spring-core", "ecosystem": "Maven"}, "version": "5.3.39"}

curl -sS -X POST 'https://api.osv.dev/v1/querybatch' \
  -H 'Content-Type: application/json' \
  -d @/tmp/osv-maven-queries.json
```

**Batch rules:**
- Max **1000** queries per batch — split large multi-module trees
- Include **direct + transitive** runtime/compile deps
- Prefer **exact locked version** from `dependency:list` or lockfile

**Optional cross-check (when Maven available):**

```bash
# OWASP dependency-check (local CVE signal — reconcile with OSV)
mvn -q org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=0 2>/dev/null
# Read target/dependency-check-report.json if generated
```

**Severity filter:** Same as `osv-sca-scan.md` — SCA section = **Critical/High only**.

---

## Phase 4 — Java reachability (SCA-MAVEN-04)

For each Critical/High OSV hit, prove use in **application source** (not test-only):

```bash
# Replace GROUP ARTIFACT with Maven coords (escape dots in groupId for rg)
rg -n "import GROUP\.|import static GROUP\." --glob "**/*.{java,kt,kts}" \
  --glob '!**/test/**' --glob '!**/*Test.java'

# Common patterns by artifact
rg -n "import org\.apache\.logging\.log4j|LogManager\.getLogger" --glob "**/*.java"
rg -n "import com\.fasterxml\.jackson|ObjectMapper" --glob "**/*.java"
rg -n "import org\.springframework" --glob "**/*.java"

# XML/Spring config references (beans, classpath)
rg -n "log4j|jackson|spring-beans" --glob "**/*.{xml,yml,yaml,properties}"
```

```bash
graphify query "Spring controller service repository import dependency" --budget 1500
graphify path "@GetMapping" "VULNERABLE_CLASS_OR_METHOD"
graphify path "HttpServletRequest" "VULNERABLE_API_FROM_ADVISORY"
```

**Reachability verdict:**

| Verdict | SCA section | Notes |
|---------|-------------|-------|
| Import + call site in `src/main` | Candidate Step 5 | cite file:line |
| Dependency in pom only, zero imports | **Exclude** | lockfile/transitive unused |
| Test scope only (`src/test`) | **Exclude** | test classpath |
| Provided scope (container supplies) | **Exclude** unless app bundles it | document scope |
| Vulnerable class only in transitive unused jar | **Exclude** | `dependency:analyze` unused |

**Optional:**

```bash
mvn -q -f pom.xml dependency:analyze 2>/dev/null
# Flags unused declared deps — helps transitive noise reduction
```

---

## Phase 5 — Exploitability (SCA-MAVEN-05)

Apply **`cve-exploitability.md`** + OSV advisory **vulnerable function/class**:

1. Read OSV `affected` + advisory text for vulnerable **class/method** (e.g. `JdbcRowSetImpl`, `Log4j lookup`, `SnakeYAML Constructor`).
2. Grep for that symbol in main code.
3. `graphify path` from HTTP/Messaging entry → sink.
4. G1–G5 gates from `manual-code-review.md`.

```bash
rg -n "VULNERABLE_CLASS|VULNERABLE_METHOD" --glob "**/*.{java,kt}" --glob '!**/test/**'
```

**FINDING bar:** Same as npm — **CVE-NNN** only when Critical/High + import + exploitable path.

---

## Report templates

### Dependency Manifests (add to SCA section)

```markdown
| Manifest | Present | OSV Scanned | Packages |
|----------|---------|-------------|----------|
| `pom.xml` | Yes | Yes | 142 direct+transitive |
| `api/pom.xml` | Yes | Yes | 38 (module) |
| `build.gradle` | No | N/A | — |
| `package.json` | Yes | Yes | 3 (Node tooling) |
```

### SCA Summary row (Maven example)

| ID | Severity | CVE / OSV ID | Package@Version | CVSS | Import file:line | Exploit trigger |
|----|----------|--------------|-----------------|------|------------------|-----------------|
| CVE-001 | Critical | CVE-2021-44228 | org.apache.logging.log4j:log4j-core@2.14.1 | 10.0 | UserController.java:45 | JNDI lookup in log pattern |

### Filtered (Maven)

| Package@Version | OSV/CVE | Severity | Reason excluded |
|-----------------|---------|----------|-----------------|
| commons-io:commons-io@2.11.0 | CVE-… | High | Transitive; no import in src/main |

---

## Appendix E rows (Maven)

| ID | Description | When N/A |
|----|-------------|----------|
| SCA-MAVEN-01 | Maven/Gradle manifest discovery | No pom.xml / build.gradle |
| SCA-MAVEN-02 | dependency:list / pom parse inventory | — |
| SCA-MAVEN-03 | OSV querybatch ecosystem Maven | — |
| SCA-MAVEN-04 | Java import reachability | — |
| SCA-MAVEN-05 | Vulnerable API exploitability | — |

Link finding refs to **CVE-NNN** in SCA section. Reconcile with **SCA-OSV-01…05** (same inventory counts).

---

## Multi-ecosystem repos

When repo has **both** `pom.xml` and `package.json`:

1. Run **Maven SCA** (this doc) + **npm OSV SCA** (`osv-sca-scan.md`) in same review.
2. Single **SCA section** — one summary table, separate **Filtered** subtables per ecosystem.
3. **MX-SCA** row count = npm + Maven + RubyGems + … unique packages scanned.

---

## Common pitfalls

| Pitfall | Fix |
|---------|-----|
| Wrong OSV name (`log4j-core` without group) | Always `groupId:artifactId` |
| BOM import counted as direct dep | Track version from BOM; don't double-count |
| Spring Boot starter hides transitive versions | Use `dependency:tree` for resolved versions |
| Kotlin sources skipped | Include `**/*.kt` in reachability rg |
| Android `build.gradle` | Same OSV Maven coords for JVM libs; native AAR → note N/A for OSV Maven |
