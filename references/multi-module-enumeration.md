# Multi-Module Enumeration (MANDATORY — Phase 0)

**Purpose:** prevent the most common silent miss — scanning only the "main" module of a multi-module repo and ignoring sibling modules that also expose HTTP, configs, and secrets.

**Trigger:** every review on any of these layouts:

| Build system | Trigger |
|--------------|---------|
| Gradle multi-project | `settings.gradle` lists `include` lines, or 2+ `build.gradle` files |
| Maven multi-module | parent `pom.xml` with `<modules>` block |
| pnpm/yarn/npm workspaces | `pnpm-workspace.yaml`, `workspaces` field in `package.json` |
| Cargo workspace | root `Cargo.toml` with `[workspace]` |
| Go workspace | `go.work` |
| Nx / Turborepo / Lerna | `nx.json`, `turbo.json`, `lerna.json` |
| Mono-repo by convention | 2+ directories each containing `src/main/`, `src/`, or service manifest |

If **any** trigger fires, you **must** run this enumeration before SAST manifests. Skipping = automatic `--strict` failure.

---

## Step 1 — Enumerate all modules

```bash
# Gradle
ls -1d */ 2>/dev/null | grep -v '^\(gradle\|out\|build\|node_modules\)/$'
find . -maxdepth 3 -name 'build.gradle*' -o -name 'pom.xml' -o -name 'settings.gradle*' 2>/dev/null

# Maven
rg -n '<module>' pom.xml 2>/dev/null

# JS workspaces
rg -n '"workspaces"' package.json 2>/dev/null
cat pnpm-workspace.yaml 2>/dev/null

# Go workspace
cat go.work 2>/dev/null
```

Record the **module inventory** in agent working notes as:

```
| Module | Has src/main | Has HTTP controllers | Has config files | Has Dockerfile |
|--------|--------------|----------------------|------------------|----------------|
```

Fill the table — one row per module.

---

## Step 2 — Find HTTP controllers in EVERY module (not just the "api" one)

Do not assume any single module owns all HTTP entry points. Run these once across the whole repo:

```bash
# Spring (Java/Kotlin)
rg -l '@RestController|@Controller\b' --type java --type kotlin

# Express / Fastify / Hapi / Koa
rg -l 'router\.(get|post|put|delete|patch)\(|app\.(get|post|put|delete|patch)\(|fastify\.(get|post)' --type js --type ts

# Flask / FastAPI / Django
rg -l '@app\.route|@router\.(get|post)|APIRouter\(|urlpatterns\s*=' --type py

# ASP.NET
rg -l '\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\]' --type cs

# Go (chi/gin/mux/echo)
rg -l '(chi|mux|gin|echo|http)\.(Get|Post|Put|Delete|Patch|HandleFunc)' --type go
```

Every match's directory must appear in the module inventory. If a module has 0 controllers, mark "no HTTP" — but still scan it for **secrets** and **deserialization sinks** (some controllers live in cache-consumers / migration jobs / cron services).

---

## Step 3 — Find ALL configuration profiles (do not sample)

Almost every gap-analysis miss for secrets came from skipping profile files. Read **every** profile file in every module:

```bash
# Spring profiles
rg --files-with-matches -g 'application*.{yml,yaml,properties}' .

# Generic
rg --files-with-matches -g '*.{yml,yaml,properties,env,conf,toml,ini}' \
   -g '!**/node_modules/**' -g '!**/build/**' -g '!**/target/**' .

# Dockerfiles (including alpine, debian, prod variants)
rg --files-with-matches -g 'Dockerfile*' .
```

**Mandatory:** read **every** `application-*.yml`/`application-*.properties` file in every module, not just `application.yml` or `application-prod.yml`. Common environments (`dev`, `dev-local`, `qa`, `qa-staging`, `uat`, `pre-prod`, `pre-prod-read`, `pre-prod-write`, `perf`, `perf-read`, `perf-write`, `prod`, `prod-read`, `prod-write`) all need to be scanned — credentials often differ per profile.

Cross-check with **`multi-profile-config-audit.md`** for the per-profile completeness gate.

---

## Step 4 — Find ALL Dockerfiles, not just the one at root

```bash
rg --files-with-matches -g 'Dockerfile*' .   # catches Dockerfile-alpine, Dockerfile.prod, etc.
```

Read each one and audit per `iac-misconfig-scan.md`. A second Dockerfile that ships the same image with different defaults is a common miss.

---

## Step 5 — Record results in the report

Add to **Scan Attestation Summary**:

```markdown
### Module & Profile Enumeration
| Modules detected | N |
| Modules scanned | N |
| HTTP controllers per module | api: 47, recon-service: 1, handle-bulk-migration-service: 1, ... |
| Profile config files scanned | 14 of 14 |
| Dockerfiles scanned | 2 of 2 |
```

If `Modules scanned < Modules detected` or `Profile config files scanned < total`, the **`--strict`** HTML run must fail.

---

## Common silent-miss patterns this step prevents

| Silent miss | Root cause | Prevention |
|-------------|-----------|-----------|
| Secrets only flagged in `api/`, missed in `cache-consumer/`, `migration-service/`, etc. | "I scanned the main module" | Step 3 + per-module inventory in Scan Attestation |
| Unauth controllers in `recon-service/`, `handle-bulk-migration-service/` | "Other modules are background jobs only" | Step 2 — actually grep all modules for HTTP annotations |
| `Dockerfile-alpine` ships with `-Dspring.profiles.active=dev` while `Dockerfile` is fixed | "There is one Dockerfile" | Step 4 — `Dockerfile*` glob |
| Production-profile YAML never read because only `application-uat.yml` was sampled | "uat is representative" | Step 3 — read **every** profile, not one sample |
