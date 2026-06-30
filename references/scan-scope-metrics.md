# Scan Scope Metrics (Files & Lines of Code)

Mandatory counts for every **`security_report.md`** Executive Summary. Full coverage context: **`vulnerability-coverage-overview.md`**.

---

## When to run

**Phase −1** (application context) or **Phase 0a** (tool bootstrap) — **before** SAST manifests.

---

## What to count

### Include

Application source and config that security checks target:

- Source: `*.js`, `*.jsx`, `*.ts`, `*.tsx`, `*.vue`, `*.html`, `*.css`, `*.scss`, `*.java`, `*.kt`, `*.py`, `*.go`, `*.rb`, `*.php`, `*.cs`
- Config/IaC: `*.xml`, `*.yaml`, `*.yml`, `*.json`, `Dockerfile*`, `*.tf`, `*.hcl`, `*.conf`

### Exclude

- `node_modules/`, `vendor/`, `.git/`, `dist/`, `build/`, `target/`, `graphify-out/`
- Generated/minified-only trees unless they are the only deployable source
- Skill scan scripts and `.cursor/` (not project code)

Document any project-specific exclusions in **Appendix F**.

---

## Commands (agent runs in Shell)

```bash
PRUNE='\( -path ./node_modules -o -path ./.git -o -path ./vendor -o -path ./dist -o -path ./build -o -path ./target -o -path ./graphify-out \) -prune -o'
EXT='\( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" -o -name "*.vue" \
  -o -name "*.html" -o -name "*.css" -o -name "*.scss" \
  -o -name "*.java" -o -name "*.kt" -o -name "*.py" -o -name "*.go" -o -name "*.rb" -o -name "*.php" -o -name "*.cs" \
  -o -name "*.xml" -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" \
  -o -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.tf" -o -name "*.hcl" \)'

# Files analyzed
find . $PRUNE -type f $EXT -print | wc -l

# Lines of code
find . $PRUNE -type f $EXT -print0 | xargs -0 wc -l 2>/dev/null | tail -1
```

Parse the `total` line from `wc -l` for **Lines of Code**.

---

## Report fields (mandatory)

In **Executive Summary → Scan Metrics**:

```markdown
| Files Analyzed | 42 |
| Lines of Code | 15,987 |
```

Also mirror in **`## Vulnerability Coverage Overview`** (see `vulnerability-coverage-overview.md`).

**HTML export (v4.10+):** The markdown tables above are the **data source** for `parse_executive_metrics()`. The HTML generator renders them **once** as the KPI dashboard — it does **not** repeat Files/LOC/Checks/SCA in scope bar + KPI grid + strip + table.

**Completion gate:** Both values must be **numeric and > 0** for repos with source code. Static-only or empty repos: document `0` with reason in Appendix F.

---

## Appendix F log row

| Phase | Step | Command / Tool | Status | Notes |
|-------|------|----------------|--------|-------|
| −1 | Scan scope | `find` + `wc -l` | PASS | N files · M LOC |
