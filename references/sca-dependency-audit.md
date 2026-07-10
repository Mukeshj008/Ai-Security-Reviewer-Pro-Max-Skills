# SCA Dependency Audit (Explicit Mode Only)

Default reviews are code-only. Use this file only when the user explicitly asks for SCA, dependency audit, full-spectrum review, dependency health, or supply-chain coverage.

## Rules

- Keep SCA separate from first-party code findings.
- Use `SCA-NNN` IDs only in explicit SCA mode.
- Do not report advisory-only issues as `VULN-NNN`.
- Prefer package-manager/advisory tooling over custom scripts.
- Still verify exploitability where practical by locating imports/call sites in first-party code.
- Mark unreachable or unused vulnerable packages separately from reachable vulnerable usage.

## Manifest Discovery

```bash
rg --files -g 'package.json' -g 'package-lock.json' -g 'pnpm-lock.yaml' -g 'yarn.lock' \
  -g 'pom.xml' -g 'build.gradle' -g 'build.gradle.kts' -g 'requirements*.txt' \
  -g 'pyproject.toml' -g 'Pipfile.lock' -g 'poetry.lock' -g 'go.mod' -g 'Cargo.toml'
```

Read manifests and lockfiles sufficiently to identify ecosystems and package-manager commands.

## Tooling By Ecosystem

Use the repo's package manager where available:

| Ecosystem | Preferred command |
|-----------|-------------------|
| npm/yarn/pnpm | `npm audit --json`, `yarn npm audit --json`, or `pnpm audit --json` |
| Maven | `mvn org.owasp:dependency-check-maven:check` only when project already uses it; otherwise document residual or use organization-approved SCA |
| Gradle | existing dependency/security task if present; otherwise document residual or use organization-approved SCA |
| Python | `pip-audit` only if available/approved; otherwise document residual |
| Go | `govulncheck` only if available/approved |
| Rust | `cargo audit` only if available/approved |

Do not install heavy scanners or container scanners unless the user approves. If a tool is missing and install is not approved, mark SCA residual rather than inventing results.

## SCA Finding Confidence

| Confidence | Criteria |
|------------|----------|
| Confirmed | Vulnerable dependency present + vulnerable first-party call path/import/use is reachable |
| Firm | Vulnerable dependency present in runtime dependency tree; reachable usage plausible but not fully traced |
| Tentative | Dev/test-only or transitive package with unclear runtime use |

## Report Section

Only in explicit SCA mode:

```markdown
## Software Composition Analysis (SCA)

| ID | Severity | Package | Version | Advisory | Reachability | Confidence | Remediation |
|----|----------|---------|---------|----------|--------------|------------|-------------|
```

For each `SCA-NNN`, include:

- package and version evidence
- advisory/source URL if tool provided one
- runtime vs dev/test scope
- first-party import/call-site evidence when available
- recommended fixed version or mitigation

## Residual Register

If SCA was not requested or tooling was unavailable:

`Residual — SCA not assessed in code-only mode / tooling unavailable / install not approved.`
