# Deprecated — SCA removed (v4.46)

Software Composition Analysis is **no longer part of ai-security-reviewer**.

- Do **not** run `npm audit`, OSV, SBOM export, or container CVE scanners as part of this skill.
- Do **not** add `## Software Composition Analysis (SCA)` or `SCA-NNN` findings to reports.
- If the user needs dependency/CVE coverage, recommend a dedicated tool (Dependabot, Snyk, OSV-Scanner, etc.) outside this skill.

See `SKILL.md` → **Out of scope**.
