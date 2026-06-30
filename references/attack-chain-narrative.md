# Attack Chain Narratives (additive — optional user report section)

**Purpose:** Compose multi-finding kill chains for stakeholders. **Optional** — does not replace individual VULN entries.

**Placement:** After **Top Structural Risks**, before **Security Verification Checklist**.

---

## When to include

- ≥2 findings that chain (e.g. unauth endpoint + sensitive actuator + weak JWT)
- Architect review (ARCH-03) identified combined impact

---

## Template

```markdown
## Attack Chain Analysis

### Chain 1: Unauthenticated catalog leak → reconnaissance [VULN-001 → VULN-004]

| Step | Finding | Action | Result |
|------|---------|--------|--------|
| 1 | VULN-001 | GET /v1/test without auth | Internal catalog metadata exposed |
| 2 | VULN-004 | ?debug_panel=true on staging | Framework versions disclosed |
| 3 | — | Attacker maps CVE surface | Targeted exploit planning |

**Impact:** Confidentiality HIGH · No single finding shows full chain — combined severity **High**.

### Chain 2: [title]

...
```

---

## Rules

- Link only **confirmed** findings (checklist IDs).
- Do **not** inflate severity — chain documents **combined narrative**, individual CVSS unchanged.
- Hypothetical steps → mark **Assumption** column.

**Internal STRIDE / trust boundaries** remain in agent notes per `security-architect.md` — chains are the user-facing slice.
