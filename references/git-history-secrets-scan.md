# Git History Secrets Scan (additive)

**Purpose:** Find credentials removed from current tree but still in git history. **Adds** to SAST-SECRET live-tree scan — does not replace it.

---

## When to run

- Any repo with `.git` present
- After SAST-SECRET hits or high-sensitivity project (payments, prod configs)

---

## Agent execution (no skill scripts)

### 1. TruffleHog / gitleaks (if installed)

```bash
# Install if missing — dependency-install-policy: optional brew/npm
which gitleaks || which trufflehog

# gitleaks (read-only detect)
gitleaks detect --source . --no-git -v 2>/dev/null | head -50
gitleaks detect -v 2>/dev/null | head -50

# trufflehog git
trufflehog git file://. --json 2>/dev/null | head -20
```

If CLI missing: **install per `dependency-install-policy.md`** or fall back to step 2.

### 2. git log fallback (always available)

```bash
git log -p --all -S 'password' -- '*.properties' '*.yml' '*.env*' 2>/dev/null | head -100
git log -p --all -S 'AKIA' 2>/dev/null | head -50
git log -p --all -S 'BEGIN RSA PRIVATE KEY' 2>/dev/null | head -30
```

### 3. AI validation

- **TRUE POSITIVE:** Real secret in historical commit, not rotated, still valid format.
- **FALSE POSITIVE:** Test fixture, revoked key, already removed from all branches.

---

## Report

| Outcome | Action |
|---------|--------|
| Active secret in history | **VULN-NNN** — Secret Type per `secret-type-labels.md`; Burp PoC N/A |
| Rotated / revoked | Appendix A |
| Scan skipped (no git) | N/A in attestation |

```markdown
### Git History Secrets (summary)

| Tool | Commits scanned | Hits | Finding refs |
|------|-----------------|------|--------------|
| gitleaks | full history | 0 | — |
```

Log command in **Appendix F**.
