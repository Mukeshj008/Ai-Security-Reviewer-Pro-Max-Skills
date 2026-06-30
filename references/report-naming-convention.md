# Report File Naming Convention (MANDATORY — v4.20)

The final user-facing report files (`*.md` and `*.html`) must be **prefixed with a clean repository name** so multiple scans in the same downloads / scratch directory do not collide and so the filename is immediately meaningful in chat threads, ticket attachments, and SIEM/SOAR ingestion.

## Output filenames

```
<repo>_security_report.md
<repo>_security_report.html
<repo>_security_report_gap_analysis.md     # if a gap-analysis pass was run
```

Where `<repo>` is derived from the **workspace root directory name** using the algorithm below.

## Derivation algorithm

Given the absolute path of the workspace root (e.g. `/Users/me/Downloads/acmeteam-oauth-user-mgmt-service-48e5b67f7489`):

1. **Take the basename** — `acmeteam-oauth-user-mgmt-service-48e5b67f7489`.
2. **Lowercase** it.
3. **Strip leading org / team prefixes** (case-insensitive, one or more in a row, each followed by a `-` or `_`):

   | Default blocklist (extend as needed) |
   |--------------------------------------|
   | `acmeteam`, `acme`, `acmelabs`, `acme-internal`, `team`, `org`, `internal`, `corp`, `eng`, `engineering`, `infra`, `platform`, `dev`, `prod`, `staging`, `qa`, `uat`, `gh`, `github`, `gitlab`, `bitbucket`, `bb`, `customer`, `client` |

   Add org-specific prefixes with `--extra-prefix` on `derive_report_name.py` (repeatable).

4. **Strip trailing hash / numeric tokens** (Bitbucket / GitHub Cloud / Cursor / archive suffixes):

   - `-?[0-9a-f]{6,40}` — git short-hash or full SHA (e.g. `-48e5b67f7489`, `-a1b2c3d4`)
   - `-?\d{6,}` — purely numeric (e.g. `-20260630`, `-1719764400`)
   - `-?v?\d+(\.\d+){1,3}` — trailing semver-ish version (e.g. `-v1.2.3`)
   - `[-_]?(main|master|develop|release)` — trailing default-branch tokens added by some download flows

   Apply repeatedly until no more match (some archives append both a SHA and a branch).

5. **Sanitize** — replace any non `[a-z0-9._-]` character with `-`, collapse consecutive `-`, trim leading/trailing `-_.`.

6. **Fallback** — if the result is empty (everything was stripped), use the **un-stripped, sanitized basename**. Never write a file named just `_security_report.md`.

## Examples

| Workspace basename | Derived `<repo>` | Output |
|--------------------|------------------|--------|
| `acmeteam-oauth-user-mgmt-service-48e5b67f7489` | `oauth-user-mgmt-service` | `oauth-user-mgmt-service_security_report.md` |
| `acme-checkout-api-a1b2c3d` | `checkout-api` | `checkout-api_security_report.md` |
| `acmeteam-acme-wallet-service-20260630-3f9a1b2c` | `wallet-service` | `wallet-service_security_report.md` |
| `internal-fraud-rules-engine` | `fraud-rules-engine` | `fraud-rules-engine_security_report.md` |
| `gh-acme-corp-orders-svc-v1.2.3` | `acme-corp-orders-svc` | `acme-corp-orders-svc_security_report.md` |
| `acmeteam-acme-checkout-v1.4.2-3f9a1b2c-main` | `checkout` | `checkout_security_report.md` |
| `react_native_app` (underscores normalised) | `react-native-app` | `react-native-app_security_report.md` |
| `48e5b67f7489` (only a hash) | `48e5b67f7489` (fallback) | `48e5b67f7489_security_report.md` |
| `my-side-project` | `my-side-project` | `my-side-project_security_report.md` |

## Override

If the user supplies an explicit project name with `--project "Foo Bar"` (or in chat), use a **sanitized** version of that string instead of the derived one:

```
project = "Acme OAuth UMS"  →  <repo> = "acme-oauth-ums"
```

User-supplied always wins over derivation.

## Reference implementation

The helper script `scripts/derive_report_name.py` implements this algorithm. Agents should call it once per review and use its stdout as `<repo>`:

```bash
REPO=$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)
# REPO=oauth-user-mgmt-service

MD="${REPO}_security_report.md"
HTML="${REPO}_security_report.html"
```

The script accepts:

| Flag | Default | Purpose |
|------|---------|---------|
| `--workdir PATH` | `$PWD` | Workspace root |
| `--project STR`  | (none) | User override; bypasses derivation |
| `--extra-prefix PREFIX` | (none, repeatable) | Add a custom org prefix to strip |
| `--suffix STR` | `_security_report` | Allows reuse for related artifacts (e.g. `_security_report_gap_analysis`) |
| `--ext STR` | (none) | If set, appends `.<ext>` to the output |

Examples:

```bash
# Just the repo slug
python3 derive_report_name.py
# → oauth-user-mgmt-service

# Full md filename
python3 derive_report_name.py --suffix _security_report --ext md
# → oauth-user-mgmt-service_security_report.md

# Gap-analysis filename
python3 derive_report_name.py --suffix _security_report_gap_analysis --ext md

# User override
python3 derive_report_name.py --project "Acme OAuth UMS" --suffix _security_report --ext html
# → acme-oauth-ums_security_report.html
```

## When to apply

| Phase | Action |
|-------|--------|
| Phase 11 (write `security_report.md`) | Save as `<repo>_security_report.md` |
| Phase 12 (HTML export) | `generate_html_report.py <repo>_security_report.md -o <repo>_security_report.html` |
| Optional gap-analysis pass | `<repo>_security_report_gap_analysis.md` |
| Baseline-delta pass (`baseline-delta-report.md`) | Compare against the previous `<repo>_security_report.md` in the same directory |

## Migration of existing reports

When entering a workspace that has the legacy `security_report.md` / `security_report.html`, rename them in place to the new convention so subsequent runs do not produce confusingly-named siblings:

```bash
REPO=$(python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py)
for f in security_report.md security_report.html security_report_gap_analysis.md security_report_delta.md; do
  if [ -f "$f" ]; then
    # Keep the literal "_security_report" stem in the new filename;
    # ${f#security_report} only strips that exact stem and leaves ".md", ".html",
    # "_gap_analysis.md", "_delta.md", etc.
    dest="${REPO}_security_report${f#security_report}"
    mv "$f" "$dest" && echo "renamed: $f → $dest"
  fi
done
```

The rename is idempotent (no-op once the `<repo>_` prefix is in place because the legacy `security_report.*` filenames no longer exist).
