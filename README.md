# AI Security Reviewer

Cursor agent skill: **you** read first-party code, trace source→sink, and write `<repo>_security_report.md` + HTML.

**Version:** see `SKILL.md` (currently **4.48.0**).

**Install:** clone/copy to `~/.cursor/skills/ai-security-reviewer`, attach the skill, ask for a security review.

## Contract (short)

- **Single agent** — no Task workers or shard subagents (`large-repo-runner.md` for big repos).
- **No SCA** — no `npm audit`, OSV, trivy, or `SCA-NNN` findings (v4.46+).
- **Helpers only:** `enumerate_inventory.py`, `derive_report_name.py`, `generate_html_report.py --strict`.
- **DAST:** Burp PoC on every HTTP finding; live `curl` only with user approval.

Full rules: `SKILL.md`. History: `CHANGELOG.md`.
