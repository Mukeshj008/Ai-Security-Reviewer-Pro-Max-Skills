# AI Security Reviewer Pro Max Skills

**AI Security Reviewer Pro Max Skills** turns an AI coding agent into a disciplined senior AppSec reviewer: it reads first-party code, builds an application threat model, traces source-to-sink and business flows, applies strict true-positive gates, and produces a professional markdown + HTML security report.

It is built for teams that want more than a regex/Semgrep-style pass: fewer false positives, deeper authorization and business-logic reasoning, better evidence, and a repeatable completion gate.

**Version 4.59.0**

**GitHub:** https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills  
**Docs:** https://mukeshj008.github.io/Ai-Security-Reviewer-Pro-Max-Skills/

Search: `AI Security Reviewer Pro Max Skills` · `Mukeshj008 Ai-Security-Reviewer-Pro-Max-Skills`

---

## Why This Skill Is Different

- **Senior AppSec mindset** — the agent starts with assets, actors, trust boundaries, sensitive operations, state transitions, and attacker stories before reporting anything.
- **Two-lane scanning** — run conventional static SAST findings, logical/business findings, or both from one file walk.
- **Scanner blind-spot coverage** — catches issues pattern scanners often miss: IDOR/BOLA, BFLA, workflow skips, webhook trust, replay/race/idempotency, tenant mix-ups, and bypasses of controls that look safe.
- **False-positive discipline** — every finding must pass G0-G5, class-specific adjudication, and `ai-validate-precision-pass.md`; false positives go to Appendix A only.
- **Coverage discipline** — no “scan complete” claim until `check_coverage_gate.py` passes against every `must_read_files` path.
- **Report-ready output** — produces `<repo>_security_report.md` and `<repo>_security_report.html` with executive summary, evidence, Burp PoCs, remediation, residual risk, and attestation.

## Core Capabilities

| Capability | What It Does |
|------------|--------------|
| Static SAST lane | Finds direct injection, dangerous APIs, hardcoded secrets, weak crypto/TLS, handler-local missing auth, CORS/header issues, open redirects, XML/XXE, and single-file IaC/mobile issues. |
| Logical lane | Finds business/auth/trust-boundary bugs: IDOR/BOLA, BFLA, mass assignment, workflow bypass, replay/race/idempotency, webhook identity, tenant confusion, async/second-order flows, and multi-file IaC/CI relationships. |
| Control-bypass review | Looks for High/Critical XSS, SSRF, SQLi, command injection, path traversal, XXE, SSTI, open redirect, or deserialization fixes that exist but can be bypassed through a reachable path. |
| Mobile and deeplinks | Reviews manifest-to-code flows, exported components, deep links, WebView bridges, app links, intent redirection, token/session exposure, and sensitive local storage when present. |
| IaC / CI review | Reviews Docker, Kubernetes, Terraform, CI permissions, workflow injection, mutable images, secrets in layers, and multi-file cloud/IAM relationships. |
| DAST-ready evidence | Writes Burp Suite PoC requests for every HTTP finding; live curl is optional and only with user permission. |

## Scan Modes

`references/scan-modes.md` is the single mode switch.

| Mode | What Runs | Best For |
|------|-----------|----------|
| No mode / `both` / `full` | Static lane + logical lane, one file walk | Full first-party security review |
| `static` | Conventional SAST-style issues only | Replacing or supplementing a normal static scanner |
| `logical` / `scanner_gaps` | Business/auth/trust-boundary/control-bypass findings only | Complementing Wiz, Checkmarx, Semgrep, or other pattern/taint scanners |

Each call site is adjudicated once and published in one lane only. Unselected-lane classes are recorded as `N/A — other scan lane not selected`, not silently passed.

## What You Get

- `<repo>_security_report.md` and `<repo>_security_report.html`
- Executive summary and severity distribution
- Security Verification Checklist with confidence and discovery source
- Detailed Findings with Description, Instances, Affected endpoints, Vulnerable Code, Data Flow Trace, Severity Rationale, Impact, Remediation, and Burp PoC
- Appendix A for false positives filtered out
- Completeness & Residual Risk Register
- Scan Attestation Summary proving coverage, precision, and limits
- Stable finding IDs and baseline delta support

## How It Produces Better Results

1. **Inventory first** — `enumerate_inventory.py` maps files, configs, HTTP modules, language packs, and read targets.
2. **AppSec operating frame** — `appsec-specialist-operating-mode.md` forces asset/actor/trust-boundary thinking before code review.
3. **Read-before-rg** — `next_read_batch.py` prints full files; `rg` is only a hint after code is opened.
4. **Lane routing** — `scan-modes.md` decides whether static, logical, or both lanes are active.
5. **Evidence gates** — G0-G5 + class-specific ADJ + AI Validate promote only proven findings.
6. **Coverage gate** — `check_coverage_gate.py` must exit 0 before final handoff.
7. **Strict report generation** — `generate_html_report.py --strict` rejects incomplete reports.

Large repos follow `references/large-repo-runner.md`: one agent, no shard workers, no “type continue,” and every module remains in scope until coverage passes.

## Trust and Accuracy Contract

| Rule | Guarantee |
|------|-----------|
| Single agent | No delegated shard workers; the same reviewer owns reads, traces, adjudication, and report. |
| Full inventory coverage | Every `must_read_files` path must be acked in `.security-review/files-read.log`. |
| No silent drops | Every plausible candidate becomes Finding, Tentative, Appendix A, or Residual with a reason. |
| False positives excluded | FP candidates never appear as open findings; they go to Appendix A with gate evidence. |
| One root cause, one ID | Same root cause gets one ID with instances, not duplicate findings per path. |
| No SCA mode | Dependency/CVE tools are out of scope; use a dedicated SCA scanner. |
| DAST-safe | Burp PoC always; live curl only after user approval; never probe localhost. |

## Out of Scope

This skill reviews **first-party code and config**. It does not run dependency/CVE/SBOM/container-image scanners.

Out of scope: `npm audit`, OSV, Trivy, Grype, SBOM, KEV, `SCA-NNN`, advisory-only CVEs, and quantum-only/HNDL-only findings. Those are recorded as Residual/not in skill scope.

## Install

```bash
git clone https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git
cp -r Ai-Security-Reviewer-Pro-Max-Skills ~/.cursor/skills/ai-security-reviewer
# Claude Code: ~/.claude/skills/ai-security-reviewer
```

Restart the IDE, attach the skill, then ask:

```text
Review this code for security vulnerabilities.
```

Useful mode-specific prompts:

```text
Run /ai-security-reviewer in static mode.
Run /ai-security-reviewer in logical mode.
Run /ai-security-reviewer in scanner_gaps mode.
Run /ai-security-reviewer in full mode.
```

Report slug helper:

```bash
python3 ~/.cursor/skills/ai-security-reviewer/scripts/derive_report_name.py
```

## Important Files

| Path | Role |
|------|------|
| `SKILL.md` | Entry contract, phase flow, gates, report rules |
| `references/appsec-specialist-operating-mode.md` | Senior AppSec / researcher reasoning frame |
| `references/scan-modes.md` | Static/logical/both mode router |
| `references/scanner-static.md` | Conventional SAST publication contract |
| `references/scanner-blind-spots.md` | Logical/scanner-gaps publication contract |
| `references/lang-packs/` | Language-specific sinks and false-positive traps |
| `references/ai-validate-precision-pass.md` | TP/FP proof bar and Appendix A discipline |
| `references/coverage-complete-gate.md` | Blocks “complete” until inventory coverage passes |
| `references/finding-templates.md` | Finding structure and narrative requirements |
| `scripts/next_read_batch.py` | Fast full-file read loop |
| `scripts/check_coverage_gate.py` | Final coverage gate |
| `scripts/generate_html_report.py` | Markdown to HTML (`--strict`) |

## Author

**Mukeshj008** — scan only systems you are authorized to test.
