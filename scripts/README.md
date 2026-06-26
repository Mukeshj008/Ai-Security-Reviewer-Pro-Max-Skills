# Scripts — Optional CI Helpers (Not Agent Workflow)

**Agents must NOT run these scripts** to find vulnerabilities or prove reachability.

The ai-security-reviewer skill is **direction-only**: the agent runs `rg`, `graphify`, `npm audit`, and Burp MCP directly per `references/*.md` manifests.

| Script | Status | Use |
|--------|--------|-----|
| `run_sast_scan.sh` | CI / human optional | Batch `rg` for pipelines only |
| `run_cve_iac_scan.sh` | CI / human optional | Batch CVE+IaC `rg` for pipelines only |
| `discover_burp_hosts.sh` | CI / human optional | Host extraction helper |
| `generate_coverage_appendix.py` | CI / human optional | Appendix E skeleton generator |
| `generate_html_report.py` | **Formatting only** | Markdown → HTML after agent wrote report |

See `references/agent-execution.md`.
