# Agent execution (pointer)

**Canonical contract:** `SKILL.md` only. This file is not loaded during scans.

| Do | Don't |
|----|--------|
| `enumerate_inventory.py`, `derive_report_name.py`, `generate_html_report.py --strict` | `run_sast_scan.sh`, `run_cve_iac_scan.sh`, `discover_burp_hosts.sh`, `generate_coverage_appendix.py` |
| Read + optional hint `rg`; Burp MCP or user-approved `curl` for DAST | Task/subagents, shard workers, `npm audit`/OSV/trivy (SCA removed v4.46) |
| `large-repo-runner.md` when inventory says large | Treat inventory `parallel` block as routing — metadata only |

Review order matches **Review sequence** in `SKILL.md` (12 steps, once each).
