#!/usr/bin/env python3
"""
Generate Appendix E/F skeleton — CI/human optional only.
Agents: write Appendix E/F directly from report-coverage-matrix.md (see agent-execution.md).

Usage:
  python generate_coverage_appendix.py -o appendix_coverage.md
  python generate_coverage_appendix.py --stdout --with-sast-results ./sast_scan_results.txt
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

# (id, layer, category, tool)
CHECKS: list[tuple[str, str, str, str]] = [
    # SAST-OG-01 .. 28
    ("SAST-OG-01", "SAST", "Active Debug Code", "rg"),
    ("SAST-OG-02", "SAST", "Code Injection", "rg + graphify path"),
    ("SAST-OG-03", "SAST", "Command Injection", "rg + graphify path"),
    ("SAST-OG-04", "SAST", "Cookie Security", "rg + Read"),
    ("SAST-OG-05", "SAST", "Cross-Site Request Forgery (CSRF)", "rg + Read"),
    ("SAST-OG-06", "SAST", "Cross-Site-Scripting (XSS)", "rg + graphify path"),
    ("SAST-OG-07", "SAST", "Cryptographic Issues", "rg"),
    ("SAST-OG-08", "SAST", "Dangerous Method or Function", "rg"),
    ("SAST-OG-09", "SAST", "Denial-of-Service (DoS)", "rg"),
    ("SAST-OG-10", "SAST", "Hard-coded Secrets", "rg"),
    ("SAST-OG-11", "SAST", "Improper Authentication", "route auth + Burp"),
    ("SAST-OG-12", "SAST", "Improper Authorization", "rg + Read"),
    ("SAST-OG-13", "SAST", "Improper Encoding", "rg"),
    ("SAST-OG-14", "SAST", "Improper Validation", "rg + Read"),
    ("SAST-OG-15", "SAST", "Insecure Deserialization", "rg + graphify path"),
    ("SAST-OG-16", "SAST", "Insecure Hashing Algorithm", "rg"),
    ("SAST-OG-17", "SAST", "Insufficient Logging", "rg"),
    ("SAST-OG-18", "SAST", "LDAP Injection", "rg"),
    ("SAST-OG-19", "SAST", "Mass Assignment", "rg"),
    ("SAST-OG-20", "SAST", "Memory Issues", "rg"),
    ("SAST-OG-21", "SAST", "Mishandled Sensitive Information", "rg"),
    ("SAST-OG-22", "SAST", "Open Redirect", "rg + graphify path"),
    ("SAST-OG-23", "SAST", "Other Security", "rg"),
    ("SAST-OG-24", "SAST", "Path Traversal", "rg + graphify path"),
    ("SAST-OG-25", "SAST", "SQL Injection", "rg + graphify path"),
    ("SAST-OG-26", "SAST", "Server-Side Request Forgery (SSRF)", "rg + graphify path"),
    ("SAST-OG-27", "SAST", "XML Injection / XXE", "rg"),
    ("SAST-OG-28", "SAST", "XPath Injection", "rg"),
    ("SAST-BUS-01", "SAST", "Message Bus Trust Boundary", "rg + Read"),
    # LEAK
    ("SAST-LEAK-01", "SAST", "Node/Express error in response", "rg"),
    ("SAST-LEAK-02", "SAST", "Stack trace fields explicitly", "rg"),
    ("SAST-LEAK-03", "SAST", "GraphQL / API verbose errors", "rg"),
    ("SAST-LEAK-04", "SAST", "Template / SSR error pages", "rg"),
    ("SAST-LEAK-05", "SAST", "React / Vue / Angular client leaks", "rg"),
    ("SAST-LEAK-06", "SAST", "Browser global error handlers", "rg"),
    ("SAST-LEAK-07", "SAST", "Sensitive fields in error payloads", "rg"),
    ("SAST-LEAK-08", "SAST", "Debug / verbose flags to frontend", "rg"),
    # SECRET
    ("SAST-SECRET-01", "SAST", "Cloud & infra keys", "rg"),
    ("SAST-SECRET-02", "SAST", "Git / package / CI tokens", "rg"),
    ("SAST-SECRET-03", "SAST", "Payment & messaging SaaS", "rg"),
    ("SAST-SECRET-04", "SAST", "DB URIs with credentials", "rg"),
    ("SAST-SECRET-05", "SAST", "Private keys & certificates", "rg"),
    ("SAST-SECRET-06", "SAST", "JWT / session / HMAC / API keys", "rg"),
    ("SAST-SECRET-07", "SAST", "Password literals", "rg"),
    ("SAST-SECRET-08", "SAST", "OAuth / OIDC client secrets", "rg"),
    ("SAST-SECRET-09", "SAST", "Env fallback to hardcoded", "rg"),
    ("SAST-SECRET-10", "SAST", "Base64 / hex encoded secrets", "rg + manual"),
    ("SAST-SECRET-11", "SAST", "Kafka / RMQ inline creds", "rg"),
    # INJ
    ("SAST-INJ-XSS", "SAST", "Cross-Site Scripting", "rg + graphify path"),
    ("SAST-INJ-RCE", "SAST", "Remote Code Execution", "rg + graphify path"),
    ("SAST-INJ-CMD", "SAST", "Command Injection (deep)", "rg + graphify path"),
    ("SAST-INJ-XXE", "SAST", "XML External Entity", "rg"),
    ("SAST-INJ-XML", "SAST", "XML Injection", "rg"),
    # EXT
    ("SAST-EXT-01", "SAST", "Trust Boundary Violation", "rg + Read"),
    ("SAST-EXT-02", "SAST", "HTTP Request Smuggling", "Read config"),
    ("SAST-EXT-03", "SAST", "JNDI Injection / Log4Shell", "rg"),
    ("SAST-EXT-04", "SAST", "Session Fixation", "rg + Read"),
    ("SAST-EXT-05", "SAST", "ReDoS", "rg"),
    ("SAST-EXT-06", "SAST", "XML Bomb", "rg"),
    ("SAST-EXT-07", "SAST", "Zip Bomb", "rg"),
    # DAST / DEPS / GRAPH
    ("DAST-HOST-01", "DAST", "Burp host discovery", "discover_burp_hosts.sh"),
    ("DAST-AUTH-PROBE", "DAST", "Unauthenticated endpoint probes", "Burp MCP"),
    ("DAST-INJ-PROBE", "DAST", "Injection PoC verification", "Burp MCP"),
    ("DEPS-01", "DEPS", "Dependency vulnerability audit", "npm audit"),
    ("GRAPH-01", "Recon", "Attack surface mapping", "graphify query"),
    ("GRAPH-02", "Recon", "Vulnerability hotspot discovery", "graphify query"),
    ("GRAPH-03", "Recon", "Source→sink path traces", "graphify path"),
    # CVE — dependency + reachability + known exploitable patterns (v3.9)
    ("CVE-DEPS-01", "CVE", "Critical dependency audit", "npm audit / pip-audit"),
    ("CVE-DEPS-02", "CVE", "High dependency audit", "npm audit"),
    ("CVE-DEPS-03", "CVE", "Lockfile vulnerable version pin", "rg + audit"),
    ("CVE-REACH-01", "CVE", "Direct import of vulnerable package", "rg"),
    ("CVE-REACH-02", "CVE", "Graphify HTTP → vuln API path", "graphify path"),
    ("CVE-REACH-03", "CVE", "Transitive dependency reachability", "rg + lockfile"),
    ("CVE-CODE-01", "CVE", "JNDI / Log4Shell class", "rg"),
    ("CVE-CODE-02", "CVE", "Insecure deserialization RCE", "rg + graphify path"),
    ("CVE-CODE-03", "CVE", "Prototype pollution chains", "rg + audit"),
    ("CVE-CODE-04", "CVE", "JWT algorithm confusion", "rg"),
    ("CVE-CODE-05", "CVE", "SSRF via vulnerable HTTP client", "rg + graphify path"),
    ("CVE-CODE-06", "CVE", "Path traversal / arbitrary file read", "rg"),
    ("CVE-CODE-07", "CVE", "Template / SSTI RCE", "rg + graphify path"),
    ("CVE-CODE-08", "CVE", "Shell via vulnerable tooling", "rg"),
    # IaC — infrastructure misconfigurations (v3.9)
    ("IAC-DOCKER-01", "IaC", "Container runs as root", "rg Dockerfile"),
    ("IAC-DOCKER-02", "IaC", "Secrets in Dockerfile ENV/ARG", "rg"),
    ("IAC-DOCKER-03", "IaC", "Unpinned / :latest base image", "rg"),
    ("IAC-DOCKER-04", "IaC", "Remote ADD supply chain", "rg"),
    ("IAC-DOCKER-05", "IaC", "Privileged container / compose", "rg"),
    ("IAC-K8S-01", "IaC", "Privileged pods", "rg yaml"),
    ("IAC-K8S-02", "IaC", "hostNetwork / hostPID / hostIPC", "rg yaml"),
    ("IAC-K8S-03", "IaC", "Missing runAsNonRoot", "rg yaml"),
    ("IAC-K8S-04", "IaC", "Secrets in plain env", "rg yaml"),
    ("IAC-K8S-05", "IaC", "Overly broad RBAC", "rg yaml"),
    ("IAC-TF-01", "IaC", "Open ingress 0.0.0.0/0", "rg tf"),
    ("IAC-TF-02", "IaC", "Public storage ACL", "rg tf"),
    ("IAC-TF-03", "IaC", "IAM wildcard permissions", "rg tf"),
    ("IAC-TF-04", "IaC", "Unencrypted storage / transit", "rg tf"),
    ("IAC-TF-05", "IaC", "Hardcoded credentials in Terraform", "rg tf"),
    ("IAC-NGINX-01", "IaC", "Weak TLS protocols", "rg nginx"),
    ("IAC-NGINX-02", "IaC", "Missing security headers at edge", "rg nginx"),
    ("IAC-NGINX-03", "IaC", "Permissive CORS at edge", "rg nginx"),
    ("IAC-CI-01", "IaC", "Secrets in CI/CD pipelines", "rg yaml"),
    ("IAC-CI-02", "IaC", "curl | bash supply chain", "rg yaml"),
    ("IAC-CI-03", "IaC", "Privileged Docker in CI", "rg yaml"),
    # Security architect / researcher (v3.9)
    ("ARCH-01", "ARCH", "Attack surface enumeration", "graphify + Read"),
    ("ARCH-02", "ARCH", "Trust boundary map", "graphify + rg"),
    ("ARCH-03", "ARCH", "STRIDE per critical component", "architect analysis"),
    ("ARCH-04", "ARCH", "Sensitive data flow (PII)", "graphify + rg"),
    ("ARCH-05", "ARCH", "Security control gap (ASVS)", "Read + compare"),
    ("ARCH-06", "ARCH", "CVE threat intel + KEV prioritization", "advisory review"),
    ("ARCH-07", "ARCH", "IaC blast radius analysis", "architect + IAC findings"),
]

PHASES: list[tuple[str, str, str, str]] = [
    ("0", "Burp host discovery", "discover_burp_hosts.sh", "burp_hosts.txt"),
    ("0", "Graphify graph available", "graphify extract / existing graph", "graphify-out/graph.json"),
    ("0", "Attack surface query", 'graphify query "API routes auth..."', "—"),
    ("0", "Vuln hotspot query", 'graphify query "SQL exec shell render..."', "—"),
    ("1", "Deterministic SAST scan", "run_sast_scan.sh", "sast_scan_results.txt"),
    ("1c", "CVE + IaC scan", "run_cve_iac_scan.sh", "cve_iac_scan_results.txt"),
    ("1d", "CVE reachability triage", "cve-exploitability.md", "CVE-NNN candidates"),
    ("1e", "IaC misconfig triage", "iac-misconfig-scan.md", "IAC-NNN candidates"),
    ("1f", "Security architect review", "security-architect.md", "Appendix G"),
    ("1", "Manifest triage (OG/LEAK/SECRET/INJ)", "sast_scan_manifest.md + refs", "—"),
    ("1a", "Route authentication audit", "route_auth_audit.md", "Appendix D"),
    ("1b", "Burp AUTH probes", "send_http1_request (user-burp)", "Appendix C"),
    ("1b", "Burp INJ probes", "dast_scan_manifest.md", "Appendix C"),
    ("2", "Data-flow path traces", "graphify path per candidate", "—"),
    ("3", "AI validation checklist", "agent Phase 3", "Findings Summary"),
    ("4", "Markdown report", "security_report.md", "this file"),
    ("5", "HTML export", "generate_html_report.py", "security_report.html"),
]


def parse_scan_results(path: Path) -> dict[str, int]:
    """Parse MATCH_COUNT lines from run_sast_scan.sh or run_cve_iac_scan.sh output."""
    counts: dict[str, int] = {}
    if not path.is_file():
        return counts
    text = path.read_text(encoding="utf-8", errors="replace")
    current_id: str | None = None
    for line in text.splitlines():
        m = re.match(r"^--- \[(SAST-[A-Z0-9-]+|CVE-[A-Z0-9-]+|IAC-[A-Z0-9-]+)\]", line)
        if m:
            current_id = m.group(1)
            continue
        m = re.match(r"^MATCH_COUNT:\s*(\d+)", line)
        if m and current_id:
            counts[current_id] = int(m.group(1))
            current_id = None
    return counts


def default_status(check_id: str, match_count: int | None) -> str:
    if check_id.startswith(("DAST-", "ARCH-", "CVE-DEPS-", "CVE-REACH-")) or check_id == "DEPS-01":
        return "PENDING"
    if match_count is None:
        return "PENDING"
    return "PENDING" if match_count > 0 else "PASS"


def render_appendix_e(
    counts: dict[str, int],
    use_counts: bool,
) -> str:
    total = len(CHECKS)
    lines = [
        "## Appendix E: Security Check Coverage Matrix (MANDATORY)",
        "",
        "### Checks Performed Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total checks defined | {total} |",
        "| Checks executed (PASS + FINDING) | PENDING |",
        "| Findings (FINDING) | PENDING |",
        "| Not applicable (N/A) | PENDING |",
        "| Skipped (SKIP) | PENDING |",
        "| Failed to run (FAIL) | PENDING |",
        "| Coverage rate | PENDING |",
        "",
        "> **Agent:** Replace PENDING summary values after setting every row below.",
        "",
        "| Check ID | Layer | Category | Tool | Status | Finding Ref | Match Count | Notes |",
        "|----------|-------|----------|------|--------|-------------|-------------|-------|",
    ]
    for check_id, layer, category, tool in CHECKS:
        mc = counts.get(check_id) if use_counts else None
        mc_str = str(mc) if mc is not None else "—"
        status = default_status(check_id, mc) if use_counts else "PENDING"
        lines.append(
            f"| {check_id} | {layer} | {category} | {tool} | {status} | — | {mc_str} | |"
        )
    lines.append("")
    lines.append(
        "**Status legend:** `PASS` | `FINDING` | `FAIL` | `N/A` | `SKIP` | `PENDING` (must clear before HTML export)"
    )
    lines.append("")
    return "\n".join(lines)


def render_appendix_f() -> str:
    lines = [
        "## Appendix F: Review Phase Execution Log (MANDATORY)",
        "",
        "| Phase | Step | Command / Tool | Status | Artifact | Notes |",
        "|-------|------|----------------|--------|----------|-------|",
    ]
    for phase, step, cmd, artifact in PHASES:
        lines.append(f"| {phase} | {step} | `{cmd}` | PENDING | `{artifact}` | |")
    lines.append("")
    lines.append("**Phase status:** `PASS` | `FAIL` | `SKIP` | `PARTIAL` | `PENDING`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Appendix E/F coverage skeleton")
    parser.add_argument("-o", "--output", type=Path, help="Write markdown to file")
    parser.add_argument("--stdout", action="store_true", help="Print to stdout")
    parser.add_argument("--project", type=str, default="", help="Project name (header comment)")
    parser.add_argument(
        "--with-sast-results",
        type=Path,
        help="Pre-fill Match Count from sast_scan_results.txt",
    )
    parser.add_argument(
        "--with-cve-iac-results",
        type=Path,
        help="Pre-fill Match Count from cve_iac_scan_results.txt",
    )
    args = parser.parse_args()

    counts: dict[str, int] = {}
    if args.with_sast_results:
        counts.update(parse_scan_results(args.with_sast_results))
    if args.with_cve_iac_results:
        counts.update(parse_scan_results(args.with_cve_iac_results))
    use_counts = bool(counts)

    header = [
        "<!-- AI Security Reviewer — Coverage Appendix Skeleton -->",
        f"<!-- Generated: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} -->",
    ]
    if args.project:
        header.append(f"<!-- Project: {args.project} -->")
    header.append("")

    body = "\n".join(header) + render_appendix_e(counts, use_counts) + render_appendix_f()

    if args.output:
        args.output.write_text(body, encoding="utf-8")
        print(f"Coverage appendix written: {args.output}", file=sys.stderr)

    if args.stdout or not args.output:
        print(body)

    return 0


if __name__ == "__main__":
    sys.exit(main())
