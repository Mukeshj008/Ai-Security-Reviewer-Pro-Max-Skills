#!/usr/bin/env python3
"""
Convert AI Security Reviewer markdown report to a styled HTML document.

Ensures every finding card includes structured Description, Source, Sink,
Impact, and Remediation sections (with line numbers when present in markdown).

The expected input filename follows the v4.20 naming convention:
``<repo>_security_report.md`` (see ``references/report-naming-convention.md``
and ``scripts/derive_report_name.py``). A bare ``security_report.md`` input
triggers a Recommendation in --strict mode but is still accepted.

Usage:
  python generate_html_report.py oauth-user-mgmt-service_security_report.md
  python generate_html_report.py <repo>_security_report.md -o <repo>_security_report.html
  python generate_html_report.py <repo>_security_report.md --project "My App"
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#64748b",
}

COVERAGE_STATUS_COLORS = {
    "pass": "#16a34a",
    "finding": "#dc2626",
    "fail": "#b91c1c",
    "n/a": "#64748b",
    "na": "#64748b",
    "skip": "#ca8a04",
    "pending": "#7c3aed",
    "partial": "#ca8a04",
}

FINDING_ID_RE = re.compile(r"\[(VULN|AUTH|CVE|IAC|LEAK)-(\d+)\]", re.I)
FINDING_HEADER_RE = re.compile(
    r"^##\s+\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(.+)$",
    re.I,
)
SEPARATOR_LINE_RE = re.compile(r"^[━─\-=\s]+$")
REPORT_META_LINE_RE = re.compile(r"^\*\*([^*]+):\*\*\s*.+$")
FILE_LINE_RE = re.compile(r"^([^\s:]+\.(?:js|ts|jsx|tsx|java|py|go|rb|php|conf|yaml|yml|json|md))(?::(\d+(?:-\d+)?))?$")

HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #030712;
      --surface: #0f172a;
      --surface2: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent2: #a78bfa;
      --accent3: #34d399;
      --pass: #22c55e;
      --source: #34d399;
      --sink: #f87171;
      --glow-cyan: rgba(56, 189, 248, 0.15);
      --glow-violet: rgba(167, 139, 250, 0.12);
      --glow-emerald: rgba(52, 211, 153, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg);
      background-image:
        radial-gradient(ellipse 80% 50% at 10% -10%, rgba(56,189,248,0.12), transparent 50%),
        radial-gradient(ellipse 60% 40% at 90% 0%, rgba(167,139,250,0.10), transparent 45%),
        radial-gradient(ellipse 50% 30% at 50% 100%, rgba(52,211,153,0.06), transparent 40%);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 2rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .report-hero {{
      background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 45%, #134e4a 100%);
      border: 1px solid rgba(56, 189, 248, 0.25);
      border-radius: 16px;
      padding: 2rem 2.25rem;
      margin-bottom: 2rem;
      box-shadow: 0 4px 24px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.06);
      position: relative;
      overflow: hidden;
    }}
    .report-hero::before {{
      content: "";
      position: absolute;
      top: -50%; right: -20%;
      width: 60%; height: 120%;
      background: radial-gradient(circle, rgba(167,139,250,0.15) 0%, transparent 70%);
      pointer-events: none;
    }}
    .report-hero h1 {{
      font-size: 2rem;
      margin-bottom: 0.75rem;
      background: linear-gradient(90deg, #f8fafc 0%, #38bdf8 50%, #a78bfa 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      position: relative;
    }}
    .report-meta {{
      display: flex; flex-wrap: wrap; gap: 0.65rem 1.25rem;
      color: var(--muted); font-size: 0.82rem; margin-top: 0.75rem;
      position: relative;
    }}
    .report-meta span {{
      display: flex; gap: 0.35rem;
      background: rgba(15, 23, 42, 0.55);
      border: 1px solid rgba(51, 65, 85, 0.6);
      border-radius: 999px;
      padding: 0.25rem 0.75rem;
    }}
    .report-meta strong {{ color: var(--accent); }}
    .scan-scope-bar {{
      display: flex; flex-wrap: wrap; gap: 1rem;
      margin: 1.25rem 0 0.5rem;
      position: relative;
    }}
    .scope-stat {{
      flex: 1 1 180px;
      background: rgba(15, 23, 42, 0.7);
      backdrop-filter: blur(8px);
      border-radius: 12px;
      padding: 1rem 1.25rem;
      border: 1px solid rgba(51, 65, 85, 0.5);
    }}
    .scope-stat.files {{ border-top: 3px solid #38bdf8; box-shadow: 0 0 20px var(--glow-cyan); }}
    .scope-stat.loc {{ border-top: 3px solid #a78bfa; box-shadow: 0 0 20px var(--glow-violet); }}
    .scope-stat .scope-value {{
      font-size: 1.85rem; font-weight: 800; line-height: 1.1;
    }}
    .scope-stat.files .scope-value {{ color: #38bdf8; }}
    .scope-stat.loc .scope-value {{ color: #c4b5fd; }}
    .scope-stat .scope-label {{
      font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em;
      color: var(--muted); margin-top: 0.35rem;
    }}
    .coverage-strip {{
      display: flex; flex-wrap: wrap; gap: 0.5rem;
      margin: 1rem 0 1.5rem;
      padding: 1rem 1.25rem;
      background: linear-gradient(90deg, rgba(56,189,248,0.08) 0%, rgba(167,139,250,0.08) 50%, rgba(52,211,153,0.08) 100%);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: 12px;
    }}
    .coverage-pill {{
      display: inline-flex; align-items: center; gap: 0.35rem;
      padding: 0.35rem 0.85rem;
      border-radius: 999px;
      font-size: 0.78rem; font-weight: 600;
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid rgba(51, 65, 85, 0.6);
    }}
    .coverage-pill .pill-num {{ color: var(--accent); font-weight: 800; }}
    .coverage-pill.layer-sast {{ border-color: rgba(56,189,248,0.4); }}
    .coverage-pill.layer-sca {{ border-color: rgba(167,139,250,0.4); }}
    .coverage-pill.layer-dast {{ border-color: rgba(251,191,36,0.4); }}
    .coverage-pill.layer-iac {{ border-color: rgba(52,211,153,0.4); }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 0.85rem;
      margin: 1.25rem 0 1.5rem;
    }}
    .kpi-card {{
      background: rgba(15, 23, 42, 0.75);
      backdrop-filter: blur(6px);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem 0.85rem;
      text-align: center;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }}
    .kpi-card:hover {{
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0,0,0,0.25);
    }}
    .kpi-card.kpi-checks {{ border-top: 3px solid #34d399; }}
    .kpi-card.kpi-findings {{ border-top: 3px solid #fb923c; }}
    .kpi-card.kpi-tp {{ border-top: 3px solid #fbbf24; }}
    .kpi-card.kpi-sca {{ border-top: 3px solid #f472b6; }}
    .kpi-card.kpi-cve {{ border-top: 3px solid #22d3ee; }}
    .kpi-card.kpi-auth {{ border-top: 3px solid #fb7185; }}
    .kpi-card.kpi-cov {{ border-top: 3px solid #818cf8; }}
    .coverage-framework {{ opacity: 0.92; margin-top: 0.5rem; }}
    .kpi-value {{
      font-size: 1.75rem; font-weight: 800; line-height: 1.2;
    }}
    .kpi-card.kpi-checks .kpi-value {{ color: #34d399; }}
    .kpi-card.kpi-findings .kpi-value {{ color: #fb923c; }}
    .kpi-card.kpi-tp .kpi-value {{ color: #fbbf24; }}
    .kpi-card.kpi-sca .kpi-value {{ color: #f472b6; }}
    .kpi-card.kpi-cve .kpi-value {{ color: #22d3ee; }}
    .kpi-card.kpi-auth .kpi-value {{ color: #fb7185; }}
    .kpi-card.kpi-cov .kpi-value {{ color: #a5b4fc; }}
    .kpi-label {{
      font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.07em;
      color: var(--muted); margin-top: 0.35rem;
    }}
    .risk-banner {{
      display: flex; align-items: center; gap: 1.25rem;
      background: linear-gradient(90deg, rgba(251,191,36,0.15) 0%, rgba(234,88,12,0.08) 100%);
      border: 1px solid rgba(251, 191, 36, 0.35);
      border-radius: 12px; padding: 1rem 1.25rem; margin: 1rem 0 1.25rem;
    }}
    .risk-score {{
      font-size: 2.25rem; font-weight: 800;
      background: linear-gradient(180deg, #fde68a 0%, #f59e0b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      min-width: 4.5rem; text-align: center;
    }}
    .toc {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1rem 1.25rem; margin: 1.5rem 0;
    }}
    .toc ul {{ margin: 0.5rem 0 0; columns: 2; column-gap: 2rem; }}
    .toc a {{ text-decoration: none; }}
    .toc a:hover {{ text-decoration: underline; }}
    .finding-core {{ overflow: hidden; max-width: 100%; }}
    details.verify-checklist {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 0.65rem 1rem; margin: 1rem 0;
    }}
    details.verify-checklist summary {{
      cursor: pointer; font-weight: 600; color: var(--accent);
      padding: 0.5rem 0; list-style: none;
    }}
    details.verify-checklist summary::-webkit-details-marker {{ display: none; }}
    details.verify-checklist summary::before {{
      content: "▸ "; color: var(--accent2);
    }}
    details.verify-checklist[open] summary::before {{ content: "▾ "; }}
    details.verify-checklist .table-wrap {{ margin-top: 0.75rem; }}
    .table-wrap {{
      width: 100%;
      overflow-x: auto;
      margin: 0.75rem 0;
      -webkit-overflow-scrolling: touch;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: rgba(15, 23, 42, 0.35);
    }}
    .table-wrap table {{ margin: 0; }}
    .master-wrap .master-register {{
      min-width: 640px;
      font-size: 0.82rem;
    }}
    .master-register td:nth-child(4),
    .master-register td:nth-child(5),
    .summary-table td:nth-child(4),
    .summary-table td:nth-child(5) {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.72rem;
      max-width: 220px;
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: normal;
    }}
    .master-register td:first-child {{ font-family: ui-monospace, monospace; font-size: 0.82rem; white-space: nowrap; }}
    .master-register td:nth-child(3) {{ max-width: 140px; }}
    .source-sink-banner {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.65rem;
      margin-bottom: 1rem;
      padding: 0.75rem 1rem;
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    @media (max-width: 768px) {{
      .source-sink-banner {{ grid-template-columns: 1fr; }}
    }}
    .source-sink-banner.missing {{ border-color: #ca8a04; color: #fbbf24; font-size: 0.85rem; }}
    .source-sink-banner .ss-label {{
      display: block;
      font-size: 0.68rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 0.25rem;
    }}
    .source-sink-banner .ss-item:first-child .ss-label {{ color: var(--source); }}
    .source-sink-banner .ss-item:last-child .ss-label {{ color: var(--sink); }}
    .source-sink-banner code {{
      display: block;
      font-size: 0.72rem;
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: pre-wrap;
    }}
    .coverage-wrap .coverage-section table {{ min-width: 720px; font-size: 0.85rem; }}
    .pill {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      white-space: nowrap;
    }}
    .verdict-tp {{ background: rgba(34,197,94,0.2); color: #22C55E; border: 1px solid rgba(34,197,94,0.35); }}
    .verdict-fp {{ background: rgba(100,116,139,0.25); color: #94A3B8; border: 1px solid rgba(100,116,139,0.4); }}
    .verdict-filtered {{ background: rgba(100,116,139,0.15); color: #64748B; border: 1px solid rgba(100,116,139,0.3); }}
    .exp-yes {{ background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }}
    .exp-no {{ background: rgba(100,116,139,0.2); color: #94A3B8; border: 1px solid rgba(100,116,139,0.35); }}
    .exp-hardening {{ background: rgba(56,189,248,0.12); color: #38BDF8; border: 1px solid rgba(56,189,248,0.25); }}
    .exp-unknown {{ background: rgba(251,191,36,0.12); color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }}
    .register-blurb {{ display: none; }}
    .data-flow h4 {{ margin: 0.75rem 0 0.35rem; font-size: 0.9rem; color: var(--muted); }}
    .simplified-flow pre {{ margin-top: 0.35rem; }}
    .badge-info {{ background: #64748b; color: #fff; }}
    .sev-medium {{ border-left: 4px solid {c_medium}; }}
    .sev-low {{ border-left: 4px solid {c_low}; }}
    .sev-critical {{ border-left: 4px solid {c_critical}; }}
    .sev-high {{ border-left: 4px solid {c_high}; }}
    .class-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(min(100%, 150px), 1fr));
      gap: 0.5rem;
      margin: 0.75rem 0;
      font-size: 0.85rem;
      max-width: 100%;
    }}
    .class-chip {{
      background: rgba(15,23,42,0.6); border: 1px solid var(--border);
      border-radius: 6px; padding: 0.4rem 0.65rem;
      min-width: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .class-chip span {{ color: var(--muted); display: block; font-size: 0.72rem; text-transform: uppercase; }}
    h1 {{ font-size: 1.75rem; margin: 0 0 0.5rem; }}
    h2 {{ color: var(--accent); margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 0.35rem; }}
    h3 {{ margin-top: 1.25rem; margin-bottom: 0.5rem; font-size: 1rem; }}
    h4 {{ margin-top: 1rem; color: var(--muted); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 0.75rem 0;
      font-size: 0.9rem;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 0.5rem 0.75rem;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%); color: var(--accent); font-weight: 600; }}
    tr:nth-child(even) {{ background: rgba(30, 41, 59, 0.5); }}
    pre, code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
    }}
    pre {{
      background: #0c1222;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    code {{ background: var(--surface); padding: 0.15rem 0.35rem; border-radius: 4px; }}
    pre code {{ background: none; padding: 0; }}
    .finding {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      margin: 1.5rem 0;
      overflow: hidden;
      max-width: 100%;
    }}
    .finding-header {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border);
    }}
    .finding-header h2 {{
      margin: 0;
      border: none;
      padding: 0;
      flex: 1 1 auto;
      font-size: 1.15rem;
    }}
    .finding-id {{
      font-family: ui-monospace, monospace;
      font-size: 0.8rem;
      color: var(--accent);
      background: rgba(56, 189, 248, 0.1);
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      border: 1px solid rgba(56, 189, 248, 0.25);
    }}
    .finding-core {{
      display: grid;
      gap: 1rem;
      margin-bottom: 1rem;
    }}
    .core-panel {{
      background: rgba(15, 23, 42, 0.55);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.85rem 1rem;
    }}
    .core-panel h3 {{
      margin-top: 0;
      color: var(--accent);
      font-size: 0.95rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .core-panel.missing h3 {{ color: var(--muted); }}
    .core-panel.missing .placeholder {{ color: var(--muted); font-style: italic; }}
    .core-panel.vuln-code {{ border-left: 3px solid var(--sink); }}
    .core-panel.data-flow {{ border-left: 3px solid var(--source); }}
    .core-panel.vuln-code pre {{ background: rgba(239, 68, 68, 0.08); }}
    .trace-table th {{ width: 120px; }}
    .trace-source {{ color: var(--source); font-weight: 600; }}
    .trace-sink {{ color: var(--sink); font-weight: 600; }}
    .finding-extra h3 {{ color: var(--muted); font-size: 0.95rem; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    .badge-critical {{ background: {c_critical}; color: #fff; }}
    .badge-high {{ background: {c_high}; color: #fff; }}
    .badge-medium {{ background: {c_medium}; color: #1e293b; }}
    .badge-low {{ background: {c_low}; color: #fff; }}
    .status-pass {{ color: {c_pass}; font-weight: 600; }}
    .status-finding {{ color: {c_finding}; font-weight: 600; }}
    .status-fail {{ color: {c_fail}; font-weight: 600; }}
    .status-na {{ color: {c_na}; font-weight: 600; }}
    .status-skip {{ color: {c_skip}; font-weight: 600; }}
    .status-pending {{ color: {c_pending}; font-weight: 600; }}
    .coverage-section h2 {{ color: #a78bfa; }}
    .burp-block {{
      border-left: 4px solid var(--accent);
      margin: 1rem 0;
    }}
    .burp-block pre {{ margin: 0; }}
    blockquote {{
      border-left: 4px solid var(--border);
      margin: 1rem 0;
      padding-left: 1rem;
      color: var(--muted);
    }}
    ul {{ padding-left: 1.25rem; }}
    a {{ color: var(--accent); }}
    footer {{
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 0.85rem;
    }}
    .section-lead {{ color: var(--muted); margin: -0.5rem 0 1rem; font-size: 0.95rem; }}
    @media (max-width: 768px) {{
      .toc ul {{ columns: 1; }}
      body {{ padding: 1rem; }}
    }}
    @media print {{
      body {{ background: #fff; color: #111; }}
      pre {{ background: #f5f5f5; border-color: #ccc; }}
      .finding {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    {body}
    <footer>
      Generated by AI Security Reviewer v4.11 · {generated_at}
    </footer>
  </div>
</body>
</html>
"""


@dataclass
class SummaryRow:
    finding_id: str
    severity: str
    category: str
    source_path: str = ""
    sink_path: str = ""
    file_line: str = ""
    method: str = ""
    status: str = ""
    verification_status: str = ""
    dast_status: str = ""


@dataclass
class ParsedFinding:
    finding_id: Optional[str]
    severity: str
    title: str
    body: str
    sections: dict[str, str] = field(default_factory=dict)
    kv_tables: dict[str, str] = field(default_factory=dict)
    summary: Optional[SummaryRow] = None


def is_separator_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if SEPARATOR_LINE_RE.match(s):
        return True
    if len(s) > 20 and s.count("━") > 10:
        return True
    return False


def parse_executive_metrics(md: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    in_section = False
    target_sections = ("executive summary", "vulnerability coverage overview")
    for line in md.splitlines():
        if line.startswith("## "):
            heading = line[3:].strip().lower()
            in_section = any(t in heading for t in target_sections)
            continue
        if in_section and line.startswith("## "):
            in_section = False
        if in_section and line.strip().startswith("|") and "|" in line:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 2 and cells[0].lower() not in ("metric", "coverage metric", "---"):
                if not all(re.match(r"^[-:]+$", c) for c in cells[:2]):
                    key = re.sub(r"\*+", "", cells[0]).strip()
                    metrics[key] = cells[1]
        if in_section and line.startswith("### Risk Score"):
            rest = line.split(":", 1)[-1].strip()
            if rest:
                metrics["Risk score"] = rest
    return metrics


EXPLOITABLE_CANONICAL = frozenset({"Yes", "No", "Hardening"})

IMPACT_GENERIC_MARKERS = (
    "Missing authentication — unauthenticated access to",
    "business and security impact depends on",
    "Infrastructure misconfiguration — expanded blast radius",
    "Information disclosure via logs or error responses",
    "Session trust boundary violation — attacker may poison",
)


def normalize_exploitable(raw: str) -> str:
    """Map free-text to Yes | No | Hardening only."""
    if not raw or not raw.strip():
        return ""
    low = re.sub(r"\*+", "", raw.strip()).lower()
    if low == "yes" or low.startswith("yes ") or low.startswith("yes("):
        return "Yes"
    if low == "no" or low.startswith("no ") or low.startswith("no("):
        return "No"
    if low == "hardening" or "hardening" in low:
        return "Hardening"
    if "conditional" in low or "depends" in low or "requires" in low:
        return "Hardening"
    if "partial" in low or "theoretical" in low or "unlikely" in low:
        return "No"
    return raw.strip()


def normalize_ai_verdict(raw: str) -> str:
    up = re.sub(r"\*+", "", raw.strip()).upper()
    if "TRUE POSITIVE" in up or "EXPLOITABLE" in up:
        return "TRUE POSITIVE"
    if "FALSE POSITIVE" in up:
        return "FALSE POSITIVE"
    if "FILTERED" in up:
        return "FILTERED"
    return raw.strip()


def is_generic_impact(text: str) -> bool:
    t = text.strip()
    if not t:
        return True
    if any(m in t for m in IMPACT_GENERIC_MARKERS):
        return True
    if "| Impact Category |" not in t and len(t) < 120:
        return True
    return False


def wrap_table_html(table_html: str, css_class: str = "table-wrap") -> str:
    if not table_html.strip():
        return ""
    return f'<div class="{css_class}">{table_html}</div>'


def normalize_finding_kv(kv: dict[str, str]) -> None:
    if kv.get("Exploitable"):
        kv["Exploitable"] = normalize_exploitable(kv["Exploitable"])
    if kv.get("AI Verdict"):
        kv["AI Verdict"] = normalize_ai_verdict(kv["AI Verdict"])


def parse_register_exploitable(md: str) -> dict[str, str]:
    """ID -> Exploitable from Verification Register or legacy Master Register."""
    rows: dict[str, str] = {}
    in_reg = False
    header: list[str] = []
    exp_col = -1
    for line in md.splitlines():
        if line.startswith("## Security Findings Verification Register") or line.startswith(
            "## Master Findings Register"
        ):
            in_reg = True
            header = []
            continue
        if in_reg and line.startswith("## ") and "Register" not in line:
            break
        if not in_reg or not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not header:
            header = [c.lower() for c in cells]
            exp_col = next((i for i, h in enumerate(header) if h == "exploitable"), 8)
            continue
        if all(re.match(r"^[-:]+$", c) for c in cells):
            continue
        if len(cells) >= 6 and re.match(r"^[A-Z]+-\d+$", cells[0]):
            idx = exp_col if 0 <= exp_col < len(cells) else 5
            rows[cells[0]] = normalize_exploitable(cells[idx])
    return rows


def validate_report_recommendations(md: str) -> list[str]:
    """v4.15 — stderr recommendations only (non-blocking unless --strict-attestation added later)."""
    recs: list[str] = []
    if "## Scan Attestation Summary" not in md and "### Scan Attestation Summary" not in md:
        recs.append("missing ## Scan Attestation Summary — see scan-attestation-summary.md")
    if "Risk Score:" in md and "rubric" not in md.lower() and "method:" not in md.lower():
        recs.append("Risk Score present without rubric method — see risk-score-rubric.md")
    return recs


def validate_finding_consistency(
    findings: list["ParsedFinding"],
    register_exp: dict[str, str],
) -> list[str]:
    issues: list[str] = []
    for f in findings:
        fid = f.finding_id or "?"
        exp = f.kv_tables.get("Exploitable", "")
        if exp and exp not in EXPLOITABLE_CANONICAL:
            issues.append(f"{fid}: Exploitable '{exp}' — use Yes, No, or Hardening only")
        reg = register_exp.get(fid or "", "")
        if fid and reg and exp and reg != exp:
            issues.append(f"{fid}: Register Exploitable={reg} ≠ Classification Exploitable={exp}")
        impact = build_impact(f)
        if impact and is_generic_impact(impact):
            issues.append(f"{fid}: Impact Assessment missing or generic — see report-impact-assessment.md")
        elif not impact.strip():
            issues.append(f"{fid}: missing ### Impact Assessment table")
        src = f.kv_tables.get("Source (full path)", "").strip()
        snk = f.kv_tables.get("Sink (full path)", "").strip()
        if not src or not snk:
            issues.append(
                f"{fid}: missing Source (full path) and/or Sink (full path) in Classification "
                "— see report-findings-verification-register.md"
            )
    return issues


def parse_report_meta(md: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in md.splitlines()[:20]:
        m = re.match(r"^\*\*([^*]+):\*\*\s*(.+)$", line.strip())
        if m:
            meta[m.group(1).strip()] = m.group(2).strip()
    return meta


def sync_attribution_agent(md: str) -> tuple[str, list[str]]:
    """Align Scan Agent & Backend Attribution table with header **Scan Agent:** value."""
    meta = parse_report_meta(md)
    agent = meta.get("Scan Agent", "").strip()
    if not agent:
        return md, []
    fixes: list[str] = []
    lines = md.splitlines()
    in_attr = False
    out: list[str] = []
    for line in lines:
        if line.startswith("## Scan Agent & Backend Attribution"):
            in_attr = True
            out.append(line)
            continue
        if in_attr and line.startswith("## "):
            in_attr = False
        if in_attr and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if (
                len(cells) >= 2
                and cells[0].lower() not in ("layer", "")
                and not all(re.match(r"^[-:]+$", c) for c in cells)
            ):
                col = cells[1]
                if col and col != agent and "backend" not in col.lower():
                    fixes.append(f"Attribution row '{cells[0]}': {col} → {agent}")
                    cells[1] = agent
                    line = "| " + " | ".join(cells) + " |"
        out.append(line)
    return "\n".join(out), fixes


def _metric_num(value: str) -> str:
    """Extract display number from metric cell (handles commas, bold, parentheticals)."""
    clean = re.sub(r"\*+", "", value.split("(")[0])
    m = re.search(r"[\d,]+", clean)
    return m.group(0) if m else clean.strip().split()[0] if clean.strip() else "—"


def _find_metric(metrics: dict[str, str], *prefixes: str) -> tuple[str, str]:
    for prefix in prefixes:
        for k, v in metrics.items():
            if k.lower().startswith(prefix.lower()) or prefix.lower() in k.lower():
                return k, v
    return "", ""


def render_scan_scope_bar(metrics: dict[str, str]) -> str:
    _, files_val = _find_metric(metrics, "Files Analyzed", "Files analyzed")
    _, loc_val = _find_metric(metrics, "Lines of Code", "Lines of code")
    if not files_val and not loc_val:
        return ""
    parts = []
    if files_val:
        parts.append(
            f'<div class="scope-stat files"><div class="scope-value">{html.escape(_metric_num(files_val))}</div>'
            f'<div class="scope-label">Files Analyzed</div></div>'
        )
    if loc_val:
        parts.append(
            f'<div class="scope-stat loc"><div class="scope-value">{html.escape(_metric_num(loc_val))}</div>'
            f'<div class="scope-label">Lines of Code Scanned</div></div>'
        )
    return f'<div class="scan-scope-bar">{"".join(parts)}</div>'


def render_framework_strip() -> str:
    """Static methodology context — no dynamic counts (avoids duplicating scope/result KPIs)."""
    pills = [
        ("layer-sast", "109", "Check framework"),
        ("layer-sast", "85+", "Vuln classes"),
        ("layer-iac", "750+", "Patterns"),
        ("layer-dast", "6", "Scan layers"),
    ]
    html_pills = "".join(
        f'<span class="coverage-pill {css}"><span class="pill-num">{html.escape(num)}</span> {html.escape(label)}</span>'
        for css, num, label in pills
    )
    return f'<div class="coverage-strip coverage-framework" aria-label="Scan methodology">{html_pills}</div>'


# Metrics shown in scan-scope bar — exclude from outcome KPI grid.
_SCOPE_METRIC_PREFIXES = frozenset(
    p.lower()
    for p in (
        "Files Analyzed",
        "Files analyzed",
        "Lines of Code",
        "Lines of code",
    )
)


def _is_scope_metric_key(key: str) -> bool:
    kl = key.lower()
    return any(kl.startswith(p) or p in kl for p in _SCOPE_METRIC_PREFIXES)


def render_kpi_dashboard(metrics: dict[str, str]) -> str:
    """Single Executive Summary visual: scope bar → risk → outcome KPIs → framework strip.

    Markdown ``### Scan Metrics`` table remains the data source; HTML does not re-render it.
    """
    outcome_key_map = [
        (("Checks Executed", "Total Security Checks"), "Checks Run", "kpi-checks"),
        (("Checks with Findings",), "With Findings", "kpi-findings"),
        (("AI-Validated True Positives", "Exploitable findings"), "True Positives", "kpi-tp"),
        (("SCA packages scanned", "SCA packages inventoried"), "SCA Pkgs", "kpi-sca"),
        (("SCA exploitable", "Reachable exploitable Critical/High"), "SCA Exploit", "kpi-cve"),
        (("Unauthenticated Endpoints",), "Open Routes", "kpi-auth"),
        (("Coverage Rate",), "Coverage", "kpi-cov"),
    ]
    cards = []
    used_keys: set[str] = set()
    for prefixes, short, css_class in outcome_key_map:
        k, v = _find_metric(metrics, *prefixes)
        if not v or k in used_keys or _is_scope_metric_key(k):
            continue
        used_keys.add(k)
        num = _metric_num(v)
        cards.append(
            f'<div class="kpi-card {css_class}"><div class="kpi-value">{html.escape(num)}</div>'
            f'<div class="kpi-label">{html.escape(short)}</div></div>'
        )
    risk = metrics.get("Risk score", "")
    risk_html = ""
    if risk:
        score_m = re.search(r"(\d+)/100", risk)
        score = score_m.group(1) if score_m else "—"
        risk_html = (
            f'<div class="risk-banner"><div class="risk-score">{html.escape(score)}</div>'
            f'<div><strong>Overall Risk Score</strong><br><span style="color:var(--muted)">'
            f'{inline_md(re.sub(r"\\*\\*", "", risk))}</span></div></div>'
        )
    scope = render_scan_scope_bar(metrics)
    framework = render_framework_strip()
    grid = ""
    if cards:
        grid = '<div class="kpi-grid">' + "".join(cards) + "</div>"
    if not scope and not grid and not risk_html:
        return ""
    return scope + risk_html + grid + framework


def render_severity_bars() -> str:
    """Deprecated — charts removed in v4.6. Returns empty string."""
    return ""


def render_toc() -> str:
    links = [
        ("executive-summary", "Executive Summary"),
        ("vulnerability-coverage", "Vulnerability Coverage"),
        ("scan-agent", "Scan Agent & Matrices"),
        ("findings-verification", "Verification Checklist"),
        ("sca", "Software Composition Analysis"),
        ("detailed-findings", "Detailed Findings"),
        ("remediation-priority", "Remediation Priority"),
    ]
    items = "".join(f'<li><a href="#{a}">{html.escape(t)}</a></li>' for a, t in links)
    return f'<nav class="toc" id="toc"><strong>Contents</strong><ul>{items}</ul></nav>'


def render_hero(title: str, meta: dict[str, str]) -> str:
    parts = []
    for key in (
        "Report ID",
        "Generated",
        "Project",
        "Skill Version",
        "Scan Agent",
        "AI Validation Agent",
        "Graph Backend",
        "DAST Backend",
        "Method",
    ):
        if key in meta:
            parts.append(f"<span><strong>{html.escape(key)}:</strong> {html.escape(meta[key])}</span>")
    meta_html = f'<div class="report-meta">{"".join(parts)}</div>' if parts else ""
    return f'<header class="report-hero"><h1>{html.escape(title)}</h1>{meta_html}</header>'


def render_classification_chips(kv: dict[str, str]) -> str:
    # Source/Sink render in source-sink-banner only — not duplicated here (avoids overflow)
    fields = [
        ("Severity", "Severity"),
        ("AI Verdict", "AI Verdict"),
        ("Exploitable", "Exploitable"),
        ("CWE", "CWE"),
        ("OWASP", "OWASP"),
        ("SANS CWE Top 25", "SANS"),
        ("Type", "Type"),
    ]
    chips = []
    for key, label in fields:
        val = kv.get(key, "")
        if key == "CWE" and not val:
            val = kv.get("CWE ID", kv.get("CWE", ""))
        if key == "Type" and not val:
            val = kv.get("Type", kv.get("Vulnerability Type", ""))
        if val:
            if key == "Exploitable":
                val = normalize_exploitable(val)
                chip_val = exploitable_pill(val)
            elif key == "AI Verdict":
                val = normalize_ai_verdict(val)
                chip_val = verdict_pill(val)
            else:
                chip_val = inline_md(val)
            chips.append(
                f'<div class="class-chip"><span>{html.escape(label)}</span>{chip_val}</div>'
            )
    if not chips:
        return ""
    return f'<div class="class-grid">{"".join(chips)}</div>'


def parse_markdown_table(lines: list[str]) -> dict[str, str]:
    """Parse a markdown pipe table into key->value (first col -> second col)."""
    result: dict[str, str] = {}
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        if i == 1 and all(re.match(r"^[-:]+$", c) for c in cells):
            continue
        if cells[0].lower() in ("attribute", "field", "th"):
            continue
        key = cells[0].strip("*")
        val = cells[1].strip("*")
        if key and val and key.lower() != "value":
            result[key] = val
    return result


def split_sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = "_preamble"
    buf: list[str] = []
    for line in body.splitlines():
        if line.startswith("### "):
            sections[current] = "\n".join(buf).strip()
            current = line[4:].strip().lower()
            buf = []
        else:
            buf.append(line)
    sections[current] = "\n".join(buf).strip()
    return sections


def extract_finding_id(text: str) -> Optional[str]:
    m = FINDING_ID_RE.search(text)
    if m:
        return f"{m.group(1).upper()}-{m.group(2)}"
    return None


def clean_title(raw: str) -> str:
    title = FINDING_HEADER_RE.match(raw)
    if not title:
        return raw.strip()
    text = title.group(2).strip()
    text = FINDING_ID_RE.sub("", text).strip()
    return text


def _header_index(header: list[str], *names: str) -> int:
    for i, h in enumerate(header):
        low = h.lower()
        if any(n.lower() in low for n in names):
            return i
    return -1


def parse_summary_table(md: str) -> dict[str, SummaryRow]:
    rows: dict[str, SummaryRow] = {}
    in_summary = False
    table_lines: list[str] = []
    register_titles = (
        "## Security Verification Checklist",
        "## Security Findings Verification Register",
        "## Master Findings Register",
        "## Findings Summary Table",
    )
    for line in md.splitlines():
        if any(line.startswith(t) for t in register_titles):
            in_summary = True
            continue
        if in_summary:
            if line.startswith("## ") and not any(t.replace("## ", "") in line for t in register_titles):
                break
            if line.strip().startswith("|"):
                table_lines.append(line)
    if len(table_lines) < 2:
        return rows
    header = [c.strip().lower() for c in table_lines[0].strip().strip("|").split("|")]
    src_col = _header_index(header, "source")
    sink_col = _header_index(header, "sink")
    verdict_col = _header_index(header, "ai verdict")
    exploitable_col = _header_index(header, "exploitable")
    verify_col = _header_index(header, "verification status", "verification")
    dast_col = _header_index(header, "dast status", "dast")
    poc_col = _header_index(header, "poc")
    status_col = _header_index(header, "status")
    for i, line in enumerate(table_lines):
        if i < 2:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        fid = cells[0]
        source = cells[src_col] if src_col >= 0 and src_col < len(cells) else (cells[3] if len(cells) > 3 else "")
        sink = cells[sink_col] if sink_col >= 0 and sink_col < len(cells) else (cells[4] if len(cells) > 4 else "")
        verification = cells[verify_col] if verify_col >= 0 and verify_col < len(cells) else ""
        dast = cells[dast_col] if dast_col >= 0 and dast_col < len(cells) else ""
        if status_col >= 0 and status_col < len(cells) and not verification:
            status = cells[status_col]
        elif verify_col >= 0 and verify_col < len(cells):
            status = cells[verify_col]
        else:
            status = cells[-1]
        rows[fid] = SummaryRow(
            finding_id=fid,
            severity=cells[1],
            category=cells[2],
            source_path=source,
            sink_path=sink,
            file_line=source,
            method=sink,
            status=status,
            verification_status=verification or status,
            dast_status=dast,
        )
    return rows


def enrich_finding_from_register(finding: ParsedFinding) -> list[str]:
    """Backfill Classification Source/Sink from verification register row (display only)."""
    notes: list[str] = []
    fid = finding.finding_id or "?"
    if finding.summary:
        if not finding.kv_tables.get("Source (full path)"):
            val = finding.summary.source_path or finding.summary.file_line
            if val:
                finding.kv_tables["Source (full path)"] = val
                notes.append(
                    f"{fid}: backfilled Source from checklist — add to Classification in markdown"
                )
        if not finding.kv_tables.get("Sink (full path)"):
            val = finding.summary.sink_path or finding.summary.method
            if val:
                finding.kv_tables["Sink (full path)"] = val
                notes.append(
                    f"{fid}: backfilled Sink from checklist — add to Classification in markdown"
                )
    source, sink, _, _ = build_source_sink(finding)
    if source and not finding.kv_tables.get("Source (full path)"):
        finding.kv_tables["Source (full path)"] = source
        notes.append(f"{fid}: backfilled Source from data flow — add to Classification in markdown")
    if sink and not finding.kv_tables.get("Sink (full path)"):
        finding.kv_tables["Sink (full path)"] = sink
        notes.append(f"{fid}: backfilled Sink from data flow — add to Classification in markdown")
    return notes


def parse_findings(md: str) -> list[ParsedFinding]:
    findings: list[ParsedFinding] = []
    in_details = False
    current_header: Optional[str] = None
    current_body: list[str] = []

    def flush():
        nonlocal current_header, current_body
        if not current_header:
            return
        body = "\n".join(current_body).strip()
        severity_m = FINDING_HEADER_RE.match(current_header)
        if not severity_m:
            current_header = None
            current_body = []
            return
        severity = severity_m.group(1).upper()
        title = clean_title(current_header)
        finding_id = extract_finding_id(current_header) or extract_finding_id(body)
        sections = split_sections(body)
        kv: dict[str, str] = {}
        for sec_text in sections.values():
            if "|" in sec_text:
                kv.update(parse_markdown_table(sec_text.splitlines()))
        for chunk in re.split(r"\n\n+", body):
            if chunk.strip().startswith("|"):
                kv.update(parse_markdown_table(chunk.splitlines()))
        normalize_finding_kv(kv)
        findings.append(
            ParsedFinding(
                finding_id=finding_id,
                severity=severity,
                title=title,
                body=body,
                sections=sections,
                kv_tables=kv,
            )
        )
        current_header = None
        current_body = []

    for line in md.splitlines():
        if line.startswith("## Detailed Findings"):
            in_details = True
            continue
        if not in_details:
            continue
        if FINDING_HEADER_RE.match(line):
            flush()
            current_header = line
            current_body = []
            continue
        if line.startswith("## ") and not FINDING_HEADER_RE.match(line):
            flush()
            break
        if current_header:
            if is_separator_line(line):
                continue
            current_body.append(line)
    flush()
    return findings


def _title_tokens(title: str) -> set[str]:
    stop = {"via", "with", "the", "and", "in", "on", "to", "a", "an", "—", "-"}
    return {
        t.lower()
        for t in re.findall(r"[A-Za-z0-9/_.]+", title)
        if len(t) > 2 and t.lower() not in stop
    }


def assign_missing_ids(findings: list[ParsedFinding], summary: dict[str, SummaryRow]) -> None:
    used = {f.finding_id for f in findings if f.finding_id}
    for finding in findings:
        if finding.finding_id:
            finding.summary = summary.get(finding.finding_id)
    for finding in findings:
        if finding.finding_id:
            continue
        ftokens = _title_tokens(finding.title)
        best: Optional[SummaryRow] = None
        best_score = 0
        for row in summary.values():
            if row.finding_id in used:
                continue
            rtokens = _title_tokens(row.category + " " + row.method)
            score = len(ftokens & rtokens)
            if row.method.lower() in finding.title.lower():
                score += 3
            if score > best_score:
                best_score = score
                best = row
        if best and best_score > 0:
            finding.finding_id = best.finding_id
            finding.summary = best
            used.add(best.finding_id)
    summary_list = [r for r in summary.values() if r.finding_id not in used]
    for finding in findings:
        if finding.finding_id:
            continue
        if summary_list:
            candidate = summary_list.pop(0)
            finding.finding_id = candidate.finding_id
            finding.summary = candidate
            used.add(candidate.finding_id)


def parse_file_line_ref(ref: str) -> tuple[str, str]:
    ref = ref.strip()
    m = FILE_LINE_RE.match(ref.split()[0] if " " in ref else ref)
    if m:
        file_part = m.group(1)
        line_part = m.group(2) or ""
        return file_part, line_part
    if ":" in ref:
        parts = ref.split(":", 1)
        return parts[0].strip(), parts[1].strip()
    return ref, ""


def extract_from_data_flow(text: str) -> tuple[str, str]:
    source, sink = "", ""
    lines = text.splitlines()
    for line in lines:
        if "SOURCE" in line.upper() or "source" in line.lower():
            m = re.search(r"\[([^\]:]+):(\d+)\]", line)
            if m:
                source = f"{m.group(1).strip()}:{m.group(2)}"
        if "SINK" in line.upper() or "sink" in line.lower() or "request(" in line:
            m = re.search(r"\[line:(\d+)\]|\[([^\]:]+):(\d+)\]", line)
            if m:
                if m.lastindex and m.lastindex >= 3 and m.group(2):
                    sink = f"{m.group(2).strip()}:{m.group(3)}"
                elif m.group(1):
                    sink = f"line {m.group(1)}"
    if not sink:
        for line in reversed(lines):
            m = re.search(r"\[([^\]:]+):(\d+)\]", line)
            if m:
                sink = f"{m.group(1).strip()}:{m.group(2)}"
                break
    if not source:
        for line in lines:
            m = re.search(r"\[([^\]:]+):(\d+)\]", line)
            if m:
                source = f"{m.group(1).strip()}:{m.group(2)}"
                break
    return source, sink


def _preamble_paragraphs(finding: ParsedFinding) -> list[str]:
    preamble = finding.sections.get("_preamble", "")
    return [
        p.strip()
        for p in preamble.split("\n\n")
        if p.strip() and not p.strip().startswith("|") and not is_separator_line(p)
    ]


def build_description(finding: ParsedFinding) -> str:
    if finding.sections.get("description"):
        return finding.sections["description"]
    paras = _preamble_paragraphs(finding)
    remediation = build_remediation(finding, _skip_summary_fallback=True)
    if paras:
        desc_paras = [p for p in paras if p.strip() != remediation.strip()]
        if desc_paras:
            return "\n\n".join(desc_paras)
    if finding.summary:
        return (
            f"**{finding.summary.category}** affecting "
            f"**{finding.summary.method}** at "
            f"**{finding.summary.file_line}**. "
            f"Validation status: {finding.summary.status}."
        )
    return ""


def build_source_sink(finding: ParsedFinding) -> tuple[str, str, str, str]:
    kv = finding.kv_tables
    file_ref = kv.get("File", "")
    method = kv.get("Method", kv.get("Methods", ""))
    route = kv.get("Route", kv.get("Routes", ""))

    source_line = kv.get("Source Line", "")
    sink_line = kv.get("Sink Line", kv.get("Sink", ""))
    if not source_line and kv.get("Source") and "line" in kv.get("Source", "").lower():
        source_line = kv["Source"]

    data_flow = finding.sections.get("data flow trace (source → sink)", "")
    if not data_flow:
        data_flow = finding.sections.get("data flow trace (source -> sink)", "")
    loc_flow = finding.sections.get("location & data flow", "")
    if loc_flow:
        data_flow = loc_flow if not data_flow else data_flow
    df_source, df_sink = extract_from_data_flow(data_flow or loc_flow)

    if finding.summary and not file_ref:
        file_ref, summary_line = parse_file_line_ref(finding.summary.file_line)
        if summary_line and not source_line:
            source_line = summary_line

    desc_text = finding.sections.get("description", "") + " " + finding.sections.get("_preamble", "")
    desc_lines = re.findall(r"at lines?\s+\*\*(\d+(?:-\d+)?(?:,\s*\*\*\d+(?:-\d+)?)*)\*\*", desc_text, re.I)
    if desc_lines:
        sink_line = sink_line or desc_lines[0].replace("**", "").replace(",", ", ")

    if file_ref and source_line and ":" not in str(source_line):
        source = f"{file_ref}:{source_line}"
    elif df_source:
        source = df_source
    elif finding.summary and not str(source_line).startswith("get"):
        source = finding.summary.file_line
    else:
        source = source_line or (finding.summary.file_line if finding.summary else "") or file_ref or ""

    if sink_line and re.match(r"routes/", str(sink_line)):
        sink = sink_line
    elif file_ref and sink_line and ":" not in str(sink_line):
        sink = f"{file_ref}:{sink_line}"
    elif df_sink:
        sink = df_sink
    elif sink_line:
        sink = sink_line
    elif file_ref and ":" in file_ref:
        sink = file_ref
    else:
        sink = ""

    if not method and finding.summary:
        method = finding.summary.method
    if route and not method:
        method = route

    return source, sink, file_ref or (finding.summary.file_line.split(":")[0] if finding.summary and ":" in finding.summary.file_line else ""), method


def build_assumptions(finding: ParsedFinding) -> str:
    for key in finding.sections:
        if key == "assumptions" or key.startswith("assumptions"):
            return finding.sections[key]
    return ""


def build_impact(finding: ParsedFinding) -> str:
    for key in finding.sections:
        if key == "impact assessment" or key.startswith("impact assessment"):
            return finding.sections[key]
    if finding.kv_tables.get("Impact"):
        return finding.kv_tables["Impact"]
    if finding.kv_tables.get("Blast radius"):
        return finding.kv_tables["Blast radius"]
    return ""


def parse_remediation_priority(md: str) -> dict[str, str]:
    """Extract numbered remediation bullets keyed by finding ID (e.g. VULN-001)."""
    items: dict[str, str] = {}
    in_section = False
    for line in md.splitlines():
        if line.startswith("## Remediation Priority"):
            in_section = True
            continue
        if in_section and line.startswith("## ") and "Remediation Priority" not in line:
            break
        if not in_section:
            continue
        m = re.match(r"^\d+\.\s+\*\*([A-Z]+-\d+)\*\*\s*[-—]\s*(.+)$", line.strip())
        if m:
            items[m.group(1).upper()] = m.group(2).strip()
    return items


REMEDIATION_VERBS = (
    "add ",
    "remove ",
    "require ",
    "restrict ",
    "build ",
    "allowlist",
    "move ",
    "use ",
    "ensure ",
    "validate ",
    "externalize",
    "scrub ",
    "protect ",
    "document ",
    "upgrade ",
    "replace ",
    "enforce ",
    "block/",
    "never ",
    "disable ",
)


def _looks_like_remediation(text: str) -> bool:
    lower = text.lower().strip()
    if not lower or lower.startswith("|"):
        return False
    if lower.startswith("**before") or lower.startswith("**after"):
        return True
    return any(v in lower[:80] for v in REMEDIATION_VERBS)


def build_remediation(
    finding: ParsedFinding,
    _skip_summary_fallback: bool = False,
    priority_map: Optional[dict[str, str]] = None,
) -> str:
    for key in finding.sections:
        if "remediation" in key:
            return finding.sections[key]
    if finding.kv_tables.get("Remediation"):
        return finding.kv_tables["Remediation"]
    paras = _preamble_paragraphs(finding)
    remediation_chunks: list[str] = []
    for para in paras:
        if _looks_like_remediation(para):
            remediation_chunks.append(para)
    if remediation_chunks:
        return "\n\n".join(remediation_chunks)
    if finding.finding_id and priority_map and not _skip_summary_fallback:
        bullet = priority_map.get(finding.finding_id.upper())
        if bullet:
            return (
                f"See Remediation Priority: **{finding.finding_id}** — {bullet}\n\n"
                "Add a full `### Remediation` section with BEFORE/AFTER code in the markdown report."
            )
    if _skip_summary_fallback:
        return ""
    return ""


def render_inline_content(text: str) -> str:
    if not text.strip():
        return ""
    parts: list[str] = []
    buf: list[str] = []
    in_code = False
    code_lang = ""
    code_lines: list[str] = []
    table_buf: list[str] = []

    def flush_table():
        nonlocal table_buf
        if table_buf:
            parts.append(wrap_table_html(md_table_to_html(table_buf)))
            table_buf = []

    def flush_code():
        nonlocal code_lines, code_lang, in_code
        if code_lines:
            lang_class = f' class="language-{code_lang}"' if code_lang else ""
            is_http = code_lang == "http" or any(
                l.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE "))
                for l in code_lines
            )
            pre = f'<pre{lang_class}><code>{html.escape(chr(10).join(code_lines))}</code></pre>'
            parts.append(f'<div class="burp-block">{pre}</div>' if is_http else pre)
            code_lines = []
            code_lang = ""
        in_code = False

    for line in text.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                flush_code()
            else:
                flush_table()
                in_code = True
                code_lang = line.strip()[3:].strip().lower()
            continue
        if in_code:
            code_lines.append(line)
            continue
        if line.strip().startswith("|"):
            table_buf.append(line)
            continue
        flush_table()
        if line.startswith("### "):
            parts.append(f'<h4 class="flow-subhead">{inline_md(line[4:].strip())}</h4>')
            continue
        if is_separator_line(line):
            continue
        if line.strip():
            parts.append(f"<p>{inline_md(line.strip())}</p>")
    flush_table()
    flush_code()
    return "\n".join(parts)


def render_core_panel(title: str, content_html: str, missing: bool = False, css_class: str = "") -> str:
    extra = f" {css_class}" if css_class else ""
    cls = f"core-panel missing{extra}" if missing else f"core-panel{extra}"
    if missing or not content_html.strip():
        inner = f'<p class="placeholder">Not documented in markdown report — add a ### {html.escape(title)} section.</p>'
    else:
        inner = content_html
    return f'<section class="{cls}"><h3>{html.escape(title)}</h3>{inner}</section>'


def _path_display(val: str) -> str:
    clean = val.strip().strip("`").strip()
    if not clean:
        return '<span class="placeholder">—</span>'
    return f"<code>{html.escape(clean)}</code>"


def render_source_sink_banner(source: str, sink: str) -> str:
    if not source.strip() and not sink.strip():
        return (
            '<div class="source-sink-banner missing">'
            "<span>Source/Sink missing — add "
            "<code>Source (full path)</code> and <code>Sink (full path)</code> "
            "to Classification (see report-findings-verification-register.md).</span>"
            "</div>"
        )
    return (
        '<div class="source-sink-banner">'
        f'<div class="ss-item"><span class="ss-label">Source (full path)</span>{_path_display(source)}</div>'
        f'<div class="ss-item"><span class="ss-label">Sink (full path)</span>{_path_display(sink)}</div>'
        "</div>"
    )


def render_trace_panel(source: str, sink: str, file_ref: str, method: str) -> str:
    def cell(val: str, css: str = "") -> str:
        if not val:
            return '<span class="placeholder">—</span>'
        escaped = inline_md(val)
        return f'<span class="{css}">{escaped}</span>' if css else escaped

    rows = [
        ("File", cell(file_ref)),
        ("Source (line)", cell(source, "trace-source")),
        ("Sink (line)", cell(sink, "trace-sink")),
        ("Method / Route", cell(method)),
    ]
    body = "".join(f"<tr><th>{html.escape(k)}</th><td>{v}</td></tr>" for k, v in rows)
    missing = not any([source, sink, file_ref])
    cls = "core-panel missing" if missing else "core-panel"
    note = ""
    if missing:
        note = '<p class="placeholder">Add Source Line / Sink Line to Location Summary, or a Data Flow Trace block.</p>'
    return f'<section class="{cls}"><h3>Source → Sink</h3>{note}<table class="trace-table"><tbody>{body}</tbody></table></section>'


def render_findings_section(findings: list[ParsedFinding], priority_map: Optional[dict[str, str]] = None) -> str:
    if not findings:
        return "<p>No detailed findings parsed.</p>"
    return "\n".join(render_finding(f, priority_map) for f in findings)


def build_vulnerable_code(finding: ParsedFinding) -> str:
    for key in ("vulnerable code snippet", "vulnerable code"):
        if finding.sections.get(key):
            return finding.sections[key]
    return ""


def build_data_flow_trace(finding: ParsedFinding) -> str:
    loc = finding.sections.get("location & data flow", "")
    trace_text = ""
    for key, content in finding.sections.items():
        if ("data flow trace" in key or key == "data flow trace") and content.strip():
            trace_text = content
            break
    if loc and loc not in trace_text:
        trace_text = f"{loc}\n\n{trace_text}" if trace_text else loc
    # Strip embedded ### Simplified Flow — rendered separately
    trace_text = re.sub(r"\n### Simplified Flow\s*\n", "\n", trace_text, flags=re.I)
    return trace_text.strip()


def build_simplified_flow(finding: ParsedFinding) -> str:
    simp = finding.sections.get("simplified flow", "")
    if simp.strip():
        return simp.strip()
    for key, content in finding.sections.items():
        if "data flow trace" in key and "### Simplified Flow" in content:
            m = re.split(r"### Simplified Flow\s*\n", content, maxsplit=1, flags=re.I)
            if len(m) > 1:
                return m[1].strip().strip("`").strip()
    return ""


def count_missing_section(
    findings: list[ParsedFinding],
    builder,
) -> list[str]:
    missing: list[str] = []
    for f in findings:
        if not builder(f).strip():
            missing.append(f.finding_id or f.title)
    return missing


def count_missing_remediation(findings: list[ParsedFinding], priority_map: Optional[dict[str, str]] = None) -> list[str]:
    missing: list[str] = []
    for f in findings:
        if not build_remediation(f, priority_map=priority_map).strip():
            missing.append(f.finding_id or f.title)
    return missing


def render_finding(finding: ParsedFinding, priority_map: Optional[dict[str, str]] = None) -> str:
    fid = finding.finding_id or "UNKNOWN"
    badge = f'<span class="badge badge-{finding.severity.lower()}">{finding.severity}</span>'
    description = build_description(finding)
    vulnerable = build_vulnerable_code(finding)
    data_flow = build_data_flow_trace(finding)
    simplified = build_simplified_flow(finding)
    source, sink, file_ref, method = build_source_sink(finding)
    reg_source = finding.kv_tables.get("Source (full path)", source)
    reg_sink = finding.kv_tables.get("Sink (full path)", sink)
    impact = build_impact(finding)
    remediation = build_remediation(finding, priority_map=priority_map)
    class_chips = render_classification_chips(finding.kv_tables)
    source_sink_banner = render_source_sink_banner(reg_source, reg_sink)
    sev_class = f"sev-{finding.severity.lower()}"

    data_flow_html = render_inline_content(data_flow)
    if simplified:
        simp_body = simplified.strip("`").strip()
        if simp_body.startswith("```"):
            data_flow_html += render_inline_content(simplified)
        else:
            data_flow_html += (
                '<div class="simplified-flow"><h4 class="flow-subhead">Simplified Flow</h4>'
                f'<pre><code>{html.escape(simp_body)}</code></pre></div>'
            )

    trace_panel = ""
    if not data_flow.strip():
        trace_panel = render_trace_panel(source, sink, file_ref, method)

    core_html = f"""
<div class="finding-core">
  {source_sink_banner}
  {class_chips}
  {render_core_panel("Description", render_inline_content(description), missing=not description.strip())}
  {render_core_panel("Vulnerable Code", render_inline_content(vulnerable), missing=not vulnerable.strip(), css_class="vuln-code")}
  {render_core_panel("Data Flow Trace", data_flow_html, missing=not data_flow.strip() and not simplified.strip(), css_class="data-flow")}
  {trace_panel}
  {render_core_panel("Impact", render_inline_content(impact), missing=not impact.strip())}
  {render_core_panel("Remediation", render_inline_content(remediation), missing=not remediation.strip())}
</div>
"""

    extra_sections: list[str] = []
    skip_keys = {
        "description",
        "_preamble",
        "remediation",
        "vulnerable code snippet",
        "vulnerable code",
        "simplified flow",
        "location summary",
        "location & data flow",
        "live verification (burp mcp)",
        "live verification",
        "classification",
        "impact assessment",
        "ai validation details",
    }
    for key, content in finding.sections.items():
        if key in skip_keys or not content.strip():
            continue
        if "data flow trace" in key or "location & data flow" in key:
            continue
        if "impact" in key:
            continue
        title = key.title()
        extra_sections.append(f'<div class="finding-extra"><h3>{html.escape(title)}</h3>{render_inline_content(content)}</div>')

    extra_html = "\n".join(extra_sections)
    anchor = f'id="{html.escape(fid)}"' if finding.finding_id else ""

    return f"""
<div class="finding {sev_class}" {anchor}>
  <div class="finding-header">
    {badge}
    <h2>{inline_md(finding.title)}</h2>
    <span class="finding-id">{html.escape(fid)}</span>
  </div>
  {core_html}
  {extra_html}
</div>
"""


def coverage_status_cell(text: str) -> str:
    raw = text.strip()
    if not raw or raw == "—":
        return inline_md(text)
    key = raw.lower().split()[0].replace("/", "")
    if key in COVERAGE_STATUS_COLORS or raw.lower().split()[0] in COVERAGE_STATUS_COLORS:
        lookup = key if key in COVERAGE_STATUS_COLORS else raw.lower().split()[0]
        cls = f"status-{lookup.replace('/', '')}"
        return f'<span class="{cls}">{html.escape(raw)}</span>'
    return inline_md(text)


def severity_badge(text: str) -> str:
    raw = text.strip().lower()
    if raw in SEVERITY_COLORS:
        return f'<span class="badge badge-{raw}">{html.escape(text.strip())}</span>'
    return inline_md(text)


def verdict_pill(text: str) -> str:
    raw = text.strip().upper()
    if "TRUE POSITIVE" in raw:
        return f'<span class="pill verdict-tp">{html.escape(text.strip())}</span>'
    if "FALSE POSITIVE" in raw:
        return f'<span class="pill verdict-fp">{html.escape(text.strip())}</span>'
    if "FILTERED" in raw:
        return f'<span class="pill verdict-filtered">{html.escape(text.strip())}</span>'
    return inline_md(text)


def exploitable_pill(text: str) -> str:
    canon = normalize_exploitable(text)
    if canon == "Yes":
        return '<span class="pill exp-yes">Yes</span>'
    if canon == "No":
        return '<span class="pill exp-no">No</span>'
    if canon == "Hardening":
        return '<span class="pill exp-hardening">Hardening</span>'
    if canon in EXPLOITABLE_CANONICAL:
        return f'<span class="pill exp-{canon.lower()}">{html.escape(canon)}</span>'
    title = html.escape(text.strip()) if text.strip() else "invalid"
    return f'<span class="pill exp-unknown" title="{title}">{html.escape(canon or text.strip())}</span>'


def md_table_to_html(lines: list[str], coverage_table: bool = False, master_register: bool = False) -> str:
    if len(lines) < 2:
        return ""
    status_col = -1
    severity_col = -1
    verdict_col = -1
    exploitable_col = -1
    header_cells: list[str] = []
    if lines[0].strip().startswith("|"):
        header_cells = [c.strip() for c in lines[0].strip().strip("|").split("|")]
        for idx, name in enumerate(header_cells):
            low = name.lower()
            if low == "status":
                status_col = idx
            if low == "severity":
                severity_col = idx
            if "ai verdict" in low:
                verdict_col = idx
            if low == "exploitable":
                exploitable_col = idx
    rows = []
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if i == 1 and all(re.match(r"^[-:]+$", c) for c in cells):
            continue
        tag = "th" if i == 0 else "td"
        if tag == "td" and (coverage_table or master_register):
            rendered = []
            for j, c in enumerate(cells):
                if coverage_table and j == status_col:
                    rendered.append(f"<td>{coverage_status_cell(c)}</td>")
                elif master_register and j == severity_col:
                    rendered.append(f"<td>{severity_badge(c)}</td>")
                elif master_register and j == verdict_col:
                    rendered.append(f"<td>{verdict_pill(c)}</td>")
                elif master_register and j == exploitable_col:
                    rendered.append(f"<td>{exploitable_pill(c)}</td>")
                else:
                    rendered.append(f"<td>{inline_md(c)}</td>")
            rows.append("<tr>" + "".join(rendered) + "</tr>")
            continue
        rows.append("<tr>" + "".join(f"<{tag}>{inline_md(c)}</{tag}>" for c in cells) + "</tr>")
    if not rows:
        return ""
    return "<table>" + "".join(rows) + "</table>"


def inline_md(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*\*([^*]+)$", r"<strong>\1</strong>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def is_finding_header(line: str) -> bool:
    return bool(FINDING_HEADER_RE.match(line))


def markdown_to_html(md: str, findings_html: str, title: str = "") -> str:
    lines = md.splitlines()
    out: list[str] = []
    i = 0
    in_code = False
    code_lang = ""
    code_buf: list[str] = []
    table_buf: list[str] = []
    in_coverage_section = False
    skip_until_remediation = False
    findings_inserted = False
    hero_done = False
    skip_header_preamble = False
    exec_kpi_done = False
    skip_exec_subsection = False  # suppress duplicate markdown tables already in KPI dashboard
    skip_register_blurb = False
    skip_suppressed_appendix: Optional[str] = None  # "F" = until Appendix F; "EOF" = until end
    wrap_next_table_in_details = False
    risk_in_banner = False
    in_details = False
    args_title = title

    meta = parse_report_meta(md)
    exec_metrics = parse_executive_metrics(md)

    def flush_table():
        nonlocal table_buf, in_coverage_section, wrap_next_table_in_details
        if table_buf:
            is_cov = in_coverage_section or (
                table_buf
                and (
                    "Check ID" in table_buf[0]
                    or ("Phase" in table_buf[0] and "Step" in table_buf[0])
                )
            )
            is_master = table_buf and table_buf[0].startswith("| ID |") and (
                "Verification Status" in table_buf[0]
                or ("AI Verdict" in table_buf[0] and "Exploitable" in table_buf[0])
            )
            is_summary = table_buf and table_buf[0].startswith("| ID |") and not is_master
            tbl = md_table_to_html(
                table_buf,
                coverage_table=is_cov,
                master_register=is_master,
            )
            if is_master:
                tbl = tbl.replace("<table>", '<table class="master-register">')
                tbl = wrap_table_html(tbl, "table-wrap master-wrap")
                if wrap_next_table_in_details:
                    n = max(0, len(table_buf) - 2)
                    tbl = (
                        f'<details class="verify-checklist">'
                        f"<summary>{n} findings — verification status (click to expand)</summary>"
                        f"{tbl}</details>"
                    )
                    wrap_next_table_in_details = False
            elif is_summary:
                tbl = tbl.replace("<table>", '<table class="summary-table">')
                tbl = wrap_table_html(tbl, "table-wrap")
            elif is_cov:
                tbl = wrap_table_html(tbl, "table-wrap coverage-wrap")
            else:
                tbl = wrap_table_html(tbl)
            out.append(tbl)
            table_buf = []

    def flush_code():
        nonlocal code_buf, code_lang, in_code
        if code_buf:
            lang_class = f' class="language-{code_lang}"' if code_lang else ""
            is_http = code_lang in ("http", "") and any(
                l.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS "))
                for l in code_buf
            )
            block_class = "burp-block" if is_http else ""
            pre = f'<pre{lang_class}><code>{html.escape(chr(10).join(code_buf))}</code></pre>'
            out.append(f'<div class="{block_class}">{pre}</div>' if block_class else pre)
            code_buf = []
            code_lang = ""
        in_code = False

    section_ids = {
        "Executive Summary": "executive-summary",
        "Vulnerability Coverage Overview": "vulnerability-coverage",
        "Scan Agent & Backend Attribution": "scan-agent",
        "Scan Matrices Executed": "scan-agent",
        "Security Findings Verification Register": "findings-verification",
        "Security Verification Checklist": "findings-verification",
        "Master Findings Register": "findings-verification",
        "Findings Summary": "findings-verification",
        "Findings Summary Table": "findings-verification",
        "Software Composition Analysis (SCA)": "sca",
        "Detailed Findings": "detailed-findings",
        "Remediation Priority": "remediation-priority",
    }

    while i < len(lines):
        line = lines[i]

        if skip_until_remediation:
            if line.startswith("## Remediation Priority"):
                skip_until_remediation = False
            else:
                i += 1
                continue

        if line.strip().startswith("<details>"):
            look = " ".join(lines[i : min(i + 4, len(lines))]).lower()
            cls = ' class="verify-checklist"' if "checklist" in look or "expand" in look else ""
            out.append(f"<details{cls}>")
            in_details = True
            i += 1
            continue
        if line.strip().startswith("</details>"):
            out.append("</details>")
            in_details = False
            i += 1
            continue
        if line.strip().startswith("<summary>"):
            out.append(f"<summary>{inline_md(line.strip()[9:-10] if line.strip().endswith('</summary>') else line.strip()[9:])}</summary>")
            i += 1
            continue

        if line.strip().startswith("```"):
            if in_code:
                flush_code()
            else:
                flush_table()
                in_code = True
                code_lang = line.strip()[3:].strip().lower()
                if code_lang == "mermaid":
                    in_code = False
                    code_lang = ""
                    i += 1
                    while i < len(lines) and not lines[i].strip().startswith("```"):
                        i += 1
                    if i < len(lines):
                        i += 1
                    continue
            i += 1
            continue

        if in_code:
            code_buf.append(line)
            i += 1
            continue

        if line.strip().startswith("|"):
            if skip_exec_subsection or skip_suppressed_appendix:
                i += 1
                continue
            table_buf.append(line)
            i += 1
            continue
        flush_table()

        if skip_header_preamble:
            stripped = line.strip()
            if stripped.startswith("## "):
                skip_header_preamble = False
            elif REPORT_META_LINE_RE.match(stripped) or stripped == "" or line.startswith("---") or is_separator_line(line):
                i += 1
                continue

        if line.startswith("# "):
            if not hero_done:
                t = args_title if args_title else line[2:].strip()
                out.append(render_hero(t, meta))
                out.append(render_toc())
                hero_done = True
                skip_header_preamble = True
                toc_done = True
            else:
                out.append(f"<h1>{inline_md(line[2:].strip())}</h1>")
        elif line.startswith("## Detailed Findings"):
            out.append(f'<h2 id="detailed-findings">{inline_md("Detailed Findings")}</h2>')
            out.append(findings_html)
            findings_inserted = True
            skip_until_remediation = True
        elif is_finding_header(line):
            pass
        elif line.startswith("## "):
            if in_coverage_section:
                out.append("</div>")
                in_coverage_section = False
            heading = line[3:].strip()
            if heading.startswith("Appendix E") or "Security Check Coverage Matrix" in heading:
                skip_suppressed_appendix = "F"
                i += 1
                continue
            if heading.startswith("Appendix G") or "Security Architecture Assessment" in heading:
                skip_suppressed_appendix = "EOF"
                i += 1
                continue
            if heading.startswith("Appendix I") or "Platform Checklist Attestation" in heading:
                skip_suppressed_appendix = "EOF"
                i += 1
                continue
            if skip_suppressed_appendix == "F" and heading.startswith("Appendix F"):
                skip_suppressed_appendix = None
            skip_exec_subsection = False
            if skip_suppressed_appendix:
                i += 1
                continue
            sid = section_ids.get(heading, "")
            anchor = f' id="{sid}"' if sid else ""
            if heading == "Executive Summary" and not exec_kpi_done:
                out.append(f"<h2{anchor}>{inline_md(heading)}</h2>")
                out.append(render_kpi_dashboard(exec_metrics))
                exec_kpi_done = True
                risk_in_banner = bool(exec_metrics.get("Risk score"))
            elif heading in (
                "Master Findings Register",
                "Security Findings Verification Register",
                "Security Verification Checklist",
            ):
                out.append(f"<h2{anchor}>{inline_md(heading)}</h2>")
                skip_register_blurb = True
                wrap_next_table_in_details = True
            elif heading == "Vulnerability Coverage Overview":
                out.append(f"<h2{anchor}>{inline_md(heading)}</h2>")
                skip_exec_subsection = True  # skip duplicate scope summary table; keep ### subsections
            elif heading.startswith("Appendix F") or heading.startswith("Appendix G"):
                out.append(f"<h2{anchor}>{inline_md(heading)}</h2>")
            else:
                out.append(f"<h2{anchor}>{inline_md(heading)}</h2>")
        elif line.startswith("### "):
            if skip_suppressed_appendix:
                i += 1
                continue
            sub = line[4:].strip()
            if exec_kpi_done and sub.lower() == "scan metrics":
                skip_exec_subsection = True
                i += 1
                continue
            if exec_kpi_done and risk_in_banner and sub.lower().startswith("risk score"):
                i += 1
                continue
            if exec_kpi_done and sub.lower() == "severity distribution":
                skip_exec_subsection = True
                i += 1
                continue
            if skip_exec_subsection and sub.lower().startswith("checks by layer"):
                skip_exec_subsection = False
            if skip_exec_subsection and sub.lower() == "checks performed summary":
                skip_exec_subsection = False
            out.append(f"<h3>{inline_md(sub)}</h3>")
        elif line.startswith("#### "):
            out.append(f"<h4>{inline_md(line[5:].strip())}</h4>")
        elif line.startswith("---"):
            out.append("<hr>")
        elif line.startswith("- "):
            out.append(f"<ul><li>{inline_md(line[2:].strip())}</li></ul>")
        elif line.startswith("> "):
            out.append(f"<blockquote>{inline_md(line[2:].strip())}</blockquote>")
        elif is_separator_line(line):
            pass
        elif line.strip() == "":
            pass
        else:
            if skip_register_blurb and line.strip().startswith("**One table only"):
                i += 1
                continue
            if skip_register_blurb and line.strip().startswith("|"):
                skip_register_blurb = False
            if skip_register_blurb and line.strip() and not line.strip().startswith("|"):
                i += 1
                continue
            if line.strip().startswith("**Architecture context:**"):
                out.append(f'<p class="section-lead">{inline_md(line.strip().replace("**Architecture context:**", "").strip())}</p>')
            else:
                out.append(f"<p>{inline_md(line.strip())}</p>")

        i += 1

    flush_table()
    flush_code()
    if in_coverage_section:
        out.append("</div>")
    if not findings_inserted and findings_html:
        out.append(f"<h2>Detailed Findings</h2>{findings_html}")

    return "\n".join(out)


def extract_title(md: str) -> str:
    for line in md.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return "Security Assessment Report"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HTML security report from markdown")
    parser.add_argument("input", type=Path, help="Markdown report path")
    parser.add_argument("-o", "--output", type=Path, help="Output HTML path (default: input with .html)")
    parser.add_argument("--project", type=str, default="", help="Project name for title")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on missing Source/Sink, Assumptions, Remediation, field issues, or backfill",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        return 1

    md = args.input.read_text(encoding="utf-8")
    md, agent_fixes = sync_attribution_agent(md)
    for fix in agent_fixes:
        print(f"Note: Scan Agent attribution synced — {fix}", file=sys.stderr)
    title = args.project or extract_title(md)

    summary = parse_summary_table(md)
    findings = parse_findings(md)
    assign_missing_ids(findings, summary)
    priority_map = parse_remediation_priority(md)

    register_exp = parse_register_exploitable(md)
    consistency_issues = validate_finding_consistency(findings, register_exp)

    backfill_notes: list[str] = []
    for finding in findings:
        backfill_notes.extend(enrich_finding_from_register(finding))

    missing_remediation = count_missing_remediation(findings, priority_map)
    missing_vuln_code = count_missing_section(findings, build_vulnerable_code)
    missing_data_flow = count_missing_section(findings, build_data_flow_trace)
    missing_assumptions = count_missing_section(findings, build_assumptions)

    for label, missing in (
        ("### Remediation", missing_remediation),
        ("### Vulnerable Code Snippet", missing_vuln_code),
        ("### Data Flow Trace", missing_data_flow),
        ("### Assumptions", missing_assumptions),
    ):
        if missing:
            print(
                f"Warning: {len(missing)} finding(s) lack {label} — "
                f"see report-finding-completeness.md / report-vulnerable-code-dataflow.md: "
                f"{', '.join(missing[:6])}"
                + (" ..." if len(missing) > 6 else ""),
                file=sys.stderr,
            )

    for issue in consistency_issues:
        print(f"Warning: {issue}", file=sys.stderr)

    for note in backfill_notes:
        print(f"Warning: {note}", file=sys.stderr)

    report_recs = validate_report_recommendations(md)
    for rec in report_recs:
        print(f"Recommendation: {rec}", file=sys.stderr)

    if not re.search(r"_security_report(_gap_analysis|_delta)?\.md$", args.input.name):
        print(
            "Recommendation: input filename does not follow v4.20 naming convention "
            "'<repo>_security_report.md' — see references/report-naming-convention.md "
            "and scripts/derive_report_name.py.",
            file=sys.stderr,
        )

    strict_fail = bool(
        consistency_issues
        or backfill_notes
        or missing_assumptions
        or missing_remediation
    )
    if args.strict and strict_fail:
        print(
            "Error: --strict: fix Classification Source/Sink, Assumptions, Remediation, "
            "and field consistency in security_report.md before handoff.",
            file=sys.stderr,
        )
        return 1

    findings_html = render_findings_section(findings, priority_map)
    body = markdown_to_html(md, findings_html, title=title)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_doc = HTML_SHELL.format(
        title=html.escape(title),
        body=body,
        generated_at=generated_at,
        c_critical=SEVERITY_COLORS["critical"],
        c_high=SEVERITY_COLORS["high"],
        c_medium=SEVERITY_COLORS["medium"],
        c_low=SEVERITY_COLORS["low"],
        c_pass=COVERAGE_STATUS_COLORS["pass"],
        c_finding=COVERAGE_STATUS_COLORS["finding"],
        c_fail=COVERAGE_STATUS_COLORS["fail"],
        c_na=COVERAGE_STATUS_COLORS["na"],
        c_skip=COVERAGE_STATUS_COLORS["skip"],
        c_pending=COVERAGE_STATUS_COLORS["pending"],
    )

    out_path = args.output or args.input.with_suffix(".html")
    out_path.write_text(html_doc, encoding="utf-8")
    print(f"HTML report written: {out_path}")
    print(f"Findings rendered: {len(findings)} (Description / Vulnerable Code / Data Flow / Source→Sink / Impact / Remediation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
