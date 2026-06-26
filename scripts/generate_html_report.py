#!/usr/bin/env python3
"""
Convert AI Security Reviewer markdown report to a styled HTML document.

Ensures every finding card includes structured Description, Source, Sink,
Impact, and Remediation sections (with line numbers when present in markdown).

Usage:
  python generate_html_report.py security_report.md
  python generate_html_report.py security_report.md -o report.html
  python generate_html_report.py security_report.md --project "My App"
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
FILE_LINE_RE = re.compile(r"^([^\s:]+\.(?:js|ts|jsx|tsx|java|py|go|rb|php|conf|yaml|yml|json|md))(?::(\d+(?:-\d+)?))?$")

HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --surface: #1e293b;
      --border: #334155;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --source: #34d399;
      --sink: #f87171;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 2rem;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
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
    th {{ background: var(--surface); }}
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
      Generated by AI Security Reviewer v4.0 · {generated_at}
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
    file_line: str
    method: str
    status: str


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


def parse_summary_table(md: str) -> dict[str, SummaryRow]:
    rows: dict[str, SummaryRow] = {}
    in_summary = False
    table_lines: list[str] = []
    for line in md.splitlines():
        if line.startswith("## Findings Summary Table"):
            in_summary = True
            continue
        if in_summary:
            if line.startswith("## ") and "Findings Summary" not in line:
                break
            if line.strip().startswith("|"):
                table_lines.append(line)
    if len(table_lines) < 2:
        return rows
    for i, line in enumerate(table_lines):
        if i < 2:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 7:
            continue
        fid = cells[0]
        rows[fid] = SummaryRow(
            finding_id=fid,
            severity=cells[1],
            category=cells[2],
            file_line=cells[3],
            method=cells[4],
            status=cells[6],
        )
    return rows


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
    df_source, df_sink = extract_from_data_flow(data_flow)

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


def build_impact(finding: ParsedFinding) -> str:
    for key in finding.sections:
        if "impact" in key:
            return finding.sections[key]
    if finding.kv_tables.get("Impact"):
        return finding.kv_tables["Impact"]
    if finding.kv_tables.get("Blast radius"):
        return finding.kv_tables["Blast radius"]
    if finding.summary:
        cat = finding.summary.category
        if "SSRF" in cat.upper():
            return "Server-side request forgery — internal network scan, metadata theft, or credential relay."
        if "auth" in cat.lower() or "Missing auth" in cat:
            return f"Missing authentication — unauthenticated access to {finding.summary.method}."
        if "Session" in cat or "trust boundary" in cat.lower():
            return "Session trust boundary violation — attacker may poison session state or bypass auth flows."
        if "IaC" in cat or "Docker" in cat:
            return "Infrastructure misconfiguration — expanded blast radius on compromise."
        if "leak" in cat.lower() or "log" in cat.lower():
            return "Information disclosure via logs or error responses."
        return f"{cat} — business and security impact depends on exposed data and route sensitivity."
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
            parts.append(md_table_to_html(table_buf))
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
    for key, content in finding.sections.items():
        if "data flow trace" in key and content.strip():
            text = content
            simplified = finding.sections.get("simplified flow", "")
            if simplified and "simplified flow" not in text.lower():
                text = f"{text}\n\n### Simplified Flow\n\n{simplified}"
            return text
    simplified = finding.sections.get("simplified flow", "")
    return simplified


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
    source, sink, file_ref, method = build_source_sink(finding)
    impact = build_impact(finding)
    remediation = build_remediation(finding, priority_map=priority_map)

    core_html = f"""
<div class="finding-core">
  {render_core_panel("Description", render_inline_content(description), missing=not description.strip())}
  {render_core_panel("Vulnerable Code", render_inline_content(vulnerable), missing=not vulnerable.strip(), css_class="vuln-code")}
  {render_core_panel("Data Flow Trace", render_inline_content(data_flow), missing=not data_flow.strip(), css_class="data-flow")}
  {render_trace_panel(source, sink, file_ref, method)}
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
    }
    for key, content in finding.sections.items():
        if key in skip_keys or not content.strip():
            continue
        if "data flow trace" in key:
            continue
        if "impact" in key:
            continue
        title = key.title()
        extra_sections.append(f'<div class="finding-extra"><h3>{html.escape(title)}</h3>{render_inline_content(content)}</div>')

    extra_html = "\n".join(extra_sections)
    anchor = f'id="{html.escape(fid)}"' if finding.finding_id else ""

    return f"""
<div class="finding" {anchor}>
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


def md_table_to_html(lines: list[str], coverage_table: bool = False) -> str:
    if len(lines) < 2:
        return ""
    status_col = -1
    if coverage_table and lines[0].strip().startswith("|"):
        header_cells = [c.strip() for c in lines[0].strip().strip("|").split("|")]
        for idx, name in enumerate(header_cells):
            if name.lower() == "status":
                status_col = idx
                break
    rows = []
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if i == 1 and all(re.match(r"^[-:]+$", c) for c in cells):
            continue
        tag = "th" if i == 0 else "td"
        if coverage_table and tag == "td" and status_col >= 0:
            rendered = []
            for j, c in enumerate(cells):
                if j == status_col:
                    rendered.append(f"<td>{coverage_status_cell(c)}</td>")
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
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def is_finding_header(line: str) -> bool:
    return bool(FINDING_HEADER_RE.match(line))


def markdown_to_html(md: str, findings_html: str) -> str:
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

    def flush_table():
        nonlocal table_buf, in_coverage_section
        if table_buf:
            is_cov = in_coverage_section or (
                table_buf
                and (
                    "Check ID" in table_buf[0]
                    or ("Phase" in table_buf[0] and "Step" in table_buf[0])
                )
            )
            out.append(md_table_to_html(table_buf, coverage_table=is_cov))
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

    while i < len(lines):
        line = lines[i]

        if skip_until_remediation:
            if line.startswith("## Remediation Priority"):
                skip_until_remediation = False
            else:
                i += 1
                continue

        if line.strip().startswith("```"):
            if in_code:
                flush_code()
            else:
                flush_table()
                in_code = True
                code_lang = line.strip()[3:].strip().lower()
            i += 1
            continue

        if in_code:
            code_buf.append(line)
            i += 1
            continue

        if line.strip().startswith("|"):
            table_buf.append(line)
            i += 1
            continue
        flush_table()

        if line.startswith("# "):
            out.append(f"<h1>{inline_md(line[2:].strip())}</h1>")
        elif line.startswith("## Detailed Findings"):
            out.append(f"<h2>{inline_md('Detailed Findings')}</h2>")
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
            if heading.startswith("Appendix E") or heading.startswith("Appendix F") or heading.startswith("Appendix G"):
                in_coverage_section = True
                out.append(f'<div class="coverage-section"><h2>{inline_md(heading)}</h2>')
            else:
                out.append(f"<h2>{inline_md(heading)}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{inline_md(line[4:].strip())}</h3>")
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
    args = parser.parse_args()

    if not args.input.is_file():
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        return 1

    md = args.input.read_text(encoding="utf-8")
    title = args.project or extract_title(md)

    summary = parse_summary_table(md)
    findings = parse_findings(md)
    assign_missing_ids(findings, summary)
    priority_map = parse_remediation_priority(md)

    missing_remediation = count_missing_remediation(findings, priority_map)
    missing_vuln_code = count_missing_section(findings, build_vulnerable_code)
    missing_data_flow = count_missing_section(findings, build_data_flow_trace)

    for label, missing in (
        ("### Remediation", missing_remediation),
        ("### Vulnerable Code Snippet", missing_vuln_code),
        ("### Data Flow Trace", missing_data_flow),
    ):
        if missing:
            print(
                f"Warning: {len(missing)} finding(s) lack {label} — "
                f"see report-finding-completeness.md / report-vulnerable-code-dataflow.md: "
                f"{', '.join(missing[:6])}"
                + (" ..." if len(missing) > 6 else ""),
                file=sys.stderr,
            )

    findings_html = render_findings_section(findings, priority_map)
    body = markdown_to_html(md, findings_html)
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
