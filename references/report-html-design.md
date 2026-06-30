# HTML Report Design (ui-ux-pro-max)

Apply when running `generate_html_report.py`. Source: ui-ux-pro-max design system — **Security Report / Enterprise Gateway / Dark OLED + vibrant accents** (v4.11).

---

## v4.11 layout fixes

| Issue | Fix |
|-------|-----|
| Wide tables overflow page | All tables wrapped in `.table-wrap` with horizontal scroll |
| Master register 11 columns | `.master-wrap` min-width; Source/Sink cols 4–5 monospace + `word-break` |
| Duplicate Risk Score h3 | Suppressed when risk banner rendered |
| Duplicate Severity Distribution | Table suppressed in HTML (counts in register + KPI) |
| `### Simplified Flow` as raw paragraph | Rendered as `<h4>` + `<pre>` inside Data Flow panel |
| Generic Impact one-liners | Generator no longer synthesizes fallback text; warns if `### Impact Assessment` missing |
| Exploitable `Conditional` / `Yes (note)` | Normalized to `Yes` / `No` / `Hardening` pills; stderr warnings |

**Agent must write:** full CIA Impact tables (`report-impact-assessment.md`) and canonical Exploitable enums (`report-finding-field-consistency.md`).

---

## Design tokens

| Token | Value | Use |
|-------|-------|-----|
| Background | `#030712` + radial gradients | Page bg (cyan/violet/emerald glow) |
| Surface | `#0F172A` (80% opacity + blur) | Cards, tables |
| Surface 2 | `#1E293B` | Nested panels |
| Border | `#334155` | Table/grid borders |
| Text | `#F8FAFC` | Body |
| Muted | `#94A3B8` | Secondary text |
| Accent cyan | `#38BDF8` | Links, files KPI, SAST pills |
| Accent violet | `#A78BFA` | LOC KPI, SCA pills |
| Accent emerald | `#34D399` | Checks KPI, IaC pills |
| Accent amber | `#FB923C` | Findings KPI, risk banner |
| CTA / Pass | `#22C55E` | TRUE POSITIVE, exploitable Yes |
| Warning | `#CA8A04` | Medium severity |
| Danger | `#DC2626` | Critical/High |
| Info | `#64748B` | Info / Hardening |

## Typography

- **Font:** IBM Plex Sans (Google Fonts)
- **Hero title:** gradient text (white → cyan → violet)
- **Headings:** 600 weight, accent underline on h2
- **Body:** 400, 0.9–1rem
- **Monospace paths:** ui-monospace for Source/Sink columns

## Executive Summary layout (v4.10 — no duplicate metrics)

One visual block from `render_kpi_dashboard()` — **each metric appears once**:

| Row | Component | Shows |
|-----|-----------|--------|
| 1 | **Scan scope bar** | Files Analyzed · Lines of Code (large cards) |
| 2 | **Risk banner** | Risk score /100 (from markdown if present) |
| 3 | **Outcome KPI grid** | Checks run · With findings · True positives · SCA pkgs · SCA exploitable · Open routes · Coverage % |
| 4 | **Framework strip** | Static methodology only: 109 framework · 85+ classes · 750+ patterns · 6 layers |

**Suppressed in HTML** (markdown retained as data source):

- `### Scan Metrics` table under Executive Summary
- First summary table under `## Vulnerability Coverage Overview` (duplicate scope rows)
- `### Risk Score` heading when risk banner shown
- `### Severity Distribution` table (duplicate of register severity counts)
- Master Register intro blurb (`**One table only**…`)

**Still rendered in HTML:**

- `### Checks Performed Summary` (layer breakdown)
- `### Checks by layer` under Coverage Overview
- `### Top Vulnerability Categories`

## Required markdown fields

Executive Summary **Scan Metrics** table (markdown only — parsed by `parse_executive_metrics()`):

| Field | HTML row |
|-------|----------|
| Files Analyzed | Scan scope bar |
| Lines of Code | Scan scope bar |
| Checks Executed / Total Security Checks | Outcome KPI grid |
| Checks with Findings | Outcome KPI grid |
| AI-Validated True Positives | Outcome KPI grid |
| SCA packages scanned | Outcome KPI grid |
| SCA exploitable (C/H) | Outcome KPI grid |
| Coverage Rate | Outcome KPI grid |
| Risk score | Risk banner |

## Table styling (Master Register)

| Severity | Badge class |
|----------|-------------|
| Critical | `badge-critical` |
| High | `badge-high` |
| Medium | `badge-medium` |
| Low | `badge-low` |
| Info | `badge-info` |

| AI Verdict | Pill class |
|------------|------------|
| TRUE POSITIVE | `verdict-tp` (green) |
| FALSE POSITIVE | `verdict-fp` (gray) |
| FILTERED | `verdict-filtered` (slate) |

| Exploitable | Pill class |
|-------------|------------|
| Yes | `exp-yes` |
| No | `exp-no` |
| Hardening | `exp-hardening` |

## Anti-patterns (do not use)

- Mermaid / Chart.js / pie charts in security reports
- Emoji icons
- Separate duplicate summary + hardening tables
- Bare filenames without repo path in Source/Sink columns
- Duplicate metadata block below hero
- **Repeating Files/LOC/Checks/SCA in scope bar + KPI grid + coverage strip + markdown table** (fixed v4.10)

## Accessibility

- Contrast ≥ 4.5:1 on body text
- Focus visible on TOC links
- `prefers-reduced-motion` respected (no animated charts)
- KPI hover uses subtle transform only (disable if reduced-motion preferred — future)
