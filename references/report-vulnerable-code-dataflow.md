# Vulnerable Code Snippet & Data Flow (MANDATORY per finding)

Every **Detailed Findings** entry must include **`### Vulnerable Code Snippet`** and **`### Data Flow Trace`** before handoff. These are separate from **`### Remediation`** (which holds the **AFTER** fix).

---

## Required sections (addition to report-finding-completeness.md)

| Section | Required | Notes |
|---------|----------|-------|
| **`### Vulnerable Code Snippet`** | **Yes** | Real code copied from the repo (not paraphrased) |
| **`### Data Flow Trace`** | **Yes** | Full source → sink path; see SKILL.md format |
| **`### Simplified Flow`** | Recommended | One-line ASCII chain under Data Flow Trace |

**Exceptions (still require both sections):**

| Finding type | Vulnerable snippet | Data flow |
|--------------|-------------------|-----------|
| VULN (taint) | Source + sink lines from actual file | Full ASCII box + simplified flow |
| AUTH | Route/middleware chain missing auth | Request → unauthenticated handler |
| CVE | `require()` + vulnerable call site | HTTP/import → vulnerable API |
| IAC | Misconfigured stanza from IaC file | Config exposure → blast radius (1–3 steps) |

---

## Vulnerable Code Snippet template

Copy **verbatim** from the codebase after `Read` at reported lines. Include file path and line range in a comment.

**Example structure** (see SKILL.md for full SQLi sample):

- Header: `### Vulnerable Code Snippet`
- Fenced block with `// file:line — SOURCE` and `// SINK` comments on the taint lines

**Rules:**
- Minimum **source line** and **sink line** in one fenced block (or two blocks if in different files)
- Mark `// SOURCE` and `// SINK` in comments
- No placeholders like `...` unless eliding unrelated middle lines
- Max ~40 lines; elide with `// ...` only for non-taint code

---

## Data Flow Trace template

Use the **full ASCII box** from SKILL.md (mandatory for VULN taint findings). Minimum content per finding:

1. **SOURCE** node — file, line, method, code, input type  
2. **≥1 STEP** nodes — transforms, missing validation  
3. **SINK** node — dangerous operation  
4. **`### Simplified Flow`** — compact chain (optional subsection under same heading or separate `### Simplified Flow`)

Use the **full ASCII box** from SKILL.md for taint findings, or a step table for AUTH/IAC/CVE (see SKILL.md AUTH template).

---

## Agent workflow

1. After validating a TRUE POSITIVE, **`Read`** source file ±10 lines at source and sink.
2. Paste into **`### Vulnerable Code Snippet`** with line comments.
3. Build **`### Data Flow Trace`** from `graphify path` output + Read — do not invent lines.
4. Keep **`### Remediation`** **AFTER** block separate (secure fix only).

---

## Completion gate (Phase 4)

```bash
FINDINGS=$(rg -c "^## \[(CRITICAL|HIGH|MEDIUM|LOW)\]" security_report.md | awk -F: '{s+=$2} END {print s+0}')
VC=$(rg -c "^### Vulnerable Code Snippet" security_report.md | awk -F: '{s+=$2} END {print s+0}')
DF=$(rg -c "^### Data Flow Trace" security_report.md | awk -F: '{s+=$2} END {print s+0}')
echo "findings=$FINDINGS vulnerable_snippets=$VC data_flows=$DF"
# All three counts must match
```

Do not run `generate_html_report.py` until counts match.

---

## HTML export

`generate_html_report.py` renders dedicated **Vulnerable Code** and **Data Flow Trace** panels when these `###` headers are present.
