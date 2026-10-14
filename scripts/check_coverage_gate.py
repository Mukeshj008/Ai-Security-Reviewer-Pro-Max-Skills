#!/usr/bin/env python3
"""
Fail unless scan-session-memory.md shows 100% inventory coverage.

Run before:
  - setting status: complete
  - telling the user the scan is complete
  - treating generate_html_report.py --strict as final handoff

Usage (from repo root):
  python3 ~/.cursor/skills/ai-security-reviewer/scripts/check_coverage_gate.py
  python3 .../check_coverage_gate.py --repo /path/to/checkout
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def _parse_memory(text: str) -> dict[str, str | int]:
    out: dict[str, str | int] = {}
    for line in text.splitlines():
        m = re.match(r"^([a-z_]+):\s*(.+)$", line.strip())
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if val.isdigit():
            out[key] = int(val)
        else:
            out[key] = val
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify 100% scan coverage before complete.")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: cwd)",
    )
    args = parser.parse_args()
    root = args.repo.resolve()
    review = root / ".security-review"
    inv_path = review / "inventory.json"
    mem_path = review / "scan-session-memory.md"

    errors: list[str] = []

    if not inv_path.is_file():
        errors.append(f"Missing {inv_path} — run enumerate_inventory.py first.")
    if not mem_path.is_file():
        errors.append(f"Missing {mem_path} — create/update session memory during scan.")

    stats: dict = {}
    inv: dict = {}
    if inv_path.is_file():
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        # Inventory writes "counts" (older drafts used "stats"). Denominators come from inventory.
        stats = inv.get("counts") or inv.get("stats") or {}
        stats = dict(stats)
        if inv.get("production_must_read_count") and not stats.get("production_must_read_files"):
            stats["production_must_read_files"] = inv["production_must_read_count"]

    mem: dict[str, str | int] = {}
    if mem_path.is_file():
        mem = _parse_memory(mem_path.read_text(encoding="utf-8"))

    # v4.52: the log is the proof. A typed counter cannot pass G1.
    # Every must_read_files path, tests included, must appear in files-read.log.
    log_path = review / "files-read.log"
    logged: set[str] = set()
    if log_path.is_file():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                logged.add(line)
    must_list = list(inv.get("must_read_files") or []) if inv_path.is_file() else []
    missing_files = [p for p in must_list if p not in logged]
    must_read = len(must_list)
    files_read = must_read - len(missing_files)

    cfg_list = list(inv.get("configs") or []) if inv_path.is_file() else []
    if not cfg_list:
        cfg_list = []
    missing_configs = [p for p in cfg_list if p not in logged]
    configs_enum = len(cfg_list) or int(mem.get("configs_enumerated") or stats.get("configs") or 0)
    configs_read = configs_enum - len(missing_configs) if cfg_list else int(mem.get("configs_read") or 0)

    http_mods = list(inv.get("http_modules") or []) if inv_path.is_file() else []
    missing_http = []
    for mod in http_mods:
        prefix = mod.rstrip("/") + "/"
        mod_files = [p for p in must_list if p.startswith(prefix)]
        if any(p not in logged for p in mod_files):
            missing_http.append(mod)
    http_enum = len(http_mods) or int(mem.get("http_modules_enumerated") or stats.get("http_modules") or 0)
    http_walked = http_enum - len(missing_http) if http_mods else int(mem.get("http_modules_walked") or 0)
    status = str(mem.get("status") or "in_progress")

    if must_read and missing_files:
        errors.append(
            f"G1 files: logged {files_read} / {must_read} in files-read.log; "
            f"next missing: {missing_files[0]}"
        )
    elif must_read and not log_path.is_file():
        errors.append("G1 files: files-read.log missing. Use next_read_batch.py.")
    if cfg_list and missing_configs:
        errors.append(f"G2 configs: logged {configs_read} / {configs_enum}; next missing: {missing_configs[0]}")
    elif configs_enum and configs_read < configs_enum:
        errors.append(f"G2 configs: read {configs_read} / {configs_enum}")
    if http_mods and missing_http:
        errors.append(f"G3 HTTP modules: logged {http_walked} / {http_enum}; not complete: {missing_http[0]}")
    elif http_enum and http_walked < http_enum:
        errors.append(f"G3 HTTP modules: walked {http_walked} / {http_enum}")
    if status != "complete":
        errors.append(f"G6 memory status is '{status}', not 'complete'")

    if errors:
        print("COVERAGE GATE: FAIL", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nDo not say 'scan complete' or ship final HTML until all gates pass.",
            file=sys.stderr,
        )
        print("Keep reading production files in this session. Do not ask the user to type continue.", file=sys.stderr)
        print("See references/coverage-complete-gate.md", file=sys.stderr)
        return 1

    print("COVERAGE GATE: PASS (100% inventory coverage per session memory)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
