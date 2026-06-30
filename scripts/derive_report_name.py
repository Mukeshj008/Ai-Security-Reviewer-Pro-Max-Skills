#!/usr/bin/env python3
"""
Derive a clean repository name from the workspace directory and print the
report basename used by the AI Security Reviewer skill.

See `references/report-naming-convention.md` for the full specification.

Examples
--------
    $ derive_report_name.py
    oauth-user-mgmt-service

    $ derive_report_name.py --suffix _security_report --ext md
    oauth-user-mgmt-service_security_report.md

    $ derive_report_name.py --project "Acme OAuth UMS" --suffix _security_report --ext html
    acme-oauth-ums_security_report.html
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

DEFAULT_PREFIXES = [
    "acmeteam",
    "acmelabs",
    "acme-internal",
    "acme",
    "team",
    "org",
    "internal",
    "corp",
    "eng",
    "engineering",
    "infra",
    "platform",
    "dev",
    "prod",
    "staging",
    "qa",
    "uat",
    "gh",
    "github",
    "gitlab",
    "bitbucket",
    "bb",
    "customer",
    "client",
]

SUFFIX_REGEXES = [
    re.compile(r"[-_]?[0-9a-f]{6,40}$"),
    re.compile(r"[-_]?\d{6,}$"),
    re.compile(r"[-_]?v?\d+(?:\.\d+){1,3}$"),
    re.compile(r"[-_]?(main|master|develop|release)$"),
]


def _sanitize(value: str) -> str:
    """Lowercase, normalise underscores to hyphens, drop other junk."""
    out = value.lower().replace("_", "-")
    out = re.sub(r"[^a-z0-9.-]+", "-", out)
    out = re.sub(r"-{2,}", "-", out)
    return out.strip("-.")


def _strip_prefixes(name: str, prefixes: list[str]) -> str:
    sorted_prefixes = sorted({p.lower() for p in prefixes}, key=len, reverse=True)
    changed = True
    while changed:
        changed = False
        for p in sorted_prefixes:
            token = f"{p}-"
            if name.startswith(token) and len(name) > len(token):
                name = name[len(token):]
                changed = True
                break
    return name


def _strip_suffixes(name: str) -> str:
    changed = True
    while changed:
        changed = False
        for regex in SUFFIX_REGEXES:
            new_name, n = regex.subn("", name)
            if n and new_name and new_name != name:
                name = new_name
                changed = True
                break
    return name


def derive_repo_name(workdir: Path, extra_prefixes: list[str] | None = None) -> str:
    base = workdir.resolve().name
    if not base:
        base = os.path.basename(os.getcwd())
    raw = _sanitize(base)
    if not raw:
        return "report"

    prefixes = list(DEFAULT_PREFIXES) + list(extra_prefixes or [])
    stripped = _strip_prefixes(raw, prefixes)
    stripped = _strip_suffixes(stripped)
    cleaned = _sanitize(stripped)
    if not cleaned:
        return raw
    return cleaned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Print the clean repo slug used to prefix AI Security Reviewer report files. "
            "See report-naming-convention.md."
        )
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=Path(os.getcwd()),
        help="Workspace root directory (default: $PWD)",
    )
    parser.add_argument(
        "--project",
        type=str,
        default=None,
        help="User-supplied project name; bypasses derivation",
    )
    parser.add_argument(
        "--extra-prefix",
        action="append",
        default=[],
        help="Additional org prefix to strip (repeatable)",
    )
    parser.add_argument(
        "--suffix",
        type=str,
        default="",
        help='Suffix to append after the repo slug, e.g. "_security_report"',
    )
    parser.add_argument(
        "--ext",
        type=str,
        default="",
        help='File extension (without the dot) to append, e.g. "md" or "html"',
    )
    parser.add_argument(
        "--print-debug",
        action="store_true",
        help="Print derivation steps to stderr",
    )
    args = parser.parse_args(argv)

    if args.project:
        slug = _sanitize(args.project) or "report"
        if args.print_debug:
            print(f"[derive_report_name] user override → {slug}", file=sys.stderr)
    else:
        slug = derive_repo_name(args.workdir, args.extra_prefix)
        if args.print_debug:
            print(
                f"[derive_report_name] workdir={args.workdir.resolve()} "
                f"basename={args.workdir.resolve().name} → {slug}",
                file=sys.stderr,
            )

    out = slug + args.suffix
    if args.ext:
        out = f"{out}.{args.ext.lstrip('.')}"
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
