#!/usr/bin/env python3
"""Verify every language pack covers every canonical vulnerability class (v4.41).

  python3 check_lang_packs.py [--write-matrix] [lang-packs-dir]

Each pack must contain a "## Class coverage index" table with one non-empty row
per class ID L01..L35. Exit code 1 lists missing or empty IDs per pack.
--write-matrix regenerates lang-packs/vuln-class-matrix.md (one table per class,
one row per language) from the pack indexes, so the two never drift.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

CLASS_IDS = [f"L{n:02d}" for n in range(1, 36)]
SKIP = {"README.md", "vuln-class-matrix.md"}
ROW_RE = re.compile(r"^\|\s*(L\d{2})\s*\|(.+)\|\s*$")


CLASS_NAMES = {
    "L01": "XSS / output encoding", "L02": "SSTI / template injection", "L03": "Code injection / eval / dynamic load",
    "L04": "SQL injection", "L05": "NoSQL injection", "L06": "OS command / argument injection",
    "L07": "LDAP / XPath / EL / other query injection", "L08": "Header / CRLF / log injection", "L09": "SSRF",
    "L10": "Path traversal / file inclusion", "L11": "File upload / archive extraction",
    "L12": "Insecure deserialization", "L13": "XML (XXE, entity expansion, structural injection)",
    "L14": "Mass assignment / prototype pollution / object injection", "L15": "Authentication & session",
    "L16": "JWT / OAuth / SAML / tokens", "L17": "Authorization (IDOR/BOLA, BFLA, route order)", "L18": "CSRF",
    "L19": "CORS", "L20": "Security headers & cookie flags", "L21": "Open redirect / URL parsing",
    "L22": "Cryptography", "L23": "Insecure randomness", "L24": "TLS / certificate validation",
    "L25": "Secrets & insecure configuration", "L26": "Error handling & information disclosure",
    "L27": "Logging & privacy (PII)", "L28": "DoS (ReDoS, limits, exhaustion)",
    "L29": "Race conditions / TOCTOU / concurrency", "L30": "Business logic & numeric/type confusion",
    "L31": "Memory safety / unsafe / FFI", "L32": "Supply chain", "L33": "API protocols (GraphQL, WebSocket, gRPC)",
    "L34": "Unsafe reflection / dynamic dispatch", "L35": "Language-specific pitfalls",
}


def parse_index(text: str) -> dict[str, list[str]] | None:
    if "## Class coverage index" not in text:
        return None
    index = text.split("## Class coverage index", 1)[1]
    index = re.split(r"\n## ", index, maxsplit=1)[0]
    rows: dict[str, list[str]] = {}
    for line in index.splitlines():
        m = ROW_RE.match(line.strip())
        if m:
            rows[m.group(1)] = [c.strip() for c in m.group(2).split("|")]
    return rows


def check_pack(path: Path) -> list[str]:
    parsed = parse_index(path.read_text(encoding="utf-8"))
    if parsed is None:
        return ["no '## Class coverage index' section"]
    rows = {k: " ".join(c for c in v if c) for k, v in parsed.items()}
    problems = []
    for cid in CLASS_IDS:
        body = rows.get(cid)
        if body is None:
            problems.append(f"{cid} missing")
        elif len(body) < 12:
            problems.append(f"{cid} too thin: {body!r}")
    extra = sorted(set(rows) - set(CLASS_IDS))
    if extra:
        problems.append(f"unknown IDs: {', '.join(extra)}")
    return problems


def write_matrix(pack_dir: Path, packs: list[Path]) -> Path:
    indexes = {p.name: parse_index(p.read_text(encoding="utf-8")) or {} for p in packs}
    out = [
        "# Vulnerability class × language matrix (generated — do not edit)",
        "",
        "Regenerate with `python3 scripts/check_lang_packs.py --write-matrix`. Source of truth: each pack's",
        "`## Class coverage index`. Use this file to compare how one class looks across languages; use the",
        "pack itself when reviewing a file.",
        "",
    ]
    for cid in CLASS_IDS:
        out += [f"## {cid} — {CLASS_NAMES[cid]}", "", "| Pack | Vulnerable | Safe equivalent | FP trap / note |",
                "|------|-----------|-----------------|----------------|"]
        for name, rows in indexes.items():
            cells = (rows.get(cid, []) + ["", "", ""])[:3]
            out.append(f"| `{name}` | " + " | ".join(cells) + " |")
        out.append("")
    dest = pack_dir / "vuln-class-matrix.md"
    dest.write_text("\n".join(out), encoding="utf-8")
    return dest


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--write-matrix"]
    here = Path(__file__).resolve().parent
    pack_dir = Path(args[0]) if args else here.parent / "references" / "lang-packs"
    packs = sorted(p for p in pack_dir.glob("*.md") if p.name not in SKIP)
    if "--write-matrix" in sys.argv:
        print(f"Wrote {write_matrix(pack_dir, packs)}")
    failed = 0
    for p in packs:
        problems = check_pack(p)
        status = "OK " if not problems else "FAIL"
        print(f"{status} {p.name}" + ("" if not problems else f": {'; '.join(problems)}"))
        failed += bool(problems)
    print(f"\n{len(packs) - failed}/{len(packs)} packs cover all {len(CLASS_IDS)} classes")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
