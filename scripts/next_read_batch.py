#!/usr/bin/env python3
"""Print the next unread must-read files in full.

Nothing is skipped. Tests are included. A file is logged only after --ack,
which you run after you have looked at every file in the batch.

  python3 next_read_batch.py [--repo ROOT] [--bytes 120000]
  python3 next_read_batch.py --ack
  python3 next_read_batch.py --status

Loop until the script prints BATCH_EMPTY. Do not stop between batches.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_BYTES = 120_000


def _load(root: Path) -> tuple[list[str], set[str]]:
    inv_path = root / ".security-review" / "inventory.json"
    if not inv_path.is_file():
        raise SystemExit(f"Missing {inv_path}. Run enumerate_inventory.py first.")
    inv = json.loads(inv_path.read_text(encoding="utf-8"))
    must = list(inv.get("must_read_files") or [])
    configs = set(inv.get("configs") or [])
    return must, configs


def _read_log(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _rank(path: str, configs: set[str]) -> tuple[int, str]:
    """Order only. Every path is still emitted."""
    low = path.lower()
    name = low.rsplit("/", 1)[-1]
    if path in configs or name.startswith(".env") or "/config/" in f"/{low}":
        group = 0
    elif any(s in low for s in ("/auth", "middleware", "routes.", "route.go", "main.go", "handler", "security")):
        group = 1
    elif name.endswith("_test.go") or name.endswith("_test.py") or ".test." in name or ".spec." in name or "/test/" in f"/{low}" or "/tests/" in f"/{low}":
        group = 3
    else:
        group = 2
    return (group, path)


def _pending_paths(pending: Path) -> list[str]:
    return _read_log(pending)


def _print_files(root: Path, paths: list[str]) -> None:
    for rel in paths:
        full = root / rel
        print(f"\n===== FILE {rel} =====")
        if not full.is_file():
            print("MISSING_ON_DISK")
            continue
        # Full text. Never truncate. A file larger than the budget is its own batch.
        text = full.read_text(encoding="utf-8", errors="replace")
        print(text, end="" if text.endswith("\n") else "\n")
    print("\n===== END BATCH =====")
    print(f"BATCH_FILES {len(paths)}")
    print("Look at every file above, then run: next_read_batch.py --ack")


def main() -> int:
    parser = argparse.ArgumentParser(description="Print the next unread files in full.")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--bytes", type=int, default=DEFAULT_BYTES)
    parser.add_argument("--ack", action="store_true", help="Log the current batch as read")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    root = args.repo.resolve()
    review = root / ".security-review"
    review.mkdir(parents=True, exist_ok=True)
    log_path = review / "files-read.log"
    pending_path = review / "batch-pending.txt"

    must, configs = _load(root)
    done = _read_log(log_path)
    done_set = set(done)

    if args.status or args.ack:
        pass

    if args.ack:
        pending = _pending_paths(pending_path)
        if not pending:
            print("ACK_EMPTY nothing pending")
            return 0
        with log_path.open("a", encoding="utf-8") as fh:
            for rel in pending:
                if rel not in done_set:
                    fh.write(rel + "\n")
                    done_set.add(rel)
        pending_path.unlink(missing_ok=True)
        print(f"ACK {len(pending)} files. logged {len(done_set)} / {len(must)}")
        return 0

    if args.status:
        missing = [p for p in must if p not in done_set]
        missing.sort(key=lambda p: _rank(p, configs))
        print(f"logged {len(must) - len(missing)} / {len(must)}")
        if missing:
            print(f"next {missing[0]}")
        else:
            print("BATCH_EMPTY")
        return 0

    if pending_path.is_file():
        pending = _pending_paths(pending_path)
        if pending:
            print("BATCH_PENDING_REPRINT ack was not run; reprinting the same files. Nothing skipped.")
            _print_files(root, pending)
            return 0

    missing = [p for p in must if p not in done_set]
    missing.sort(key=lambda p: _rank(p, configs))
    if not missing:
        print("BATCH_EMPTY")
        print(f"logged {len(must)} / {len(must)}")
        return 0

    batch: list[str] = []
    size = 0
    for rel in missing:
        full = root / rel
        try:
            n = full.stat().st_size if full.is_file() else 0
        except OSError:
            n = 0
        # Always take at least one file, even if it is larger than the budget.
        if batch and size + n > args.bytes:
            break
        batch.append(rel)
        size += n

    pending_path.write_text("\n".join(batch) + "\n", encoding="utf-8")
    print(f"BATCH_START {len(batch)} files, {size} bytes, remaining_after_this {len(missing) - len(batch)}")
    _print_files(root, batch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
