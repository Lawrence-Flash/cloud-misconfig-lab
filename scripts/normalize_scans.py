"""Rewrite committed scanner JSON so it stays reviewable.

The planted secret is replaced, and absolute checkout paths are made
repo-relative. Check ids, severities, and counts are left as the tools wrote them.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_LINE = re.compile(r'default\s*=\s*"([^"]+)"\s*#\s*gitleaks:allow')
REDACTION = "[REDACTED-FAKE-LAB-SECRET]"


def planted_secret() -> str:
    text = (ROOT / "vulnerable" / "variables.tf").read_text(encoding="utf-8")
    match = SECRET_LINE.search(text)
    if not match:
        sys.exit("normalize_scans: planted secret line not found in vulnerable/variables.tf")
    return match.group(1)


def main() -> int:
    secret = planted_secret()
    prefix = str(ROOT) + "/"
    scan_dir = ROOT / "scan-results"
    changed = 0
    for path in sorted(scan_dir.glob("*.json")):
        original = path.read_text(encoding="utf-8")
        updated = original.replace(secret, REDACTION).replace(prefix, "")
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            changed += 1
    print(f"normalized {changed} scan file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
