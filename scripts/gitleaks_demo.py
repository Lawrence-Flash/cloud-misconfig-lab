"""Record the gitleaks rule for the planted line with the allow comment removed.

The value is redacted before the JSON is written. This file is evidence of the
rule id. The tree that CI scans still has the allow comment.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_LINE = re.compile(r'default\s*=\s*"([^"]+)"\s*#\s*gitleaks:allow')
ALLOW_COMMENT = re.compile(r"\s*#\s*gitleaks:allow[^\n]*")
REDACTION = "[REDACTED-FAKE-LAB-SECRET]"


def main() -> int:
    source_path = ROOT / "vulnerable" / "variables.tf"
    source = source_path.read_text(encoding="utf-8")
    match = SECRET_LINE.search(source)
    if not match:
        raise SystemExit("gitleaks_demo: allow-commented default not found")
    secret = match.group(1)
    stripped = ALLOW_COMMENT.sub("", source)
    if secret not in stripped:
        raise SystemExit("gitleaks_demo: secret missing after the allow comment was removed")

    with tempfile.TemporaryDirectory(prefix="misconfig-gitleaks-") as tmp:
        demo = Path(tmp) / "variables.tf"
        demo.write_text(stripped, encoding="utf-8")
        report_path = Path(tmp) / "report.json"
        completed = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--no-git",
                "--source",
                tmp,
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--exit-code",
                "1",
                "--redact",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise SystemExit(completed.stderr or completed.stdout or "gitleaks failed")
        raw = report_path.read_text(encoding="utf-8") if report_path.exists() else "[]"
        findings = json.loads(raw or "[]")

    redacted = []
    for item in findings:
        cleaned = {}
        for key, value in item.items():
            if isinstance(value, str):
                value = value.replace(secret, REDACTION)
                if key == "File":
                    value = "vulnerable/variables.tf"
                if key == "Fingerprint":
                    value = "vulnerable/variables.tf:aws-access-token:29"
            cleaned[key] = value
        redacted.append(cleaned)

    if not any(item.get("RuleID") for item in redacted):
        raise SystemExit("gitleaks_demo: no rule matched the line with the allow comment removed")

    destination = ROOT / "scan-results" / "gitleaks-without-allow-comment.json"
    destination.write_text(json.dumps(redacted, indent=2) + "\n", encoding="utf-8")
    rules = sorted({item.get("RuleID") for item in redacted})
    print(f"wrote {destination.name} rules={rules}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
