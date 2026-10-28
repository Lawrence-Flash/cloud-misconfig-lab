# Scan outputs

These files are the scanner output used by `python3 -m misconfig report` and by the numbers in the README. `scripts/scan.sh` regenerates them. The tool versions are in `tool-versions.txt`.

`checkov-*.json` and `trivy-*.json` are the JSON those tools wrote. Two edits are applied afterwards by `scripts/normalize_scans.py`:

- The planted fake secret is replaced with `[REDACTED-FAKE-LAB-SECRET]`. The only committed copy of the value is the default in `vulnerable/variables.tf`.
- Absolute paths from the machine that ran the scan are rewritten so they start at the repo.

`gitleaks.json` is `gitleaks detect --no-git` on this repo with the allow comment in place. It is an empty list.

`gitleaks-without-allow-comment.json` is a separate scan of `vulnerable/variables.tf` after the `# gitleaks:allow` comment was removed. That is the run that produced the rule id. Gitleaks redacts the match. The file path in the report is rewritten to `vulnerable/variables.tf`. This file is not what CI scans.
