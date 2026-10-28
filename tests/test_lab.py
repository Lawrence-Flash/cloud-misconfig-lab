"""Checks against the committed Terraform, scan JSON, and finding notes."""

import re
import unittest
from pathlib import Path

from misconfig.report import gate_problems, load_side, write_report

ROOT = Path(__file__).resolve().parents[1]
SECRET_LINE = re.compile(r'default\s*=\s*"([^"]+)"\s*#\s*gitleaks:allow')
FINDING_ID = re.compile(r"`((?:CKV[0-9A-Z_]+)|(?:AWS-\d+)|aws-access-token)`")


def _planted_secret() -> str:
    text = (ROOT / "vulnerable" / "variables.tf").read_text(encoding="utf-8")
    match = SECRET_LINE.search(text)
    if not match:
        raise AssertionError("vulnerable/variables.tf is missing the allow-commented default")
    return match.group(1)


def _observed_ids() -> set[str]:
    found = set()
    for side in ("vulnerable", "fixed"):
        for scan in load_side(ROOT / "scan-results", side):
            for finding in scan.findings:
                found.add(finding.check_id)
    gitleaks = (ROOT / "scan-results" / "gitleaks-without-allow-comment.json").read_text(encoding="utf-8")
    for match in re.finditer(r'"RuleID":\s*"([^"]+)"', gitleaks):
        found.add(match.group(1))
    return found


class CommittedScanTests(unittest.TestCase):
    def test_counts_match_the_readme_table(self):
        vulnerable = load_side(ROOT / "scan-results", "vulnerable")
        fixed = load_side(ROOT / "scan-results", "fixed")

        def count(scans, scanner, severity=None):
            total = 0
            for scan in scans:
                if scan.scanner != scanner:
                    continue
                for finding in scan.findings:
                    if severity is None or finding.severity == severity:
                        total += 1
            return total

        self.assertEqual(count(vulnerable, "Checkov"), 57)
        self.assertEqual(count(fixed, "Checkov"), 10)
        self.assertEqual(count(vulnerable, "Checkov", "unscored"), 57)
        self.assertEqual(count(vulnerable, "Checkov", "HIGH"), 0)
        self.assertEqual(count(fixed, "Checkov", "HIGH"), 0)
        self.assertEqual(count(fixed, "Checkov", "CRITICAL"), 0)
        self.assertEqual(count(vulnerable, "Trivy"), 27)
        self.assertEqual(count(vulnerable, "Trivy", "CRITICAL"), 1)
        self.assertEqual(count(vulnerable, "Trivy", "HIGH"), 16)
        self.assertEqual(count(vulnerable, "Trivy", "MEDIUM"), 6)
        self.assertEqual(count(vulnerable, "Trivy", "LOW"), 4)
        self.assertEqual(count(fixed, "Trivy"), 0)

    def test_fixed_gate_passes_and_vulnerable_has_findings(self):
        fixed = load_side(ROOT / "scan-results", "fixed")
        vulnerable = load_side(ROOT / "scan-results", "vulnerable")
        self.assertEqual(gate_problems(fixed, {"CRITICAL", "HIGH"}, expect_findings=False), [])
        self.assertEqual(gate_problems(vulnerable, set(), expect_findings=True), [])

    def test_planted_checks_are_cleared(self):
        vulnerable = load_side(ROOT / "scan-results", "vulnerable")
        fixed = load_side(ROOT / "scan-results", "fixed")

        def ids(scans):
            return {finding.check_id for scan in scans for finding in scan.findings}

        cleared = {
            "CKV_AWS_24",
            "CKV_AWS_25",
            "CKV_AWS_79",
            "CKV_AWS_17",
            "CKV_AWS_7",
            "CKV_SECRET_2",
            "AWS-0104",
            "AWS-0107",
            "AWS-0028",
            "AWS-0180",
            "AWS-0065",
        }
        self.assertTrue(cleared <= ids(vulnerable))
        self.assertTrue(cleared.isdisjoint(ids(fixed)))

    def test_summary_matches_the_json(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "scan-summary.md"
            write_report(ROOT / "scan-results", output)
            committed = (ROOT / "docs" / "scan-summary.md").read_text(encoding="utf-8")
            self.assertEqual(output.read_text(encoding="utf-8"), committed)


class RepoHygieneTests(unittest.TestCase):
    def test_secret_is_only_in_the_vulnerable_variable(self):
        secret = _planted_secret()
        self.assertIn("NOTREAL", secret)
        offenders = []
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {".git", ".terraform", "__pycache__"} for part in path.parts):
                continue
            if path == ROOT / "vulnerable" / "variables.tf":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if secret in text:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_gitleaks_allow_comment_is_only_on_that_terraform_line(self):
        hits = []
        for path in ROOT.rglob("*.tf"):
            if ".terraform" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            if "gitleaks:allow" in text:
                hits.append(str(path.relative_to(ROOT)))
        self.assertEqual(hits, ["vulnerable/variables.tf"])

    def test_finding_ids_were_observed(self):
        observed = _observed_ids()
        missing = []
        for path in sorted((ROOT / "findings").glob("*.md")):
            text = path.read_text(encoding="utf-8")
            for match in FINDING_ID.finditer(text):
                check_id = match.group(1)
                if check_id not in observed:
                    missing.append(f"{path.name}: {check_id}")
        self.assertEqual(missing, [])

    def test_gitleaks_reports(self):
        clean = (ROOT / "scan-results" / "gitleaks.json").read_text(encoding="utf-8").strip()
        self.assertEqual(clean, "[]")
        demo = (ROOT / "scan-results" / "gitleaks-without-allow-comment.json").read_text(encoding="utf-8")
        self.assertIn('"RuleID": "aws-access-token"', demo)
        self.assertNotIn("/tmp/", demo)


if __name__ == "__main__":
    unittest.main()
