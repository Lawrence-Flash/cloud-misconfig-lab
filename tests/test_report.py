import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from misconfig.report import (
    ScanError,
    gate_problems,
    load_checkov,
    load_side,
    load_trivy,
    render_markdown,
    render_text,
    write_report,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ParseTests(unittest.TestCase):
    def test_checkov_list_null_severity_is_unscored(self):
        scan = load_checkov(FIXTURES / "checkov-list.json", "vulnerable")
        self.assertEqual(scan.tool_version, "3.2.449")
        self.assertEqual(len(scan.findings), 2)
        self.assertEqual(scan.findings[0].severity, "unscored")
        self.assertEqual(scan.findings[0].check_id, "CKV_AWS_24")
        self.assertEqual(scan.findings[1].check_id, "CKV_SECRET_2")
        self.assertEqual(scan.parsing_errors, 0)

    def test_checkov_single_object(self):
        scan = load_checkov(FIXTURES / "checkov-object.json", "fixed")
        self.assertEqual(len(scan.findings), 1)
        self.assertEqual(scan.findings[0].severity, "HIGH")
        self.assertEqual(scan.skips[0].check_id, "CKV_AWS_144")
        self.assertEqual(scan.skips[0].justification, "Single-region lab, no second bucket.")
        self.assertEqual(scan.skips[1].justification, "")

    def test_trivy_ignores_pass_status(self):
        scan = load_trivy(FIXTURES / "trivy.json", "vulnerable")
        self.assertEqual(scan.tool_version, "0.76.1")
        self.assertEqual([item.check_id for item in scan.findings], ["AWS-0107", "AWS-0104"])
        self.assertEqual(scan.findings[0].severity, "HIGH")
        self.assertEqual(scan.findings[1].severity, "CRITICAL")
        self.assertEqual(scan.findings[0].resource, "aws_security_group_rule.app_ssh")

    def test_trivy_empty_results(self):
        scan = load_trivy(FIXTURES / "trivy-empty.json", "fixed")
        self.assertEqual(scan.findings, [])

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ScanError):
                load_checkov(path, "fixed")

    def test_missing_side_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ScanError):
                load_side(Path(tmp), "fixed")


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.scan_dir = FIXTURES / "pair"
        self.vulnerable = load_side(self.scan_dir, "vulnerable")
        self.fixed = load_side(self.scan_dir, "fixed")

    def test_severity_counts(self):
        text = render_text(self.vulnerable, self.fixed)
        self.assertRegex(text, r"Checkov\s+unscored")
        self.assertRegex(text, r"Trivy\s+CRITICAL")
        self.assertRegex(text, r"Trivy\s+HIGH")
        self.assertIn("Checkov: vulnerable 2, fixed 1", text)
        self.assertIn("Trivy: vulnerable 2, fixed 0", text)

    def test_same_check_on_both_sides(self):
        markdown = render_markdown(self.vulnerable, self.fixed)
        self.assertIn("| Checkov | CKV_AWS_144 | unscored | 1 | 1 |", markdown)
        self.assertIn("| Trivy | AWS-0104 | CRITICAL | 1 | 0 |", markdown)
        self.assertIn("Still reported in fixed/", markdown)
        self.assertIn("CKV_AWS_144", markdown)

    def test_skipped_checks_are_not_failures(self):
        fixed = load_side(self.scan_dir, "fixed")
        checkov = next(scan for scan in fixed if scan.scanner == "Checkov")
        self.assertEqual(len(checkov.skips), 1)
        self.assertEqual(len(checkov.findings), 1)
        problems = gate_problems(fixed, {"CRITICAL", "HIGH"}, expect_findings=False)
        self.assertEqual(problems, [])

    def test_markdown_has_versions_block(self):
        markdown = render_markdown(self.vulnerable, self.fixed, "checkov 3.2.449\n")
        self.assertIn("## Tool versions", markdown)
        self.assertIn("checkov 3.2.449", markdown)


class GateTests(unittest.TestCase):
    def test_high_finding_fails(self):
        scans = load_side(FIXTURES / "pair", "vulnerable")
        problems = gate_problems(scans, {"CRITICAL", "HIGH"}, expect_findings=False)
        self.assertTrue(any("AWS-0104" in problem for problem in problems))
        self.assertTrue(any("AWS-0107" in problem for problem in problems))
        self.assertFalse(any("CKV_AWS_24" in problem for problem in problems))

    def test_unscored_does_not_fail_high_gate(self):
        scans = load_side(FIXTURES / "pair", "fixed")
        self.assertEqual(gate_problems(scans, {"CRITICAL", "HIGH"}, False), [])

    def test_expect_findings(self):
        vulnerable = load_side(FIXTURES / "pair", "vulnerable")
        fixed = load_side(FIXTURES / "pair", "fixed")
        self.assertEqual(gate_problems(vulnerable, set(), expect_findings=True), [])
        empty = load_side(FIXTURES / "empty-fixed", "fixed")
        problems = gate_problems(empty, set(), expect_findings=True)
        self.assertEqual(len(problems), 1)
        self.assertIn("expected findings", problems[0])

    def test_unjustified_high_skip_fails(self):
        scan = load_checkov(FIXTURES / "checkov-object.json", "fixed")
        problems = gate_problems([scan], {"HIGH"}, expect_findings=False)
        self.assertTrue(any("CKV_AWS_18" in problem and "no justification" in problem for problem in problems))
        self.assertFalse(any("CKV_AWS_144" in problem for problem in problems))

    def test_parsing_errors_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkov-fixed.json"
            path.write_text(
                json.dumps(
                    {
                        "check_type": "terraform",
                        "results": {"failed_checks": [], "skipped_checks": []},
                        "summary": {"failed": 0, "parsing_errors": 2, "checkov_version": "3.2.449"},
                    }
                ),
                encoding="utf-8",
            )
            scan = load_checkov(path, "fixed")
            problems = gate_problems([scan], set(), expect_findings=False)
            self.assertIn("2 parsing error(s)", problems[0])


class CliTests(unittest.TestCase):
    def test_report_writes_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "scan-summary.md"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "misconfig",
                    "report",
                    "--scan-dir",
                    str(FIXTURES / "pair"),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Failed checks by severity", completed.stdout)
            self.assertIn("CKV_AWS_24", completed.stdout)
            self.assertTrue(output.is_file())
            self.assertIn("# Scan summary", output.read_text(encoding="utf-8"))

    def test_gate_exit_codes(self):
        failed = subprocess.run(
            [
                sys.executable,
                "-m",
                "misconfig",
                "gate",
                "--scan-dir",
                str(FIXTURES / "pair"),
                "--side",
                "vulnerable",
                "--fail-on",
                "CRITICAL,HIGH",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(failed.returncode, 1)
        self.assertIn("AWS-0104", failed.stderr)

        passed = subprocess.run(
            [
                sys.executable,
                "-m",
                "misconfig",
                "gate",
                "--scan-dir",
                str(FIXTURES / "pair"),
                "--side",
                "fixed",
                "--fail-on",
                "CRITICAL,HIGH",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertIn("gate passed", passed.stdout)

    def test_report_and_gate_round_trip_helpers(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            (scan_dir / "checkov-vulnerable.json").write_text(
                (FIXTURES / "pair" / "checkov-vulnerable.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (scan_dir / "checkov-fixed.json").write_text(
                (FIXTURES / "pair" / "checkov-fixed.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (scan_dir / "trivy-vulnerable.json").write_text(
                (FIXTURES / "pair" / "trivy-vulnerable.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (scan_dir / "trivy-fixed.json").write_text(
                (FIXTURES / "pair" / "trivy-fixed.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            output = scan_dir / "out.md"
            text = write_report(scan_dir, output)
            self.assertIn("Vulnerable", text)
            self.assertIn("CKV_AWS_144", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
