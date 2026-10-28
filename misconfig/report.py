"""Read scanner JSON and print a vulnerable/fixed comparison.

Checkov and Trivy do not use the same severity scale. A missing Checkov
severity stays ``unscored``. This module does not invent one.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "unscored")
CHECKOV_FILES = {
    "vulnerable": "checkov-vulnerable.json",
    "fixed": "checkov-fixed.json",
}
TRIVY_FILES = {
    "vulnerable": "trivy-vulnerable.json",
    "fixed": "trivy-fixed.json",
}


class ScanError(Exception):
    """The scan directory or a JSON file cannot be used."""


@dataclass(frozen=True)
class Finding:
    scanner: str
    check_id: str
    severity: str
    title: str
    location: str
    resource: str


@dataclass(frozen=True)
class Skip:
    scanner: str
    check_id: str
    severity: str
    justification: str
    location: str
    resource: str


@dataclass
class LoadedScan:
    scanner: str
    side: str
    findings: list[Finding] = field(default_factory=list)
    skips: list[Skip] = field(default_factory=list)
    parsing_errors: int = 0
    tool_version: str | None = None


def normalize_severity(value: object) -> str:
    if value is None:
        return "unscored"
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return "unscored"
    upper = text.upper()
    if upper == "UNSCORED":
        return "unscored"
    return upper


def _json_payload(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScanError(f"cannot read {path}: {exc}") from exc
    start_candidates = [index for index in (text.find("["), text.find("{")) if index != -1]
    if not start_candidates:
        raise ScanError(f"{path} does not contain JSON")
    try:
        return json.loads(text[min(start_candidates) :])
    except json.JSONDecodeError as exc:
        raise ScanError(f"{path} is not valid JSON: {exc}") from exc


def _as_blocks(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [block for block in payload if isinstance(block, dict)]
    raise ScanError("scanner JSON must be an object or a list of objects")


def load_checkov(path: Path, side: str) -> LoadedScan:
    scan = LoadedScan(scanner="Checkov", side=side)
    versions: list[str] = []
    for block in _as_blocks(_json_payload(path)):
        summary = block.get("summary") or {}
        scan.parsing_errors += int(summary.get("parsing_errors") or 0)
        version = summary.get("checkov_version")
        if version and version not in versions:
            versions.append(str(version))
        results = block.get("results") or {}
        for item in results.get("failed_checks") or []:
            if not isinstance(item, dict):
                continue
            scan.findings.append(
                Finding(
                    scanner="Checkov",
                    check_id=str(item.get("check_id") or ""),
                    severity=normalize_severity(item.get("severity")),
                    title=str(item.get("check_name") or ""),
                    location=str(item.get("file_path") or ""),
                    resource=str(item.get("resource") or ""),
                )
            )
        for item in results.get("skipped_checks") or []:
            if not isinstance(item, dict):
                continue
            check_result = item.get("check_result") or {}
            justification = item.get("suppress_comment") or check_result.get("suppress_comment") or ""
            scan.skips.append(
                Skip(
                    scanner="Checkov",
                    check_id=str(item.get("check_id") or ""),
                    severity=normalize_severity(item.get("severity")),
                    justification=str(justification).strip(),
                    location=str(item.get("file_path") or ""),
                    resource=str(item.get("resource") or ""),
                )
            )
    scan.tool_version = ", ".join(versions) or None
    return scan


def load_trivy(path: Path, side: str) -> LoadedScan:
    scan = LoadedScan(scanner="Trivy", side=side)
    payload = _json_payload(path)
    if isinstance(payload, list):
        raise ScanError(f"{path} is a list; Trivy config JSON is an object")
    if not isinstance(payload, dict):
        raise ScanError(f"{path} is not a Trivy JSON object")
    trivy_meta = payload.get("Trivy") or {}
    if isinstance(trivy_meta, dict) and trivy_meta.get("Version"):
        scan.tool_version = str(trivy_meta["Version"])
    for result in payload.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for item in result.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                continue
            status = str(item.get("Status") or "FAIL").upper()
            if status != "FAIL":
                continue
            cause = item.get("CauseMetadata") or {}
            resource = ""
            if isinstance(cause, dict):
                resource = str(cause.get("Resource") or "")
            scan.findings.append(
                Finding(
                    scanner="Trivy",
                    check_id=str(item.get("ID") or ""),
                    severity=normalize_severity(item.get("Severity")),
                    title=str(item.get("Title") or ""),
                    location=target,
                    resource=resource,
                )
            )
    return scan


def load_side(scan_dir: Path, side: str) -> list[LoadedScan]:
    if side not in CHECKOV_FILES:
        raise ScanError(f"unknown side {side!r}")
    scans: list[LoadedScan] = []
    checkov_path = scan_dir / CHECKOV_FILES[side]
    trivy_path = scan_dir / TRIVY_FILES[side]
    if checkov_path.is_file():
        scans.append(load_checkov(checkov_path, side))
    if trivy_path.is_file():
        scans.append(load_trivy(trivy_path, side))
    if not scans:
        raise ScanError(
            f"no scanner JSON for {side} in {scan_dir} "
            f"(looked for {CHECKOV_FILES[side]} and {TRIVY_FILES[side]})"
        )
    return scans


def _severity_key(severity: str) -> tuple[int, str]:
    try:
        return (SEVERITY_ORDER.index(severity), severity)
    except ValueError:
        return (len(SEVERITY_ORDER), severity)


def severity_rows(vulnerable: list[LoadedScan], fixed: list[LoadedScan]) -> list[tuple[str, str, int, int]]:
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    for index, scans in enumerate((vulnerable, fixed)):
        for scan in scans:
            for finding in scan.findings:
                counts[(finding.scanner, finding.severity)][index] += 1
    scanners = []
    for name in ("Checkov", "Trivy"):
        if any(key[0] == name for key in counts):
            scanners.append(name)
    rows: list[tuple[str, str, int, int]] = []
    for scanner in scanners:
        present = {severity for name, severity in counts if name == scanner}
        ordered = [severity for severity in SEVERITY_ORDER if severity in present or severity in {"CRITICAL", "HIGH"}]
        for severity in present:
            if severity not in ordered:
                ordered.append(severity)
        for severity in sorted(ordered, key=_severity_key):
            vulnerable_count, fixed_count = counts.get((scanner, severity), [0, 0])
            rows.append((scanner, severity, vulnerable_count, fixed_count))
    return rows


def check_rows(vulnerable: list[LoadedScan], fixed: list[LoadedScan]) -> list[tuple[str, str, str, int, int, str]]:
    """One row per scanner + check id.

    The count is failed check instances (one resource failing one check counts once).
    Severity is the highest severity seen for that check. Title is the first non-empty title.
    """
    grouped: dict[tuple[str, str], dict] = {}
    for index, scans in enumerate((vulnerable, fixed)):
        for scan in scans:
            for finding in scan.findings:
                key = (finding.scanner, finding.check_id)
                slot = grouped.setdefault(
                    key,
                    {
                        "counts": [0, 0],
                        "severity": finding.severity,
                        "title": finding.title,
                    },
                )
                slot["counts"][index] += 1
                if _severity_key(finding.severity) < _severity_key(slot["severity"]):
                    slot["severity"] = finding.severity
                if not slot["title"] and finding.title:
                    slot["title"] = finding.title
    rows = []
    for (scanner, check_id), slot in grouped.items():
        rows.append(
            (
                scanner,
                check_id,
                slot["severity"],
                slot["counts"][0],
                slot["counts"][1],
                slot["title"],
            )
        )
    rows.sort(key=lambda row: (_severity_key(row[2]), row[0], row[1]))
    return rows


def _totals(scans: list[LoadedScan]) -> dict[str, int]:
    totals: dict[str, int] = defaultdict(int)
    for scan in scans:
        totals[scan.scanner] += len(scan.findings)
    return totals


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_table(headers: list[str], rows: list[tuple]) -> str:
    head = "| " + " | ".join(headers) + " |"
    alignments = []
    for index, _header in enumerate(headers):
        numeric = all(isinstance(row[index], int) for row in rows) if rows else False
        alignments.append("---:" if numeric else "---")
    align = "| " + " | ".join(alignments) + " |"
    body = ["| " + " | ".join(_cell(cell) for cell in row) + " |" for row in rows]
    return "\n".join([head, align, *body])


def text_table(headers: list[str], rows: list[tuple]) -> str:
    rendered = [[_cell(cell) for cell in row] for row in rows]
    header_text = [_cell(header) for header in headers]
    widths = [len(header) for header in header_text]
    for row in rendered:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(row: list[str]) -> str:
        parts = []
        for index, cell in enumerate(row):
            numeric = bool(rows) and all(isinstance(item[index], int) for item in rows)
            if numeric:
                parts.append(cell.rjust(widths[index]))
            else:
                parts.append(cell.ljust(widths[index]))
        return "  ".join(parts)

    lines = [
        format_row(header_text),
        format_row(["-" * width for width in widths]),
    ]
    lines.extend(format_row(row) for row in rendered)
    return "\n".join(lines)


def render_text(vulnerable: list[LoadedScan], fixed: list[LoadedScan]) -> str:
    severity = severity_rows(vulnerable, fixed)
    checks = check_rows(vulnerable, fixed)
    vulnerable_totals = _totals(vulnerable)
    fixed_totals = _totals(fixed)
    lines = [
        "Failed checks by severity",
        "",
        text_table(["Scanner", "Severity", "Vulnerable", "Fixed"], severity),
        "",
        "Failed checks by check",
        "",
        text_table(
            ["Scanner", "Check", "Severity", "Vulnerable", "Fixed", "Name"],
            checks,
        ),
        "",
        "Totals (failed check instances)",
    ]
    scanners = sorted(set(vulnerable_totals) | set(fixed_totals))
    for scanner in scanners:
        lines.append(
            f"  {scanner}: vulnerable {vulnerable_totals.get(scanner, 0)}, "
            f"fixed {fixed_totals.get(scanner, 0)}"
        )
    lines.append("")
    lines.append("One failed check on one resource counts as 1. Skipped checks are not included.")
    return "\n".join(lines)


def render_markdown(
    vulnerable: list[LoadedScan],
    fixed: list[LoadedScan],
    versions_text: str | None = None,
) -> str:
    severity = severity_rows(vulnerable, fixed)
    checks = check_rows(vulnerable, fixed)
    vulnerable_totals = _totals(vulnerable)
    fixed_totals = _totals(fixed)
    parts = [
        "# Scan summary",
        "",
        "Generated by `python3 -m misconfig report` from the JSON files in `scan-results/`.",
        "Counts are failed check instances: one resource failing one check counts as 1.",
        "Skipped checks are not counted as failures.",
        "",
        "Checkov 3.2.449 leaves `severity` null in this open-source run. Those rows are `unscored`.",
        "The severity was not filled in from anywhere else. Trivy severities are the severities Trivy printed.",
        "",
    ]
    if versions_text:
        parts.extend(["## Tool versions", "", "```", versions_text.rstrip(), "```", ""])
    versions = []
    for scan in vulnerable + fixed:
        if scan.tool_version:
            versions.append(f"{scan.scanner} {scan.side}: {scan.tool_version}")
    if versions:
        parts.extend(["Versions recorded inside the JSON:", ""])
        parts.extend(f"- {line}" for line in versions)
        parts.append("")
    parts.extend(
        [
            "## Failed checks by severity",
            "",
            markdown_table(["Scanner", "Severity", "Vulnerable", "Fixed"], severity),
            "",
            "## Totals",
            "",
        ]
    )
    for scanner in sorted(set(vulnerable_totals) | set(fixed_totals)):
        parts.append(
            f"- {scanner}: vulnerable {vulnerable_totals.get(scanner, 0)}, "
            f"fixed {fixed_totals.get(scanner, 0)}"
        )
    parts.extend(
        [
            "",
            "## Failed checks by check",
            "",
            markdown_table(
                ["Scanner", "Check", "Severity", "Vulnerable", "Fixed", "Name"],
                checks,
            ),
            "",
            "## Still reported in fixed/",
            "",
        ]
    )
    remaining = [row for row in checks if row[4] > 0]
    if not remaining:
        parts.append("No failed checks in the fixed JSON.")
    else:
        parts.append(
            markdown_table(
                ["Scanner", "Check", "Severity", "Fixed count", "Name"],
                [(row[0], row[1], row[2], row[4], row[5]) for row in remaining],
            )
        )
        parts.append("")
        if all(row[2] == "unscored" for row in remaining):
            parts.append(
                "Every check still failing in fixed/ is unscored in the scanner JSON. "
                "None of them is labeled critical or high."
            )
        if fixed_totals.get("Trivy", 0) == 0 and any(scan.scanner == "Trivy" for scan in fixed):
            parts.append("Trivy reported no failed checks on fixed/.")
    parts.append("")
    return "\n".join(parts)


def gate_problems(
    scans: list[LoadedScan],
    fail_on: set[str],
    expect_findings: bool,
) -> list[str]:
    problems: list[str] = []
    for scan in scans:
        if scan.parsing_errors:
            problems.append(f"{scan.scanner} {scan.side}: {scan.parsing_errors} parsing error(s)")
    findings = [finding for scan in scans for finding in scan.findings]
    if expect_findings and not findings:
        names = ", ".join(scan.scanner for scan in scans)
        problems.append(f"expected findings in {scans[0].side} from {names}, found none")
    for scan in scans:
        for finding in scan.findings:
            if finding.severity in fail_on:
                problems.append(
                    f"{scan.side} {finding.scanner} {finding.severity} {finding.check_id} "
                    f"on {finding.resource or finding.location}"
                )
        for skip in scan.skips:
            if skip.severity in fail_on and not skip.justification:
                problems.append(
                    f"{scan.side} {skip.scanner} {skip.severity} {skip.check_id} "
                    f"is skipped with no justification ({skip.resource or skip.location})"
                )
    return problems


def _read_versions(scan_dir: Path) -> str | None:
    path = scan_dir / "tool-versions.txt"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def write_report(scan_dir: Path, output: Path) -> str:
    vulnerable = load_side(scan_dir, "vulnerable")
    fixed = load_side(scan_dir, "fixed")
    text = render_text(vulnerable, fixed)
    markdown = render_markdown(vulnerable, fixed, _read_versions(scan_dir))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return text


def _split_severities(value: str) -> set[str]:
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="misconfig")
    sub = parser.add_subparsers(dest="command", required=True)

    report = sub.add_parser("report", help="print a before/after table and write docs/scan-summary.md")
    report.add_argument("--scan-dir", default="scan-results", type=Path)
    report.add_argument("--output", default="docs/scan-summary.md", type=Path)

    gate = sub.add_parser("gate", help="exit 1 when a side breaks the lab rules")
    gate.add_argument("--scan-dir", default="scan-results", type=Path)
    gate.add_argument("--side", required=True, choices=("vulnerable", "fixed"))
    gate.add_argument("--fail-on", default="", help="comma-separated severities, for example CRITICAL,HIGH")
    gate.add_argument(
        "--expect-findings",
        action="store_true",
        help="exit 1 when this side has no failed checks",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            text = write_report(args.scan_dir, args.output)
            print(text)
            print(f"\nWrote {args.output}")
            return 0
        scans = load_side(args.scan_dir, args.side)
        problems = gate_problems(scans, _split_severities(args.fail_on), args.expect_findings)
    except ScanError as exc:
        print(f"misconfig: {exc}", file=sys.stderr)
        return 2
    if problems:
        print(f"misconfig gate failed for {args.side}:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    finding_count = sum(len(scan.findings) for scan in scans)
    print(f"{args.side}: {finding_count} failed check(s); gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
