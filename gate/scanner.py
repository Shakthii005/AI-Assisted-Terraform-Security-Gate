
"""
Checkov finding models and JSON parser.

Day 3: AI-Assisted Terraform Security Gate
"""

import argparse
import json
import os
import shutil
import subprocess

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# Project-defined severity policy.
# These are not official Checkov severity ratings.
HIGH_SEVERITY_CHECKS = {
    "CKV_AWS_17",
    "CKV_AWS_20",
    "CKV_AWS_24",
    "CKV_AWS_25",
    "CKV_AWS_62",
    "CKV_AWS_63",
    "CKV_AWS_79",
    "CKV_AWS_88",
    "CKV_AWS_287",
    "CKV_AWS_286",
    "CKV_AWS_289",
}


@dataclass
class Finding:
    """Structured representation of one Checkov finding."""

    check_id: str
    check_name: str
    file_path: str
    resource: str
    line_start: int | None
    line_end: int | None
    guideline: str
    severity: str
    severity_source: str


def determine_severity(
    raw_finding: dict[str, Any]
) -> tuple[str, str]:
    """Use Checkov severity or our local severity policy."""

    checkov_severity = raw_finding.get("severity")

    if isinstance(checkov_severity, str) and checkov_severity.strip():
        return checkov_severity.upper(), "checkov"

    check_id = str(raw_finding.get("check_id", ""))

    if check_id in HIGH_SEVERITY_CHECKS:
        return "HIGH", "local-rule-map"

    return "UNCLASSIFIED", "unmapped-default"


def parse_checkov_report(
    report: dict[str, Any]
) -> list[Finding]:
    """Convert Checkov JSON failed checks into Finding objects."""

    results = report.get("results", {})

    if not isinstance(results, dict):
        raise ValueError(
            "Invalid Checkov report: results must be an object"
        )

    failed_checks = results.get("failed_checks", [])

    if not isinstance(failed_checks, list):
        raise ValueError(
            "Invalid Checkov report: failed_checks must be a list"
        )

    findings: list[Finding] = []

    for item in failed_checks:

        if not isinstance(item, dict):
            continue

        # Checkov 3.4.0 uses file_line_range.
        line_range = item.get("file_line_range") or []

        line_start = None
        line_end = None

        if isinstance(line_range, (list, tuple)) and len(line_range) >= 2:
            try:
                line_start = int(line_range[0])
                line_end = int(line_range[1])
            except (TypeError, ValueError):
                pass

        severity, severity_source = determine_severity(item)

        finding = Finding(
            check_id=str(item.get("check_id") or ""),
            check_name=str(item.get("check_name") or ""),
            file_path=str(item.get("file_path") or ""),
            resource=str(item.get("resource") or ""),
            line_start=line_start,
            line_end=line_end,
            guideline=str(item.get("guideline") or ""),
            severity=severity,
            severity_source=severity_source,
        )

        findings.append(finding)

    return findings


def run_checkov(target: Path) -> dict[str, Any]:
    """
    Execute Checkov against a Terraform directory or file.

    Windows .CMD/.BAT launchers are executed through cmd.exe.
    Security findings can produce exit code 1, so their JSON
    output must still be parsed.
    """

    target = target.resolve()

    if not target.exists():
        raise FileNotFoundError(
            f"Target does not exist: {target}"
        )

    if target.is_dir():
        target_flag = "-d"

    elif target.is_file() and target.suffix.lower() == ".tf":
        target_flag = "-f"

    else:
        raise ValueError(
            "Target must be a directory or Terraform .tf file"
        )

    # Locate Checkov in the active Python environment.
    checkov_executable = shutil.which("checkov")

    if checkov_executable is None:
        raise FileNotFoundError(
            "Checkov executable not found. "
            "Activate the project's virtual environment and "
            "install Checkov using: python -m pip install checkov"
        )

    checkov_args = [
        target_flag,
        str(target),
        "--framework",
        "terraform",
        "-o",
        "json",
    ]

    # Windows pip installations may expose Checkov as .CMD/.BAT.
    if (
        os.name == "nt"
        and Path(checkov_executable).suffix.lower() in {".cmd", ".bat"}
    ):
        command = [
            "cmd.exe",
            "/d",
            "/c",
            "call",
            checkov_executable,
            *checkov_args,
        ]
    else:
        command = [
            checkov_executable,
            *checkov_args,
        ]

    print(f"Running Checkov on: {target}")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
    )

    try:
        report = json.loads(result.stdout)

    except json.JSONDecodeError as exc:
        error_details = result.stderr or result.stdout[:1000]

        raise RuntimeError(
            "Could not parse Checkov JSON output.\n"
            f"Exit code: {result.returncode}\n"
            f"Details: {error_details}"
        ) from exc

    if not isinstance(report, dict):
        raise ValueError(
            "Checkov returned an unexpected JSON structure"
        )

    # Exit code 1 is accepted because it may represent failed checks.
    # Other nonzero codes indicate a possible execution problem.
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Checkov execution failed with exit code "
            f"{result.returncode}. Details: {result.stderr[:1000]}"
        )

    return report


def scan_targets(targets: list[Path]) -> list[Finding]:
    """
    Scan one directory, one Terraform file,
    or multiple selected Terraform files.
    """

    if not targets:
        raise ValueError("At least one scan target is required")

    findings: list[Finding] = []

    if len(targets) == 1:
        report = run_checkov(targets[0])
        return parse_checkov_report(report)

    for target in targets:

        if not target.is_file() or target.suffix.lower() != ".tf":
            raise ValueError(
                "When supplying multiple targets, "
                "each target must be a Terraform .tf file"
            )

        report = run_checkov(target)
        findings.extend(parse_checkov_report(report))

    return findings


def group_findings(
    findings: list[Finding],
) -> dict[tuple[str, str], list[Finding]]:
    """Group findings by Terraform file and resource."""

    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        key = (finding.file_path, finding.resource)
        groups[key].append(finding)

    return dict(groups)


def main() -> None:
    """Command-line entry point for the security scanner."""

    parser = argparse.ArgumentParser(
        description="Scan Terraform infrastructure using Checkov."
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="Terraform directory or one/more Terraform files",
    )

    args = parser.parse_args()

    targets = [Path(target) for target in args.targets]

    try:
        findings = scan_targets(targets)

        print("\n" + "=" * 65)
        print("TERRAFORM SECURITY GATE - SCAN RESULTS")
        print("=" * 65)

        print(f"Total findings: {len(findings)}")

        # Severity summary
        severity_counts = Counter(
            finding.severity for finding in findings
        )

        print("\nSEVERITY SUMMARY")

        for severity, count in sorted(severity_counts.items()):
            print(f"{severity}: {count}")

        # Group findings by file and resource.
        groups = group_findings(findings)

        print("\nFINDINGS BY RESOURCE")

        for (file_path, resource), resource_findings in groups.items():

            print(f"\nFile: {file_path}")
            print(f"Resource: {resource}")
            print(f"Failed checks: {len(resource_findings)}")

            for finding in resource_findings:
                print(
                    f"  [{finding.severity}] "
                    f"{finding.check_id}: "
                    f"{finding.check_name}"
                )

                print(
                    f"    Lines: "
                    f"{finding.line_start}-{finding.line_end}"
                )

                print(
                    f"    Severity source: "
                    f"{finding.severity_source}"
                )

        print("\n" + "=" * 65)
        print("SCAN COMPLETED")
        print("=" * 65)

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        OSError,
    ) as exc:

        parser.exit(1, f"\nScanner error: {exc}\n")


if __name__ == "__main__":
    main()
