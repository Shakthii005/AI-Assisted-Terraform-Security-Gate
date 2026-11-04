
"""
Baseline-aware Checkov security enforcement.

Day 8: AI-Assisted Terraform Security Gate

Allows previously documented baseline findings,
but rejects newly introduced Checkov finding identities.

Incomplete scans and parsing errors fail closed.
No AWS resources are deployed.
"""

import argparse
import json

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gate.scanner import parse_checkov_report
from gate.finding_identity import finding_key


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_BASELINE = ROOT / "eval" / "baseline.json"
DEFAULT_OUTPUT = ROOT / "eval" / "reports" / "baseline-gate.json"


# ============================================================
# REPORT VALIDATION
# ============================================================

def validate_checkov_report(
    report: dict[str, Any],
    report_name: str,
) -> list:
    """
    Validate a Checkov report before comparing findings.

    Rejects:
    - Invalid JSON structures.
    - Missing summaries.
    - Missing failed_checks.
    - Parsing errors.
    - Incomplete finding identities.
    - Inconsistent summary counts.
    """

    if not isinstance(report, dict):
        raise ValueError(
            f"{report_name} must be a JSON object"
        )

    if report.get("check_type") not in (None, "terraform"):
        raise ValueError(
            f"{report_name} is not a Terraform Checkov report"
        )

    results = report.get("results")

    if not isinstance(results, dict):
        raise ValueError(
            f"{report_name}: results must be an object"
        )

    summary = report.get("summary")

    if not isinstance(summary, dict):
        raise ValueError(
            f"{report_name}: summary is missing or invalid"
        )

    parsing_errors = summary.get("parsing_errors")

    if not isinstance(parsing_errors, int) or isinstance(
        parsing_errors, bool
    ):
        raise ValueError(
            f"{report_name}: parsing_errors is missing or invalid"
        )

    if parsing_errors != 0:
        raise ValueError(
            f"{report_name}: Checkov reported "
            f"{parsing_errors} Terraform parsing errors"
        )

    failed_checks = results.get("failed_checks")

    if not isinstance(failed_checks, list):
        raise ValueError(
            f"{report_name}: failed_checks must be a list"
        )

    passed_count = summary.get("passed")
    failed_count = summary.get("failed")

    if not isinstance(passed_count, int) or not isinstance(
        failed_count, int
    ):
        raise ValueError(
            f"{report_name}: summary passed/failed counts are invalid"
        )

    if failed_count != len(failed_checks):
        raise ValueError(
            f"{report_name}: summary failed count does not match "
            "the failed_checks list"
        )

    # Validate every finding before passing it to the parser.
    for index, item in enumerate(failed_checks):

        if not isinstance(item, dict):
            raise ValueError(
                f"{report_name}: finding {index} is not an object"
            )

        required_fields = (
            "check_id",
            "resource",
            "file_path",
        )

        for field in required_fields:

            value = item.get(field)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{report_name}: finding {index} "
                    f"has missing or invalid {field}"
                )

    return parse_checkov_report(report)


# ============================================================
# CHECKOV VERSION CONSISTENCY
# ============================================================

def validate_checkov_versions(
    baseline_report: dict[str, Any],
    current_report: dict[str, Any],
) -> None:
    """
    Prevent comparisons between different Checkov versions.

    A Checkov upgrade can change the set of available checks.
    A baseline generated with one version should not silently
    be compared against an incompatible scanner version.
    """

    baseline_version = (
        baseline_report["summary"].get("checkov_version")
    )

    current_version = (
        current_report["summary"].get("checkov_version")
    )

    if (
        baseline_version
        and current_version
        and baseline_version != current_version
    ):
        raise ValueError(
            "Checkov version mismatch: "
            f"baseline={baseline_version}, "
            f"current={current_version}. "
            "Regenerate or explicitly migrate the baseline."
        )


# ============================================================
# BASELINE COMPARISON ENGINE
# ============================================================

def compare_baseline(
    baseline_report: dict[str, Any],
    current_report: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare current Checkov findings with the approved baseline.

    Finding identity:
        check_id
        resource
        normalized Terraform file path

    Decision:
        No new finding identities = PASS
        One or more new finding identities = FAIL

    Fixing existing findings is permitted.
    Fixing old findings does not excuse new findings.
    """

    baseline_findings = validate_checkov_report(
        baseline_report,
        "Baseline report",
    )

    current_findings = validate_checkov_report(
        current_report,
        "Current report",
    )

    validate_checkov_versions(
        baseline_report,
        current_report,
    )

    # Build identity maps.
    baseline_map = {
        finding_key(finding): finding
        for finding in baseline_findings
    }

    current_map = {
        finding_key(finding): finding
        for finding in current_findings
    }

    baseline_keys = set(baseline_map)
    current_keys = set(current_map)

    # Calculate the difference.
    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    unchanged_keys = baseline_keys & current_keys

    # Convert finding identities to readable JSON records.
    def serialize_finding(key, finding):
        return {
            "check_id": key[0],
            "resource": key[1],
            "file_path": key[2],
            "check_name": finding.check_name,
            "severity": finding.severity,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
        }

    new_findings = [
        serialize_finding(key, current_map[key])
        for key in sorted(new_keys)
    ]

    resolved_findings = [
        serialize_finding(key, baseline_map[key])
        for key in sorted(resolved_keys)
    ]

    unchanged_findings = [
        serialize_finding(key, current_map[key])
        for key in sorted(unchanged_keys)
    ]

    # Any new finding fails the gate.
    passed = len(new_keys) == 0

    return {
        "project": "AI-Assisted Terraform Security Gate",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "status": "PASS" if passed else "FAIL",

        "gate_policy": {
            "identity_fields": [
                "check_id",
                "resource",
                "normalized_file_path",
            ],
            "line_numbers_in_identity": False,
            "allow_existing_findings": True,
            "fail_on_new_findings": True,
            "fail_on_parsing_errors": True,
            "require_matching_checkov_versions": True,
        },

        "baseline": {
            "checkov_version": baseline_report[
                "summary"
            ].get("checkov_version"),
            "failed_findings": len(baseline_findings),
            "unique_findings": len(baseline_keys),
        },

        "current": {
            "checkov_version": current_report[
                "summary"
            ].get("checkov_version"),
            "failed_findings": len(current_findings),
            "unique_findings": len(current_keys),
        },

        "comparison": {
            "new_findings_count": len(new_keys),
            "resolved_findings_count": len(resolved_keys),
            "unchanged_findings_count": len(unchanged_keys),
        },

        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged_findings,
    }


# ============================================================
# FILE HANDLING
# ============================================================

def load_json_report(path: Path) -> dict[str, Any]:
    """Load a Checkov JSON report from disk."""

    if not path.is_file():
        raise FileNotFoundError(
            f"Checkov report not found: {path}"
        )

    try:
        report = json.loads(
            path.read_text(encoding="utf-8-sig")
        )

    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid Checkov JSON report: {path}"
        ) from exc

    if not isinstance(report, dict):
        raise ValueError(
            f"Checkov report must be a JSON object: {path}"
        )

    return report


def save_gate_report(
    report: dict[str, Any],
    output_path: Path,
) -> None:
    """Save the baseline comparison evidence."""

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )


# ============================================================
# COMMAND-LINE INTERFACE
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare a current Checkov scan against an "
            "approved security baseline."
        )
    )

    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE),
        help="Original approved Checkov baseline JSON",
    )

    parser.add_argument(
        "--current",
        required=True,
        help="Current Checkov scan JSON",
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Baseline gate JSON report output",
    )

    args = parser.parse_args()

    try:

        baseline_path = Path(args.baseline).resolve()
        current_path = Path(args.current).resolve()
        output_path = Path(args.output).resolve()

        print("\n" + "=" * 65)
        print("BASELINE-AWARE SECURITY GATE")
        print("=" * 65)

        print(f"Baseline: {baseline_path}")
        print(f"Current:  {current_path}")

        baseline_report = load_json_report(
            baseline_path
        )

        current_report = load_json_report(
            current_path
        )

        result = compare_baseline(
            baseline_report,
            current_report,
        )

        save_gate_report(
            result,
            output_path,
        )

        print("\nSECURITY COMPARISON")

        print(
            "Baseline findings:",
            result["baseline"]["failed_findings"],
        )

        print(
            "Current findings:",
            result["current"]["failed_findings"],
        )

        print(
            "New findings:",
            result["comparison"]["new_findings_count"],
        )

        print(
            "Resolved findings:",
            result["comparison"]["resolved_findings_count"],
        )

        print(
            "Unchanged findings:",
            result["comparison"]["unchanged_findings_count"],
        )

        if result["new_findings"]:

            print("\nNEW SECURITY FINDINGS")

            for finding in result["new_findings"]:

                print(
                    f"[{finding['check_id']}] "
                    f"{finding['resource']} "
                    f"({finding['file_path']})"
                )

        print("\n" + "=" * 65)

        print(
            "FINAL DECISION:",
            result["status"],
        )

        print(f"Evidence saved: {output_path}")

        print("=" * 65)

        return 0 if result["status"] == "PASS" else 1

    except (
        ValueError,
        RuntimeError,
        FileNotFoundError,
        OSError,
    ) as exc:

        parser.exit(
            2,
            f"\nBaseline gate error: {exc}\n",
        )


if __name__ == "__main__":
    raise SystemExit(main())
