
"""Tests for baseline-aware Checkov security enforcement."""

import pytest

from gate.baseline_gate import compare_baseline


CHECKOV_VERSION = "3.4.0"


def make_finding(
    check_id,
    resource,
    file_path,
):
    return {
        "check_id": check_id,
        "check_name": f"Test finding {check_id}",
        "file_path": file_path,
        "resource": resource,
        "file_line_range": [10, 20],
        "guideline": "",
        "severity": None,
    }


def make_report(
    findings,
    parsing_errors=0,
    version=CHECKOV_VERSION,
):
    return {
        "check_type": "terraform",
        "summary": {
            "passed": 10,
            "failed": len(findings),
            "skipped": 0,
            "parsing_errors": parsing_errors,
            "checkov_version": version,
        },
        "results": {
            "passed_checks": [],
            "failed_checks": findings,
            "skipped_checks": [],
        },
    }


BASELINE_FINDINGS = [
    make_finding(
        "CKV_AWS_24",
        "aws_security_group.ssh_open",
        r"\day2_s3_network.tf",
    ),
    make_finding(
        "CKV_AWS_79",
        "aws_instance.company_app",
        r"\day2_compute_database.tf",
    ),
]


def test_unchanged_baseline_passes():

    baseline = make_report(BASELINE_FINDINGS)
    current = make_report(BASELINE_FINDINGS)

    result = compare_baseline(
        baseline,
        current,
    )

    assert result["status"] == "PASS"

    assert result["comparison"]["new_findings_count"] == 0

    assert result["comparison"]["unchanged_findings_count"] == 2


def test_new_finding_fails_gate():

    baseline = make_report(BASELINE_FINDINGS)

    current_findings = BASELINE_FINDINGS + [
        make_finding(
            "CKV_AWS_20",
            "aws_s3_bucket.company_data",
            "infra/day2_s3_network.tf",
        )
    ]

    current = make_report(current_findings)

    result = compare_baseline(
        baseline,
        current,
    )

    assert result["status"] == "FAIL"

    assert result["comparison"]["new_findings_count"] == 1

    assert result["new_findings"][0]["check_id"] == "CKV_AWS_20"


def test_resolving_existing_finding_is_allowed():

    baseline = make_report(BASELINE_FINDINGS)

    current = make_report(
        [BASELINE_FINDINGS[1]]
    )

    result = compare_baseline(
        baseline,
        current,
    )

    assert result["status"] == "PASS"

    assert result["comparison"]["resolved_findings_count"] == 1

    assert result["comparison"]["new_findings_count"] == 0


def test_fixing_findings_does_not_excuse_new_finding():

    baseline = make_report(BASELINE_FINDINGS)

    current = make_report([
        make_finding(
            "CKV_AWS_25",
            "aws_security_group.rdp_open",
            "infra/day2_s3_network.tf",
        )
    ])

    result = compare_baseline(
        baseline,
        current,
    )

    assert result["status"] == "FAIL"

    assert result["comparison"]["resolved_findings_count"] == 2

    assert result["comparison"]["new_findings_count"] == 1


def test_windows_and_linux_paths_are_treated_as_same():

    baseline = make_report([
        make_finding(
            "CKV_AWS_24",
            "aws_security_group.ssh_open",
            r"\day2_s3_network.tf",
        )
    ])

    current = make_report([
        make_finding(
            "CKV_AWS_24",
            "aws_security_group.ssh_open",
            "infra/day2_s3_network.tf",
        )
    ])

    result = compare_baseline(
        baseline,
        current,
    )

    assert result["status"] == "PASS"

    assert result["comparison"]["new_findings_count"] == 0


def test_parsing_errors_fail_closed():

    baseline = make_report(BASELINE_FINDINGS)

    current = make_report(
        BASELINE_FINDINGS,
        parsing_errors=1,
    )

    with pytest.raises(
        ValueError,
        match="parsing errors",
    ):
        compare_baseline(
            baseline,
            current,
        )


def test_missing_summary_fails_closed():

    baseline = make_report(BASELINE_FINDINGS)

    current = make_report(BASELINE_FINDINGS)

    del current["summary"]

    with pytest.raises(
        ValueError,
        match="summary is missing",
    ):
        compare_baseline(
            baseline,
            current,
        )


def test_checkov_version_mismatch_is_rejected():

    baseline = make_report(
        BASELINE_FINDINGS,
        version="3.4.0",
    )

    current = make_report(
        BASELINE_FINDINGS,
        version="3.5.0",
    )

    with pytest.raises(
        ValueError,
        match="version mismatch",
    ):
        compare_baseline(
            baseline,
            current,
        )


def test_inconsistent_failed_count_is_rejected():

    baseline = make_report(BASELINE_FINDINGS)

    current = make_report(BASELINE_FINDINGS)

    current["summary"]["failed"] = 99

    with pytest.raises(
        ValueError,
        match="does not match",
    ):
        compare_baseline(
            baseline,
            current,
        )
