
"""
Automated tests for the Checkov scanner.

Day 3: AI-Assisted Terraform Security Gate
"""

import json
from pathlib import Path

import pytest

from gate.scanner import (
    Finding,
    determine_severity,
    group_findings,
    parse_checkov_report,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = PROJECT_ROOT / "eval" / "baseline.json"


def make_sample_finding(**overrides):
    """Create a sample Checkov finding for unit tests."""

    finding = {
        "check_id": "CKV_AWS_88",
        "check_name": "EC2 instance should not have public IP.",
        "file_path": "infra/example.tf",
        "resource": "aws_instance.example",
        "file_line_range": [10, 25],
        "severity": None,
        "guideline": "https://example.com/security-guide",
    }

    finding.update(overrides)
    return finding


def test_parse_single_finding():
    """Check that one JSON finding becomes a Finding object."""

    report = {
        "results": {
            "failed_checks": [
                make_sample_finding()
            ]
        }
    }

    findings = parse_checkov_report(report)

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)

    assert findings[0].check_id == "CKV_AWS_88"
    assert findings[0].severity == "HIGH"
    assert findings[0].line_start == 10
    assert findings[0].line_end == 25


def test_empty_report():
    """An empty failed_checks list should return no findings."""

    report = {
        "results": {
            "failed_checks": []
        }
    }

    assert parse_checkov_report(report) == []


def test_checkov_severity_is_preserved():
    """Prefer severity supplied by Checkov."""

    raw_finding = make_sample_finding(
        severity="critical"
    )

    severity, source = determine_severity(raw_finding)

    assert severity == "CRITICAL"
    assert source == "checkov"


def test_unmapped_severity():
    """Unknown checks should not receive an invented risk rating."""

    raw_finding = make_sample_finding(
        check_id="UNKNOWN_RULE"
    )

    severity, source = determine_severity(raw_finding)

    assert severity == "UNCLASSIFIED"
    assert source == "unmapped-default"


def test_malformed_line_range():
    """Malformed line ranges should not crash the parser."""

    report = {
        "results": {
            "failed_checks": [
                make_sample_finding(
                    file_line_range=["invalid", 20]
                )
            ]
        }
    }

    findings = parse_checkov_report(report)

    assert len(findings) == 1
    assert findings[0].line_start is None
    assert findings[0].line_end is None


def test_invalid_report_structure():
    """Invalid report structures should raise a clear error."""

    with pytest.raises(ValueError):
        parse_checkov_report(
            {"results": "invalid"}
        )


def test_group_findings_by_resource():
    """Findings should be grouped by file and resource."""

    first = Finding(
        check_id="CKV_AWS_88",
        check_name="Public IP",
        file_path="infra/app.tf",
        resource="aws_instance.app",
        line_start=1,
        line_end=10,
        guideline="example",
        severity="HIGH",
        severity_source="local-rule-map",
    )

    second = Finding(
        check_id="CKV_AWS_79",
        check_name="IMDSv1",
        file_path="infra/app.tf",
        resource="aws_instance.app",
        line_start=1,
        line_end=10,
        guideline="example",
        severity="HIGH",
        severity_source="local-rule-map",
    )

    third = Finding(
        check_id="CKV_AWS_20",
        check_name="Public S3 ACL",
        file_path="infra/storage.tf",
        resource="aws_s3_bucket.data",
        line_start=1,
        line_end=10,
        guideline="example",
        severity="HIGH",
        severity_source="local-rule-map",
    )

    groups = group_findings([first, second, third])

    assert len(groups) == 2
    assert len(groups[("infra/app.tf", "aws_instance.app")]) == 2
    assert len(groups[("infra/storage.tf", "aws_s3_bucket.data")]) == 1


def test_real_baseline_contains_66_findings():
    """Regression test against our saved Day 2 baseline."""

    assert BASELINE_PATH.exists(), "Day 2 baseline JSON is missing"

    report = json.loads(
        BASELINE_PATH.read_text(encoding="utf-8-sig")
    )

    findings = parse_checkov_report(report)

    assert len(findings) == 66

    assert all(
        finding.check_id for finding in findings
    )


def test_all_real_baseline_findings_have_resource():
    """Verify that baseline findings contain resource identifiers."""

    report = json.loads(
        BASELINE_PATH.read_text(encoding="utf-8-sig")
    )

    findings = parse_checkov_report(report)

    assert all(
        finding.resource for finding in findings
    )

import pytest

from pathlib import Path
from gate.scanner import Finding
from gate.extract import resolve_finding_path


def test_path_traversal_is_blocked():
    """The extractor must reject paths outside infra/."""

    malicious_finding = Finding(
        check_id="TEST",
        check_name="Path traversal test",
        file_path=r"..\..\outside.tf",
        resource="aws_instance.test",
        line_start=1,
        line_end=5,
        guideline="",
        severity="HIGH",
        severity_source="test",
    )

    with pytest.raises(
        ValueError,
        match="escapes the infrastructure directory"
    ):
        resolve_finding_path(
            malicious_finding,
            Path("infra")
        )
