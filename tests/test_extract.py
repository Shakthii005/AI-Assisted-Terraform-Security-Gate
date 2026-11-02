
import json
from pathlib import Path

import pytest

from gate.scanner import Finding, parse_checkov_report
from gate.extract import extract_resource, resolve_finding_path


ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra"
BASELINE = ROOT / "eval" / "baseline.json"


def test_extract_five_resource_types():
    """Extract five actual resources from our Day 2 baseline."""

    report = json.loads(
        BASELINE.read_text(encoding="utf-8-sig")
    )

    findings = parse_checkov_report(report)

    test_cases = {
        ("CKV_AWS_88", "aws_instance.company_app"),
        ("CKV_AWS_20", "aws_s3_bucket.company_data"),
        ("CKV_AWS_24", "aws_security_group.ssh_open"),
        ("CKV_AWS_17", "aws_db_instance.company"),
        ("CKV_AWS_62", "aws_iam_policy.wildcard_admin"),
    }

    for check_id, expected_resource in test_cases:

        finding = next(
            (
                f for f in findings
                if f.check_id == check_id
                and f.resource == expected_resource
            ),
            None,
        )

        assert finding is not None, (
            f"Finding not found: {check_id}"
        )

        extracted = extract_resource(finding, INFRA)

        assert extracted.resource == expected_resource
        assert extracted.resource_block.startswith("resource ")
        assert extracted.start_line > 0
        assert extracted.end_line >= extracted.start_line

        print(
            f"PASS: {check_id} -> {extracted.resource}"
        )


def test_path_traversal_is_blocked():
    """Ensure paths outside infra/ are rejected."""

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
        match="escapes the infrastructure directory",
    ):
        resolve_finding_path(
            malicious_finding,
            INFRA,
        )
