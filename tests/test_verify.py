
"""Tests for the automated Terraform verification engine."""

from pathlib import Path

from gate.scanner import Finding

from gate.verify import (
    finding_key,
    verify_target_finding,
    check_checkov_scan_complete,
    find_changed_terraform_files,
    collect_terraform_files,
)


def make_finding(
    check_id="CKV_AWS_24",
    resource="aws_security_group.ssh_open",
    file_path=r"\day2_s3_network.tf",
):
    return Finding(
        check_id=check_id,
        check_name="Test security finding",
        file_path=file_path,
        resource=resource,
        line_start=10,
        line_end=20,
        guideline="",
        severity="HIGH",
        severity_source="test",
    )


def test_finding_key_normalizes_file_path():
    finding = make_finding(
        file_path=r"\DAY2_S3_NETWORK.TF"
    )

    key = finding_key(finding)

    assert key == (
        "CKV_AWS_24",
        "aws_security_group.ssh_open",
        "day2_s3_network.tf",
    )


def test_target_finding_explicitly_passed():
    report = {
        "results": {
            "passed_checks": [
                {
                    "check_id": "CKV_AWS_24",
                    "resource": "aws_security_group.ssh_open",
                }
            ],
            "failed_checks": [],
        }
    }

    assert verify_target_finding(
        report,
        "CKV_AWS_24",
        "aws_security_group.ssh_open",
    ) is True


def test_target_finding_still_failing():
    report = {
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_24",
                    "resource": "aws_security_group.ssh_open",
                }
            ],
        }
    }

    assert verify_target_finding(
        report,
        "CKV_AWS_24",
        "aws_security_group.ssh_open",
    ) is False


def test_missing_target_is_not_accepted():
    report = {
        "results": {
            "passed_checks": [],
            "failed_checks": [],
        }
    }

    assert verify_target_finding(
        report,
        "CKV_AWS_24",
        "aws_security_group.ssh_open",
    ) is False


def test_checkov_scan_complete_without_parsing_errors():
    report = {
        "summary": {
            "parsing_errors": 0,
        }
    }

    assert check_checkov_scan_complete(report) is True


def test_checkov_scan_rejected_with_parsing_errors():
    report = {
        "summary": {
            "parsing_errors": 2,
        }
    }

    assert check_checkov_scan_complete(report) is False


def test_changed_terraform_files_are_detected(tmp_path):
    original = tmp_path / "original"
    patched = tmp_path / "patched"

    original.mkdir()
    patched.mkdir()

    (original / "network.tf").write_text(
        'resource "test" "example" {}',
        encoding="utf-8",
    )

    (patched / "network.tf").write_text(
        'resource "test" "example" { name = "changed" }',
        encoding="utf-8",
    )

    (original / "main.tf").write_text(
        'resource "test" "main" {}',
        encoding="utf-8",
    )

    (patched / "main.tf").write_text(
        'resource "test" "main" {}',
        encoding="utf-8",
    )

    changed = find_changed_terraform_files(
        original,
        patched,
    )

    assert changed == ["network.tf"]


def test_generated_terraform_artifacts_are_ignored(tmp_path):
    infra = tmp_path / "infra"

    infra.mkdir()

    (infra / "main.tf").write_text(
        'resource "test" "main" {}',
        encoding="utf-8",
    )

    generated = infra / ".terraform" / "providers"
    generated.mkdir(parents=True)

    (generated / "generated.tf").write_text(
        "generated content",
        encoding="utf-8",
    )

    files = collect_terraform_files(infra)

    assert "main.tf" in files
    assert not any(".terraform" in name for name in files)
