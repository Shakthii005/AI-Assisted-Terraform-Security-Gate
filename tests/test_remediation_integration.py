
"""Integration tests for the AI remediation security boundary.

Groq is mocked. No external API requests are performed.
"""

import json
import sys

import pytest

import gate.remediate as remediate

from gate.scanner import Finding
from gate.extract import ExtractedResource


ORIGINAL_BLOCK = '''resource "aws_security_group" "ssh_open" {
  name   = "company-ssh-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}'''


SAFE_PATCH = '''resource "aws_security_group" "ssh_open" {
  name   = "company-ssh-open"
}'''


def prepare_environment(
    tmp_path,
    monkeypatch,
    proposal,
):
    """Prepare an isolated mocked remediation environment."""

    root = tmp_path / "project"

    infra = root / "infra"
    proposals = root / "eval" / "proposals"

    infra.mkdir(parents=True)
    proposals.mkdir(parents=True)

    terraform_file = infra / "network.tf"

    terraform_file.write_text(
        ORIGINAL_BLOCK + "\n",
        encoding="utf-8",
    )

    baseline = root / "eval" / "baseline.json"

    baseline.write_text(
        json.dumps({"results": {}}),
        encoding="utf-8",
    )

    finding = Finding(
        check_id="CKV_AWS_24",
        check_name="Public SSH access",
        file_path=r"\network.tf",
        resource="aws_security_group.ssh_open",
        line_start=1,
        line_end=10,
        guideline="SSH must not be publicly accessible.",
        severity="HIGH",
        severity_source="test",
    )

    extracted = ExtractedResource(
        file_path=terraform_file,
        resource="aws_security_group.ssh_open",
        start_line=1,
        end_line=10,
        resource_block=ORIGINAL_BLOCK,
        context_before="",
        context_after="",
    )

    # Redirect the application to our isolated test directory.
    monkeypatch.setattr(
        remediate,
        "ROOT",
        root,
    )

    monkeypatch.setattr(
        remediate,
        "BASELINE",
        baseline,
    )

    monkeypatch.setattr(
        remediate,
        "INFRA",
        infra,
    )

    # Mock Checkov baseline parsing.
    monkeypatch.setattr(
        remediate,
        "parse_checkov_report",
        lambda report: [finding],
    )

    # Mock Terraform resource extraction.
    monkeypatch.setattr(
        remediate,
        "extract_resource",
        lambda *args, **kwargs: extracted,
    )

    # Mock prompt construction.
    monkeypatch.setattr(
        remediate,
        "build_remediation_prompt",
        lambda *args: (
            "Trusted system instructions",
            "Mocked untrusted task data",
        ),
    )

    # Mock Groq. No real API request is made.
    monkeypatch.setattr(
        remediate,
        "call_model",
        lambda **kwargs: proposal,
    )

    # Mock command-line arguments.
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "remediate",
            "--check-id",
            "CKV_AWS_24",
            "--resource",
            "aws_security_group.ssh_open",
            "--output",
            "eval/proposals/integration_test.json",
        ],
    )

    output_path = (
        proposals / "integration_test.json"
    )

    return root, output_path


def test_safe_proposal_is_validated_and_saved(
    tmp_path,
    monkeypatch,
):
    """A valid AI proposal should pass validation and be saved."""

    proposal = {
        "patched_block": SAFE_PATCH,
        "additional_blocks": [],
        "explanation": "Removed public SSH ingress.",
    }

    root, output_path = prepare_environment(
        tmp_path,
        monkeypatch,
        proposal,
    )

    remediate.main()

    assert output_path.is_file()

    saved = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert saved["check_id"] == "CKV_AWS_24"

    assert saved["resource"] == (
        "aws_security_group.ssh_open"
    )

    assert saved["status"] == "PROPOSED_NOT_VERIFIED"

    # Confirm the original Terraform is unchanged.
    original_file = root / "infra" / "network.tf"

    assert original_file.read_text(
        encoding="utf-8"
    ) == ORIGINAL_BLOCK + "\n"


def test_external_data_source_is_rejected_and_not_saved(
    tmp_path,
    monkeypatch,
):
    """An external data source must be rejected before saving."""

    malicious = {
        "patched_block": SAFE_PATCH,
        "additional_blocks": [
            '''data "external" "command" {
  program = ["powershell", "-Command", "whoami"]
}'''
        ],
        "explanation": "Attempted unsafe external data source.",
    }

    root, output_path = prepare_environment(
        tmp_path,
        monkeypatch,
        malicious,
    )

    with pytest.raises(SystemExit) as exc:

        remediate.main()

    assert exc.value.code == 1

    # Unsafe proposal must never be saved.
    assert not output_path.exists()

    # Original source must remain untouched.
    original_file = root / "infra" / "network.tf"

    assert original_file.read_text(
        encoding="utf-8"
    ) == ORIGINAL_BLOCK + "\n"


def test_public_ingress_proposal_is_rejected_and_not_saved(
    tmp_path,
    monkeypatch,
):
    """An AI proposal retaining public SSH must be rejected."""

    malicious = {
        "patched_block": ORIGINAL_BLOCK,
        "additional_blocks": [],
        "explanation": "Attempted to retain public SSH access.",
    }

    root, output_path = prepare_environment(
        tmp_path,
        monkeypatch,
        malicious,
    )

    with pytest.raises(SystemExit) as exc:

        remediate.main()

    assert exc.value.code == 1

    assert not output_path.exists()

    original_file = root / "infra" / "network.tf"

    assert original_file.read_text(
        encoding="utf-8"
    ) == ORIGINAL_BLOCK + "\n"
