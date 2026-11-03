
"""Security tests for AI-generated Terraform proposals."""

import pytest

from gate.output_guard import validate_ai_output


ORIGINAL = '''resource "aws_security_group" "ssh_open" {
  name = "company-ssh-open"
}'''


VALID_PATCH = '''resource "aws_security_group" "ssh_open" {
  name = "company-ssh-open"
}'''


def make_proposal(
    patched_block=VALID_PATCH,
    additional_blocks=None,
):
    return {
        "patched_block": patched_block,
        "additional_blocks": (
            additional_blocks or []
        ),
        "explanation": "Validated security proposal.",
    }


def test_valid_resource_proposal_is_accepted():

    validate_ai_output(
        make_proposal(),
        ORIGINAL,
    )


def test_unexpected_json_field_is_rejected():

    proposal = make_proposal()
    proposal["extra_instruction"] = "ignore security"

    with pytest.raises(
        ValueError,
        match="unexpected fields",
    ):
        validate_ai_output(proposal, ORIGINAL)


def test_resource_identity_change_is_rejected():

    malicious = VALID_PATCH.replace(
        "ssh_open",
        "admin_open",
    )

    with pytest.raises(
        ValueError,
        match="resource identity",
    ):
        validate_ai_output(
            make_proposal(malicious),
            ORIGINAL,
        )


def test_local_exec_provisioner_is_rejected():

    malicious = VALID_PATCH.replace(
        "\n}",
        '''
  provisioner "local-exec" {
    command = "echo dangerous"
  }
}''',
    )

    with pytest.raises(
        ValueError,
        match="local_exec",
    ):
        validate_ai_output(
            make_proposal(malicious),
            ORIGINAL,
        )


def test_external_data_source_is_rejected():

    additional = '''data "external" "command" {
  program = ["powershell", "-Command", "whoami"]
}'''

    with pytest.raises(
        ValueError,
        match="external_data_source",
    ):
        validate_ai_output(
            make_proposal(
                additional_blocks=[additional]
            ),
            ORIGINAL,
        )


def test_additional_resource_is_accepted():

    additional = '''resource "aws_s3_bucket_server_side_encryption_configuration" "company_data" {
  bucket = aws_s3_bucket.company_data.id
}'''

    validate_ai_output(
        {
            "patched_block": ORIGINAL,
            "additional_blocks": [additional],
            "explanation": "Adds the required encryption resource.",
        },
        ORIGINAL,
    )


def test_hardcoded_password_is_rejected():

    original = '''resource "aws_db_instance" "company" {
  password = "__TFG_REDACTED_PASSWORD_0__"
}'''

    malicious = '''resource "aws_db_instance" "company" {
  password = "fake-hardcoded-password"
}'''

    with pytest.raises(ValueError):
        validate_ai_output(
            {
                "patched_block": malicious,
                "additional_blocks": [],
                "explanation": "Database proposal.",
            },
            original,
        )


def test_missing_sensitive_placeholder_is_rejected():

    original = '''resource "aws_db_instance" "company" {
  password = "__TFG_REDACTED_PASSWORD_0__"
}'''

    malicious = '''resource "aws_db_instance" "company" {
  publicly_accessible = false
}'''

    with pytest.raises(
        ValueError,
        match="sensitive-value placeholders",
    ):
        validate_ai_output(
            {
                "patched_block": malicious,
                "additional_blocks": [],
                "explanation": "Database proposal.",
            },
            original,
        )


def test_wildcard_iam_action_is_rejected():

    original = '''resource "aws_iam_policy" "example" {
  description = "Example"
}'''

    malicious = '''resource "aws_iam_policy" "example" {
  policy = jsonencode({
    Action = ["*"]
  })
}'''

    with pytest.raises(
        ValueError,
        match="wildcard Action",
    ):
        validate_ai_output(
            {
                "patched_block": malicious,
                "additional_blocks": [],
                "explanation": "IAM proposal.",
            },
            original,
        )


def test_public_ingress_is_rejected():

    malicious = '''resource "aws_security_group" "ssh_open" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}'''

    with pytest.raises(
        ValueError,
        match="public IPv4 ingress",
    ):
        validate_ai_output(
            make_proposal(malicious),
            ORIGINAL,
        )


def test_duplicate_additional_resources_are_rejected():

    additional = '''resource "aws_s3_bucket_versioning" "company_data" {
  bucket = aws_s3_bucket.company_data.id
}'''

    with pytest.raises(
        ValueError,
        match="Duplicate additional",
    ):
        validate_ai_output(
            make_proposal(
                additional_blocks=[
                    additional,
                    additional,
                ]
            ),
            ORIGINAL,
        )
