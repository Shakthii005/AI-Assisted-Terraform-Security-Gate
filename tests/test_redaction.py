
"""Security tests for Terraform secret redaction."""

import pytest

from gate.redaction import (
    redact_sensitive_assignments,
    restore_redacted_assignments,
)


def test_common_secret_name_variants_are_redacted():

    source = """
admin_password = "admin-secret-123"
db_password = "database-secret-456"
oauth_access_token = "oauth-secret-789"
aws_secret_access_key = "aws-secret-000"
"""

    redacted = redact_sensitive_assignments(source)

    assert "admin-secret-123" not in redacted
    assert "database-secret-456" not in redacted
    assert "oauth-secret-789" not in redacted
    assert "aws-secret-000" not in redacted

    assert "__TFG_REDACTED_ADMIN_PASSWORD_" in redacted
    assert "__TFG_REDACTED_DB_PASSWORD_" in redacted
    assert "__TFG_REDACTED_OAUTH_ACCESS_TOKEN_" in redacted


def test_secret_heredoc_is_redacted():

    source = (
        'private_key = <<-KEY\n'
        '-----BEGIN PRIVATE KEY-----\n'
        'example-sensitive-value\n'
        '-----END PRIVATE KEY-----\n'
        'KEY\n'
    )

    redacted = redact_sensitive_assignments(source)

    assert "example-sensitive-value" not in redacted
    assert "BEGIN PRIVATE KEY" not in redacted
    assert "__TFG_REDACTED_PRIVATE_KEY_" in redacted


def test_heredoc_secret_can_be_restored():

    source = (
        'private_key = <<-KEY\n'
        'example-sensitive-value\n'
        'KEY\n'
    )

    redacted = redact_sensitive_assignments(source)

    restored = restore_redacted_assignments(
        redacted,
        source,
    )

    assert restored == source


def test_normal_terraform_configuration_is_preserved():

    source = (
        'instance_type = "t3.micro"\n'
        'region = "us-east-1"\n'
    )

    assert redact_sensitive_assignments(source) == source


def test_single_line_secret_can_be_restored():

    source = (
        'admin_password = "example-password"\n'
        'instance_type = "t3.micro"\n'
    )

    redacted = redact_sensitive_assignments(source)

    restored = restore_redacted_assignments(
        redacted,
        source,
    )

    assert restored == source


def test_missing_placeholder_is_rejected():

    original = 'password = "example-password"'

    with pytest.raises(
        ValueError,
        match="exactly once",
    ):
        restore_redacted_assignments(
            'password = "different-value"',
            original,
        )


def test_duplicate_placeholder_is_rejected():

    original = 'password = "example-password"'

    redacted = redact_sensitive_assignments(original)

    duplicate = (
        redacted
        + "\n"
        + redacted
    )

    with pytest.raises(
        ValueError,
        match="exactly once",
    ):
        restore_redacted_assignments(
            duplicate,
            original,
        )


def test_multiline_sensitive_expression_fails_closed():

    source = (
        'password = (\n'
        '  "sensitive-value"\n'
        ')\n'
    )

    with pytest.raises(
        ValueError,
        match="unsupported multiline expression",
    ):
        redact_sensitive_assignments(source)


def test_unterminated_sensitive_heredoc_fails_closed():

    source = (
        'private_key = <<KEY\n'
        'sensitive-value\n'
        # Missing KEY terminator.
    )

    with pytest.raises(
        ValueError,
        match="Unterminated sensitive heredoc",
    ):
        redact_sensitive_assignments(source)
