
"""Redact sensitive Terraform attribute values before AI requests."""

import re


SECRET_PATTERN = re.compile(
    r'(?im)^([ \t]*(?:password|secret|secret_key|'
    r'secret_access_key|aws_secret_access_key|access_key|'
    r'api_key|client_secret|private_key)[ \t]*=[ \t]*)'
    r'("(?:\\.|[^"\\])*"|[^#\r\n]+?)([ \t]*(?:#.*)?)$'
)


def redact_sensitive_assignments(source: str) -> str:
    """Replace sensitive assignment values with deterministic markers."""

    counter = 0

    def replace(match):
        nonlocal counter

        key = match.group(1).split("=", 1)[0].strip().upper()
        token = f"__TFG_REDACTED_{key}_{counter}__"
        counter += 1

        return f'{match.group(1)}"{token}"{match.group(3)}'

    return SECRET_PATTERN.sub(replace, source)


def restore_redacted_assignments(
    proposed: str,
    original: str,
) -> str:
    """
    Restore sensitive values locally from the original block.

    The original values are never requested from the AI.
    Every marker must appear exactly once in the proposal.
    """

    original_values = []

    def capture(match):
        key = match.group(1).split("=", 1)[0].strip().upper()
        token = f"__TFG_REDACTED_{key}_{len(original_values)}__"

        original_values.append((token, match.group(2)))

        return f'{match.group(1)}"{token}"{match.group(3)}'

    SECRET_PATTERN.sub(capture, original)

    for token, original_value in original_values:
        marker = f'"{token}"'

        if proposed.count(marker) != 1:
            raise ValueError(
                f"Missing or duplicated secret placeholder: {token}"
            )

        proposed = proposed.replace(
            marker,
            original_value,
            1,
        )

    if "__TFG_REDACTED_" in proposed:
        raise ValueError("Unresolved secret placeholder remains")

    return proposed
