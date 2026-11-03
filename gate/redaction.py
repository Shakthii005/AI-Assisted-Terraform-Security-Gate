
"""
Terraform sensitive-value detection and redaction.

Day 6: AI-Assisted Terraform Security Gate

Sensitive values are replaced before being sent to an AI provider.
Original values are restored locally when applying a proposal.

Unsupported multiline expressions fail closed.
"""

import re
from typing import Any


# Attribute names containing common sensitive-value identifiers.
SENSITIVE_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:"
    r"password|passwd|pwd|"
    r"secret|secret_key|secret_access_key|aws_secret_access_key|"
    r"token|access_token|refresh_token|id_token|session_token|"
    r"api_key|apikey|"
    r"access_key|accesskey|aws_access_key_id|"
    r"private_key|privatekey|"
    r"client_secret|clientsecret|"
    r"authorization|auth_token|"
    r"credential|credentials|"
    r"connection_string|database_url|db_url|dsn"
    r")(?:_|$)",
    re.IGNORECASE,
)


# Terraform attribute assignment.
ASSIGNMENT_PATTERN = re.compile(
    r"^(?P<prefix>[ \t]*"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*)"
    r"[ \t]*=[ \t]*)"
    r"(?P<value>.*)$"
)

# Heredoc opening marker.
HEREDOC_PATTERN = re.compile(
    r"<<-?([A-Za-z_][A-Za-z0-9_]*)"
)

REDACTION_PREFIX = "__TFG_REDACTED_"


def normalize_key(key: str) -> str:
    """Normalize Terraform attribute names."""

    key = re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])",
        "_",
        key,
    )

    key = key.replace("-", "_")

    return key.lower().strip("_")


def is_sensitive_key(key: str) -> bool:
    """Determine whether an attribute name indicates sensitive data."""

    normalized = normalize_key(key)

    return bool(
        SENSITIVE_NAME_PATTERN.search(normalized)
    )


def normalize_token_name(key: str) -> str:
    """Create a safe identifier for a redaction placeholder."""

    return re.sub(
        r"[^A-Z0-9_]",
        "_",
        normalize_key(key).upper(),
    )


def has_unclosed_expression(value: str) -> bool:
    """
    Detect unclosed delimiters or strings in a single-line value.

    Multiline sensitive expressions that cannot safely be
    processed are rejected instead of being sent to AI.
    """

    stack = []

    pairs = {
        ")": "(",
        "]": "[",
        "}": "{",
    }

    in_string = False
    escaped = False
    block_comment = False

    index = 0

    while index < len(value):

        char = value[index]

        next_char = (
            value[index + 1]
            if index + 1 < len(value)
            else ""
        )

        if block_comment:

            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
                continue

        elif in_string:

            if escaped:
                escaped = False

            elif char == "\\":
                escaped = True

            elif char == '"':
                in_string = False

        else:

            if char == '"':
                in_string = True

            elif char == "#" or (
                char == "/" and next_char == "/"
            ):
                break

            elif char == "/" and next_char == "*":
                block_comment = True
                index += 2
                continue

            elif char in "([{":
                stack.append(char)

            elif char in ")]}":

                if not stack or stack[-1] != pairs[char]:
                    raise ValueError(
                        "Malformed sensitive Terraform expression"
                    )

                stack.pop()

        index += 1

    return bool(stack or in_string or block_comment)


def _redact_with_mapping(
    source: str,
) -> tuple[str, list[tuple[str, str]]]:
    """
    Redact sensitive assignments and retain a local restoration map.

    Supports:
    - Normal single-line assignments.
    - Common secret-name variants.
    - Terraform heredoc values.

    Unsupported multiline sensitive expressions fail closed.
    """

    lines = source.splitlines(keepends=True)

    output = []
    original_values = []

    counter = 0
    index = 0

    while index < len(lines):

        line = lines[index]

        if line.endswith("\r\n"):
            newline = "\r\n"
            body = line[:-2]

        elif line.endswith("\n") or line.endswith("\r"):
            newline = line[-1]
            body = line[:-1]

        else:
            newline = ""
            body = line

        match = ASSIGNMENT_PATTERN.match(body)

        if not match:
            output.append(line)
            index += 1
            continue

        key = match.group("key")

        if not is_sensitive_key(key):
            output.append(line)
            index += 1
            continue

        token = (
            f"{REDACTION_PREFIX}"
            f"{normalize_token_name(key)}_{counter}__"
        )

        counter += 1

        prefix = match.group("prefix")
        value = match.group("value")

        # ----------------------------------------------------
        # Handle Terraform heredoc secrets.
        # ----------------------------------------------------

        heredoc_match = HEREDOC_PATTERN.match(
            value.lstrip()
        )

        if heredoc_match:

            delimiter = heredoc_match.group(1)

            original_expression = (
                value + newline
            )

            index += 1
            delimiter_found = False

            while index < len(lines):

                body_line = lines[index]

                original_expression += body_line

                if body_line.strip() == delimiter:
                    delimiter_found = True
                    index += 1
                    break

                index += 1

            if not delimiter_found:
                raise ValueError(
                    f"Unterminated sensitive heredoc "
                    f"for attribute '{key}'. Refusing to send input."
                )

            # Preserve the original expression but remove
            # its final line ending because the assignment's
            # placeholder already retains that newline.
            original_expression = (
                original_expression.rstrip("\r\n")
            )

            original_values.append(
                (token, original_expression)
            )

            output.append(
                f'{prefix}"{token}"{newline}'
            )

            continue

        # ----------------------------------------------------
        # Handle normal single-line secret assignments.
        # ----------------------------------------------------

        if has_unclosed_expression(value):
            raise ValueError(
                f"Sensitive attribute '{key}' contains an "
                "unsupported multiline expression. "
                "Refusing to send input to the AI provider."
            )

        original_values.append(
            (token, value)
        )

        output.append(
            f'{prefix}"{token}"{newline}'
        )

        index += 1

    return "".join(output), original_values


def redact_sensitive_assignments(source: str) -> str:
    """
    Replace sensitive Terraform attribute values with markers.

    Example:
        admin_password = "secret123"

    Becomes:
        admin_password = "__TFG_REDACTED_ADMIN_PASSWORD_0__"
    """

    if not isinstance(source, str):
        raise TypeError("Source must be a string")

    redacted, _ = _redact_with_mapping(source)

    return redacted


def restore_redacted_assignments(
    proposed: str,
    original: str,
) -> str:
    """
    Restore original sensitive values locally.

    Each original placeholder must occur exactly once.
    Unknown or unresolved placeholders are rejected.
    """

    if not isinstance(proposed, str):
        raise TypeError("Proposed Terraform must be a string")

    if not isinstance(original, str):
        raise TypeError("Original Terraform must be a string")

    _, original_values = _redact_with_mapping(original)

    for token, original_value in original_values:

        marker = f'"{token}"'

        occurrences = proposed.count(marker)

        if occurrences != 1:
            raise ValueError(
                f"Sensitive placeholder must appear exactly once: "
                f"{token}"
            )

        proposed = proposed.replace(
            marker,
            original_value,
            1,
        )

    # Reject unknown or unresolved markers.
    if REDACTION_PREFIX in proposed:
        raise ValueError(
            "Unknown or unresolved sensitive placeholder detected"
        )

    return proposed
