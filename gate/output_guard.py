
"""
AI proposal security validation.

Day 6: AI-Assisted Terraform Security Gate

Rejects malformed or potentially dangerous AI-generated
Terraform proposals before they are saved.
"""

import re

from collections import Counter
from typing import Any

from gate.extract import find_matching_brace

from gate.redaction import (
    ASSIGNMENT_PATTERN,
    REDACTION_PREFIX,
    is_sensitive_key,
    redact_sensitive_assignments,
)


# ============================================================
# PATTERNS
# ============================================================

RESOURCE_PATTERN = re.compile(
    r'^[ \t]*resource[ \t]+"([^"]+)"[ \t]+"([^"]+)"[ \t]*\{',
    re.MULTILINE,
)

MARKER_PATTERN = re.compile(
    re.escape(REDACTION_PREFIX) + r"[A-Z0-9_]+__"
)


# Prohibited Terraform execution constructs.
FORBIDDEN_PATTERNS = {
    "local_exec": re.compile(
        r'\bprovisioner\s+"local-exec"',
        re.IGNORECASE,
    ),

    "remote_exec": re.compile(
        r'\bprovisioner\s+"remote-exec"',
        re.IGNORECASE,
    ),

    "external_data_source": re.compile(
        r'\bdata\s+"external"\s+',
        re.IGNORECASE,
    ),

    "null_resource": re.compile(
        r'\bresource\s+"null_resource"\s+',
        re.IGNORECASE,
    ),
}


# Recognizable hardcoded credential patterns.
CREDENTIAL_PATTERNS = {
    "aws_access_key": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),

    "github_token": re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        re.IGNORECASE,
    ),

    "private_key": re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    ),
}


# ============================================================
# TERRAFORM RESOURCE VALIDATION
# ============================================================

def validate_resource_block(
    block: str,
) -> tuple[str, str]:
    """
    Validate exactly one Terraform resource declaration.

    Returns:
        (resource_type, resource_name)
    """

    matches = list(
        RESOURCE_PATTERN.finditer(block)
    )

    if len(matches) != 1:
        raise ValueError(
            "Each Terraform block must contain exactly "
            "one resource declaration"
        )

    match = matches[0]

    opening_brace = match.end() - 1

    try:
        closing_brace = find_matching_brace(
            block,
            opening_brace,
        )

    except (ValueError, IndexError) as exc:
        raise ValueError(
            "Terraform resource has invalid or unbalanced braces"
        ) from exc

    if block[closing_brace + 1:].strip():
        raise ValueError(
            "Unexpected content outside the Terraform resource block"
        )

    return (
        match.group(1),
        match.group(2),
    )


# ============================================================
# SECRET VALIDATION
# ============================================================

def validate_secret_assignments(
    block: str,
    allow_placeholders: bool = True,
) -> None:
    """
    Reject unredacted values assigned to sensitive attributes.
    """

    for line in block.splitlines():

        match = ASSIGNMENT_PATTERN.match(line)

        if not match:
            continue

        key = match.group("key")
        value = match.group("value").strip()

        if not is_sensitive_key(key):
            continue

        if (
            allow_placeholders
            and re.fullmatch(
                r'"__TFG_REDACTED_[A-Z0-9_]+__"',
                value,
            )
        ):
            continue

        raise ValueError(
            f"Sensitive Terraform attribute '{key}' "
            "contains an unapproved value"
        )


def validate_sensitive_markers(
    patched_block: str,
    original_block: str,
    additional_blocks: list[str],
) -> None:
    """
    Ensure every original sensitive placeholder is preserved
    exactly once in the proposed resource.
    """

    redacted_original = redact_sensitive_assignments(
        original_block
    )

    expected_markers = Counter(
        MARKER_PATTERN.findall(redacted_original)
    )

    actual_markers = Counter(
        MARKER_PATTERN.findall(patched_block)
    )

    if expected_markers != actual_markers:
        raise ValueError(
            "AI proposal changed, removed, or introduced "
            "sensitive-value placeholders"
        )

    for block in additional_blocks:

        if MARKER_PATTERN.search(block):
            raise ValueError(
                "Secret placeholder found in additional resource"
            )


def validate_no_literal_credentials(
    text: str,
) -> None:
    """Reject recognizable hardcoded credentials."""

    for name, pattern in CREDENTIAL_PATTERNS.items():

        if pattern.search(text):
            raise ValueError(
                f"Potential hardcoded credential detected: {name}"
            )


# ============================================================
# DANGEROUS TERRAFORM CONSTRUCT VALIDATION
# ============================================================


def validate_terraform_security_patterns(
    block: str,
) -> None:
    """
    Reject explicitly prohibited Terraform constructs.
    """

    # 1. Reject prohibited execution constructs.
    for name, pattern in FORBIDDEN_PATTERNS.items():

        if pattern.search(block):
            raise ValueError(
                f"Prohibited Terraform construct detected: {name}"
            )

    # 2. Reject wildcard IAM actions.
    wildcard_action = re.search(
        r'\bAction\s*=\s*(?:"\*"|\[[^\]]*"\*"[^]]*\])',
        block,
        re.IGNORECASE,
    )

    if wildcard_action:
        raise ValueError(
            "Unrestricted IAM wildcard Action detected"
        )

    # 3. Reject wildcard IAM resources.
    wildcard_resource = re.search(
        r'\bResource\s*=\s*(?:"\*"|\[[^\]]*"\*"[^]]*\])',
        block,
        re.IGNORECASE,
    )

    if wildcard_resource:
        raise ValueError(
            "Unrestricted IAM wildcard Resource detected"
        )

    # 4. Find security-group ingress blocks.
    ingress_blocks = re.findall(
        r'\bingress\s*\{([^{}]*)\}',
        block,
        re.IGNORECASE | re.DOTALL,
    )

    # 5. Check public IPv4 and IPv6 separately.
    for ingress in ingress_blocks:

        if re.search(
            r"""["']0\.0\.0\.0/0["']""",
            ingress,
        ):
            raise ValueError(
                "Unrestricted public IPv4 ingress detected"
            )

        if re.search(
            r"""["']::/0["']""",
            ingress,
        ):
            raise ValueError(
                "Unrestricted public IPv6 ingress detected"
            )

# ============================================================
# AI OUTPUT VALIDATION
# ============================================================

def validate_ai_output(
    proposal: dict[str, Any],
    original_block: str,
) -> None:
    """
    Perform generic security checks on an AI-generated proposal.

    Checkov-specific validation remains in remediate.py.
    Terraform syntax validation remains in the Day 5 engine.
    """

    if not isinstance(proposal, dict):
        raise ValueError(
            "AI response must be a JSON object"
        )

    required_fields = {
        "patched_block",
        "additional_blocks",
        "explanation",
    }

    if set(proposal.keys()) != required_fields:
        raise ValueError(
            "AI response contains missing or unexpected fields"
        )

    patched_block = proposal["patched_block"]
    additional_blocks = proposal["additional_blocks"]
    explanation = proposal["explanation"]

    # --------------------------------------------------------
    # 1. Validate output types and size.
    # --------------------------------------------------------

    if not isinstance(patched_block, str):
        raise ValueError(
            "patched_block must be a string"
        )

    if not patched_block.strip():
        raise ValueError(
            "patched_block cannot be empty"
        )

    if len(patched_block) > 50_000:
        raise ValueError(
            "Patched block exceeds the size limit"
        )

    if not isinstance(additional_blocks, list):
        raise ValueError(
            "additional_blocks must be a list"
        )

    if len(additional_blocks) > 10:
        raise ValueError(
            "Too many additional Terraform resources"
        )

    if not all(
        isinstance(block, str) and block.strip()
        for block in additional_blocks
    ):
        raise ValueError(
            "Additional blocks must be non-empty strings"
        )

    if sum(map(len, additional_blocks)) > 50_000:
        raise ValueError(
            "Additional Terraform blocks exceed the size limit"
        )

    if not isinstance(explanation, str):
        raise ValueError(
            "Explanation must be a string"
        )

    if not explanation.strip() or len(explanation) > 10_000:
        raise ValueError(
            "Invalid explanation length"
        )

    # --------------------------------------------------------
    # 2. SECURITY PREFLIGHT.
    #
    # This MUST happen before resource parsing.
    # For example, data "external" is rejected here rather
    # than receiving an unrelated resource-declaration error.
    # --------------------------------------------------------

    all_code = "\n".join(
        [patched_block, *additional_blocks]
    )

    validate_terraform_security_patterns(
        all_code
    )

    validate_no_literal_credentials(
        all_code
    )

    validate_no_literal_credentials(
        explanation
    )

    # --------------------------------------------------------
    # 3. Validate resource declarations.
    # --------------------------------------------------------

    original_identity = validate_resource_block(
        original_block
    )

    proposed_identity = validate_resource_block(
        patched_block
    )

    if original_identity != proposed_identity:
        raise ValueError(
            "AI changed the original Terraform resource identity"
        )

    additional_identities = []

    for block in additional_blocks:

        identity = validate_resource_block(block)

        if identity == original_identity:
            raise ValueError(
                "Additional block duplicates the target resource"
            )

        if identity in additional_identities:
            raise ValueError(
                "Duplicate additional Terraform resource"
            )

        additional_identities.append(identity)

    # --------------------------------------------------------
    # 4. Validate sensitive-value preservation.
    # --------------------------------------------------------

    validate_sensitive_markers(
        patched_block,
        original_block,
        additional_blocks,
    )

    # --------------------------------------------------------
    # 5. Check sensitive Terraform assignments.
    # --------------------------------------------------------

    validate_secret_assignments(
        patched_block,
        allow_placeholders=True,
    )

    for block in additional_blocks:

        validate_secret_assignments(
            block,
            allow_placeholders=False,
        )
