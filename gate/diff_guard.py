
"""
Resource-level Terraform diff protection.

Ensures that AI changes are restricted to the
intended resource and explicitly approved additions.
"""

import re

from pathlib import Path
from typing import Any

from gate.extract import (
    ExtractedResource,
    find_matching_brace,
)
from gate.redaction import restore_redacted_assignments


RESOURCE_PATTERN = re.compile(
    r'^[ \t]*resource[ \t]+"([^"]+)"[ \t]+"([^"]+)"[ \t]*\{',
    re.MULTILINE,
)


def collect_resource_blocks(
    directory: Path,
) -> dict[tuple[str, str, str], str]:
    """Collect all Terraform resource blocks."""

    directory = directory.resolve()

    if not directory.is_dir():
        raise FileNotFoundError(directory)

    resources = {}

    for file_path in directory.rglob("*.tf"):

        if ".terraform" in file_path.parts:
            continue

        relative_path = file_path.relative_to(
            directory
        ).as_posix()

        source = file_path.read_text(
            encoding="utf-8-sig"
        )

        for match in RESOURCE_PATTERN.finditer(source):

            resource_type = match.group(1)
            resource_name = match.group(2)

            opening_brace = match.end() - 1

            closing_brace = find_matching_brace(
                source,
                opening_brace,
            )

            block = source[
                match.start():closing_brace + 1
            ]

            key = (
                relative_path,
                resource_type,
                resource_name,
            )

            if key in resources:
                raise ValueError(
                    f"Duplicate resource declaration: {key}"
                )

            resources[key] = block

    return resources


def resource_identity(
    block: str,
) -> tuple[str, str]:
    """Extract a Terraform resource type and name."""

    matches = list(RESOURCE_PATTERN.finditer(block))

    if len(matches) != 1:
        raise ValueError(
            "Expected exactly one resource declaration"
        )

    return matches[0].group(1), matches[0].group(2)


def describe_keys(keys: set[tuple]) -> list[dict[str, str]]:
    """Convert resource keys into JSON-friendly dictionaries."""

    return [
        {
            "file": key[0],
            "resource_type": key[1],
            "resource_name": key[2],
        }
        for key in sorted(keys)
    ]


def verify_resource_scope(
    original_infra: Path,
    patched_infra: Path,
    target_file: str,
    extracted: ExtractedResource,
    proposal: dict[str, Any],
) -> dict[str, Any]:
    """
    Verify that only the intended Terraform resource
    and explicitly proposed additional resources changed.

    Also reconstruct the expected target file and compare
    it exactly against the patched file. This detects
    unrelated edits to variables, locals, outputs and comments
    within that file.
    """

    original_infra = original_infra.resolve()
    patched_infra = patched_infra.resolve()

    original_resources = collect_resource_blocks(
        original_infra
    )

    patched_resources = collect_resource_blocks(
        patched_infra
    )

    # Locate the target file.
    target_file_path = extracted.file_path.resolve()

    try:
        relative_target = target_file_path.relative_to(
            original_infra
        ).as_posix()
    except ValueError as exc:
        raise ValueError(
            "Target resource is outside original infrastructure"
        ) from exc

    if relative_target != target_file.replace("\\", "/"):
        raise ValueError(
            "Target file does not match the extracted resource"
        )

    original_identity = resource_identity(
        extracted.resource_block
    )

    target_key = (
        relative_target,
        original_identity[0],
        original_identity[1],
    )

    if target_key not in original_resources:
        raise ValueError(
            "Target resource does not exist in original infrastructure"
        )

    if (
        original_resources[target_key]
        != extracted.resource_block
    ):
        raise ValueError(
            "Extracted resource does not match original resource"
        )

    # Restore redacted values locally before comparison.
    patched_block = restore_redacted_assignments(
        proposal["patched_block"],
        extracted.resource_block,
    )

    proposal_additions = proposal["additional_blocks"]

    expected_target_identity = resource_identity(
        patched_block
    )

    if expected_target_identity != original_identity:
        raise ValueError(
            "Proposed resource identity was changed"
        )

    # Determine the resources the proposal is allowed to add.
    expected_added = set()

    for block in proposal_additions:

        identity = resource_identity(block)

        key = (
            relative_target,
            identity[0],
            identity[1],
        )

        if key in expected_added:
            raise ValueError(
                f"Duplicate proposed additional resource: {key}"
            )

        if key == target_key:
            raise ValueError(
                "Additional resource duplicates target resource"
            )

        expected_added.add(key)

    expected_modified = (
        {target_key}
        if patched_block != extracted.resource_block
        else set()
    )

    # Compare actual resource blocks.
    original_keys = set(original_resources)
    patched_keys = set(patched_resources)

    actual_added = patched_keys - original_keys
    actual_removed = original_keys - patched_keys

    actual_modified = {
        key
        for key in original_keys & patched_keys
        if original_resources[key] != patched_resources[key]
    }

    unexpected_modified = actual_modified - expected_modified
    missing_expected_modified = expected_modified - actual_modified

    unexpected_added = actual_added - expected_added
    missing_expected_added = expected_added - actual_added

    # Reconstruct exactly what the target Terraform file
    # should contain after the approved proposal.
    original_file = target_file_path

    patched_file = patched_infra / relative_target

    if not patched_file.is_file():
        raise FileNotFoundError(patched_file)

    original_text = original_file.read_text(
        encoding="utf-8-sig"
    )

    actual_patched_text = patched_file.read_text(
        encoding="utf-8-sig"
    )

    if original_text.count(extracted.resource_block) != 1:
        raise ValueError(
            "Original target block is not uniquely identifiable"
        )

    expected_text = original_text.replace(
        extracted.resource_block,
        patched_block.rstrip(),
        1,
    )

    if proposal_additions:
        expected_text = (
            expected_text.rstrip("\r\n")
            + "\n\n"
            + "\n\n".join(
                block.strip()
                for block in proposal_additions
            )
            + "\n"
    )

    exact_file_match = (
        expected_text == actual_patched_text
    )

    # The actual change must match the exact proposal.
    passed = all([
        actual_modified == expected_modified,
        actual_added == expected_added,
        not actual_removed,
        exact_file_match,
    ])

    return {
        "passed": passed,
        "target_resource": {
            "file": target_key[0],
            "resource_type": target_key[1],
            "resource_name": target_key[2],
        },
        "expected_modified": describe_keys(expected_modified),
        "actual_modified": describe_keys(actual_modified),
        "unexpected_modified": describe_keys(unexpected_modified),
        "missing_expected_modified": describe_keys(
            missing_expected_modified
        ),
        "expected_added": describe_keys(expected_added),
        "actual_added": describe_keys(actual_added),
        "unexpected_added": describe_keys(unexpected_added),
        "missing_expected_added": describe_keys(
            missing_expected_added
        ),
        "removed_resources": describe_keys(actual_removed),
        "exact_target_file_match": exact_file_match,
    }
