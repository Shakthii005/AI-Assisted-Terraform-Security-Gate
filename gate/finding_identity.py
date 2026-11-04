
"""
Shared Checkov finding identity.

Used by:
- Day 5: Remediation verification
- Day 8: Baseline-aware security enforcement

Line numbers are deliberately excluded from finding identity.
"""

import re


def normalize_file_path(file_path: str) -> str:
    """
    Normalize Windows, Linux and Terraform-root-relative paths.

    Examples:
        \\day2_compute_database.tf
        infra/day2_compute_database.tf
        /infra/day2_compute_database.tf
        D:/project/infra/day2_compute_database.tf

    All normalize to:
        day2_compute_database.tf
    """

    normalized = str(file_path or "").strip()
    normalized = normalized.replace("\\", "/")

    # Remove Windows drive letters.
    normalized = re.sub(
        r"^[A-Za-z]:",
        "",
        normalized,
    )

    # Remove empty and current-directory components.
    parts = [
        part
        for part in normalized.split("/")
        if part not in ("", ".")
    ]

    # Remove everything preceding the actual Terraform root.
    infra_positions = [
        index
        for index, part in enumerate(parts)
        if part.casefold() == "infra"
    ]

    if infra_positions:
        parts = parts[infra_positions[-1] + 1:]

    return "/".join(parts).casefold()


def finding_key(finding) -> tuple[str, str, str]:
    """
    Generate a stable Checkov finding identity.

    Identity consists of:
        Checkov ID
        Terraform resource address
        Normalized Terraform file path

    Line numbers, descriptions and severity are excluded.
    """

    return (
        str(finding.check_id or "").strip().upper(),
        str(finding.resource or "").strip(),
        normalize_file_path(finding.file_path),
    )
