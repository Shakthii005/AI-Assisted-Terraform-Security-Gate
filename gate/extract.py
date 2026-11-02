
"""
Terraform resource extraction module.

Day 4: AI-Assisted Terraform Security Gate

Extracts individual Terraform resource blocks identified
by Checkov findings, together with surrounding context.
"""

import ntpath
import re

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from gate.scanner import Finding


@dataclass
class ExtractedResource:
    """Represents an extracted Terraform resource."""

    file_path: Path
    resource: str
    start_line: int
    end_line: int
    resource_block: str
    context_before: str
    context_after: str


def resolve_finding_path(
    finding: Finding,
    infra_root: Path,
) -> Path:
    """
    Resolve a Checkov file path safely inside infra_root.

    Checkov may return paths such as:
        \\day2_compute_database.tf

    Absolute paths and path traversal outside infra_root
    are rejected.
    """

    root = infra_root.resolve()
    raw_path = finding.file_path.strip().replace("\\", "/")

    if not raw_path:
        raise ValueError("Finding does not contain a file path")

    drive, _ = ntpath.splitdrive(raw_path)

    if drive or raw_path.startswith("//"):
        candidate = Path(raw_path).resolve()
    else:
        relative_path = raw_path.lstrip("/")

        # Also support paths prefixed with the infra directory name.
        prefix = root.name + "/"

        if relative_path.lower().startswith(prefix.lower()):
            relative_path = relative_path[len(prefix):]

        parts = PurePosixPath(relative_path).parts
        candidate = (root.joinpath(*parts)).resolve()

    # Prevent directory traversal and symlink escapes.
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Finding path escapes the infrastructure directory: "
            f"{finding.file_path}"
        ) from exc

    if not candidate.is_file():
        raise FileNotFoundError(
            f"Terraform file not found: {candidate}"
        )

    if candidate.suffix.lower() != ".tf":
        raise ValueError("Only Terraform .tf files can be extracted")

    return candidate


def parse_resource_address(
    resource_address: str,
) -> tuple[str, str]:
    """
    Extract Terraform resource type and name.

    Example:
        aws_instance.company_app

    Returns:
        ("aws_instance", "company_app")
    """

    matches = re.findall(
        r"([A-Za-z_][A-Za-z0-9_-]*)\."
        r"([A-Za-z_][A-Za-z0-9_-]*)",
        resource_address,
    )

    if not matches:
        raise ValueError(
            f"Unsupported Terraform resource address: "
            f"{resource_address}"
        )

    # The final type.name pair supports addresses prefixed
    # with module paths.
    return matches[-1]


def find_matching_brace(
    source: str,
    opening_brace: int,
) -> int:
    """
    Find the closing brace matching an opening brace.

    Ignores braces inside quoted strings and comments.
    Supports Terraform #, // and /* */ comments.
    """

    depth = 0
    in_string = False
    escaped = False
    line_comment = False
    block_comment = False

    index = opening_brace

    while index < len(source):
        char = source[index]
        next_char = (
            source[index + 1]
            if index + 1 < len(source)
            else ""
        )

        if line_comment:
            if char == "\n":
                line_comment = False

        elif block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 1

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

            elif char == "#":
                line_comment = True

            elif char == "/" and next_char == "/":
                line_comment = True
                index += 1

            elif char == "/" and next_char == "*":
                block_comment = True
                index += 1

            elif char == "{":
                depth += 1

            elif char == "}":
                depth -= 1

                if depth == 0:
                    return index

                if depth < 0:
                    raise ValueError("Unexpected closing brace")

        index += 1

    raise ValueError("Terraform resource has an unclosed block")


def extract_resource(
    finding: Finding,
    infra_root: Path,
    context_lines: int = 3,
) -> ExtractedResource:
    """
    Extract one Terraform resource from a Checkov finding.

    The original Terraform file is opened read-only.
    No source file is modified.
    """

    if context_lines < 0:
        raise ValueError("context_lines cannot be negative")

    file_path = resolve_finding_path(
        finding,
        infra_root,
    )

    source = file_path.read_text(
        encoding="utf-8-sig"
    )

    resource_type, resource_name = parse_resource_address(
        finding.resource
    )

    resource_pattern = re.compile(
        r'^[ \t]*resource[ \t]+'
        r'"(?P<type>[^"]+)"[ \t]+'
        r'"(?P<name>[^"]+)"[ \t]*'
        r'\{',
        re.MULTILINE,
    )

    matches = []

    for match in resource_pattern.finditer(source):

        if (
            match.group("type") == resource_type
            and match.group("name") == resource_name
        ):
            matches.append(match)

    if len(matches) == 0:
        raise ValueError(
            f"Resource declaration not found: {finding.resource}"
        )

    if len(matches) > 1:
        raise ValueError(
            f"Multiple matching resource declarations found: "
            f"{finding.resource}. Manual disambiguation required."
        )

    match = matches[0]

    opening_brace = match.end() - 1

    closing_brace = find_matching_brace(
        source,
        opening_brace,
    )

    start_offset = match.start()
    end_offset = closing_brace + 1

    start_line = source.count(
        "\n", 0, start_offset
    ) + 1

    end_line = source.count(
        "\n", 0, end_offset
    ) + 1

    # Confirm Checkov's reported line range overlaps the resource.
    if finding.line_start is not None:
        reported_end = finding.line_end or finding.line_start

        if (
            finding.line_start > end_line
            or reported_end < start_line
        ):
            raise ValueError(
                "Checkov line range does not overlap the "
                "matched Terraform resource"
            )

    lines = source.splitlines()

    before_start = max(
        0,
        start_line - 1 - context_lines,
    )

    after_end = min(
        len(lines),
        end_line + context_lines,
    )

    context_before = "\n".join(
        lines[before_start:start_line - 1]
    )

    context_after = "\n".join(
        lines[end_line:after_end]
    )

    resource_block = source[
        start_offset:end_offset
    ]

    return ExtractedResource(
        file_path=file_path,
        resource=f"{resource_type}.{resource_name}",
        start_line=start_line,
        end_line=end_line,
        resource_block=resource_block,
        context_before=context_before,
        context_after=context_after,
    )


def format_extraction(
    extracted: ExtractedResource,
) -> str:
    """Produce a readable representation of the extraction."""

    return (
        f"File: {extracted.file_path}\n"
        f"Resource: {extracted.resource}\n"
        f"Lines: {extracted.start_line}-{extracted.end_line}\n\n"
        f"Context before:\n{extracted.context_before}\n\n"
        f"Resource block:\n{extracted.resource_block}\n\n"
        f"Context after:\n{extracted.context_after}"
    )
