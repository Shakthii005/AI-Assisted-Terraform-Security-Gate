
"""
Temporary Terraform patcher.

Applies AI proposals to a separate infrastructure copy.
Restores locally redacted secrets.
Never modifies the original Terraform source.
"""

import argparse
import json
import re
import shutil

from pathlib import Path
from typing import Any

from gate.redaction import restore_redacted_assignments
from gate.extract import ExtractedResource, extract_resource
from gate.scanner import parse_checkov_report


ROOT = Path(__file__).resolve().parents[1]
WORK_ROOT = ROOT / "eval" / "work"


# Terraform resource declaration pattern.
RESOURCE_PATTERN = re.compile(
    r'^[ \t]*resource[ \t]+"([^"]+)"[ \t]+"([^"]+)"[ \t]*\{',
    re.MULTILINE,
)


def get_resource_identity(block: str) -> tuple[str, str]:
    """Extract Terraform resource type and name."""

    matches = list(RESOURCE_PATTERN.finditer(block))

    if len(matches) != 1:
        raise ValueError(
            "Expected exactly one Terraform resource declaration"
        )

    return matches[0].group(1), matches[0].group(2)


def validate_proposal_structure(
    proposal: dict[str, Any],
) -> None:
    """Validate the structure of the AI-generated proposal."""

    if not isinstance(proposal, dict):
        raise ValueError("Proposal must be a JSON object")

    patched_block = proposal.get("patched_block")
    additional_blocks = proposal.get("additional_blocks")
    explanation = proposal.get("explanation")

    if not isinstance(patched_block, str) or not patched_block.strip():
        raise ValueError("Invalid or empty patched_block")

    if not isinstance(additional_blocks, list):
        raise ValueError("additional_blocks must be a list")

    if not all(
        isinstance(block, str) and block.strip()
        for block in additional_blocks
    ):
        raise ValueError("Additional Terraform blocks must be non-empty strings")

    if not isinstance(explanation, str) or not explanation.strip():
        raise ValueError("Proposal explanation is missing")


def ensure_workspace_is_safe(
    source_root: Path,
    workspace: Path,
) -> None:
    """Ensure the workspace is inside eval/work and outside infra."""

    try:
        workspace.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise ValueError(
            "Workspace must be outside the original infrastructure directory"
        )

    try:
        workspace.relative_to(WORK_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(
            "Temporary workspace must be inside eval/work/"
        ) from exc


def apply_proposal_to_copy(
    infra_root: Path,
    extracted: ExtractedResource,
    proposal: dict[str, Any],
    workspace: Path,
) -> Path:
    """
    Copy infrastructure and apply an AI proposal.

    Steps:
    1. Validate proposal.
    2. Restore sensitive values locally.
    3. Verify resource identity.
    4. Copy original infrastructure.
    5. Replace exactly one resource block.
    6. Append permitted additional blocks.

    The original infrastructure is never modified.
    """

    # --------------------------------------------------------
    # 1. Resolve paths
    # --------------------------------------------------------

    source_root = infra_root.resolve()
    workspace = workspace.resolve()

    if not source_root.is_dir():
        raise FileNotFoundError(
            f"Infrastructure directory not found: {source_root}"
        )

    ensure_workspace_is_safe(
        source_root,
        workspace,
    )

    if workspace.exists():
        raise FileExistsError(
            f"Workspace already exists: {workspace}. "
            "Inspect or remove it before retrying."
        )

    # --------------------------------------------------------
    # 2. Validate proposal fields
    # --------------------------------------------------------

    validate_proposal_structure(proposal)

    # IMPORTANT:
    # First retrieve patched_block from proposal.
    patched_block = proposal["patched_block"]

    additional_blocks = proposal["additional_blocks"]
    explanation = proposal["explanation"]

    # --------------------------------------------------------
    # 3. Restore redacted secrets locally
    # --------------------------------------------------------

    patched_block = restore_redacted_assignments(
        patched_block,
        extracted.resource_block,
    )

    # Do not allow unresolved secret markers.
    if "__TFG_REDACTED_" in patched_block:
        raise ValueError(
            "Unresolved secret placeholder in patched resource"
        )

    if any(
        "__TFG_REDACTED_" in block
        for block in additional_blocks
    ):
        raise ValueError(
            "Secret placeholder found in additional Terraform blocks"
        )

    # --------------------------------------------------------
    # 4. Verify resource identity
    # --------------------------------------------------------

    original_identity = get_resource_identity(
        extracted.resource_block
    )

    proposed_identity = get_resource_identity(
        patched_block
    )

    if original_identity != proposed_identity:
        raise ValueError(
            "AI proposal changed the Terraform resource identity"
        )

    # --------------------------------------------------------
    # 5. Verify additional resource declarations
    # --------------------------------------------------------

    additional_identities = []

    for block in additional_blocks:

        identity = get_resource_identity(block)

        if identity in additional_identities:
            raise ValueError(
                f"Duplicate additional resource: {identity}"
            )

        if identity == original_identity:
            raise ValueError(
                "Additional block duplicates the target resource"
            )

        additional_identities.append(identity)

    # --------------------------------------------------------
    # 6. Resolve original Terraform file safely
    # --------------------------------------------------------

    original_file = extracted.file_path.resolve()

    try:
        relative_file = original_file.relative_to(source_root)
    except ValueError as exc:
        raise ValueError(
            "Extracted source file is outside infra/"
        ) from exc

    if not original_file.is_file():
        raise FileNotFoundError(
            f"Original Terraform file not found: {original_file}"
        )

    # --------------------------------------------------------
    # 7. Create temporary workspace
    # --------------------------------------------------------

    workspace.mkdir(
        parents=True,
        exist_ok=False,
    )

    copied_infra = workspace / "infra"

    try:

        # Exclude local artifacts and Terraform state.
        def ignore_terraform_artifacts(directory, names):

            ignored = []

            for name in names:

                if name in {
                    ".terraform",
                    "__pycache__",
                    ".pytest_cache",
                }:
                    ignored.append(name)

                elif (
                    name.endswith(".tfstate")
                    or ".tfstate." in name
                ):
                    ignored.append(name)

            return ignored

        shutil.copytree(
            source_root,
            copied_infra,
            ignore=ignore_terraform_artifacts,
        )

        copied_file = copied_infra / relative_file

        # ----------------------------------------------------
        # 8. Read original source
        # ----------------------------------------------------

        source_text = original_file.read_text(
            encoding="utf-8-sig"
        )

        # Ensure the extracted block matches exactly once.
        occurrences = source_text.count(
            extracted.resource_block
        )

        if occurrences != 1:
            raise ValueError(
                f"Expected exactly one original block match; "
                f"found {occurrences}"
            )

        # ----------------------------------------------------
        # 9. Replace original resource in temporary copy
        # ----------------------------------------------------

        patched_text = source_text.replace(
            extracted.resource_block,
            patched_block.rstrip(),
            1,
        )

        # ----------------------------------------------------
        # 10. Append additional Terraform resources
        # ----------------------------------------------------

        if additional_blocks:

            patched_text = (
                patched_text.rstrip("\r\n")
                + "\n\n"
                + "\n\n".join(
                    block.strip()
                    for block in additional_blocks
             )
             + "\n"
         )

        copied_file.write_text(
            patched_text,
            encoding="utf-8",
        )

        return copied_file

    except Exception:
        # Remove incomplete workspace if anything fails.
        shutil.rmtree(
            workspace,
            ignore_errors=True,
        )
        raise


def main() -> None:
    """Command-line entry point."""

    parser = argparse.ArgumentParser(
        description="Apply AI proposals to temporary Terraform copies."
    )

    parser.add_argument(
        "--proposal",
        required=True,
        help="Path to saved AI proposal JSON",
    )

    parser.add_argument(
        "--check-id",
        required=True,
        help="Checkov finding ID",
    )

    parser.add_argument(
        "--resource",
        required=True,
        help="Terraform resource address",
    )

    parser.add_argument(
        "--workspace",
        default=str(WORK_ROOT / "ssh_open_trial"),
        help="Temporary workspace inside eval/work/",
    )

    args = parser.parse_args()

    try:

        # ----------------------------------------------------
        # 1. Load saved proposal
        # ----------------------------------------------------

        proposal_path = Path(args.proposal)

        if not proposal_path.is_absolute():
            proposal_path = ROOT / proposal_path

        saved_proposal = json.loads(
            proposal_path.read_text(encoding="utf-8")
        )

        if not isinstance(saved_proposal, dict):
            raise ValueError("Saved proposal must be a JSON object")

        if saved_proposal.get("check_id") != args.check_id:
            raise ValueError("Proposal Checkov ID does not match")

        if saved_proposal.get("resource") != args.resource:
            raise ValueError("Proposal resource does not match")

        if saved_proposal.get("status") != "PROPOSED_NOT_VERIFIED":
            raise ValueError("Unexpected proposal status")

        # ----------------------------------------------------
        # 2. Load original Checkov baseline
        # ----------------------------------------------------

        baseline_path = ROOT / "eval" / "baseline.json"

        report = json.loads(
            baseline_path.read_text(encoding="utf-8-sig")
        )

        findings = parse_checkov_report(report)

        # ----------------------------------------------------
        # 3. Find exact security finding
        # ----------------------------------------------------

        matches = [
            finding
            for finding in findings
            if finding.check_id == args.check_id
            and finding.resource == args.resource
        ]

        if len(matches) != 1:
            raise RuntimeError(
                f"Expected exactly one matching finding, "
                f"found {len(matches)}"
            )

        finding = matches[0]

        # ----------------------------------------------------
        # 4. Extract original Terraform resource
        # ----------------------------------------------------

        extracted = extract_resource(
            finding,
            ROOT / "infra",
        )

        # ----------------------------------------------------
        # 5. Apply proposal to temporary copy
        # ----------------------------------------------------

        workspace = Path(args.workspace)

        if not workspace.is_absolute():
            workspace = ROOT / workspace

        patched_file = apply_proposal_to_copy(
            infra_root=ROOT / "infra",
            extracted=extracted,
            proposal=saved_proposal["proposal"],
            workspace=workspace,
        )

        # ----------------------------------------------------
        # 6. Display result
        # ----------------------------------------------------

        print("\nTEMPORARY PATCH CREATED")
        print("=" * 55)

        print(f"Original infrastructure: {ROOT / 'infra'}")
        print(f"Patched Terraform file: {patched_file}")

        print("\nOriginal Terraform source remains unchanged.")
        print("Restored secrets only exist in the local temporary copy.")

        print("\nStatus: PROPOSED_NOT_VERIFIED")

        print(f"\nAI explanation: {saved_proposal['proposal']['explanation']}")

    except (
        FileNotFoundError,
        FileExistsError,
        ValueError,
        RuntimeError,
        OSError,
        json.JSONDecodeError,
    ) as exc:

        parser.exit(
            1,
            f"\nPatcher error: {exc}\n",
        )


if __name__ == "__main__":
    main()
