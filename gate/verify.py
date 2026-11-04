
"""
Automated Terraform remediation verification engine.

Day 5: AI-Assisted Terraform Security Gate

Compares the original Checkov baseline against AI-patched
infrastructure and independently verifies the proposed fix.

No AWS resources are deployed.
"""

import argparse
import json
import re
import subprocess
from gate.finding_identity import (
    finding_key,
    normalize_file_path,
)
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gate.diff_guard import verify_resource_scope
from gate.extract import extract_resource
from gate.scanner import parse_checkov_report, run_checkov


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

BASELINE_PATH = ROOT / "eval" / "baseline.json"
INFRA_ROOT = ROOT / "infra"
WORK_ROOT = ROOT / "eval" / "work"
PROPOSALS_ROOT = ROOT / "eval" / "proposals"
REPORT_ROOT = ROOT / "eval" / "reports"


# ============================================================
# TERRAFORM COMMAND EXECUTION
# ============================================================

def run_terraform(
    command: list[str],
    working_directory: Path,
) -> dict[str, Any]:
    """Execute Terraform and capture its result."""

    try:
        result = subprocess.run(
            command,
            cwd=working_directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=300,
            shell=False,
        )

    except FileNotFoundError as exc:
        raise RuntimeError(
            "Terraform executable was not found. "
            "Check that Terraform is installed and available in PATH."
        ) from exc

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Terraform command timed out: {' '.join(command)}"
        ) from exc

    return {
        "command": " ".join(command),
        "return_code": result.returncode,
        "passed": result.returncode == 0,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }




def verify_target_finding(
    patched_report: dict[str, Any],
    check_id: str,
    resource: str,
) -> bool:
    """
    Confirm the exact target appears in passed_checks
    and does not appear in failed_checks.

    Merely disappearing from failed_checks is insufficient:
    a skipped or unscanned finding must not be accepted.
    """

    results = patched_report.get("results", {})

    if not isinstance(results, dict):
        return False

    passed_checks = results.get("passed_checks", [])
    failed_checks = results.get("failed_checks", [])

    if not isinstance(passed_checks, list):
        return False

    if not isinstance(failed_checks, list):
        return False

    target_passed = any(
        isinstance(item, dict)
        and item.get("check_id") == check_id
        and item.get("resource") == resource
        for item in passed_checks
    )

    target_failed = any(
        isinstance(item, dict)
        and item.get("check_id") == check_id
        and item.get("resource") == resource
        for item in failed_checks
    )

    return target_passed and not target_failed


def check_checkov_scan_complete(
    report: dict[str, Any],
) -> bool:
    """Reject incomplete Checkov scans with parsing errors."""

    summary = report.get("summary")

    if not isinstance(summary, dict):
        return False

    parsing_errors = summary.get("parsing_errors")

    if parsing_errors is None:
        return False

    try:
        return int(parsing_errors) == 0
    except (TypeError, ValueError):
        return False


# ============================================================
# TERRAFORM FILE COMPARISON
# ============================================================

def collect_terraform_files(
    directory: Path,
) -> dict[str, bytes]:
    """Collect Terraform source files, excluding generated artifacts."""

    directory = directory.resolve()

    if not directory.is_dir():
        raise FileNotFoundError(
            f"Terraform directory not found: {directory}"
        )

    files: dict[str, bytes] = {}

    for path in directory.rglob("*.tf"):

        if ".terraform" in path.parts:
            continue

        if ".git" in path.parts:
            continue

        relative_path = path.relative_to(
            directory
        ).as_posix()

        files[relative_path] = path.read_bytes()

    return files


def find_changed_terraform_files(
    original_directory: Path,
    patched_directory: Path,
) -> list[str]:
    """Identify added, modified and deleted Terraform files."""

    original_files = collect_terraform_files(
        original_directory
    )

    patched_files = collect_terraform_files(
        patched_directory
    )

    all_paths = set(original_files) | set(patched_files)

    changed = []

    for path in sorted(all_paths):

        if original_files.get(path) != patched_files.get(path):
            changed.append(path)

    return changed


# ============================================================
# SAFE PATH RESOLUTION
# ============================================================

def resolve_proposal_path(
    proposal_path: Path,
) -> Path:
    """Only permit proposal files inside eval/proposals/."""

    proposal_path = Path(proposal_path)

    if not proposal_path.is_absolute():
        proposal_path = ROOT / proposal_path

    proposal_path = proposal_path.resolve()

    proposals_root = PROPOSALS_ROOT.resolve()

    try:
        proposal_path.relative_to(proposals_root)
    except ValueError as exc:
        raise ValueError(
            "Proposal must be located inside eval/proposals/"
        ) from exc

    if not proposal_path.is_file():
        raise FileNotFoundError(
            f"Proposal file not found: {proposal_path}"
        )

    return proposal_path


def resolve_workspace_path(
    workspace: Path,
) -> Path:
    """Only permit temporary workspaces inside eval/work/."""

    workspace = Path(workspace)

    if not workspace.is_absolute():
        workspace = ROOT / workspace

    workspace = workspace.resolve()

    work_root = WORK_ROOT.resolve()

    try:
        workspace.relative_to(work_root)
    except ValueError as exc:
        raise ValueError(
            "Workspace must be located inside eval/work/"
        ) from exc

    if workspace == work_root:
        raise ValueError(
            "Workspace must be a trial subdirectory inside eval/work/"
        )

    return workspace


# ============================================================
# PROPOSAL LOADING
# ============================================================

def load_saved_proposal(
    proposal_path: Path,
    check_id: str,
    resource: str,
) -> dict[str, Any]:
    """Load and verify the saved AI proposal metadata."""

    saved = json.loads(
        proposal_path.read_text(encoding="utf-8")
    )

    if not isinstance(saved, dict):
        raise ValueError(
            "Saved proposal must be a JSON object"
        )

    if saved.get("check_id") != check_id:
        raise ValueError(
            "Proposal Checkov ID does not match requested finding"
        )

    if saved.get("resource") != resource:
        raise ValueError(
            "Proposal resource does not match requested resource"
        )

    if saved.get("status") != "PROPOSED_NOT_VERIFIED":
        raise ValueError(
            "Unexpected saved proposal status"
        )

    proposal = saved.get("proposal")

    if not isinstance(proposal, dict):
        raise ValueError(
            "Proposal content is missing"
        )

    patched_block = proposal.get("patched_block")
    additional_blocks = proposal.get("additional_blocks")
    explanation = proposal.get("explanation")

    if not isinstance(patched_block, str) or not patched_block.strip():
        raise ValueError(
            "Proposal patched_block is missing"
        )

    if not isinstance(additional_blocks, list):
        raise ValueError(
            "Proposal additional_blocks must be a list"
        )

    if not all(
        isinstance(block, str) and block.strip()
        for block in additional_blocks
    ):
        raise ValueError(
            "Invalid additional Terraform blocks"
        )

    if not isinstance(explanation, str) or not explanation.strip():
        raise ValueError(
            "Proposal explanation is missing"
        )

    return saved


# ============================================================
# MAIN VERIFICATION ENGINE
# ============================================================

def verify_trial(
    workspace: Path,
    check_id: str,
    resource: str,
    proposal_path: Path,
) -> dict[str, Any]:
    """
    Verify one AI-remediation trial.

    Acceptance requires:

    1. Terraform formatting passes.
    2. Terraform initialization passes.
    3. Terraform validation passes.
    4. Checkov scan completes without parsing errors.
    5. Target finding explicitly passes Checkov.
    6. No new Checkov finding identities appear.
    7. Only the intended Terraform file changes.
    8. Only the approved Terraform resource changes.
    9. Additional resources match the saved AI proposal.
    """

    # --------------------------------------------------------
    # 1. Resolve and validate paths
    # --------------------------------------------------------

    workspace = resolve_workspace_path(workspace)

    proposal_path = resolve_proposal_path(
        proposal_path
    )

    patched_infra = workspace / "infra"

    if not patched_infra.is_dir():
        raise FileNotFoundError(
            f"Patched Terraform directory not found: {patched_infra}"
        )

    if not INFRA_ROOT.is_dir():
        raise FileNotFoundError(
            f"Original Terraform directory not found: {INFRA_ROOT}"
        )

    # --------------------------------------------------------
    # 2. Load original baseline
    # --------------------------------------------------------

    if not BASELINE_PATH.is_file():
        raise FileNotFoundError(
            f"Original baseline not found: {BASELINE_PATH}"
        )

    baseline_report = json.loads(
        BASELINE_PATH.read_text(encoding="utf-8-sig")
    )

    baseline_findings = parse_checkov_report(
        baseline_report
    )

    baseline_keys = {
        finding_key(finding)
        for finding in baseline_findings
    }

    # --------------------------------------------------------
    # 3. Load and identify the exact target finding
    # --------------------------------------------------------

    target_matches = [
        finding
        for finding in baseline_findings
        if finding.check_id == check_id
        and finding.resource == resource
    ]

    if len(target_matches) != 1:
        raise ValueError(
            f"Expected exactly one baseline finding for "
            f"{check_id} / {resource}; found {len(target_matches)}"
        )

    target_finding = target_matches[0]

    target_key = finding_key(target_finding)

    extracted = extract_resource(
        target_finding,
        INFRA_ROOT,
        context_lines=0,
    )

    relative_target_file = extracted.file_path.relative_to(
        INFRA_ROOT.resolve()
    ).as_posix()

    # --------------------------------------------------------
    # 4. Load saved AI proposal
    # --------------------------------------------------------

    saved_proposal = load_saved_proposal(
        proposal_path,
        check_id,
        resource,
    )

    proposal = saved_proposal["proposal"]

    # --------------------------------------------------------
    # 5. Check Terraform formatting
    # --------------------------------------------------------

    print("\n[1/6] Checking Terraform formatting...")

    fmt_result = run_terraform(
        [
            "terraform",
            "fmt",
            "-check",
            "-recursive",
        ],
        patched_infra,
    )

    # --------------------------------------------------------
    # 6. Initialize Terraform
    # --------------------------------------------------------

    print("[2/6] Initializing temporary Terraform workspace...")

    init_result = run_terraform(
        [
            "terraform",
            "init",
            "-backend=false",
            "-input=false",
            "-no-color",
        ],
        patched_infra,
    )

    # --------------------------------------------------------
    # 7. Validate Terraform
    # --------------------------------------------------------

    print("[3/6] Validating Terraform configuration...")

    if init_result["passed"]:

        validate_result = run_terraform(
            [
                "terraform",
                "validate",
                "-no-color",
            ],
            patched_infra,
        )

    else:

        validate_result = {
            "command": "terraform validate",
            "return_code": None,
            "passed": False,
            "stdout": "",
            "stderr": (
                "Skipped because Terraform initialization failed."
            ),
        }

    # --------------------------------------------------------
    # 8. Run complete Checkov scan
    # --------------------------------------------------------

    print("[4/6] Running full Checkov scan...")

    patched_report = run_checkov(
        patched_infra
    )

    patched_findings = parse_checkov_report(
        patched_report
    )

    patched_keys = {
        finding_key(finding)
        for finding in patched_findings
    }

    scan_complete = check_checkov_scan_complete(
        patched_report
    )

    # --------------------------------------------------------
    # 9. Compare original and patched Checkov findings
    # --------------------------------------------------------

    resolved_keys = baseline_keys - patched_keys

    new_keys = patched_keys - baseline_keys

    target_resolved = (
        verify_target_finding(
            patched_report,
            check_id,
            resource,
        )
        and target_key not in patched_keys
    )

    # --------------------------------------------------------
    # 10. Check Terraform file-change scope
    # --------------------------------------------------------

    print("[5/6] Checking Terraform file-change scope...")

    changed_files = find_changed_terraform_files(
        INFRA_ROOT,
        patched_infra,
    )

    file_scope_passed = (
        changed_files == [relative_target_file]
    )

    # --------------------------------------------------------
    # 11. Check resource-level change scope
    # --------------------------------------------------------

    print("[6/6] Checking Terraform resource-level diff...")

    resource_scope_error = None

    try:

        resource_scope = verify_resource_scope(
            original_infra=INFRA_ROOT,
            patched_infra=patched_infra,
            target_file=relative_target_file,
            extracted=extracted,
            proposal=proposal,
        )

    except (ValueError, OSError) as exc:

        resource_scope_error = str(exc)

        resource_scope = {
            "passed": False,
            "error": resource_scope_error,
        }

    resource_scope_passed = resource_scope["passed"]

    combined_scope_passed = (
        file_scope_passed
        and resource_scope_passed
    )

    # --------------------------------------------------------
    # 12. Evaluate acceptance conditions
    # --------------------------------------------------------

    checks = {

        "terraform_format": fmt_result["passed"],

        "terraform_init": init_result["passed"],

        "terraform_validate": validate_result["passed"],

        "checkov_scan_complete": scan_complete,

        "target_finding_resolved": target_resolved,

        "no_new_checkov_findings": (
            scan_complete and len(new_keys) == 0
        ),

        "terraform_file_scope": file_scope_passed,

        "terraform_resource_scope": resource_scope_passed,

        "terraform_change_scope": combined_scope_passed,
    }

    accepted = all(checks.values())

    status = (
        "ACCEPTED_FOR_HUMAN_REVIEW"
        if accepted
        else "REJECTED"
    )

    # --------------------------------------------------------
    # 13. Build verification report
    # --------------------------------------------------------

    report = {

        "project": "AI-Assisted Terraform Security Gate",

        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "check_id": check_id,

        "resource": resource,

        "workspace": str(workspace),

        "proposal_path": str(proposal_path),

        "status": status,

        "checks": checks,

        "baseline": {
            "failed_findings": len(baseline_findings),
            "unique_finding_keys": len(baseline_keys),
        },

        "patched": {
            "failed_findings": len(patched_findings),
            "unique_finding_keys": len(patched_keys),
        },

        "resolved_findings": [
            {
                "check_id": key[0],
                "resource": key[1],
                "file_path": key[2],
            }
            for key in sorted(resolved_keys)
        ],

        "new_findings": [
            {
                "check_id": key[0],
                "resource": key[1],
                "file_path": key[2],
            }
            for key in sorted(new_keys)
        ],

        "target_finding_resolved": target_resolved,

        "changed_terraform_files": changed_files,

        "expected_changed_file": relative_target_file,

        "resource_diff": resource_scope,

        "terraform_commands": {
            "format": {
                "command": fmt_result["command"],
                "return_code": fmt_result["return_code"],
                "passed": fmt_result["passed"],
            },
            "init": {
                "command": init_result["command"],
                "return_code": init_result["return_code"],
                "passed": init_result["passed"],
            },
            "validate": {
                "command": validate_result["command"],
                "return_code": validate_result["return_code"],
                "passed": validate_result["passed"],
            },
        },
    }

    # --------------------------------------------------------
    # 14. Save verification evidence
    # --------------------------------------------------------

    REPORT_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_resource = re.sub(
        r"[^A-Za-z0-9_-]",
        "_",
        resource,
    )

    report_path = REPORT_ROOT / (
        f"verification_{check_id}_{safe_resource}.json"
    )

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # 15. Display final report
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("TERRAFORM REMEDIATION VERIFICATION REPORT")
    print("=" * 70)

    print(f"Target: {check_id}")
    print(f"Resource: {resource}")

    print("\nVERIFICATION CONDITIONS")

    for name, passed in checks.items():

        result = "PASSED" if passed else "FAILED"

        print(f"{name}: {result}")

    print("\nCHECKOV COMPARISON")

    print(f"Baseline findings: {len(baseline_findings)}")
    print(f"Patched findings:  {len(patched_findings)}")
    print(f"Resolved finding keys: {len(resolved_keys)}")
    print(f"New finding keys: {len(new_keys)}")

    print("\nCHANGED TERRAFORM FILES")

    for file in changed_files:
        print(f"  {file}")

    print("\nRESOURCE DIFF")

    print(
        "Resource-level scope:",
        "PASSED" if resource_scope_passed else "FAILED",
    )

    if resource_scope_error:
        print("Diff error:", resource_scope_error)

    print("\nFINAL DECISION:", status)

    print(f"Evidence saved: {report_path}")

    print("=" * 70)

    return report


# ============================================================
# COMMAND-LINE ENTRY POINT
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Independently verify an AI-generated "
            "Terraform remediation."
        )
    )

    parser.add_argument(
        "--workspace",
        required=True,
        help="Temporary workspace inside eval/work/",
    )

    parser.add_argument(
        "--check-id",
        required=True,
        help="Original Checkov finding ID",
    )

    parser.add_argument(
        "--resource",
        required=True,
        help="Target Terraform resource address",
    )

    parser.add_argument(
        "--proposal",
        required=True,
        help="Saved AI proposal JSON inside eval/proposals/",
    )

    args = parser.parse_args()

    try:

        verify_trial(
            workspace=Path(args.workspace),
            check_id=args.check_id,
            resource=args.resource,
            proposal_path=Path(args.proposal),
        )

    except (
        ValueError,
        RuntimeError,
        FileNotFoundError,
        OSError,
        json.JSONDecodeError,
    ) as exc:

        parser.exit(
            1,
            f"\nVerification error: {exc}\n",
        )


if __name__ == "__main__":
    main()
