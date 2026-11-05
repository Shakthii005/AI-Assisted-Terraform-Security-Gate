
"""
Multi-model evaluation for AI-Assisted Terraform Security Gate.

Day 9:
Compare Groq and Gemini using identical Terraform remediation inputs.

Every successful proposal passes through:
1. AI output safety validation.
2. Checkov-specific proposal validation.
3. Isolated Terraform workspace patching.
4. Independent Terraform and Checkov verification.

Original infrastructure is never modified.
"""

import argparse
import hashlib
import json
import os
import re
import time

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gate.config import load_settings
from gate.extract import extract_resource
from gate.gemini_llm import DEFAULT_MODEL, call_gemini_model
from gate.llm import call_model
from gate.output_guard import validate_ai_output
from gate.patcher import apply_proposal_to_copy
from gate.prompts import build_remediation_prompt
from gate.remediate import (
    BASELINE,
    INFRA,
    REMEDIATION_INSTRUCTIONS,
    validate_proposal,
)
from gate.scanner import parse_checkov_report
from gate.verify import verify_trial


ROOT = Path(__file__).resolve().parents[1]

PROPOSALS_ROOT = ROOT / "eval" / "proposals"
WORK_ROOT = ROOT / "eval" / "work"
REPORT_ROOT = ROOT / "eval" / "reports"

# Existing original proposal files provide the authoritative
# Checkov finding IDs and Terraform resource addresses.
CASE_FILES = {
    "CKV_AWS_24": "CKV_AWS_24_ssh_open.json",
    "CKV_AWS_79": "CKV_AWS_79_ec2_imdsv2.json",
    "CKV_AWS_145": "CKV_AWS_145_s3_encryption.json",
    "CKV_AWS_17": "CKV_AWS_17_rds_public_access.json",
    "CKV_AWS_62": "CKV_AWS_62_iam_least_privilege.json",
}


def safe_slug(value: str) -> str:
    """Convert an identifier into a filesystem-safe name."""

    return re.sub(
        r"[^A-Za-z0-9_-]",
        "_",
        value,
    )


def load_case_inputs(
    check_id: str,
) -> tuple[Any, Any, str, str, str]:
    """
    Reconstruct the original remediation input.

    Both models receive the same finding, extracted resource,
    system prompt and user prompt.
    """

    if check_id not in CASE_FILES:
        raise ValueError(f"Unsupported evaluation case: {check_id}")

    metadata_path = PROPOSALS_ROOT / CASE_FILES[check_id]

    if not metadata_path.is_file():
        raise FileNotFoundError(metadata_path)

    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )

    if metadata.get("check_id") != check_id:
        raise ValueError("Saved proposal metadata has an incorrect Checkov ID")

    resource = metadata.get("resource")

    if not isinstance(resource, str) or not resource.strip():
        raise ValueError("Saved proposal has no valid resource address")

    guidance = REMEDIATION_INSTRUCTIONS.get(check_id)

    if not guidance:
        raise ValueError(f"No approved remediation instructions for {check_id}")

    baseline_report = json.loads(
        BASELINE.read_text(encoding="utf-8-sig")
    )

    findings = parse_checkov_report(baseline_report)

    matches = [
        finding
        for finding in findings
        if finding.check_id == check_id
        and finding.resource == resource
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one baseline finding for "
            f"{check_id}/{resource}; found {len(matches)}"
        )

    finding = matches[0]

    extracted = extract_resource(
        finding,
        INFRA,
        context_lines=3,
    )

    system_prompt, user_prompt = build_remediation_prompt(
        finding,
        extracted,
    )

    user_prompt += (
        "\n\nREMEDIATION-SPECIFIC REQUIREMENTS:\n"
        + guidance
    )

    fingerprint = hashlib.sha256(
        (system_prompt + "\0" + user_prompt).encode("utf-8")
    ).hexdigest()

    return (
        finding,
        extracted,
        system_prompt,
        user_prompt,
        fingerprint,
    )


def model_information(model_name: str) -> str:
    """Return the configured model ID without exposing API keys."""

    if model_name == "groq":
        return load_settings().model

    if model_name == "gemini":
        return os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip()

    raise ValueError(f"Unsupported model: {model_name}")


def generate_proposal(
    model_name: str,
    system_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    """Call the selected provider using the identical prompt."""

    if model_name == "groq":
        return call_model(
            system=system_prompt,
            user=user_prompt,
            temperature=0.2,
        )

    if model_name == "gemini":
        return call_gemini_model(
            system=system_prompt,
            user=user_prompt,
        )

    raise ValueError(f"Unsupported model: {model_name}")


def save_proposal(
    run_id: str,
    model_name: str,
    finding: Any,
    proposal: dict[str, Any],
) -> Path:
    """Save a validated proposal in the approved proposal directory."""

    model_dir = (
        PROPOSALS_ROOT
        / "model-comparison"
        / run_id
        / model_name
    )

    model_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    filename = (
        f"{finding.check_id}_"
        f"{safe_slug(finding.resource)}.json"
    )

    proposal_path = model_dir / filename

    saved_data = {
        "check_id": finding.check_id,
        "resource": finding.resource,
        "original_file": str(finding.file_path),
        "original_line_start": finding.line_start,
        "original_line_end": finding.line_end,
        "status": "PROPOSED_NOT_VERIFIED",
        "model_provider": model_name,
        "proposal": proposal,
    }

    proposal_path.write_text(
        json.dumps(saved_data, indent=2),
        encoding="utf-8",
    )

    return proposal_path


def run_trial(
    run_id: str,
    model_name: str,
    check_id: str,
    prompts: tuple[Any, Any, str, str, str],
) -> dict[str, Any]:
    """Generate, validate, patch and independently verify one trial."""

    (
        finding,
        extracted,
        system_prompt,
        user_prompt,
        prompt_fingerprint,
    ) = prompts

    model_id = model_information(model_name)

    trial = {
        "run_id": run_id,
        "provider": model_name,
        "model": model_id,
        "check_id": check_id,
        "resource": finding.resource,
        "prompt_sha256": prompt_fingerprint,
        "generation_latency_ms": None,
        "proposal_validation": "NOT_RUN",
        "verification_status": "NOT_RUN",
        "status": "STARTED",
    }

    # --------------------------------------------------------
    # 1. Generate proposal
    # --------------------------------------------------------

    print(f"\nGenerating: {model_name} / {check_id}")

    started = time.perf_counter()

    try:
        proposal = generate_proposal(
            model_name,
            system_prompt,
            user_prompt,
        )

        trial["generation_latency_ms"] = round(
            (time.perf_counter() - started) * 1000,
            2,
        )

    except Exception as exc:
        trial.update({
            "status": "GENERATION_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        })

        return trial

    # --------------------------------------------------------
    # 2. Apply independent AI output validation
    # --------------------------------------------------------

    try:
        validate_ai_output(
            proposal,
            extracted.resource_block,
        )

        validate_proposal(
            finding,
            extracted,
            proposal,
        )

        trial["proposal_validation"] = "PASSED"

    except Exception as exc:
        trial.update({
            "status": "PROPOSAL_REJECTED",
            "proposal_validation": "FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        })

        return trial

    # --------------------------------------------------------
    # 3. Save validated proposal
    # --------------------------------------------------------

    proposal_path = save_proposal(
        run_id,
        model_name,
        finding,
        proposal,
    )

    trial["proposal_path"] = str(
        proposal_path.relative_to(ROOT)
    )

    # --------------------------------------------------------
    # 4. Apply to an isolated Terraform copy
    # --------------------------------------------------------

    workspace = (
        WORK_ROOT
        / "model-comparison"
        / run_id
        / model_name
        / f"{check_id}_{safe_slug(finding.resource)}"
    )

    try:
        apply_proposal_to_copy(
            infra_root=INFRA,
            extracted=extracted,
            proposal=proposal,
            workspace=workspace,
        )

    except Exception as exc:
        trial.update({
            "status": "PATCH_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        })

        return trial

    trial["workspace"] = str(
        workspace.relative_to(ROOT)
    )

    # --------------------------------------------------------
    # 5. Independent Terraform and Checkov verification
    # --------------------------------------------------------

    verification_path = (
        REPORT_ROOT
        / "model-comparison"
        / run_id
        / model_name
        / f"{check_id}_{safe_slug(finding.resource)}.json"
    )

    try:
        verification = verify_trial(
            workspace=workspace,
            check_id=check_id,
            resource=finding.resource,
            proposal_path=proposal_path,
            report_path=verification_path,
        )

        trial["verification_status"] = verification["status"]

        trial["checks"] = verification["checks"]

        trial["new_finding_count"] = len(
            verification["new_findings"]
        )

        trial["resolved_finding_count"] = len(
            verification["resolved_findings"]
        )

        trial["verification_report"] = str(
            verification_path.relative_to(ROOT)
        )

        trial["status"] = (
            "ACCEPTED_FOR_HUMAN_REVIEW"
            if verification["status"] == "ACCEPTED_FOR_HUMAN_REVIEW"
            else "VERIFICATION_REJECTED"
        )

    except Exception as exc:
        trial.update({
            "status": "VERIFICATION_ERROR",
            "error": f"{type(exc).__name__}: {exc}",
        })

    return trial


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare Groq and Gemini Terraform remediation quality."
    )

    parser.add_argument(
        "--case",
        choices=["all", *CASE_FILES.keys()],
        default="all",
    )

    parser.add_argument(
        "--model",
        choices=["groq", "gemini", "both"],
        default="gemini",
    )

    args = parser.parse_args()

    if args.model == "both":
        models = ["groq", "gemini"]
    else:
        models = [args.model]

    if args.case == "all":
        cases = list(CASE_FILES.keys())
    else:
        cases = [args.case]

    run_id = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    results = []

    print("=" * 65)
    print("AI TERRAFORM REMEDIATION MODEL EVALUATION")
    print("=" * 65)
    print("Run ID:", run_id)
    print("Cases:", len(cases))
    print("Models:", ", ".join(models))

    # Construct each original prompt once.
    # Both providers receive its identical content.
    prepared_inputs = {}

    for check_id in cases:
        prepared_inputs[check_id] = load_case_inputs(check_id)

    for check_id in cases:
        for model_name in models:

            result = run_trial(
                run_id=run_id,
                model_name=model_name,
                check_id=check_id,
                prompts=prepared_inputs[check_id],
            )

            results.append(result)

            print(
                f"Result: {result['status']} "
                f"| {model_name} | {check_id}"
            )

    # --------------------------------------------------------
    # Save aggregate evaluation evidence
    # --------------------------------------------------------

    summary = {
        "project": "AI-Assisted Terraform Security Gate",
        "evaluation": "Groq versus Gemini",
        "run_id": run_id,
        "cases": cases,
        "models": models,
        "total_trials": len(results),
        "accepted_trials": sum(
            item["status"] == "ACCEPTED_FOR_HUMAN_REVIEW"
            for item in results
        ),
        "results": results,
    }

    summary_dir = REPORT_ROOT / "model-comparison" / run_id

    summary_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path = summary_dir / "summary.json"

    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print("\n" + "=" * 65)
    print("MODEL EVALUATION SUMMARY")
    print("=" * 65)
    print("Total trials:", len(results))
    print("Accepted:", summary["accepted_trials"])
    print("Summary saved:", summary_path.relative_to(ROOT))


if __name__ == "__main__":
    main()
