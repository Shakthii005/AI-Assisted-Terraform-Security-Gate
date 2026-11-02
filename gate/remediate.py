
"""
Generic AI Terraform remediation proposal generator.

Day 4: AI-Assisted Terraform Security Gate

The model proposes changes only.
Original infrastructure is never modified.
"""

import argparse
import json
import re

from pathlib import Path
from typing import Any

from gate.scanner import parse_checkov_report
from gate.extract import extract_resource
from gate.prompts import build_remediation_prompt
from gate.llm import call_model
from gate.redaction import redact_sensitive_assignments


ROOT = Path(__file__).resolve().parents[1]

BASELINE = ROOT / "eval" / "baseline.json"
INFRA = ROOT / "infra"


# ============================================================
# REMEDIATION INSTRUCTIONS
# ============================================================

REMEDIATION_INSTRUCTIONS = {

    # Experiment 1: Remove public SSH access.
    "CKV_AWS_24": """
Remove the entire SSH ingress rule from the specified
security group.

Do not replace it with another CIDR range.
No administrator IP range has been provided.

Preserve the resource name, VPC association and tags.

Update the description to:
SSH inbound access disabled.

Do not introduce public ingress.
Return the complete corrected resource block.
""",

    # Experiment 2: Require IMDSv2.
    "CKV_AWS_79": """
Fix the EC2 Instance Metadata Service configuration.

Inside metadata_options, set:

http_tokens = "required"

This requires IMDSv2 tokens and disables IMDSv1.

Preserve all other EC2 settings, including AMI,
instance type, subnet, security groups, storage settings
and tags.

Do not change unrelated security controls.
Return the complete corrected resource block.
""",

    # Experiment 3: Enable S3 KMS encryption.
    "CKV_AWS_145": """
Fix the S3 bucket's default server-side encryption.

Keep the existing aws_s3_bucket resource unchanged.

Create exactly one additional Terraform resource:

resource "aws_s3_bucket_server_side_encryption_configuration" "company_data" {
  bucket = aws_s3_bucket.company_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

Use the AWS-managed S3 KMS key by omitting
kms_master_key_id.

Do not create another KMS key.
Do not modify unrelated S3 settings.

Return the original bucket block unchanged and the
encryption resource in additional_blocks.
""",

    # Experiment 4: Disable public RDS accessibility.
    "CKV_AWS_17": """
Fix the public accessibility of the RDS database.

Set:

publicly_accessible = false

Preserve the existing resource identity and all unrelated
database configuration.

IMPORTANT:
The password value has been replaced by a redaction token.

Preserve the exact password placeholder, including
its spelling and capitalization.

Never invent, reveal, remove or modify the password.
Do not attempt to reconstruct the original value.

Do not add new resources.

Return the complete corrected RDS resource block.
""",

    # Experiment 5: Replace wildcard IAM permissions.
    "CKV_AWS_62": """
The existing IAM policy grants unrestricted administrative
permissions using Action = "*" and Resource = "*".

Replace these permissions with the following
laboratory least-privilege permission:

Effect   = "Allow"
Action   = ["s3:GetObject"]
Resource = "arn:aws:s3:::company-internal-data/*"

This permission is based on the existing S3 read permission
already demonstrated in the project's inline IAM policy.

Requirements:

1. Preserve the IAM policy resource name.
2. Preserve the policy description.
3. Preserve the Terraform resource identity.
4. Allow only s3:GetObject.
5. Allow access only to the specified S3 object ARN pattern.
6. Do not introduce wildcard actions.
7. Do not use Resource = "*".
8. Do not add any additional IAM permissions.
9. Do not add additional Terraform resources.

Return the complete corrected IAM policy resource.
"""
}


# ============================================================
# PROPOSAL VALIDATION
# ============================================================

def validate_proposal(
    finding,
    extracted,
    proposal: dict[str, Any],
) -> None:
    """
    Perform preliminary structural and security checks
    before an AI proposal is saved.
    """

    if not isinstance(proposal, dict):
        raise ValueError("AI proposal must be a JSON object")

    patched_block = proposal.get("patched_block")
    additional_blocks = proposal.get("additional_blocks")
    explanation = proposal.get("explanation")

    if not isinstance(patched_block, str) or not patched_block.strip():
        raise ValueError("patched_block is missing or empty")

    if not isinstance(additional_blocks, list):
        raise ValueError("additional_blocks must be a list")

    if not all(
        isinstance(block, str) and block.strip()
        for block in additional_blocks
    ):
        raise ValueError("Invalid additional Terraform block")

    if not isinstance(explanation, str) or not explanation.strip():
        raise ValueError("AI explanation is missing")

    # Check that the resource identity remains unchanged.
    parts = finding.resource.split(".")

    if len(parts) < 2:
        raise ValueError("Unsupported Terraform resource address")

    expected_header = (
        f'resource "{parts[-2]}" "{parts[-1]}"'
    )

    if not re.search(re.escape(expected_header), patched_block):
        raise ValueError(
            "AI proposal changed or omitted the target resource identity"
        )

    # --------------------------------------------------------
    # CKV_AWS_24: SSH remediation
    # --------------------------------------------------------

    if finding.check_id == "CKV_AWS_24":

        if re.search(r"\bingress\s*\{", patched_block):
            raise ValueError(
                "SSH remediation still contains an ingress block"
            )

        if "0.0.0.0/0" in patched_block:
            raise ValueError(
                "SSH remediation still contains public access"
            )

        if additional_blocks:
            raise ValueError(
                "Unexpected additional resources for SSH remediation"
            )

    # --------------------------------------------------------
    # CKV_AWS_79: EC2 IMDSv2 remediation
    # --------------------------------------------------------

    elif finding.check_id == "CKV_AWS_79":

        if not re.search(
            r'http_tokens\s*=\s*"required"',
            patched_block,
        ):
            raise ValueError(
                "EC2 remediation does not enforce IMDSv2"
            )

        if additional_blocks:
            raise ValueError(
                "Unexpected additional resources for EC2 remediation"
            )

    # --------------------------------------------------------
    # CKV_AWS_145: S3 KMS encryption
    # --------------------------------------------------------

    elif finding.check_id == "CKV_AWS_145":

        if patched_block.strip() != extracted.resource_block.strip():
            raise ValueError(
                "Original S3 bucket resource was unexpectedly modified"
            )

        if len(additional_blocks) != 1:
            raise ValueError(
                "Expected exactly one S3 encryption resource"
            )

        block = additional_blocks[0]

        expected_resource = (
            'resource "aws_s3_bucket_server_side_encryption_configuration" '
            '"company_data"'
        )

        if expected_resource not in block:
            raise ValueError(
                "Unexpected S3 encryption resource identity"
            )

        if not re.search(
            r'bucket\s*=\s*aws_s3_bucket\.company_data\.id\b',
            block,
        ):
            raise ValueError(
                "Encryption resource references the wrong bucket"
            )

        if not re.search(
            r'sse_algorithm\s*=\s*"aws:kms"',
            block,
        ):
            raise ValueError(
                "S3 KMS encryption is not configured"
            )

        if "kms_master_key_id" in block:
            raise ValueError(
                "Expected AWS-managed S3 KMS encryption"
            )

    # --------------------------------------------------------
    # CKV_AWS_17: RDS public accessibility
    # --------------------------------------------------------

    elif finding.check_id == "CKV_AWS_17":

        if not re.search(
            r'publicly_accessible\s*=\s*false',
            patched_block,
        ):
            raise ValueError(
                "RDS is still publicly accessible"
            )

        if additional_blocks:
            raise ValueError(
                "Unexpected additional resources for RDS remediation"
            )

        # Check that the original sensitive values were redacted.
        redacted_original = redact_sensitive_assignments(
            extracted.resource_block
        )

        original_markers = re.findall(
            r'"(__TFG_REDACTED_[A-Z0-9_]+__)"',
            redacted_original,
        )

        if not original_markers:
            raise ValueError(
                "Expected a sensitive-value redaction marker"
            )

        for marker in original_markers:

            if patched_block.count(f'"{marker}"') != 1:
                raise ValueError(
                    f"AI proposal removed or changed a "
                    f"sensitive placeholder: {marker}"
                )

    # --------------------------------------------------------
    # CKV_AWS_62: IAM least-privilege remediation
    # --------------------------------------------------------

    elif finding.check_id == "CKV_AWS_62":

        # Only one Action assignment is allowed.
        action_assignments = re.findall(
            r'\bAction\s*=\s*(\[[^\]]*\]|"[^"]*")',
            patched_block,
            re.DOTALL,
        )

        if len(action_assignments) != 1:
            raise ValueError(
                "Expected exactly one IAM Action assignment"
            )

        action_value = re.sub(
            r'[\[\]\s"]',
            "",
            action_assignments[0],
        )

        if action_value != "s3:GetObject":
            raise ValueError(
                "IAM policy contains permissions outside "
                "the approved s3:GetObject action"
            )

        # Only one Resource assignment is allowed.
        resource_assignments = re.findall(
            r'\bResource\s*=\s*(\[[^\]]*\]|"[^"]*")',
            patched_block,
            re.DOTALL,
        )

        if len(resource_assignments) != 1:
            raise ValueError(
                "Expected exactly one IAM Resource assignment"
            )

        resource_value = re.sub(
            r'[\[\]\s"]',
            "",
            resource_assignments[0],
        )

        expected_arn = "arn:aws:s3:::company-internal-data/*"

        if resource_value != expected_arn:
            raise ValueError(
                "IAM policy references an unapproved resource"
            )

        if additional_blocks:
            raise ValueError(
                "Unexpected additional resources for IAM remediation"
            )

    else:
        raise ValueError(
            f"No validation rules available for {finding.check_id}"
        )


# ============================================================
# MAIN REMEDIATION WORKFLOW
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description="Generate AI Terraform remediation proposals."
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
        "--output",
        required=True,
        help="Output JSON proposal path",
    )

    args = parser.parse_args()

    try:

        # 1. Load approved remediation guidance.
        guidance = REMEDIATION_INSTRUCTIONS.get(args.check_id)

        if guidance is None:
            raise ValueError(
                f"No approved experiment instructions for "
                f"{args.check_id}"
            )

        # 2. Load original Checkov baseline.
        if not BASELINE.exists():
            raise FileNotFoundError(
                f"Baseline not found: {BASELINE}"
            )

        report = json.loads(
            BASELINE.read_text(encoding="utf-8-sig")
        )

        findings = parse_checkov_report(report)

        # 3. Select the exact finding and resource.
        matches = [
            item
            for item in findings
            if item.check_id == args.check_id
            and item.resource == args.resource
        ]

        if len(matches) != 1:
            raise RuntimeError(
                f"Expected exactly one matching finding, "
                f"found {len(matches)}"
            )

        finding = matches[0]

        # 4. Extract the Terraform resource.
        extracted = extract_resource(
            finding,
            INFRA,
            context_lines=3,
        )

        # 5. Build the remediation prompt.
        system_prompt, user_prompt = build_remediation_prompt(
            finding,
            extracted,
        )

        user_prompt += (
            "\n\nREMEDIATION-SPECIFIC REQUIREMENTS:\n"
            + guidance
        )

        print(f"Finding: {finding.check_id}")
        print(f"Resource: {finding.resource}")
        print("Sending selected resource to Groq...")

        # 6. Request the AI proposal.
        proposal = call_model(
            system=system_prompt,
            user=user_prompt,
            temperature=0.2,
        )

        # 7. Validate the AI proposal.
        validate_proposal(
            finding,
            extracted,
            proposal,
        )

        # 8. Resolve output path.
        output_path = Path(args.output)

        if not output_path.is_absolute():
            output_path = ROOT / output_path

        output_path = output_path.resolve()

        proposals_dir = (
            ROOT / "eval" / "proposals"
        ).resolve()

        try:
            output_path.relative_to(proposals_dir)

        except ValueError as exc:
            raise ValueError(
                "Proposal output must be inside eval/proposals/"
            ) from exc

        # 9. Save the proposal separately.
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        saved_data = {
            "check_id": finding.check_id,
            "resource": finding.resource,
            "original_file": finding.file_path,
            "original_line_start": finding.line_start,
            "original_line_end": finding.line_end,
            "status": "PROPOSED_NOT_VERIFIED",
            "proposal": proposal,
        }

        output_path.write_text(
            json.dumps(saved_data, indent=2),
            encoding="utf-8",
        )

        # 10. Display result.
        print("\nAI REMEDIATION PROPOSAL")
        print("=" * 55)

        print(proposal["patched_block"])

        if proposal["additional_blocks"]:
            print("\nAdditional Terraform resources:")

            for block in proposal["additional_blocks"]:
                print(block)

        print("\nExplanation:")
        print(proposal["explanation"])

        print(f"\nSaved: {output_path}")
        print("Status: PROPOSED_NOT_VERIFIED")
        print("Original Terraform file remains unchanged.")

    except (
        ValueError,
        RuntimeError,
        FileNotFoundError,
        OSError,
        json.JSONDecodeError,
    ) as exc:

        parser.exit(
            1,
            f"\nRemediation error: {exc}\n",
        )


if __name__ == "__main__":
    main()
