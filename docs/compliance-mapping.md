
# Cloud Security Compliance Mapping

## 1. Purpose

This document maps five implemented Terraform security remediation scenarios to selected AWS Security Hub CSPM controls and NIST SP 800-53 Revision 5 control references.

The purpose is to demonstrate traceability between:

- Terraform infrastructure security requirements
- Checkov security findings
- AWS security configuration controls
- NIST security control objectives
- Automated remediation and verification evidence

This document represents a limited technical control-alignment exercise. It is not a formal compliance assessment, certification, or attestation.

## 2. Frameworks and references

### CIS AWS Foundations Benchmark

The CIS AWS Foundations Benchmark provides secure configuration recommendations for AWS environments.

The CIS website currently lists AWS Foundations Benchmark 7.1.0.

Some version-specific CIS references below come from the related-requirements sections of AWS Security Hub documentation. These references include older benchmark versions.

This project does not claim that every mapping has been independently verified against CIS 7.1.0.

Official reference:
https://www.cisecurity.org/benchmark/amazon-web-services

### AWS Security Hub CSPM

AWS Security Hub CSPM provides resource-level security controls for identifying configurations that deviate from AWS security best practices.

This project uses the published Security Hub control descriptions as a practical mapping reference.

### NIST SP 800-53 Revision 5

NIST SP 800-53 provides a catalogue of security and privacy controls for information systems and organizations.

The controls referenced in this project include:

- AC-3: Access Enforcement
- AC-4: Information Flow Enforcement
- AC-6: Least Privilege
- SC-7: Boundary Protection
- SC-13: Cryptographic Protection
- SC-28: Protection of Information at Rest

Official reference:
https://csrc.nist.gov/pubs/sp/800/53/r5/final

## 3. Detailed control mapping

### 3.1 Unrestricted SSH access

**Checkov ID:** CKV_AWS_24

**Resource:** aws_security_group.ssh_open

**Security issue:**

The Terraform security group originally allowed SSH access from an unrestricted public source.

**Remediation:**

Remove the unrestricted SSH ingress rule.

**AWS Security Hub mapping:**

EC2.53 — EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports.

AWS reference:
https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html

**CIS references listed by AWS:**

- AWS Foundations Benchmark v5.0.0: 5.3
- AWS Foundations Benchmark v3.0.0: 5.2

**NIST alignment:**

SC-7 — Boundary Protection.

This is a conceptual alignment based on the objective of restricting unauthorized network communications. The AWS EC2.53 page does not list an explicit NIST cross-reference.

**Verification evidence:**

- SSH Checkov finding resolved.
- Terraform validation passed.
- No new Checkov findings.
- Resource-level change scope passed.

**Evaluation outcome:**

Groq: Accepted for human review.

Gemini: Accepted for human review.

### 3.2 EC2 Instance Metadata Service v2

**Checkov ID:** CKV_AWS_79

**Resource:** aws_instance.company_app

**Security issue:**

The EC2 instance originally allowed IMDSv1.

**Remediation:**

Require IMDSv2 by configuring:

http_tokens = "required"

**AWS Security Hub mapping:**

EC2.8 — EC2 instances should use Instance Metadata Service Version 2 (IMDSv2).

AWS reference:
https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html

**CIS references listed by AWS:**

- AWS Foundations Benchmark v5.0.0: 5.7
- AWS Foundations Benchmark v3.0.0: 5.6

**NIST alignment:**

- AC-3: Access Enforcement
- AC-3(7): Role-based Access Control
- AC-3(15): Discretionary and Mandatory Access Control
- AC-6: Least Privilege

These are related requirements listed in the AWS Security Hub EC2.8 control documentation.

**Verification evidence:**

- IMDSv2 finding resolved.
- Terraform validation passed.
- No new Checkov findings.
- Resource-level change scope passed.

**Evaluation outcome:**

Groq: Accepted for human review.

Gemini: Accepted for human review.

### 3.3 S3 KMS encryption

**Checkov ID:** CKV_AWS_145

**Resource:** aws_s3_bucket.company_data

**Security issue:**

The S3 bucket did not have the required AWS KMS-based default encryption configuration.

**Remediation:**

Create the separate S3 server-side encryption configuration resource.

Use:

sse_algorithm = "aws:kms"

The original bucket resource must be preserved.

**AWS Security Hub mapping:**

S3.17 — S3 general purpose buckets should be encrypted at rest with AWS KMS keys.

AWS reference:
https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html

**NIST alignment:**

- SC-13: Cryptographic Protection
- SC-28: Protection of Information at Rest
- SC-28(1): Protection of Information at Rest enhancement

These controls are included in the related requirements listed by AWS for S3.17.

**CIS mapping note:**

The AWS S3.17 control page does not list a CIS AWS Foundations Benchmark reference in its related-requirements section. No CIS control number is asserted here.

**Verification evidence:**

- S3 encryption finding resolved.
- Original bucket preserved.
- Terraform validation passed.
- No new Checkov findings.
- Additional-resource scope passed.

**Evaluation outcome:**

Groq: Accepted for human review.

Gemini: Accepted for human review.

### 3.4 RDS public accessibility

**Checkov ID:** CKV_AWS_17

**Resource:** aws_db_instance.company

**Security issue:**

The RDS database instance was configured as publicly accessible.

**Remediation:**

Set:

publicly_accessible = false

Preserve the existing database configuration and password redaction placeholder.

**AWS Security Hub mapping:**

RDS.2 — RDS DB instances should prohibit public access, as determined by the PubliclyAccessible configuration.

AWS reference:
https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html

**CIS references listed by AWS:**

- AWS Foundations Benchmark v5.0.0: 2.2.3
- AWS Foundations Benchmark v3.0.0: 2.3.3

**NIST alignment:**

- AC-4: Information Flow Enforcement
- AC-4(21): Physical or Logical Separation of Information Flows
- SC-7: Boundary Protection
- SC-7(11): Restrict Incoming Communications Traffic
- SC-7(16): Prevent Discovery of System Components

These are related requirements listed in the AWS RDS.2 control documentation.

**Verification evidence:**

Groq:
- RDS public access finding resolved.
- Terraform validation passed.
- No new Checkov findings.
- Resource-level scope passed.

Gemini:
- Generation failed with HTTP 503 UNAVAILABLE.
- No remediation proposal was generated.
- No Terraform or Checkov verification was performed.

This is classified as a provider availability failure, not a failed security remediation.

### 3.5 IAM least-privilege permissions

**Checkov ID:** CKV_AWS_62

**Resource:** aws_iam_policy.wildcard_admin

**Security issue:**

The original IAM policy granted unrestricted administrative permissions using wildcard actions and resources.

**Remediation:**

Replace unrestricted permissions with the approved laboratory permission:

Effect = "Allow"

Action = ["s3:GetObject"]

Resource = "arn:aws:s3:::company-internal-data/*"

**AWS Security Hub mapping:**

IAM.1 — IAM policies should not allow full "*" administrative privileges.

AWS reference:
https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html

**CIS references listed by AWS:**

- AWS Foundations Benchmark v1.2.0: 1.22
- AWS Foundations Benchmark v1.4.0: 1.16

**NIST alignment:**

- AC-2: Account Management
- AC-3: Access Enforcement
- AC-5: Separation of Duties
- AC-6: Least Privilege
- AC-6(2): Non-privileged Access for Nonsecurity Functions
- AC-6(3): Network Access to Privileged Commands
- AC-6(10): Prohibit Non-privileged Users from Executing Privileged Functions

These are related requirements listed by AWS for IAM.1.

**Verification evidence:**

- IAM administrative wildcard finding resolved.
- Nine finding identities resolved.
- Terraform validation passed.
- No new Checkov findings.
- Resource-level change scope passed.

**Evaluation outcome:**

Groq: Accepted for human review.

Gemini: Accepted for human review.

## 4. Consolidated evidence summary

| Checkov finding | AWS control | Groq | Gemini |
|---|---|---|---|
| CKV_AWS_24 | EC2.53 | Accepted | Accepted |
| CKV_AWS_79 | EC2.8 | Accepted | Accepted |
| CKV_AWS_145 | S3.17 | Accepted | Accepted |
| CKV_AWS_17 | RDS.2 | Accepted | HTTP 503 |
| CKV_AWS_62 | IAM.1 | Accepted | Accepted |

All nine successfully generated remediation proposals passed the project's independent verification requirements.

No new Checkov finding identities were introduced by the accepted proposals.

## 5. Evidence locations

The local evaluation evidence is available under:

eval/reports/model-comparison/

The aggregate model evaluation is available in:

eval/reports/model-comparison/day9-final-summary.json

eval/reports/model-comparison/day9-trials.csv

Individual Terraform and Checkov verification reports are saved under their corresponding run ID and model directories.

The evidence includes:

- Original Checkov finding identifiers.
- Terraform resource identity.
- Prompt fingerprints.
- Model and generation latency.
- Terraform formatting, initialization and validation results.
- Checkov finding comparisons.
- File and resource scope results.
- Final verification decision.

## 6. Compliance limitations

This project demonstrates technical alignment with selected AWS and NIST control objectives.

It does not establish full organizational compliance.

In particular:

1. Only five selected Terraform security scenarios are covered.
2. No deployed AWS environment was assessed.
3. Organizational access policies and procedures were not audited.
4. Continuous monitoring, incident response and audit processes were not implemented.
5. No formal NIST control assessment or authorization was performed.
6. The CIS references must be checked against the benchmark version formally adopted by an organization.
7. A successful Terraform and Checkov verification is not equivalent to an external audit or certification.

The project should therefore be described as a Terraform security automation and selected compliance-control alignment tool.

## 7. Conclusion

The AI-Assisted Terraform Security Gate demonstrates how infrastructure-as-code security controls can be linked to recognized AWS and NIST security objectives.

AI-generated remediation proposals are not trusted automatically. They must pass independent Terraform validation, Checkov scanning, and resource-level change verification.

The compliance mapping provides traceability between security findings, remediation decisions, and evidence produced by the automated gate.
