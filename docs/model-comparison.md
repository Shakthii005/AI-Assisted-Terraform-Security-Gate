# Day 9 — AI Remediation Model Comparison

## 1. Objective

Compare Groq GPT-OSS 120B and Google Gemini 3.6 Flash across five predefined AWS Terraform security remediation scenarios.

Both models received identical remediation prompts for each paired experiment. Prompt SHA-256 fingerprints were compared to confirm input equivalence.

The objective was to evaluate whether AI-generated Terraform remediation proposals could pass independent security verification, while recording model generation latency and provider availability.

## 2. Models Evaluated

| Provider | Model |
|---|---|
| Groq | `openai/gpt-oss-120b` |
| Google | `gemini-3.6-flash` |

## 3. Evaluation Methodology

Each successfully generated proposal passed through the following verification pipeline:

1. AI response structure validation.
2. AI output security guard.
3. Checkov-specific remediation validation.
4. Isolated Terraform workspace patching.
5. Terraform formatting validation.
6. Terraform initialization and validation.
7. Full Checkov infrastructure rescan.
8. Target security finding resolution and regression comparison.
9. File-level and resource-level change verification.

The original Terraform infrastructure was not modified. Proposed changes were applied and evaluated in isolated temporary workspaces.

A proposal was accepted only when all nine verification conditions passed.

The final decision was:

`ACCEPTED_FOR_HUMAN_REVIEW`

This status indicates successful verification within the project's defined test scenarios. It does not constitute production deployment approval.

## 4. Experiment Results

Five AWS security scenarios were evaluated.

| Security scenario | Checkov ID | Groq | Gemini |
|---|---|---|---|
| Unrestricted SSH access | CKV_AWS_24 | Accepted | Accepted |
| EC2 IMDSv2 enforcement | CKV_AWS_79 | Accepted | Accepted |
| S3 KMS encryption | CKV_AWS_145 | Accepted | Accepted |
| RDS public accessibility | CKV_AWS_17 | Accepted | Generation failed — HTTP 503 |
| IAM least privilege | CKV_AWS_62 | Accepted | Accepted |

### 4.1 Quantitative Results

| Metric | Groq | Gemini |
|---|---:|---:|
| Evaluation attempts | 5 | 5 |
| Proposals generated | 5 | 4 |
| Accepted proposals | 5 | 4 |
| Generation failures | 0 | 1 |
| Acceptance among generated proposals | 100% | 100% |
| Generation success rate | 100% | 80% |
| Resolved Checkov finding identities | 13 | 12 |
| New Checkov finding identities | 0 | 0 |
| Average generation latency | 2,940.23 ms | 9,923.06 ms |

**Overall outcome:**

- Ten model requests were attempted.
- Nine remediation proposals were successfully generated.
- All nine generated proposals passed the project's independent verification pipeline.
- No new Checkov finding identities were introduced by the accepted proposals.

The successful verification rate is calculated only among proposals that were generated. The generation failure is reported separately.

## 5. Latency Comparison

The following averages were calculated from the recorded generation latency measurements.

### All successful generations

| Provider | Successful requests | Average latency |
|---|---:|---:|
| Groq | 5 | 2,940.23 ms |
| Gemini | 4 | 9,923.06 ms |

### Paired comparison

For a direct comparison, only the four scenarios where both providers successfully generated proposals were included.

| Provider | Average latency |
|---|---:|
| Groq | 2,952.24 ms |
| Gemini | 9,923.06 ms |

Groq was approximately 3.36 times faster than Gemini across these four paired experiments.

These measurements represent individual observed requests, not statistically conclusive performance benchmarks.

**Raw measurement evidence:**
[View latency-summary.csv](../eval/compliance-evidence/model-comparison/latency-summary.csv)

## 6. Gemini Provider Availability Issue

During the RDS public-access remediation experiment (`CKV_AWS_17`), Gemini returned:

`HTTP 503 UNAVAILABLE`

The provider's response indicated temporary service overload.

As a result:

- No Gemini remediation proposal was generated.
- Terraform verification was not performed for that