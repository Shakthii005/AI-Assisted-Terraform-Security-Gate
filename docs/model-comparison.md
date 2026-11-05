
# Day 9 — AI Remediation Model Comparison

## Objective

Compare Groq GPT-OSS 120B and Google Gemini 3.6 Flash on five Terraform security remediation scenarios.

Both models received identical remediation prompts for each paired experiment.

## Evaluation methodology

Each successful proposal passed through the same security pipeline:

1. AI output structure validation.
2. AI output safety guard.
3. Checkov-specific remediation validation.
4. Isolated Terraform workspace patching.
5. Terraform formatting.
6. Terraform initialization and validation.
7. Full Checkov scan.
8. Target finding resolution.
9. Resource-level and file-level change verification.

Original Terraform infrastructure was not modified.

## Models

| Provider | Model |
|---|---|
| Groq | openai/gpt-oss-120b |
| Google | gemini-3.6-flash |

## Experiment results

| Security scenario | Groq | Gemini |
|---|---|---|
| SSH access (CKV_AWS_24) | Accepted | Accepted |
| EC2 IMDSv2 (CKV_AWS_79) | Accepted | Accepted |
| S3 KMS encryption (CKV_AWS_145) | Accepted | Accepted |
| RDS public access (CKV_AWS_17) | Accepted | Generation failed — HTTP 503 |
| IAM least privilege (CKV_AWS_62) | Accepted | Accepted |

## Quantitative results

| Metric | Groq | Gemini |
|---|---:|---:|
| Evaluation attempts | 5 | 5 |
| Proposals generated | 5 | 4 |
| Accepted proposals | 5 | 4 |
| Generation failures | 0 | 1 |
| Acceptance when generated | 100% | 100% |
| Generation success rate | 100% | 80% |
| Resolved Checkov finding identities | 13 | 12 |
| New finding identities | 0 | 0 |
| Average generation latency | 2940.23 ms | 9923.06 ms |

## Latency comparison

For the four scenarios where both models generated proposals:

- Groq average latency: approximately 2952.24 ms.
- Gemini average latency: approximately 9923.06 ms.
- Groq was approximately 3.36 times faster in these experiments.

These measurements are based on single runs and are not a statistically conclusive benchmark.

## Gemini availability issue

Gemini returned HTTP 503 UNAVAILABLE for the RDS remediation request.

Google's response indicated temporary service overload.

This is classified as a provider availability failure, not a rejected security remediation.

Earlier Gemini 3.8 Flash attempts also experienced HTTP 503 errors and are excluded from the five-case comparison.

## Important experimental limitations

- Only five security scenarios were evaluated.
- Each scenario was run once per model.
- Groq used temperature 0.2; Gemini used its default generation setting.
- Provider availability affected Gemini's completion rate.
- Terraform validation and Checkov verification were performed locally.
- ACCEPTED_FOR_HUMAN_REVIEW does not mean production deployment approval.
- No live AWS deployment was performed.

## Conclusion

Both models produced accepted remediations for every proposal successfully generated.

Groq demonstrated higher generation reliability and lower latency in this experiment.

Gemini demonstrated equivalent security verification results on its four successfully generated proposals.

The experiment demonstrates how AI-generated Terraform changes can be evaluated through independent security controls rather than relying solely on model-generated explanations.
