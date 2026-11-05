# Day 9 — AI Remediation Model Comparison

## 1. Objective

Compare Groq GPT-OSS 120B and Google Gemini 3.6 Flash across five predefined AWS Terraform security remediation scenarios.

Both models received identical remediation prompts for each paired experiment.

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
- Terraform verification was not performed for that attempt.
- Checkov verification was not performed for that attempt.
- The result was classified as a provider availability failure, not a rejected security remediation.

## 7. Important Experimental Limitations

The results must be interpreted within the scope of the experiment.

1. Only five predefined Terraform security scenarios were evaluated.
2. Each scenario was executed once per provider.
3. The remediation prompts were prescriptive and included task-specific security requirements.
4. Individual security checks used experiment-specific validation rules.
5. Groq used temperature 0.2, while Gemini was called without an explicit temperature setting.
6. Provider availability affected Gemini's generation success rate.
7. Terraform and Checkov verification of individual AI proposals was performed locally.
8. No live AWS deployment or runtime security assessment was conducted.
9. `ACCEPTED_FOR_HUMAN_REVIEW` does not establish that a proposal is production-ready.

An important distinction is that the 100% acceptance rate among successfully generated proposals demonstrates that the verification pipeline accepted the proposed changes for these predefined scenarios.

It does not establish that either model can independently discover optimal security configurations or safely remediate arbitrary Terraform infrastructure.

The highly prescriptive prompts and task-specific validators constrain the remediation space. Broader testing with less prescriptive prompts, more complex infrastructure and repeated trials would be needed to evaluate general model remediation capability.

## 8. Interpretation

**Groq GPT-OSS 120B**

Groq successfully generated all five proposals and achieved a 100% acceptance rate among generated proposals. It also recorded lower generation latency in these experiments.

**Google Gemini 3.6 Flash**

Gemini generated four proposals, and all four passed independent verification. Its fifth request failed because of provider service unavailability.

**Comparative conclusion**

Both models produced proposals that passed the project's defined security verification requirements whenever generation succeeded.

Groq demonstrated higher observed generation availability and lower latency in this experiment. Gemini achieved equivalent verification outcomes across its four successfully generated proposals.

These results should not be interpreted as proof of universal model superiority.

## 9. Evidence and Reproducibility

Sanitized verification evidence is committed under:

`eval/compliance-evidence/model-comparison/`

The directory contains:

- Groq verification reports.
- Gemini verification reports.
- Gemini RDS generation-failure evidence.
- Recorded latency measurements.

The aggregate model evaluation measurements are available in:

`eval/compliance-evidence/model-comparison/latency-summary.csv`

The compliance evidence register is available in:

`eval/compliance-evidence/control-mapping.csv`

The original detailed evaluation reports remain in the locally generated and Git-ignored evaluation workspace.

## 10. Conclusion

This experiment demonstrates a controlled approach to evaluating AI-generated Terraform security remediation.

Rather than relying on the model's explanation or confidence, every generated proposal was subjected to independent application-side validation, Terraform checks, Checkov rescanning and resource-level change verification.

The results show that AI can assist with predefined infrastructure security remediation tasks when its outputs are constrained and independently verified.

The main contribution is not simply the use of multiple AI models. It is the security verification architecture that evaluates their proposed infrastructure changes before accepting them for human review.

**AI proposes. Deterministic security controls verify. Humans approve.**
