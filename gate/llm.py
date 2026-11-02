
"""
LLM client for AI-assisted Terraform remediation.

Day 4: Groq integration.
The model only proposes patches; it never edits files.
"""

import json
from typing import Any

from groq import Groq

from gate.config import load_settings


PATCH_SCHEMA = {
    "type": "object",
    "properties": {
        "patched_block": {
            "type": "string"
        },
        "additional_blocks": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "explanation": {
            "type": "string"
        }
    },
    "required": [
        "patched_block",
        "additional_blocks",
        "explanation"
    ],
    "additionalProperties": False
}


def call_model(
    system: str,
    user: str,
    temperature: float = 0.5,
) -> dict[str, Any]:
    """
    Send a request to Groq and return validated JSON data.

    The function has no filesystem or shell access.
    It only communicates with the configured model.
    """

    if not system.strip() or not user.strip():
        raise ValueError("System and user prompts cannot be empty")

    if not 0.0 <= temperature <= 2.0:
        raise ValueError("Temperature must be between 0 and 2")

    settings = load_settings()

    client = Groq(
        api_key=settings.api_key,
        timeout=60.0,
        max_retries=1,
    )

    # GPT-OSS documentation recommends placing instructions
    # in the user message rather than a system message.
    combined_prompt = (
        "INSTRUCTIONS:\n"
        f"{system}\n\n"
        "TASK:\n"
        f"{user}"
    )

    try:
        response = client.chat.completions.create(
            model=settings.model,
            messages=[
                {
                    "role": "user",
                    "content": combined_prompt,
                }
            ],
            temperature=temperature,
            max_completion_tokens=4096,
            reasoning_effort="medium",
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "terraform_remediation",
                    "strict": True,
                    "schema": PATCH_SCHEMA,
                },
            },
        )

    except Exception as exc:
        raise RuntimeError(
            f"Groq API request failed: {type(exc).__name__}: {exc}"
        ) from exc

    if not response.choices:
        raise RuntimeError("Groq returned no completion choices")

    content = response.choices[0].message.content

    if not content:
        raise RuntimeError("Groq returned an empty response")

    try:
        result = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Groq response was not valid JSON"
        ) from exc

    # Independent application-side validation.
    if not isinstance(result, dict):
        raise ValueError("Model response must be a JSON object")

    required = {
        "patched_block",
        "additional_blocks",
        "explanation",
    }

    if set(result.keys()) != required:
        raise ValueError("Model response has unexpected fields")

    if not isinstance(result["patched_block"], str):
        raise ValueError("patched_block must be a string")

    if not isinstance(result["additional_blocks"], list):
        raise ValueError("additional_blocks must be a list")

    if not all(
        isinstance(block, str)
        for block in result["additional_blocks"]
    ):
        raise ValueError("Every additional block must be a string")

    if not isinstance(result["explanation"], str):
        raise ValueError("explanation must be a string")

    return result
