
"""
Gemini client for AI-assisted Terraform remediation.

Day 9: Multi-model remediation evaluation.

Gemini only proposes Terraform patches.
It never edits files or executes commands.
"""

import json
import os
from pathlib import Path
from typing import Any

from google.genai import types
from dotenv import load_dotenv
from google import genai


PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(PROJECT_ROOT / ".env")


DEFAULT_MODEL = "gemini-3.8-flash"

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


def validate_gemini_response(
    result: Any,
) -> dict[str, Any]:
    """
    Independently validate Gemini's returned JSON.
    """

    if not isinstance(result, dict):
        raise ValueError(
            "Gemini response must be a JSON object"
        )

    required = {
        "patched_block",
        "additional_blocks",
        "explanation",
    }

    if set(result.keys()) != required:
        raise ValueError(
            "Gemini response has unexpected fields"
        )

    if not isinstance(result["patched_block"], str):
        raise ValueError(
            "patched_block must be a string"
        )

    if not isinstance(result["additional_blocks"], list):
        raise ValueError(
            "additional_blocks must be a list"
        )

    if not all(
        isinstance(block, str)
        for block in result["additional_blocks"]
    ):
        raise ValueError(
            "Every additional block must be a string"
        )

    if not isinstance(result["explanation"], str):
        raise ValueError(
            "explanation must be a string"
        )

    return result



def call_gemini_model(
    system: str,
    user: str,
    temperature: float | None = None,
) -> dict[str, Any]:
    """
    Send a remediation request to Gemini.

    Returns validated JSON containing:
    - patched_block
    - additional_blocks
    - explanation

    Gemini never modifies Terraform files directly.
    """

    if not system.strip() or not user.strip():
        raise ValueError(
            "System and user prompts cannot be empty"
        )

    if temperature is not None:
        raise ValueError(
            "Gemini 3.8 Flash does not support explicit temperature; omit it."
        )

    # --------------------------------------------------------
    # 1. Load API configuration
    # --------------------------------------------------------

    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is missing from the root .env file"
        )

    model = os.getenv(
        "GEMINI_MODEL",
        DEFAULT_MODEL,
    ).strip()

    if not model:
        raise ValueError(
            "GEMINI_MODEL cannot be empty"
        )

    # --------------------------------------------------------
    # 2. Initialize client with controlled retries
    # --------------------------------------------------------

    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            retry_options=types.HttpRetryOptions(
                attempts=3,
                initial_delay=1.0,
                max_delay=4.0,
                exp_base=2.0,
                jitter=1.0,
                http_status_codes=[500, 502, 503, 504],
            )
        ),
    )

    # --------------------------------------------------------
    # 3. Construct the common model prompt
    # --------------------------------------------------------

    combined_prompt = (
        "INSTRUCTIONS:\n"
        f"{system}\n\n"
        "TASK:\n"
        f"{user}"
    )

    # --------------------------------------------------------
    # 4. Send structured JSON request
    # --------------------------------------------------------

    try:
        response = client.models.generate_content(
            model=model,
            contents=combined_prompt,
            config={
                "max_output_tokens": 4096,
                "response_mime_type": "application/json",
                "response_json_schema": PATCH_SCHEMA,
            },
        )

    except Exception as exc:
        error_details = str(exc)

        error_details = error_details.replace(
            api_key,
            "[REDACTED]",
        )

        status_code = (
            getattr(exc, "code", None)
            or getattr(exc, "status_code", None)
        )

        raise RuntimeError(
            f"Gemini API request failed: "
            f"{type(exc).__name__}; "
            f"HTTP status: {status_code}; "
            f"Details: {error_details[:1000]}"
        ) from exc

    # --------------------------------------------------------
    # 5. Extract model response
    # --------------------------------------------------------

    content = response.text

    if not content:
        raise RuntimeError(
            "Gemini returned an empty response"
        )

    # --------------------------------------------------------
    # 6. Parse JSON
    # --------------------------------------------------------

    try:
        result = json.loads(content)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Gemini response was not valid JSON"
        ) from exc

    # --------------------------------------------------------
    # 7. Independently validate response
    # --------------------------------------------------------

    return validate_gemini_response(result)
