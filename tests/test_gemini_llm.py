
import json
from types import SimpleNamespace

import pytest

from gate import gemini_llm


def valid_response():
    """Return a valid Gemini Terraform remediation response."""

    return {
        "patched_block": 'resource "aws_s3_bucket" "example" {}',
        "additional_blocks": [],
        "explanation": "Example remediation proposal.",
    }


# ============================================================
# RESPONSE VALIDATION TESTS
# ============================================================

def test_valid_gemini_response():
    result = valid_response()

    assert gemini_llm.validate_gemini_response(result) == result


def test_missing_response_field_is_rejected():
    result = valid_response()
    del result["explanation"]

    with pytest.raises(ValueError, match="unexpected fields"):
        gemini_llm.validate_gemini_response(result)


def test_extra_response_field_is_rejected():
    result = valid_response()
    result["unexpected"] = "value"

    with pytest.raises(ValueError, match="unexpected fields"):
        gemini_llm.validate_gemini_response(result)


def test_patched_block_must_be_string():
    result = valid_response()
    result["patched_block"] = 123

    with pytest.raises(ValueError, match="patched_block"):
        gemini_llm.validate_gemini_response(result)


def test_additional_blocks_must_be_list():
    result = valid_response()
    result["additional_blocks"] = "not-a-list"

    with pytest.raises(ValueError, match="additional_blocks"):
        gemini_llm.validate_gemini_response(result)


def test_additional_blocks_items_must_be_strings():
    result = valid_response()
    result["additional_blocks"] = [123]

    with pytest.raises(ValueError, match="Every additional block"):
        gemini_llm.validate_gemini_response(result)


def test_explanation_must_be_string():
    result = valid_response()
    result["explanation"] = None

    with pytest.raises(ValueError, match="explanation"):
        gemini_llm.validate_gemini_response(result)


def test_non_dictionary_response_is_rejected():
    with pytest.raises(ValueError, match="JSON object"):
        gemini_llm.validate_gemini_response("invalid")


# ============================================================
# INPUT VALIDATION TESTS
# ============================================================

def test_empty_prompts_are_rejected():
    with pytest.raises(ValueError, match="cannot be empty"):
        gemini_llm.call_gemini_model("", "task")


def test_explicit_temperature_is_rejected():
    with pytest.raises(
        ValueError,
        match="does not support explicit temperature",
    ):
        gemini_llm.call_gemini_model(
            "instructions",
            "task",
            temperature=2.5,
        )


def test_missing_api_key_is_rejected(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        gemini_llm.call_gemini_model(
            "instructions",
            "task",
        )


# ============================================================
# GEMINI CLIENT INTEGRATION TEST
# ============================================================

def test_gemini_request_uses_structured_json_output(monkeypatch):
    """
    Verify Gemini client configuration without making
    an actual API request.

    Checks:
    - API key handling
    - Retry configuration
    - Structured JSON response configuration
    - Model selection
    - Combined prompt construction
    """

    expected = valid_response()
    captured = {}

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")

    # Mock Gemini's generate_content method.
    def fake_generate_content(**kwargs):
        captured.update(kwargs)

        return SimpleNamespace(
            text=json.dumps(expected)
        )

    # Mock Gemini client.
    class FakeClient:

        def __init__(self, api_key, http_options=None):
            assert api_key == "test-key"

            captured["http_options"] = http_options

            self.models = SimpleNamespace(
                generate_content=fake_generate_content
            )

    monkeypatch.setattr(
        gemini_llm.genai,
        "Client",
        FakeClient,
    )

    # Execute the function FIRST.
    result = gemini_llm.call_gemini_model(
        "trusted instructions",
        "remediation task",
    )

    # --------------------------------------------------------
    # Verify response
    # --------------------------------------------------------

    assert result == expected

    # --------------------------------------------------------
    # Verify model configuration
    # --------------------------------------------------------

    assert captured["model"] == "test-model"

    # --------------------------------------------------------
    # Verify structured JSON configuration
    # --------------------------------------------------------

    config = captured["config"]

    assert config["response_mime_type"] == "application/json"

    assert (
        config["response_json_schema"]
        == gemini_llm.PATCH_SCHEMA
    )

    assert "temperature" not in config

    assert config["max_output_tokens"] == 4096

    # --------------------------------------------------------
    # Verify prompt construction
    # --------------------------------------------------------

    assert "INSTRUCTIONS:" in captured["contents"]

    assert "TASK:" in captured["contents"]

    assert "trusted instructions" in captured["contents"]

    assert "remediation task" in captured["contents"]

    # --------------------------------------------------------
    # Verify retry configuration
    # --------------------------------------------------------

    retry_options = captured["http_options"].retry_options

    assert retry_options.attempts == 3

    assert retry_options.initial_delay == 1.0

    assert retry_options.max_delay == 4.0

    assert retry_options.http_status_codes == [
        500,
        502,
        503,
        504,
    ]
