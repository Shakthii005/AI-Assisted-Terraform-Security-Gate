
"""Configuration for the AI remediation engine."""

import os

from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    provider: str
    model: str
    api_key: str


def load_settings() -> Settings:

    provider = os.getenv("LLM_PROVIDER", "groq").strip().lower()
    model = os.getenv(
        "LLM_MODEL",
        "openai/gpt-oss-120b"
    ).strip()

    api_key = os.getenv("GROQ_API_KEY", "").strip()

    if provider != "groq":
        raise ValueError(
            f"Unsupported provider: {provider}"
        )

    if not model:
        raise ValueError("LLM_MODEL cannot be empty")

    if not api_key:
        raise ValueError(
            "GROQ_API_KEY is missing. Configure it in the root .env file."
        )

    return Settings(
        provider=provider,
        model=model,
        api_key=api_key,
    )
