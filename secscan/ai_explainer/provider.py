"""Provider-agnostic interface for the optional AI explainer.

No real LLM provider is implemented in v0.1.  Any future provider must
implement :class:`AIProvider` and receive only redacted text after explicit
user confirmation.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

API_KEY_ENV_VAR = "SECSCAN_AI_API_KEY"


class AIProviderError(Exception):
    """Raised when an AI provider fails or is not configured."""


@runtime_checkable
class AIProvider(Protocol):
    """Protocol that any optional LLM backend must implement."""

    provider_name: str

    def explain(self, redacted_text: str) -> str:
        """Send redacted finding text to the LLM and return an explanation."""
        ...


def get_api_key_from_env(env_var: str = API_KEY_ENV_VAR) -> str | None:
    """Read the AI API key from the environment, never from files or code.

    Returns ``None`` if the variable is unset or empty.
    """
    value = os.environ.get(env_var, "").strip()
    return value or None
