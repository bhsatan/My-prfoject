"""Optional AI explainer with PII redaction (disabled by default)."""

from secscan.ai_explainer.explainer import AIExplainer, cli_confirm_payload
from secscan.ai_explainer.provider import (
    API_KEY_ENV_VAR,
    AIProvider,
    AIProviderError,
    get_api_key_from_env,
)
from secscan.ai_explainer.redactor import Redactor

__all__ = [
    "API_KEY_ENV_VAR",
    "AIExplainer",
    "AIProvider",
    "AIProviderError",
    "Redactor",
    "cli_confirm_payload",
    "get_api_key_from_env",
]
