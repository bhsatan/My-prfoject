"""Orchestrator for the optional AI explainer.

Ensures that:
1. Finding data is always redacted before leaving the machine.
2. The user sees the exact redacted payload and must confirm before sending.
3. No data is ever sent if the user declines.
"""

from __future__ import annotations

from collections.abc import Callable

from secscan.ai_explainer.provider import AIProvider
from secscan.ai_explainer.redactor import Redactor
from secscan.engine.models import Finding


def cli_confirm_payload(redacted_payload: str) -> bool:
    """Display the exact redacted payload and ask the user for confirmation."""
    print("\n--- Redacted payload to be sent to AI provider ---")
    print(redacted_payload)
    print("--- End of payload ---\n")
    try:
        answer = input("Send this redacted payload to the AI provider? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


class AIExplainer:
    """Coordinates redaction, explicit user confirmation, and AI explanation."""

    def __init__(self, provider: AIProvider, redactor: Redactor | None = None) -> None:
        self.provider = provider
        self.redactor = redactor or Redactor()

    @staticmethod
    def build_payload(finding: Finding) -> str:
        """Format a Finding into a plain-text summary for explanation."""
        steps = "\n".join(f"- {step}" for step in finding.how_to_fix) or "- (none)"
        return (
            f"Rule: {finding.rule_id} — {finding.title}\n"
            f"Status: {finding.status} (Severity: {finding.severity}, "
            f"Difficulty: {finding.difficulty})\n"
            f"Detail: {finding.detail}\n"
            f"Why it matters: {finding.why_it_matters}\n"
            f"How to fix:\n{steps}"
        )

    def explain_finding(
        self,
        finding: Finding,
        confirm_callback: Callable[[str], bool] = cli_confirm_payload,
    ) -> str | None:
        """Redact a finding, confirm with the user, and request an explanation.

        Returns ``None`` if the user declines confirmation; otherwise returns
        the provider's explanation string.
        """
        raw_payload = self.build_payload(finding)
        redacted_payload, _ = self.redactor.redact(raw_payload)

        if not confirm_callback(redacted_payload):
            return None

        return self.provider.explain(redacted_payload)
