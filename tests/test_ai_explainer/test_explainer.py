"""Tests for AIExplainer orchestrator and environment API key loading."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from secscan.ai_explainer.explainer import AIExplainer
from secscan.ai_explainer.provider import API_KEY_ENV_VAR, AIProvider, get_api_key_from_env
from secscan.ai_explainer.redactor import Redactor
from tests.conftest import make_finding


class _DummyProvider:
    provider_name = "dummy"

    def __init__(self) -> None:
        self.received_texts: list[str] = []

    def explain(self, redacted_text: str) -> str:
        self.received_texts.append(redacted_text)
        return "Plain-language explanation."


class TestGetApiKeyFromEnv:
    def test_returns_none_when_unset(self, monkeypatch) -> None:
        monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
        assert get_api_key_from_env() is None

    def test_returns_none_when_blank(self, monkeypatch) -> None:
        monkeypatch.setenv(API_KEY_ENV_VAR, "   ")
        assert get_api_key_from_env() is None

    def test_returns_key_when_set(self, monkeypatch) -> None:
        monkeypatch.setenv(API_KEY_ENV_VAR, "sk-test-12345")
        assert get_api_key_from_env() == "sk-test-12345"


class TestAIExplainer:
    def test_provider_implements_protocol(self) -> None:
        provider = _DummyProvider()
        assert isinstance(provider, AIProvider)

    def test_does_not_send_when_user_declines(self) -> None:
        provider = _DummyProvider()
        redactor = Redactor(usernames=["alice"], include_system_identity=False)
        explainer = AIExplainer(provider=provider, redactor=redactor)

        finding = make_finding(
            rule_id="NET-001",
            title="Risky port open",
            status="fail",
            detail="User alice exposed 192.168.1.10 on C:\\Users\\alice\\app.exe",
        )

        seen_payloads: list[str] = []

        def decline(payload: str) -> bool:
            seen_payloads.append(payload)
            return False

        result = explainer.explain_finding(finding, confirm_callback=decline)

        assert result is None
        assert provider.received_texts == []
        assert len(seen_payloads) == 1
        # Even the preview shown to the user is already redacted
        assert "alice" not in seen_payloads[0]
        assert "192.168.1.10" not in seen_payloads[0]

    def test_sends_only_redacted_payload_when_confirmed(self) -> None:
        provider = _DummyProvider()
        redactor = Redactor(
            usernames=["alice"],
            hostnames=["workstation-01"],
            include_system_identity=False,
        )
        explainer = AIExplainer(provider=provider, redactor=redactor)

        finding = make_finding(
            rule_id="SSH-001",
            title="SSH root login",
            status="fail",
            detail="Host workstation-01 at 10.0.0.99 allows alice via /home/alice/.ssh/config",
        )

        result = explainer.explain_finding(finding, confirm_callback=lambda _p: True)

        assert result == "Plain-language explanation."
        assert len(provider.received_texts) == 1
        sent = provider.received_texts[0]
        assert "alice" not in sent
        assert "workstation-01" not in sent
        assert "10.0.0.99" not in sent
        assert "/home/alice/.ssh/config" not in sent
        assert "[HOST-1]" in sent
        assert "[IP-1]" in sent
        assert "[PATH-1]" in sent

    def test_cli_ai_explain_off_by_default(self, capsys) -> None:
        from secscan.cli import main

        collector = MagicMock()
        collector.name = "firewall"
        collector.is_supported.return_value = True
        collector.get_facts.return_value = {
            "firewall": {"all_profiles_enabled": True, "detail": "All enabled."},
        }

        with (
            patch("secscan.cli.get_platform", return_value="windows"),
            patch("secscan.cli.get_all_collectors", return_value=[collector]),
        ):
            rc = main(["scan", "--yes"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "AI explainer" not in out

    def test_cli_ai_explain_without_key_reports_cleanly(self, monkeypatch, capsys) -> None:
        from secscan.cli import main

        monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
        collector = MagicMock()
        collector.name = "firewall"
        collector.is_supported.return_value = True
        collector.get_facts.return_value = {
            "firewall": {"all_profiles_enabled": True, "detail": "All enabled."},
        }

        with (
            patch("secscan.cli.get_platform", return_value="windows"),
            patch("secscan.cli.get_all_collectors", return_value=[collector]),
        ):
            rc = main(["scan", "--yes", "--ai-explain"])

        assert rc == 0
        out = capsys.readouterr().out
        assert API_KEY_ENV_VAR in out
