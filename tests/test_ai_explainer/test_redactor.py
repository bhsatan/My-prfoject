"""Thorough unit tests for the PII redaction layer."""

from __future__ import annotations

from unittest.mock import patch

from secscan.ai_explainer.redactor import Redactor


class TestRedactorNetworkIdentifiers:
    def test_redacts_ipv4_addresses(self) -> None:
        r = Redactor(include_system_identity=False)
        text = "Listening on 192.168.1.42 and 10.0.0.5 (also 192.168.1.42)"
        redacted, mapping = r.redact(text)

        assert "192.168.1.42" not in redacted
        assert "10.0.0.5" not in redacted
        assert "[IP-1]" in redacted
        assert "[IP-2]" in redacted
        # Repeated IP reuses the same placeholder
        assert redacted.count("[IP-1]") == 2
        assert mapping["[IP-1]"] == "192.168.1.42"
        assert mapping["[IP-2]"] == "10.0.0.5"

    def test_redacts_ipv6_addresses(self) -> None:
        r = Redactor(include_system_identity=False)
        text = "Bound to fe80::1ff:fe23:4567:890a and ::1 and 2001:db8:85a3::8a2e:370:7334"
        redacted, mapping = r.redact(text)

        assert "fe80::1ff:fe23:4567:890a" not in redacted
        assert "::1" not in redacted
        assert "2001:db8:85a3::8a2e:370:7334" not in redacted
        assert len(mapping) == 3

    def test_redacts_mac_addresses(self) -> None:
        r = Redactor(include_system_identity=False)
        text = "NICs: 00:1A:2B:3C:4D:5E and aa-bb-cc-dd-ee-ff"
        redacted, mapping = r.redact(text)

        assert "00:1A:2B:3C:4D:5E" not in redacted
        assert "aa-bb-cc-dd-ee-ff" not in redacted
        assert "[MAC-1]" in redacted
        assert "[MAC-2]" in redacted
        assert mapping["[MAC-1]"] == "00:1A:2B:3C:4D:5E"
        assert mapping["[MAC-2]"] == "aa-bb-cc-dd-ee-ff"


class TestRedactorPaths:
    def test_redacts_windows_paths_and_unc(self) -> None:
        r = Redactor(include_system_identity=False)
        text = r"Check C:\Users\alice\Documents\secret.txt and \\fileserver\share\data.csv"
        redacted, mapping = r.redact(text)

        assert r"C:\Users\alice\Documents\secret.txt" not in redacted
        assert r"\\fileserver\share\data.csv" not in redacted
        assert "alice" not in redacted
        assert "[PATH-1]" in redacted
        assert "[PATH-2]" in redacted
        assert len(mapping) == 2

    def test_redacts_posix_paths(self) -> None:
        r = Redactor(include_system_identity=False)
        text = "Inspect /home/bob/.ssh/id_rsa and /etc/ssh/sshd_config"
        redacted, mapping = r.redact(text)

        assert "/home/bob/.ssh/id_rsa" not in redacted
        assert "/etc/ssh/sshd_config" not in redacted
        assert "bob" not in redacted
        assert "[PATH-1]" in redacted
        assert "[PATH-2]" in redacted

    def test_preserves_http_source_urls(self) -> None:
        r = Redactor(include_system_identity=False)
        text = "Source: https://learn.microsoft.com/en-us/windows/security/firewall"
        redacted, mapping = r.redact(text)

        assert "https://learn.microsoft.com/en-us/windows/security/firewall" in redacted
        assert mapping == {}


class TestRedactorIdentities:
    def test_redacts_domain_backslash_username(self) -> None:
        r = Redactor(include_system_identity=False)
        text = r"Admin members: CORP\alice, WORKSTATION\bob"
        redacted, mapping = r.redact(text)

        assert r"CORP\alice" not in redacted
        assert r"WORKSTATION\bob" not in redacted
        assert "[USER-1]" in redacted
        assert "[USER-2]" in redacted

    def test_redacts_explicit_usernames_and_hostnames_case_insensitive(self) -> None:
        r = Redactor(
            usernames=["Alice"],
            hostnames=["prod-web-01.corp.local"],
            include_system_identity=False,
        )
        text = "User alice logged into PROD-WEB-01.CORP.LOCAL"
        redacted, _ = r.redact(text)

        assert "alice" not in redacted.lower()
        assert "prod-web-01" not in redacted.lower()
        assert "[USER-1]" in redacted
        assert "[HOST-1]" in redacted

    @patch("secscan.ai_explainer.redactor.socket.gethostname", return_value="my-laptop.local")
    @patch("secscan.ai_explainer.redactor.getpass.getuser", return_value="jdoe")
    def test_auto_detects_system_identity(self, mock_user, mock_host) -> None:
        r = Redactor(include_system_identity=True)
        text = "Running on my-laptop as jdoe (short: my-laptop.local)"
        redacted, _ = r.redact(text)

        assert "jdoe" not in redacted
        assert "my-laptop" not in redacted
        assert "[USER-1]" in redacted
        assert "[HOST-1]" in redacted

    def test_empty_string_returns_empty(self) -> None:
        r = Redactor(include_system_identity=False)
        redacted, mapping = r.redact("")
        assert redacted == ""
        assert mapping == {}
