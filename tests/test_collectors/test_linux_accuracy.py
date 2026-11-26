"""Regression tests for false passes and false fails on Linux."""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest

from secscan.collectors.firewall import FirewallCollector
from secscan.collectors.network import NetworkCollector
from secscan.collectors.password_policy import PasswordPolicyCollector
from secscan.collectors.ssh import SSHCollector
from secscan.engine.evaluator import evaluate
from secscan.engine.loader import load_rules


def fake_files(files: dict[str, str]):
    """Patch ``open`` so that only the given paths exist."""

    def opener(path, *args, **kwargs):
        key = str(path).replace("\\", "/")
        if key not in files:
            raise OSError(f"No such file: {key}")
        return io.StringIO(files[key])

    return patch("builtins.open", side_effect=opener)


def password_facts(files: dict[str, str]) -> dict:
    with (
        patch("secscan.collectors.password_policy.get_platform", return_value="linux"),
        patch("secscan.collectors.password_policy.glob.glob", return_value=[]),
        fake_files(files),
    ):
        return PasswordPolicyCollector().get_facts()["password_policy"]


def ssh_facts(files: dict[str, str], included: list[str]) -> dict:
    with (
        patch("secscan.collectors.ssh.safe_run", return_value=("active\n", "", 0)),
        patch("secscan.collectors.ssh.glob.glob", return_value=included),
        fake_files(files),
    ):
        return SSHCollector().get_facts()["ssh"]


def test_ssh_first_value_wins_across_include():
    drop_in = "/etc/ssh/sshd_config.d/00-hardening.conf"
    facts = ssh_facts(
        {
            "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
            drop_in: "PermitRootLogin=no\n",
        },
        [drop_in],
    )
    assert facts["permit_root_login"] == "no"


def test_ssh_match_block_does_not_change_global_value():
    config = "PasswordAuthentication no\nMatch User bob\n  PermitRootLogin yes\n"
    facts = ssh_facts({"/etc/ssh/sshd_config": config}, [])
    assert facts["permit_root_login"] == "prohibit-password"
    assert facts["password_auth_enabled"] is False


@patch("secscan.collectors.firewall.get_platform", return_value="linux")
def test_ufw_service_active_but_disabled_is_not_a_pass(_plat):
    def run(args, **kwargs):
        return ("active\n", "", 0) if args[-1] == "ufw" else ("inactive\n", "", 3)

    with (
        patch("secscan.collectors.firewall.safe_run", side_effect=run),
        fake_files({"/etc/ufw/ufw.conf": "ENABLED=no\n"}),
    ):
        facts = FirewallCollector().get_facts()["firewall"]
    assert facts["all_profiles_enabled"] is False


def test_password_settings_read_from_conf_files():
    facts = password_facts(
        {
            "/etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3\n",
            "/etc/security/pwquality.conf": "minlen = 12\n",
            "/etc/pam.d/common-auth": (
                "auth required pam_faillock.so preauth\n"
                "auth [default=die] pam_faillock.so authfail\n"
            ),
            "/etc/security/faillock.conf": "deny = 5\n",
        }
    )
    assert facts["min_length"] == 12
    assert facts["lockout_threshold"] == 5


def test_commented_pam_lines_are_ignored():
    facts = password_facts(
        {
            "/etc/pam.d/common-password": (
                "# password requisite pam_pwquality.so minlen=20\n"
                "password [success=1 default=ignore] pam_unix.so obscure\n"
            ),
            "/etc/pam.d/common-auth": "# auth required pam_faillock.so authfail deny=5\n",
        }
    )
    assert facts["min_length"] == 6
    assert facts["lockout_threshold"] == 0


def test_unreadable_pam_is_unknown_not_fail():
    facts = password_facts({})
    assert facts["min_length"] is None
    assert facts["lockout_threshold"] is None


@pytest.mark.parametrize("local", ["*:21", "0.0.0.0%eth0:21"])
def test_wildcard_listeners_are_detected(local):
    output = f"State Recv-Q Send-Q Local Peer\nLISTEN 0 32 {local} *:*\n"
    with (
        patch("secscan.collectors.network.get_platform", return_value="linux"),
        patch("secscan.collectors.network.safe_run", return_value=(output, "", 0)),
    ):
        facts = NetworkCollector().get_facts()["network"]
    assert facts["risky_ports_exposed"] == [21]


def test_collector_error_message_reaches_finding():
    rules = [r for r in load_rules() if r.id == "SSH-001"]
    finding = evaluate(rules, {"ssh": {"error": "Cannot read config."}}, "linux")[0]
    assert finding.status == "unknown"
    assert "Cannot read config." in finding.detail


def test_source_matches_platform():
    rules = [r for r in load_rules() if r.id == "FW-001"]
    assert "ubuntu" in evaluate(rules, {}, "linux")[0].source
    assert "microsoft" in evaluate(rules, {}, "windows")[0].source
