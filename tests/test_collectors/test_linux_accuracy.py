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


def fake_files(files: dict[str, str | Exception]):
    """Patch ``open`` so that only the given paths exist (or raise)."""

    def opener(path, *args, **kwargs):
        key = str(path).replace("\\", "/")
        if key not in files:
            raise FileNotFoundError(f"No such file: {key}")
        entry = files[key]
        if isinstance(entry, Exception):
            raise entry
        return io.StringIO(entry)

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


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ENABLED=yes # trailing comment\n", True),
        ("ENABLED=yes#x\n", False),
        ("ENABLED=no\n", False),
    ],
)
@patch("secscan.collectors.firewall.get_platform", return_value="linux")
def test_ufw_comment_handling(_plat, line, expected):
    with (
        patch("secscan.collectors.firewall.safe_run", return_value=("inactive\n", "", 3)),
        fake_files({"/etc/ufw/ufw.conf": line}),
    ):
        facts = FirewallCollector().get_facts()["firewall"]
    assert facts["all_profiles_enabled"] is expected


def test_faillock_custom_conf_argument():
    facts = password_facts(
        {
            "/etc/pam.d/common-auth": (
                "auth required pam_faillock.so preauth conf=/etc/security/custom.conf\n"
                "auth [default=die] pam_faillock.so authfail\n"
            ),
            "/etc/security/custom.conf": "deny = 4\n",
            "/etc/security/faillock.conf": "deny = 9\n",
        }
    )
    assert facts["lockout_threshold"] == 4


def test_pwquality_permission_error_is_unknown():
    facts = password_facts(
        {
            "/etc/pam.d/common-password": "password requisite pam_pwquality.so\n",
            "/etc/security/pwquality.conf": PermissionError("Access denied"),
        }
    )
    assert facts["min_length"] is None


def test_pwquality_enforcing_zero_falls_back_or_unknown():
    # Falls back to pam_unix when pam_pwquality is not enforcing
    facts_fallback = password_facts(
        {
            "/etc/pam.d/common-password": (
                "password requisite pam_pwquality.so enforcing=0 minlen=14\n"
                "password [success=1 default=ignore] pam_unix.so obscure\n"
            ),
        }
    )
    assert facts_fallback["min_length"] == 6

    # Reports unknown when no other enforced module exists
    facts_unknown = password_facts(
        {
            "/etc/pam.d/common-password": "password requisite pam_pwquality.so\n",
            "/etc/security/pwquality.conf": "enforcing = 0\nminlen = 14\n",
        }
    )
    assert facts_unknown["min_length"] is None


def test_pwquality_dropin_precedence():
    drop_in = "/etc/security/pwquality.conf.d/10-local.conf"
    with (
        patch("secscan.collectors.password_policy.get_platform", return_value="linux"),
        patch("secscan.collectors.password_policy.glob.glob", return_value=[drop_in]),
        fake_files(
            {
                "/etc/pam.d/common-password": "password requisite pam_pwquality.so\n",
                drop_in: "minlen = 10\n",
                "/etc/security/pwquality.conf": "minlen = 14\n",
            }
        ),
    ):
        facts = PasswordPolicyCollector().get_facts()["password_policy"]
    assert facts["min_length"] == 14


def test_ssh_match_override_returns_unknown():
    config = "PermitRootLogin no\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n"
    facts = ssh_facts({"/etc/ssh/sshd_config": config}, [])
    assert facts["permit_root_login"] is None


def test_ssh_include_quoted_space_and_unreadable_fails():
    quoted_file = "/etc/ssh/my dir/00-hardening.conf"
    extra_file = "/etc/ssh/extra.conf"
    with (
        patch("secscan.collectors.ssh.safe_run", return_value=("active\n", "", 0)),
        patch(
            "secscan.collectors.ssh.glob.glob",
            side_effect=[[quoted_file], [extra_file]],
        ),
        fake_files(
            {
                "/etc/ssh/sshd_config": f'Include "{quoted_file}" {extra_file}\n',
                quoted_file: "PermitRootLogin no\n",
                extra_file: "PasswordAuthentication no\n",
            }
        ),
    ):
        facts = SSHCollector().get_facts()["ssh"]
    assert facts["permit_root_login"] == "no"
    assert facts["password_auth_enabled"] is False

    # Unreadable include propagates as error
    with (
        patch("secscan.collectors.ssh.safe_run", return_value=("active\n", "", 0)),
        patch("secscan.collectors.ssh.glob.glob", return_value=[quoted_file]),
        fake_files(
            {
                "/etc/ssh/sshd_config": f'Include "{quoted_file}"\nPermitRootLogin no\n',
                quoted_file: PermissionError("Permission denied"),
            }
        ),
    ):
        facts_err = SSHCollector().get_facts()["ssh"]
    assert "error" in facts_err
