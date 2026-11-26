"""Tests for all collectors using mocked command output.

Every test mocks ``safe_run`` and/or file reads so tests run on **any OS**
without touching the real system.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import mock_open, patch

import pytest

from secscan.collectors.accounts import AccountsCollector
from secscan.collectors.antivirus import AntivirusCollector
from secscan.collectors.autologin import AutologinCollector
from secscan.collectors.base import get_platform, safe_run
from secscan.collectors.disk_encryption import DiskEncryptionCollector
from secscan.collectors.firewall import FirewallCollector
from secscan.collectors.network import NetworkCollector
from secscan.collectors.password_policy import PasswordPolicyCollector
from secscan.collectors.remote_access import RemoteAccessCollector
from secscan.collectors.ssh import SSHCollector

# ===================================================================
# Helper: mock safe_run
# ===================================================================


def _mock_safe_run(responses: dict[str, tuple[str, str, int]]):
    """Return a side_effect function for mocking safe_run.

    ``responses`` maps a substring of the command to ``(stdout, stderr, rc)``.
    If no substring matches, returns ``("", "mocked: not found", -1)``.
    """

    def _side_effect(args: list[str], **kwargs: Any) -> tuple[str, str, int]:
        cmd = " ".join(args)
        for key, response in responses.items():
            if key in cmd:
                return response
        return ("", "mocked: not found", -1)

    return _side_effect


# ===================================================================
# Firewall
# ===================================================================


class TestFirewallCollector:
    @patch("secscan.collectors.firewall.get_platform", return_value="windows")
    @patch("secscan.collectors.firewall.safe_run")
    def test_windows_all_enabled(self, mock_run, mock_plat):
        profiles = [
            {"Name": "Domain", "Enabled": True},
            {"Name": "Private", "Enabled": True},
            {"Name": "Public", "Enabled": True},
        ]
        mock_run.return_value = (json.dumps(profiles), "", 0)
        facts = FirewallCollector().get_facts()
        assert facts["firewall"]["all_profiles_enabled"] is True

    @patch("secscan.collectors.firewall.get_platform", return_value="windows")
    @patch("secscan.collectors.firewall.safe_run")
    def test_windows_one_disabled(self, mock_run, mock_plat):
        profiles = [
            {"Name": "Domain", "Enabled": True},
            {"Name": "Public", "Enabled": False},
        ]
        mock_run.return_value = (json.dumps(profiles), "", 0)
        facts = FirewallCollector().get_facts()
        assert facts["firewall"]["all_profiles_enabled"] is False
        assert "Public" in facts["firewall"]["detail"]

    @patch("secscan.collectors.firewall.get_platform", return_value="windows")
    @patch("secscan.collectors.firewall.safe_run")
    def test_windows_command_fails(self, mock_run, mock_plat):
        mock_run.return_value = ("", "access denied", 1)
        facts = FirewallCollector().get_facts()
        assert "error" in facts["firewall"]

    @patch("secscan.collectors.firewall.get_platform", return_value="linux")
    @patch("secscan.collectors.firewall.safe_run")
    def test_linux_ufw_active(self, mock_run, mock_plat):
        with patch("builtins.open", mock_open(read_data="ENABLED=yes\n")):
            facts = FirewallCollector().get_facts()
        assert facts["firewall"]["all_profiles_enabled"] is True
        assert facts["firewall"]["backend"] == "ufw"

    @patch("secscan.collectors.firewall.get_platform", return_value="linux")
    @patch("secscan.collectors.firewall.safe_run")
    def test_linux_no_firewall(self, mock_run, mock_plat):
        mock_run.return_value = ("inactive\n", "", 3)
        # Also mock file read for ufw.conf to not exist
        with patch("builtins.open", side_effect=OSError("No such file")):
            facts = FirewallCollector().get_facts()
        assert facts["firewall"]["all_profiles_enabled"] is False


# ===================================================================
# Disk Encryption
# ===================================================================


class TestDiskEncryptionCollector:
    @patch("secscan.collectors.disk_encryption.get_platform", return_value="windows")
    @patch("secscan.collectors.disk_encryption.safe_run")
    def test_windows_encrypted(self, mock_run, mock_plat):
        data = [{"MountPoint": "C:", "VolumeStatus": 1, "ProtectionStatus": 1}]
        mock_run.return_value = (json.dumps(data), "", 0)
        facts = DiskEncryptionCollector().get_facts()
        assert facts["disk_encryption"]["os_drive_encrypted"] is True

    @patch("secscan.collectors.disk_encryption.get_platform", return_value="windows")
    @patch("secscan.collectors.disk_encryption.safe_run")
    def test_windows_needs_admin(self, mock_run, mock_plat):
        mock_run.return_value = ("", "access denied", 1)
        facts = DiskEncryptionCollector().get_facts()
        assert facts["disk_encryption"]["os_drive_encrypted"] is None
        assert "administrator" in facts["disk_encryption"]["error"].lower()

    @patch("secscan.collectors.disk_encryption.get_platform", return_value="linux")
    @patch("secscan.collectors.disk_encryption.safe_run")
    def test_linux_luks_detected(self, mock_run, mock_plat):
        lsblk_data = {
            "blockdevices": [
                {
                    "name": "sda",
                    "type": "disk",
                    "fstype": None,
                    "children": [
                        {"name": "sda1", "type": "part", "fstype": "crypto_LUKS"},
                    ],
                },
            ],
        }
        mock_run.return_value = (json.dumps(lsblk_data), "", 0)
        facts = DiskEncryptionCollector().get_facts()
        assert facts["disk_encryption"]["os_drive_encrypted"] is True

    @patch("secscan.collectors.disk_encryption.get_platform", return_value="linux")
    @patch("secscan.collectors.disk_encryption.safe_run")
    def test_linux_no_encryption(self, mock_run, mock_plat):
        lsblk_data = {
            "blockdevices": [
                {"name": "sda", "type": "disk", "fstype": "ext4"},
            ],
        }
        mock_run.return_value = (json.dumps(lsblk_data), "", 0)
        with patch("builtins.open", side_effect=OSError):
            facts = DiskEncryptionCollector().get_facts()
        assert facts["disk_encryption"]["os_drive_encrypted"] is False


# ===================================================================
# Antivirus
# ===================================================================


class TestAntivirusCollector:
    @patch("secscan.collectors.antivirus.safe_run")
    def test_defender_active(self, mock_run):
        data = {
            "AMServiceEnabled": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "AntispywareEnabled": True,
            "AntivirusSignatureLastUpdated": "2024-01-15",
        }
        mock_run.return_value = (json.dumps(data), "", 0)
        facts = AntivirusCollector().get_facts()
        assert facts["antivirus"]["real_time_enabled"] is True

    @patch("secscan.collectors.antivirus.safe_run")
    def test_defender_disabled(self, mock_run):
        data = {"RealTimeProtectionEnabled": False, "AMServiceEnabled": False}
        mock_run.return_value = (json.dumps(data), "", 0)
        facts = AntivirusCollector().get_facts()
        assert facts["antivirus"]["real_time_enabled"] is False

    @patch("secscan.collectors.antivirus.safe_run")
    def test_command_fails(self, mock_run):
        mock_run.return_value = ("", "not recognized", 1)
        facts = AntivirusCollector().get_facts()
        assert "error" in facts["antivirus"]


# ===================================================================
# Network (Listening Ports)
# ===================================================================


class TestNetworkCollector:
    @patch("secscan.collectors.network.get_platform", return_value="windows")
    @patch("secscan.collectors.network.safe_run")
    def test_windows_no_risky_ports(self, mock_run, mock_plat):
        data = [
            {"LocalAddress": "127.0.0.1", "LocalPort": 5432, "OwningProcess": 100},
        ]
        mock_run.return_value = (json.dumps(data), "", 0)
        facts = NetworkCollector().get_facts()
        assert facts["network"]["has_risky_ports"] is False

    @patch("secscan.collectors.network.get_platform", return_value="windows")
    @patch("secscan.collectors.network.safe_run")
    def test_windows_risky_port_exposed(self, mock_run, mock_plat):
        data = [
            {"LocalAddress": "0.0.0.0", "LocalPort": 445, "OwningProcess": 4},  # noqa: S104
            {"LocalAddress": "127.0.0.1", "LocalPort": 8080, "OwningProcess": 200},
        ]
        mock_run.return_value = (json.dumps(data), "", 0)
        facts = NetworkCollector().get_facts()
        assert facts["network"]["has_risky_ports"] is True
        assert 445 in facts["network"]["risky_ports_exposed"]

    @patch("secscan.collectors.network.get_platform", return_value="linux")
    @patch("secscan.collectors.network.safe_run")
    def test_linux_ss_output(self, mock_run, mock_plat):
        ss_output = (
            "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
            "LISTEN 0      128    0.0.0.0:22           0.0.0.0:*\n"
            "LISTEN 0      5      127.0.0.1:5432       0.0.0.0:*\n"
        )
        mock_run.return_value = (ss_output, "", 0)
        facts = NetworkCollector().get_facts()
        # Port 22 is not in _RISKY_PORTS
        assert facts["network"]["has_risky_ports"] is False
        assert len(facts["network"]["listening_ports"]) == 2


# ===================================================================
# Accounts
# ===================================================================


class TestAccountsCollector:
    @patch("secscan.collectors.accounts.get_platform", return_value="windows")
    @patch("secscan.collectors.accounts.safe_run")
    def test_windows_guest_disabled(self, mock_run, mock_plat):
        guest_data = json.dumps({"Name": "Guest", "Enabled": False})
        admin_data = json.dumps([{"Name": "Admin", "ObjectClass": "User"}])
        mock_run.side_effect = _mock_safe_run(
            {
                "Guest": (guest_data, "", 0),
                "Administrators": (admin_data, "", 0),
            }
        )
        facts = AccountsCollector().get_facts()
        assert facts["accounts"]["guest_enabled"] is False
        assert facts["accounts"]["admin_count"] == 1

    @patch("secscan.collectors.accounts.get_platform", return_value="linux")
    def test_linux_reads_passwd_group(self, mock_plat):
        passwd = "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000::/home/john:/bin/bash\n"  # noqa: S105
        group = "sudo:x:27:john\nwheel:x:10:\n"

        def mock_open_fn(path, **kwargs):
            if "passwd" in str(path):
                return mock_open(read_data=passwd)()
            if "group" in str(path):
                return mock_open(read_data=group)()
            raise OSError("not found")

        with patch("builtins.open", side_effect=mock_open_fn):
            facts = AccountsCollector().get_facts()
        assert facts["accounts"]["guest_enabled"] is False
        assert facts["accounts"]["admin_count"] == 1
        assert "john" in facts["accounts"]["admin_users"]


# ===================================================================
# Password Policy
# ===================================================================


class TestPasswordPolicyCollector:
    @patch("secscan.collectors.password_policy.get_platform", return_value="windows")
    @patch("secscan.collectors.password_policy.safe_run")
    def test_windows_parses_net_accounts(self, mock_run, mock_plat):
        output = (
            "Force user logoff how long after time expires?:       Never\n"
            "Minimum password age (days):                          0\n"
            "Maximum password age (days):                          42\n"
            "Minimum password length:                              8\n"
            "Length of password history maintained:                 None\n"
            "Lockout threshold:                                    5\n"
            "Lockout duration (minutes):                           30\n"
            "Lockout observation window (minutes):                 30\n"
        )
        mock_run.return_value = (output, "", 0)
        facts = PasswordPolicyCollector().get_facts()
        assert facts["password_policy"]["min_length"] == 8
        assert facts["password_policy"]["lockout_threshold"] == 5

    @patch("secscan.collectors.password_policy.get_platform", return_value="windows")
    @patch("secscan.collectors.password_policy.safe_run")
    def test_windows_lockout_never(self, mock_run, mock_plat):
        output = (
            "Minimum password length:                              0\n"
            "Lockout threshold:                                    Never\n"
        )
        mock_run.return_value = (output, "", 0)
        facts = PasswordPolicyCollector().get_facts()
        assert facts["password_policy"]["lockout_threshold"] == 0


# ===================================================================
# SSH
# ===================================================================


class TestSSHCollector:
    @patch("secscan.collectors.ssh.safe_run")
    def test_root_login_disabled(self, mock_run):
        mock_run.side_effect = _mock_safe_run({"sshd": ("active\n", "", 0)})
        config = "PermitRootLogin no\nPasswordAuthentication no\n"

        with (
            patch.object(Path, "is_dir", return_value=False),
            patch("builtins.open", mock_open(read_data=config)),
        ):
            facts = SSHCollector().get_facts()
        assert facts["ssh"]["permit_root_login"] == "no"
        assert facts["ssh"]["password_auth_enabled"] is False
        assert facts["ssh"]["service_running"] is True

    @patch("secscan.collectors.ssh.safe_run")
    def test_defaults_when_not_configured(self, mock_run):
        mock_run.return_value = ("inactive\n", "", 3)
        config = "# Only comments\n"

        with (
            patch.object(Path, "is_dir", return_value=False),
            patch("builtins.open", mock_open(read_data=config)),
        ):
            facts = SSHCollector().get_facts()
        # Defaults: PermitRootLogin=prohibit-password, PasswordAuthentication=yes
        assert facts["ssh"]["permit_root_login"] == "prohibit-password"
        assert facts["ssh"]["password_auth_enabled"] is True

    @patch("secscan.collectors.ssh.safe_run")
    def test_config_unreadable(self, mock_run):
        mock_run.return_value = ("inactive\n", "", 3)

        with (
            patch.object(Path, "is_dir", return_value=False),
            patch("builtins.open", side_effect=OSError("Permission denied")),
        ):
            facts = SSHCollector().get_facts()
        # Unknown, rather than guessing the defaults
        assert "error" in facts["ssh"]


# ===================================================================
# Remote Access (RDP / SMBv1)
# ===================================================================


class TestRemoteAccessCollector:
    @patch("secscan.collectors.remote_access.safe_run")
    def test_rdp_disabled(self, mock_run):
        rdp_data = json.dumps({"fDenyTSConnections": 1})
        smb_data = json.dumps({"EnableSMB1Protocol": False})
        mock_run.side_effect = _mock_safe_run(
            {
                "fDenyTSConnections": (rdp_data, "", 0),
                "SmbServerConfiguration": (smb_data, "", 0),
            }
        )
        facts = RemoteAccessCollector().get_facts()
        assert facts["remote_access"]["rdp_enabled"] is False
        assert facts["remote_access"]["rdp_nla_required"] is True  # Safe when RDP off
        assert facts["remote_access"]["smb1_enabled"] is False

    @patch("secscan.collectors.remote_access.safe_run")
    def test_rdp_enabled_no_nla(self, mock_run):
        rdp_data = json.dumps({"fDenyTSConnections": 0})
        nla_data = json.dumps({"UserAuthentication": 0})
        smb_data = json.dumps({"EnableSMB1Protocol": False})
        mock_run.side_effect = _mock_safe_run(
            {
                "fDenyTSConnections": (rdp_data, "", 0),
                "UserAuthentication": (nla_data, "", 0),
                "SmbServerConfiguration": (smb_data, "", 0),
            }
        )
        facts = RemoteAccessCollector().get_facts()
        assert facts["remote_access"]["rdp_enabled"] is True
        assert facts["remote_access"]["rdp_nla_required"] is False

    @patch("secscan.collectors.remote_access.safe_run")
    def test_smb_needs_admin(self, mock_run):
        rdp_data = json.dumps({"fDenyTSConnections": 1})
        mock_run.side_effect = _mock_safe_run(
            {
                "fDenyTSConnections": (rdp_data, "", 0),
                "SmbServerConfiguration": ("", "access denied", 1),
            }
        )
        facts = RemoteAccessCollector().get_facts()
        assert facts["remote_access"]["smb1_enabled"] is None
        assert "administrator" in facts["remote_access"].get("smb1_error", "").lower()


# ===================================================================
# Autologin
# ===================================================================


class TestAutologinCollector:
    @patch("secscan.collectors.autologin.get_platform", return_value="windows")
    @patch("secscan.collectors.autologin.safe_run")
    def test_windows_autologin_off(self, mock_run, mock_plat):
        data = json.dumps({"AutoAdminLogon": "0"})
        mock_run.return_value = (data, "", 0)
        facts = AutologinCollector().get_facts()
        assert facts["autologin"]["enabled"] is False

    @patch("secscan.collectors.autologin.get_platform", return_value="windows")
    @patch("secscan.collectors.autologin.safe_run")
    def test_windows_autologin_on(self, mock_run, mock_plat):
        data = json.dumps({"AutoAdminLogon": "1"})
        mock_run.return_value = (data, "", 0)
        facts = AutologinCollector().get_facts()
        assert facts["autologin"]["enabled"] is True

    @patch("secscan.collectors.autologin.get_platform", return_value="linux")
    def test_linux_gdm_autologin(self, mock_plat):
        gdm_conf = "[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=testuser\n"

        def mock_open_fn(path, **kwargs):
            if "gdm3" in str(path):
                return mock_open(read_data=gdm_conf)()
            raise OSError

        with patch("builtins.open", side_effect=mock_open_fn):
            facts = AutologinCollector().get_facts()
        assert facts["autologin"]["enabled"] is True

    @patch("secscan.collectors.autologin.get_platform", return_value="linux")
    def test_linux_no_autologin(self, mock_plat):
        with patch("builtins.open", side_effect=OSError):
            facts = AutologinCollector().get_facts()
        assert facts["autologin"]["enabled"] is False

    @patch("secscan.collectors.autologin.get_platform", return_value="linux")
    def test_linux_lightdm_autologin(self, mock_plat):
        lightdm_conf = "[Seat:*]\nautologin-user=alice\n"

        def mock_open_fn(path, **kwargs):
            if "lightdm" in str(path):
                return mock_open(read_data=lightdm_conf)()
            raise OSError

        with patch("builtins.open", side_effect=mock_open_fn):
            facts = AutologinCollector().get_facts()
        assert facts["autologin"]["enabled"] is True


# ===================================================================
# Base utilities
# ===================================================================


class TestBaseUtilities:
    @patch("secscan.collectors.base.platform.system", return_value="Windows")
    def test_get_platform_windows(self, mock_sys):
        assert get_platform() == "windows"

    @patch("secscan.collectors.base.platform.system", return_value="Linux")
    def test_get_platform_linux(self, mock_sys):
        assert get_platform() == "linux"

    @patch("secscan.collectors.base.platform.system", return_value="Darwin")
    def test_get_platform_unsupported(self, mock_sys):
        with pytest.raises(RuntimeError, match="Unsupported"):
            get_platform()

    @patch("secscan.collectors.base.subprocess.run")
    def test_safe_run_success(self, mock_subprocess):
        mock_subprocess.return_value.stdout = "output"
        mock_subprocess.return_value.stderr = ""
        mock_subprocess.return_value.returncode = 0
        stdout, stderr, rc = safe_run(["echo", "test"])
        assert rc == 0
        assert stdout == "output"

    def test_safe_run_command_not_found(self):
        stdout, stderr, rc = safe_run(["__nonexistent_command_12345__"])
        assert rc == -1
        assert "not found" in stderr.lower()

    def test_collector_is_supported(self):
        c = FirewallCollector()
        assert c.is_supported("windows") is True
        assert c.is_supported("linux") is True
        assert c.is_supported("macos") is False

    def test_collector_dry_run_returns_list(self):
        """Every collector's dry_run_info returns a list of dicts."""
        from secscan.collectors import get_all_collectors

        for collector in get_all_collectors():
            info = collector.get_dry_run_info()
            assert isinstance(info, list)
            for item in info:
                assert isinstance(item, dict)
                assert "type" in item
                assert "detail" in item
