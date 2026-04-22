from __future__ import annotations

import unittest
from unittest.mock import patch

from controlguard.checks.linux import (
    run_linux_auditd_check,
    run_linux_firewall_check,
    run_linux_ssh_password_auth_disabled_check,
)
from controlguard.models import ControlDefinition, ControlStatus, LabConfig


class LinuxChecksTests(unittest.TestCase):
    @patch("controlguard.checks.linux._command_exists")
    @patch("controlguard.checks.linux.run_command")
    @patch("controlguard.checks.linux.ensure_linux")
    def test_linux_firewall_passes_for_active_ufw(
        self, mocked_ensure_linux, mocked_run_command, mocked_command_exists
    ) -> None:
        del mocked_ensure_linux
        mocked_command_exists.side_effect = lambda name: name == "ufw"
        mocked_run_command.return_value = "Status: active\n"
        control = ControlDefinition(id="linux-fw", title="Linux FW", type="linux_firewall_enabled")

        result = run_linux_firewall_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)
        self.assertEqual(result.evidence["provider"], "ufw")

    @patch("controlguard.checks.linux._command_exists")
    @patch("controlguard.checks.linux._systemctl_state")
    @patch("controlguard.checks.linux.ensure_linux")
    def test_linux_auditd_fails_when_disabled(
        self, mocked_ensure_linux, mocked_systemctl_state, mocked_command_exists
    ) -> None:
        del mocked_ensure_linux
        mocked_command_exists.return_value = True
        mocked_systemctl_state.side_effect = ["inactive", "disabled"]
        control = ControlDefinition(id="auditd", title="auditd", type="linux_auditd_running")

        result = run_linux_auditd_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)

    @patch("controlguard.checks.linux.ensure_linux")
    @patch("controlguard.checks.linux.Path.exists")
    @patch("controlguard.checks.linux.Path.read_text")
    def test_linux_ssh_password_auth_disabled_detects_enabled(
        self, mocked_read_text, mocked_exists, mocked_ensure_linux
    ) -> None:
        del mocked_ensure_linux
        mocked_exists.side_effect = lambda *args, **kwargs: True
        mocked_read_text.return_value = "PasswordAuthentication yes\n"
        control = ControlDefinition(id="ssh", title="ssh", type="linux_ssh_password_auth_disabled")

        result = run_linux_ssh_password_auth_disabled_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["effective"]["value"], "yes")
