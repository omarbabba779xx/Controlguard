from __future__ import annotations

import unittest
from unittest.mock import patch

from controlguard.checks.windows import (
    run_bitlocker_check,
    run_secure_boot_enabled_check,
    run_windows_defender_check,
    run_windows_event_log_check,
)
from controlguard.models import ControlDefinition, ControlStatus, LabConfig


class WindowsChecksTests(unittest.TestCase):
    @patch("controlguard.checks.windows.run_powershell_json")
    def test_event_log_accepts_numeric_service_states(self, mocked_run) -> None:
        mocked_run.return_value = {"Name": "EventLog", "Status": 4, "StartType": 2}
        control = ControlDefinition(id="event-log", title="Event Log", type="windows_event_log_running")

        result = run_windows_event_log_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)

    @patch("controlguard.checks.windows.run_powershell_json")
    def test_defender_control_detects_missing_protection(self, mocked_run) -> None:
        mocked_run.return_value = {
            "AMServiceEnabled": True,
            "AntivirusEnabled": False,
            "RealTimeProtectionEnabled": True,
        }
        control = ControlDefinition(id="defender", title="Defender", type="windows_defender_running")

        result = run_windows_defender_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertIn("AntivirusEnabled", result.evidence["failing_checks"])

    @patch("controlguard.checks.windows.run_powershell_json")
    def test_secure_boot_not_supported_is_not_applicable(self, mocked_run) -> None:
        mocked_run.return_value = {"Supported": False, "Enabled": None, "Error": "BIOS mode"}
        control = ControlDefinition(id="boot", title="Secure Boot", type="secure_boot_enabled")

        result = run_secure_boot_enabled_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.NOT_APPLICABLE)

    @patch("controlguard.checks.windows.run_powershell_json")
    def test_bitlocker_without_data_is_evidence_missing(self, mocked_run) -> None:
        mocked_run.return_value = None
        control = ControlDefinition(id="bitlocker", title="BitLocker", type="bitlocker_system_drive")

        result = run_bitlocker_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.EVIDENCE_MISSING)
