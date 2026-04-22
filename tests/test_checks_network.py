from __future__ import annotations

import unittest
from unittest.mock import patch

from controlguard.checks.network import run_sensitive_ports_check
from controlguard.models import ControlDefinition, ControlStatus, LabConfig


class NetworkChecksTests(unittest.TestCase):
    @patch("controlguard.checks.network._list_listening_connections")
    def test_sensitive_ports_ignore_loopback(self, mocked_connections) -> None:
        mocked_connections.return_value = [
            {"LocalAddress": "127.0.0.1", "LocalPort": 3389, "OwningProcess": 999, "ProcessName": "rdp"},
            {"LocalAddress": "10.0.0.5", "LocalPort": 445, "OwningProcess": 888, "ProcessName": "system"},
        ]
        control = ControlDefinition(
            id="ports",
            title="Ports",
            type="sensitive_ports_exposed",
            params={"ports": [3389, 445], "ignore_loopback": True},
        )

        result = run_sensitive_ports_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(len(result.evidence["findings"]), 1)
        self.assertEqual(result.evidence["findings"][0]["process_name"], "system")
        self.assertEqual(len(result.evidence["loopback_only"]), 1)
