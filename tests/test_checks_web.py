from __future__ import annotations

import unittest
from unittest.mock import patch

from controlguard.checks.web import run_security_headers_check
from controlguard.models import ControlDefinition, ControlStatus, LabConfig


class WebChecksTests(unittest.TestCase):
    @patch("controlguard.checks.web._request_headers")
    def test_security_headers_detect_invalid_rule(self, mocked_request) -> None:
        mocked_request.return_value = {
            "request_method": "GET",
            "status_code": 200,
            "final_url": "https://demo.local",
            "headers": {
                "Strict-Transport-Security": "max-age=63072000",
                "X-Frame-Options": "ALLOWALL",
                "X-Content-Type-Options": "nosniff",
            },
        }
        control = ControlDefinition(
            id="headers",
            title="Headers",
            type="security_headers",
            params={
                "url": "https://demo.local",
                "required_headers": [
                    "strict-transport-security",
                    "x-content-type-options",
                    "x-frame-options",
                ],
                "header_rules": {
                    "x-frame-options": {"one_of": ["DENY", "SAMEORIGIN"]},
                    "x-content-type-options": "nosniff",
                },
            },
        )

        result = run_security_headers_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["invalid_headers"][0]["header"], "x-frame-options")
