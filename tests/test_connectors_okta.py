from __future__ import annotations

import unittest
from unittest.mock import patch

from controlguard.checks.okta import run_okta_admin_mfa_check
from controlguard.connectors.okta import OktaClient, OktaSettings
from controlguard.models import ControlDefinition, ControlStatus, LabConfig


class OktaConnectorTests(unittest.TestCase):
    @patch("controlguard.connectors.okta._request_json")
    def test_okta_client_follows_next_link(self, mocked_request_json) -> None:
        mocked_request_json.side_effect = [
            (
                {
                    "value": [{"id": "1"}],
                    "_links": {"next": {"href": "https://example.okta.com/api/v1/iam/assignees/users?after=abc"}},
                },
                {},
            ),
            (
                {"value": [{"id": "2"}]},
                {},
            ),
        ]
        client = OktaClient(OktaSettings(okta_domain="https://example.okta.com", access_token="token"))

        users, auth_mode = client.list_admin_users()

        self.assertEqual(auth_mode, "oauth_access_token")
        self.assertEqual([user["id"] for user in users], ["1", "2"])

    def test_okta_settings_reads_api_token_env(self) -> None:
        settings = OktaSettings(okta_domain="https://example.okta.com", api_token_env="OKTA_TOKEN")
        with patch.dict("os.environ", {"OKTA_TOKEN": "secret"}, clear=True):
            header, auth_mode = settings.resolve_auth_header()
        self.assertEqual(header, "SSWS secret")
        self.assertEqual(auth_mode, "api_token")


class OktaControlTests(unittest.TestCase):
    @patch("controlguard.checks.okta.OktaClient.list_user_factors")
    @patch("controlguard.checks.okta.OktaClient.list_admin_users")
    def test_okta_admin_mfa_fails_for_admin_without_strong_factor(self, mocked_admins, mocked_factors) -> None:
        mocked_admins.return_value = ([{"id": "1", "profile": {"login": "admin@example.com"}}], "oauth_access_token")
        mocked_factors.return_value = [
            {"factorType": "sms", "status": "ACTIVE"},
        ]
        control = ControlDefinition(
            id="okta-admin-mfa",
            title="Okta admin MFA",
            type="okta_admin_mfa",
            params={"okta_domain": "https://example.okta.com", "access_token": "token"},
        )

        result = run_okta_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["non_compliant_admins"][0]["login"], "admin@example.com")

    @patch("controlguard.checks.okta.OktaClient.list_user_factors")
    @patch("controlguard.checks.okta.OktaClient.list_admin_users")
    def test_okta_admin_mfa_passes_for_webauthn(self, mocked_admins, mocked_factors) -> None:
        mocked_admins.return_value = ([{"id": "1", "profile": {"login": "admin@example.com"}}], "api_token")
        mocked_factors.return_value = [
            {"factorType": "webauthn", "status": "ACTIVE"},
        ]
        control = ControlDefinition(
            id="okta-admin-mfa",
            title="Okta admin MFA",
            type="okta_admin_mfa",
            params={"okta_domain": "https://example.okta.com", "api_token": "token"},
        )

        result = run_okta_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)
        self.assertEqual(result.evidence["compliant_admin_count"], 1)
