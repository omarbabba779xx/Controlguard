from __future__ import annotations

import unittest
from unittest.mock import patch

from controlguard.checks.graph import run_microsoft_graph_admin_mfa_check
from controlguard.connectors.microsoft_graph import MicrosoftGraphClient, MicrosoftGraphSettings
from controlguard.models import ControlDefinition, ControlStatus, LabConfig


class MicrosoftGraphConnectorTests(unittest.TestCase):
    @patch("controlguard.connectors.microsoft_graph._request_json")
    def test_graph_client_follows_next_link(self, mocked_request_json) -> None:
        mocked_request_json.side_effect = [
            {
                "value": [{"id": "1", "isAdmin": True, "isMfaCapable": True}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$skiptoken=abc",
            },
            {
                "value": [{"id": "2", "isAdmin": False, "isMfaCapable": False}],
            },
        ]
        client = MicrosoftGraphClient(MicrosoftGraphSettings(access_token="token"))

        rows, auth_mode = client.list_user_registration_details()

        self.assertEqual(auth_mode, "access_token")
        self.assertEqual([row["id"] for row in rows], ["1", "2"])

    def test_graph_settings_reads_env_credentials(self) -> None:
        settings = MicrosoftGraphSettings(
            tenant_env="TENANT",
            client_id_env="CLIENT_ID",
            client_secret_env="CLIENT_SECRET",
        )
        with patch.dict(
            "os.environ",
            {"TENANT": "tenant-id", "CLIENT_ID": "client-id", "CLIENT_SECRET": "secret"},
            clear=True,
        ):
            with patch(
                "controlguard.connectors.microsoft_graph._request_client_credentials_token", return_value="token"
            ):
                token, auth_mode = settings.resolve_access_token()

        self.assertEqual(token, "token")
        self.assertEqual(auth_mode, "client_credentials")


class GraphControlTests(unittest.TestCase):
    @patch("controlguard.checks.graph.MicrosoftGraphClient.list_user_registration_details")
    def test_graph_admin_mfa_fails_for_non_compliant_admin(self, mocked_list) -> None:
        mocked_list.return_value = (
            [
                {
                    "id": "1",
                    "isAdmin": True,
                    "userPrincipalName": "admin1@contoso.com",
                    "userDisplayName": "Admin 1",
                    "userType": "member",
                    "isMfaRegistered": True,
                    "isMfaCapable": True,
                    "methodsRegistered": ["microsoftAuthenticatorPush"],
                    "lastUpdatedDateTime": "2026-04-21T00:00:00Z",
                },
                {
                    "id": "2",
                    "isAdmin": True,
                    "userPrincipalName": "admin2@contoso.com",
                    "userDisplayName": "Admin 2",
                    "userType": "member",
                    "isMfaRegistered": False,
                    "isMfaCapable": False,
                    "methodsRegistered": [],
                    "lastUpdatedDateTime": "2026-04-21T00:00:00Z",
                },
            ],
            "client_credentials",
        )
        control = ControlDefinition(
            id="admin-mfa",
            title="Admin MFA",
            type="microsoft_graph_admin_mfa",
            params={"access_token": "token", "mfa_requirement": "capable"},
        )

        result = run_microsoft_graph_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["admin_count"], 2)
        self.assertEqual(result.evidence["non_compliant_admins"][0]["userPrincipalName"], "admin2@contoso.com")

    @patch("controlguard.checks.graph.MicrosoftGraphClient.list_user_registration_details")
    def test_graph_admin_mfa_passes_when_all_admins_are_capable(self, mocked_list) -> None:
        mocked_list.return_value = (
            [
                {
                    "id": "1",
                    "isAdmin": True,
                    "userPrincipalName": "admin1@contoso.com",
                    "userDisplayName": "Admin 1",
                    "userType": "member",
                    "isMfaRegistered": True,
                    "isMfaCapable": True,
                    "methodsRegistered": ["microsoftAuthenticatorPush"],
                    "lastUpdatedDateTime": "2026-04-21T00:00:00Z",
                }
            ],
            "access_token",
        )
        control = ControlDefinition(
            id="admin-mfa",
            title="Admin MFA",
            type="microsoft_graph_admin_mfa",
            params={"access_token": "token", "mfa_requirement": "capable"},
        )

        result = run_microsoft_graph_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)
        self.assertEqual(result.evidence["compliant_admin_count"], 1)

    def test_graph_admin_mfa_reports_missing_configuration(self) -> None:
        control = ControlDefinition(
            id="admin-mfa",
            title="Admin MFA",
            type="microsoft_graph_admin_mfa",
            params={},
        )

        result = run_microsoft_graph_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.EVIDENCE_MISSING)
        self.assertIn("not configured", result.message)
