from __future__ import annotations

import unittest
from unittest.mock import patch

from controlguard.engine import ScanEngine, filter_report
from controlguard.models import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    LabConfig,
    ScanReport,
    ScanSummary,
    Severity,
)


class ModelTests(unittest.TestCase):
    def test_definition_normalizes_severity_from_string(self) -> None:
        control = ControlDefinition(id="mfa", title="MFA", type="manual_assertion", severity="critical")
        self.assertEqual(control.severity, Severity.CRITICAL)


class SummaryTests(unittest.TestCase):
    def test_evidence_missing_is_blocking_and_scores_zero(self) -> None:
        engine = ScanEngine()
        config = LabConfig(
            lab_name="demo",
            description="",
            manual_evidence={},
            controls=[
                ControlDefinition(
                    id="mfa",
                    title="MFA",
                    type="manual_assertion",
                    severity=Severity.CRITICAL,
                )
            ],
        )

        report = engine.run(config)

        self.assertEqual(report.results[0].status, ControlStatus.EVIDENCE_MISSING)
        self.assertEqual(report.summary.score, 0.0)
        self.assertFalse(report.summary.compliant)
        self.assertEqual(report.summary.blocking_controls, ["mfa"])
        self.assertEqual(report.summary.posture, "critical")

    def test_not_applicable_is_excluded_from_score(self) -> None:
        engine = ScanEngine()
        results = [
            ControlResult(
                control_id="secure-boot",
                title="Secure Boot",
                control_type="secure_boot_enabled",
                severity=Severity.MEDIUM,
                status=ControlStatus.NOT_APPLICABLE,
                message="unsupported",
            ),
            ControlResult(
                control_id="fw",
                title="FW",
                control_type="windows_firewall_enabled",
                severity=Severity.CRITICAL,
                status=ControlStatus.PASS,
                message="ok",
            ),
        ]

        summary = engine._build_summary(results)

        self.assertEqual(summary.score, 100.0)
        self.assertEqual(summary.applicable_controls, 1)
        self.assertTrue(summary.compliant)

    @patch("controlguard.engine.platform.system", return_value="Windows")
    def test_engine_marks_linux_control_not_applicable_on_windows_host(self, mocked_system) -> None:
        del mocked_system
        config = LabConfig(
            lab_name="linux",
            description="",
            manual_evidence={},
            controls=[
                ControlDefinition(
                    id="linux-only",
                    title="Linux only",
                    type="linux_firewall_enabled",
                    supported_platforms=["linux"],
                )
            ],
        )
        report = ScanEngine().run(config)

        self.assertEqual(report.results[0].status, ControlStatus.NOT_APPLICABLE)

    def test_filter_report_keeps_only_findings(self) -> None:
        report = ScanReport(
            lab_name="Lab",
            description="",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="a",
                    title="A",
                    control_type="manual_assertion",
                    severity=Severity.MEDIUM,
                    status=ControlStatus.PASS,
                    message="ok",
                ),
                ControlResult(
                    control_id="b",
                    title="B",
                    control_type="manual_assertion",
                    severity=Severity.HIGH,
                    status=ControlStatus.FAIL,
                    message="no",
                ),
            ],
            summary=ScanSummary(
                total_controls=2,
                applicable_controls=2,
                score=50.0,
                counts={status.value: 0 for status in ControlStatus},
                posture="weak",
                compliant=False,
                blocking_controls=["b"],
            ),
        )

        filtered = filter_report(report, only_failed=True)

        self.assertEqual(len(filtered.results), 1)
        self.assertEqual(filtered.results[0].control_id, "b")
