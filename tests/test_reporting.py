from __future__ import annotations

import json
import unittest

from controlguard.models import (
    ControlResult,
    ControlStatus,
    FrameworkSummary,
    ScanReport,
    ScanSummary,
    Severity,
)
from controlguard.reporting import render_csv, render_markdown, render_sarif


class ReportingTests(unittest.TestCase):
    def test_markdown_report_contains_new_summary_fields(self) -> None:
        report = ScanReport(
            lab_name="Security Lab",
            description="Demo report",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="firewall",
                    title="Pare-feu",
                    control_type="windows_firewall_enabled",
                    severity=Severity.CRITICAL,
                    status=ControlStatus.PASS,
                    message="ok",
                    evidence={"profiles": []},
                )
            ],
            summary=ScanSummary(
                total_controls=1,
                applicable_controls=1,
                score=100.0,
                counts={status.value: 0 for status in ControlStatus} | {"pass": 1},
                posture="strong",
                compliant=True,
                frameworks={
                    "CIS Controls v8": FrameworkSummary(
                        score=100.0,
                        total_controls=1,
                        applicable_controls=1,
                        compliant=True,
                        blocking_controls=[],
                    )
                },
                blocking_controls=[],
            ),
        )

        rendered = render_markdown(report)
        self.assertIn("Compliant: `true`", rendered)
        self.assertIn("not applicable", rendered)
        self.assertIn("Framework summary", rendered)

    def test_sarif_omits_passing_controls(self) -> None:
        report = ScanReport(
            lab_name="Security Lab",
            description="Demo report",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="pass",
                    title="Pass",
                    control_type="manual_assertion",
                    severity=Severity.LOW,
                    status=ControlStatus.PASS,
                    message="ok",
                ),
                ControlResult(
                    control_id="fail",
                    title="Fail",
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
                blocking_controls=["fail"],
            ),
        )

        sarif = json.loads(render_sarif(report))
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "fail")

    def test_csv_contains_status_column(self) -> None:
        report = ScanReport(
            lab_name="Security Lab",
            description="Demo report",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="firewall",
                    title="Pare-feu",
                    control_type="windows_firewall_enabled",
                    severity=Severity.CRITICAL,
                    status=ControlStatus.PASS,
                    message="ok",
                )
            ],
            summary=ScanSummary(
                total_controls=1,
                applicable_controls=1,
                score=100.0,
                counts={status.value: 0 for status in ControlStatus},
                posture="strong",
                compliant=True,
                blocking_controls=[],
            ),
        )

        rendered = render_csv(report)
        self.assertIn('"status"', rendered.splitlines()[0])
        self.assertIn('"pass"', rendered)
