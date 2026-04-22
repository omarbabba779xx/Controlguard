from __future__ import annotations

import unittest

from controlguard.comparison import compare_report_payloads


class ComparisonTests(unittest.TestCase):
    def test_compare_report_payloads_detects_resolved_blocker(self) -> None:
        comparison = compare_report_payloads(
            baseline={
                "generated_at": "2026-04-20T00:00:00+00:00",
                "results": [{"control_id": "a", "status": "fail", "severity": "high", "title": "A"}],
                "summary": {"score": 10.0, "blocking_controls": ["a"], "frameworks": {}},
            },
            current={
                "generated_at": "2026-04-21T00:00:00+00:00",
                "results": [{"control_id": "a", "status": "pass", "severity": "high", "title": "A"}],
                "summary": {"score": 90.0, "blocking_controls": [], "frameworks": {}},
            },
        )

        self.assertEqual(comparison["score_delta"], 80.0)
        self.assertEqual(comparison["resolved_blocking_controls"], ["a"])
