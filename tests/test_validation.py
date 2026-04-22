from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from controlguard.loaders import load_config


class ValidationTests(unittest.TestCase):
    def test_duplicate_control_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "bad.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "bad",
                        "controls": [
                            {"id": "dup", "title": "A", "type": "manual_assertion", "evidence_key": "x"},
                            {"id": "dup", "title": "B", "type": "manual_assertion", "evidence_key": "y"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Duplicate control id detected: dup"):
                load_config(config_path)

    def test_missing_required_param_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "bad.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "bad",
                        "controls": [{"id": "mfa", "title": "MFA", "type": "manual_assertion"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing required parameter 'evidence_key'"):
                load_config(config_path)

    def test_graph_control_requires_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "bad.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "bad",
                        "controls": [
                            {
                                "id": "graph",
                                "title": "Graph MFA",
                                "type": "microsoft_graph_admin_mfa",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must define either access_token/access_token_env"):
                load_config(config_path)
