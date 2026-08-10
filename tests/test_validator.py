"""Tests for KQL validator agent."""
import os
import unittest
from agents.agent_08_validator import auto_fix_kql, agent_8


class TestAutoFixKql(unittest.TestCase):
    def test_commandline_fixed(self):
        kql = "DeviceProcessEvents | where CommandLine has '-enc'"
        fixed, fixes = auto_fix_kql(kql)
        self.assertIn("ProcessCommandLine", fixed)
        self.assertTrue(len(fixes) > 0)

    def test_parent_process_fixed(self):
        kql = "DeviceProcessEvents | where ParentProcessName == 'cmd.exe'"
        fixed, _ = auto_fix_kql(kql)
        self.assertIn("InitiatingProcessFileName", fixed)


class TestValidatorScoring(unittest.TestCase):
    def setUp(self):
        os.environ["MIN_VALIDATION_SCORE"] = "70"

    def test_valid_query_passes(self):
        state = {
            "huntable": True,
            "generated_queries": [
                {
                    "angle_id": "B1-behavioral-DeviceProcessEvents",
                    "kql_detection": (
                        "DeviceProcessEvents\n"
                        "| where TimeGenerated >= ago(1d)\n"
                        "| where FileName =~ 'powershell.exe'\n"
                        "| where ProcessCommandLine has '-enc'\n"
                        "| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName"
                    ),
                    "blocked": False,
                }
            ],
            "detection_angles": [
                {
                    "angle_id": "B1-behavioral-DeviceProcessEvents",
                    "target_table": "DeviceProcessEvents",
                }
            ],
            "schema_snippets": {
                "DeviceProcessEvents": [
                    {"column": "FileName"},
                    {"column": "ProcessCommandLine"},
                    {"column": "TimeGenerated"},
                    {"column": "DeviceName"},
                    {"column": "AccountName"},
                    {"column": "InitiatingProcessFileName"},
                ]
            },
            "validation_scores": {},
            "retry_counts": {},
        }
        result = agent_8(state)
        self.assertEqual(len(result["validated_queries"]), 1)
        self.assertEqual(len(result["failed_queries"]), 0)

    def test_empty_query_fails(self):
        state = {
            "huntable": True,
            "generated_queries": [
                {"angle_id": "X", "kql_detection": "", "blocked": True}
            ],
            "detection_angles": [],
            "schema_snippets": {},
            "validation_scores": {},
            "retry_counts": {},
        }
        result = agent_8(state)
        self.assertEqual(len(result["validated_queries"]), 0)
        self.assertEqual(len(result["failed_queries"]), 1)


if __name__ == "__main__":
    unittest.main()
