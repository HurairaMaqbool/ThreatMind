import unittest
from agents.agent_00_triage import agent_0
from agents.agent_08_validator import auto_fix_kql, agent_8
from pipeline.state import ThreatState

class TestAgents(unittest.TestCase):
    def test_auto_fix_kql(self):
        kql = "DeviceProcessEvents | where CommandLine contains 'powershell'"
        fixed, fixes = auto_fix_kql(kql)
        self.assertIn("ProcessCommandLine", fixed)
        self.assertTrue(len(fixes) > 0)

    def test_validator_scoring(self):
        state: ThreatState = {
            "huntable": True,
            "generated_queries": [
                {
                    "angle_id": "A1",
                    "kql_detection": "DeviceProcessEvents | where TimeGenerated >= ago(1d) | where ProcessCommandLine contains 'cmd.exe'",
                }
            ],
            "detection_angles": [{"angle_id": "A1", "target_table": "DeviceProcessEvents"}],
            "schema_snippets": {"DeviceProcessEvents": [{"column": "ProcessCommandLine"}]},
            "validation_scores": {},
            "retry_counts": {},
        }
        res = agent_8(state)
        self.assertIn("A1", res["validation_scores"])
        self.assertGreaterEqual(res["validation_scores"]["A1"], 70)
        self.assertEqual(len(res["validated_queries"]), 1)

if __name__ == "__main__":
    unittest.main()
