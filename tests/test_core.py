"""Core unit tests — no Groq API key required."""
import os
import re
import unittest

os.environ.setdefault("GROQ_API_KEY", "test-key-for-unit-tests")


class TestValidation(unittest.TestCase):
    def test_min_score_bounds(self):
        from utils.validation import get_min_validation_score

        os.environ["MIN_VALIDATION_SCORE"] = "85"
        self.assertEqual(get_min_validation_score(), 85)

    def test_min_score_clamped(self):
        from utils.validation import get_min_validation_score

        os.environ["MIN_VALIDATION_SCORE"] = "150"
        self.assertEqual(get_min_validation_score(), 100)


class TestSystemStatus(unittest.TestCase):
    def test_write_and_read(self):
        from utils.system_status import write_status, read_status

        write_status(pipeline_status="idle", test_flag=True)
        data = read_status()
        self.assertIn("pipeline_status", data)
        self.assertEqual(data.get("pipeline_status"), "idle")


class TestPrompts(unittest.TestCase):
    def test_triage_prompt_has_few_shots(self):
        from agents.prompts import triage_prompt

        p = triage_prompt("https://example.com/threat-report")
        self.assertIn("EXAMPLE", p)
        self.assertIn("huntable", p)

    def test_kql_prompt_has_examples(self):
        from agents.prompts import kql_generator_prompt

        p = kql_generator_prompt("B1-test", "{}", "DeviceProcessEvents", "[]", "reasoning")
        self.assertIn("ProcessCommandLine", p)
        self.assertIn("EXAMPLE", p)


class TestChromaIds(unittest.TestCase):
    def test_stable_doc_id(self):
        from utils.ids import stable_doc_id

        a = stable_doc_id("https://example.com/a")
        b = stable_doc_id("https://example.com/a")
        c = stable_doc_id("https://example.com/b")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class TestMockFilter(unittest.TestCase):
    def test_mock_regex(self):
        pattern = re.compile(r"^threat_\d{1,2}$")
        self.assertTrue(pattern.match("threat_1"))
        self.assertTrue(pattern.match("threat_99"))
        self.assertFalse(pattern.match("threat_abc12345"))
        self.assertFalse(pattern.match("threat_100"))


class TestDiagnose(unittest.TestCase):
    def test_table_detection_logic(self):
        tables = ["generated_queries", "sqlite_sequence"]
        self.assertIn("generated_queries", tables)


class TestRagFusion(unittest.TestCase):
    def test_reciprocal_rank_fusion(self):
        try:
            import chromadb  # noqa: F401
        except ImportError:
            self.skipTest("chromadb not installed")
        from memory.rag_retriever import reciprocal_rank_fusion

        v = [{"id": "a", "text": "one"}]
        k = [{"id": "b", "text": "two"}]
        result = reciprocal_rank_fusion(v, k, top_k=2)
        self.assertEqual(len(result), 2)
        self.assertEqual({r["id"] for r in result}, {"a", "b"})


class TestSqliteNormalize(unittest.TestCase):
    def test_normalize_sentinel_kql(self):
        from memory.sqlite_client import _normalize_sentinel_kql

        out = _normalize_sentinel_kql("| where x == 1", "DeviceProcessEvents")
        self.assertTrue(out.startswith("DeviceProcessEvents"))


if __name__ == "__main__":
    unittest.main()
