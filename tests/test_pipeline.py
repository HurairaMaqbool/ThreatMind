import unittest
from pipeline.graph import build_graph
from pipeline.router import route_after_agent_0, route_after_agent_8
from pipeline.state import ThreatState

class TestPipeline(unittest.TestCase):
    def test_build_graph(self):
        graph = build_graph()
        self.assertIsNotNone(graph)

    def test_route_after_agent_0_huntable(self):
        state: ThreatState = {"huntable": True}
        next_node = route_after_agent_0(state)
        self.assertEqual(next_node, "agent_1")

    def test_route_after_agent_0_not_huntable(self):
        state: ThreatState = {"huntable": False}
        next_node = route_after_agent_0(state)
        self.assertEqual(next_node, "__end__")

    def test_route_after_agent_8_retry(self):
        state: ThreatState = {
            "failed_queries": [{"angle_id": "A1"}],
            "retry_counts": {"A1": 1},
        }
        next_node = route_after_agent_8(state)
        self.assertEqual(next_node, "agent_7")

    def test_route_after_agent_8_max_retries(self):
        state: ThreatState = {
            "failed_queries": [{"angle_id": "A1"}],
            "retry_counts": {"A1": 3},
        }
        next_node = route_after_agent_8(state)
        self.assertEqual(next_node, "agent_9")

if __name__ == "__main__":
    unittest.main()
