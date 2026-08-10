from utils.logger import logger
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from pipeline.state import ThreatState
from pipeline.router import route_after_agent_0, route_after_agent_8
import os
import time

from agents.agent_00_triage import agent_0
from agents.agent_01_discovery import agent_1
from agents.agent_02_extraction import agent_2
from agents.agent_03_threat_intel import agent_3
from agents.agent_04_coverage_planner import agent_4
from agents.agent_05_rag import agent_5
from agents.agent_06_reasoning import agent_6
from agents.agent_07_kql_generator import agent_7
from agents.agent_08_validator import agent_8
from agents.agent_09_coverage_critic import agent_9
from agents.agent_10_report import agent_10


def _wrap_with_delay(agent_func, is_heavy: bool = False):
    """Wrap an agent with a configurable sleep delay to respect API rate limits."""
    def wrapper(state: ThreatState):
        delay_key = "DELAY_BETWEEN_HEAVY_AGENTS" if is_heavy else "DELAY_BETWEEN_LIGHT_AGENTS"
        delay = int(os.getenv(delay_key, "0"))
        if delay > 0:
            logger.info(f"[{delay_key}] Sleeping {delay}s to respect rate limits...")
            time.sleep(delay)
        return agent_func(state)
    return wrapper

def build_graph():
    checkpointer = MemorySaver()
    # 1. Initialize the graph with our shared state structure
    builder = StateGraph(ThreatState)

    # 2. Add all 11 agents as nodes with appropriate delays
    builder.add_node("agent_0", _wrap_with_delay(agent_0, is_heavy=False))
    builder.add_node("agent_1", _wrap_with_delay(agent_1, is_heavy=False))
    builder.add_node("agent_2", _wrap_with_delay(agent_2, is_heavy=True))  # 70b
    builder.add_node("agent_3", _wrap_with_delay(agent_3, is_heavy=True))  # 70b
    builder.add_node("agent_4", _wrap_with_delay(agent_4, is_heavy=True))  # 70b
    builder.add_node("agent_5", _wrap_with_delay(agent_5, is_heavy=False)) # rag
    builder.add_node("agent_6", _wrap_with_delay(agent_6, is_heavy=True))  # 70b
    builder.add_node("agent_7", _wrap_with_delay(agent_7, is_heavy=True))  # 70b
    builder.add_node("agent_8", _wrap_with_delay(agent_8, is_heavy=False))
    builder.add_node("agent_9", _wrap_with_delay(agent_9, is_heavy=False))
    builder.add_node("agent_10", _wrap_with_delay(agent_10, is_heavy=False))

    # 3. Set where the pipeline starts
    builder.set_entry_point("agent_0")

    # 4. Agent 0 Conditional Routing
    builder.add_conditional_edges(
        "agent_0",
        route_after_agent_0,
        {
            "agent_1": "agent_1",
            END: END
        }
    )

    # 5. Standard Sequential Flow
    builder.add_edge("agent_1", "agent_2")
    builder.add_edge("agent_2", "agent_3")
    builder.add_edge("agent_3", "agent_4")
    builder.add_edge("agent_4", "agent_5")
    builder.add_edge("agent_5", "agent_6")
    builder.add_edge("agent_6", "agent_7")
    builder.add_edge("agent_7", "agent_8")

    # 6. Agent 8 Conditional Routing (Validation Retry Loop)
    builder.add_conditional_edges(
        "agent_8",
        route_after_agent_8,
        {
            "agent_9": "agent_9",
            "agent_7": "agent_7"
        }
    )

    # 7. Final Steps
    builder.add_edge("agent_9", "agent_10")
    builder.add_edge("agent_10", END)

    # 8. Compile the pipeline with checkpointer
    return builder.compile(checkpointer=checkpointer)

if __name__ == "__main__":
    app = build_graph()
    
    # We count only our defined agent nodes (ignoring internal LangGraph nodes)
    agent_nodes = [node for node in app.nodes if node.startswith("agent_")]
    if len(agent_nodes) == 11:
        logger.info("AutoThreat pipeline initialized with 11 nodes")
