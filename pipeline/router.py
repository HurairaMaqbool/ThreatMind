from utils.logger import logger
from langgraph.graph import END
from pipeline.state import ThreatState
import os

MAX_RETRIES = int(os.getenv("MAX_VALIDATION_RETRIES", "3"))

def route_after_agent_0(state: ThreatState) -> str:
    if state.get("huntable", False):
        return "agent_1"
    else:
        return END

def route_after_agent_8(state: ThreatState) -> str:
    failed = state.get("failed_queries", [])
    retry_counts = state.get("retry_counts", {})

    # Check if any failed query still has retries left
    needs_retry = any(
        retry_counts.get(q.get("angle_id", ""), 0) < MAX_RETRIES
        for q in failed
    )

    if failed and needs_retry:
        logger.info(f"ROUTER: {len(failed)} queries failed validation. Routing back to Agent 7.")
        return "agent_7"
    else:
        logger.info("ROUTER: All queries passed or max retries reached. Proceeding to Agent 9.")
        return "agent_9"
