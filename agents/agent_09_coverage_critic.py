import json
from utils.logger import logger
from utils.groq_client import call_groq_with_retry, safe_parse_json, GROQ_MODEL_LIGHT
from agents.prompts import coverage_critic_prompt
from pipeline.state import ThreatState


def agent_9(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 9: COVERAGE CRITIC ---")

    if not state.get("huntable", True) or not state.get("behaviors"):
        return state

    behaviors = state.get("behaviors", [])
    angles = state.get("detection_angles", [])
    validated = state.get("validated_queries", [])
    iocs = state.get("iocs", {})

    prompt = coverage_critic_prompt(
        behaviors_json=json.dumps(behaviors[:5], indent=2),
        angles_json=json.dumps(angles[:8], indent=2),
        validated_count=len(validated),
        iocs_json=json.dumps(iocs, indent=2),
    )

    try:
        resp = call_groq_with_retry(
            agent_name="agent_09_critic",
            prompt=prompt,
            model=GROQ_MODEL_LIGHT,
            max_tokens=512,
            response_format={"type": "json_object"},
        )
        parsed = safe_parse_json(resp, "dict", "agent_09_critic")

        state["severity_level"] = parsed.get("severity_level", "MEDIUM")
        state["overall_coverage"] = parsed.get("overall_coverage", "PARTIAL")
        state["coverage_report"] = parsed.get("coverage_report", {})
    except Exception as e:
        logger.error(f"[Coverage Critic] Error: {e}")
        state["severity_level"] = "MEDIUM"
        state["overall_coverage"] = "PARTIAL"
        state["coverage_report"] = {}

    return state
