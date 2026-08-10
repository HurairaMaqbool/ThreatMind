import json
from utils.logger import logger
from utils.groq_client import call_groq_with_retry, safe_parse_json, GROQ_MODEL_LIGHT
from agents.prompts import coverage_planner_prompt
from pipeline.state import ThreatState


def agent_4(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 4: COVERAGE PLANNER ---")

    behaviors = state.get("behaviors", [])
    if not state.get("huntable", True) or not behaviors:
        logger.warning(
            f"[Coverage Planner] Skipping: huntable={state.get('huntable')}, "
            f"behaviors_count={len(behaviors)}"
        )
        state["detection_angles"] = []
        return state

    behavior_summary = json.dumps(
        [
            {
                "id": b.get("behavior_id", "B?"),
                "desc": b.get("description", "")[:100],
                "technique": b.get("attack_technique", ""),
                "tactic": b.get("attack_tactic", ""),
            }
            for b in behaviors[:5]
        ],
        indent=2,
    )

    try:
        resp = call_groq_with_retry(
            agent_name="agent_04_planner",
            prompt=coverage_planner_prompt(behavior_summary),
            model=GROQ_MODEL_LIGHT,
            max_tokens=1024,
            response_format={"type": "json_object"},
        )
        parsed = safe_parse_json(resp, "dict", "agent_04_planner")

        angles = []
        if isinstance(parsed, list):
            angles = parsed
        elif isinstance(parsed, dict):
            for key in ("angles", "detection_angles", "detections", "results"):
                if key in parsed and isinstance(parsed[key], list):
                    angles = parsed[key]
                    break
            if not angles:
                for v in parsed.values():
                    if isinstance(v, list) and len(v) > 0:
                        angles = v
                        break

        state["detection_angles"] = angles if angles else []
        logger.info(f"[Coverage Planner] Generated {len(state['detection_angles'])} detection angles")
    except Exception as e:
        logger.error(f"[Coverage Planner] Error: {e}")
        state["detection_angles"] = []

    return state
