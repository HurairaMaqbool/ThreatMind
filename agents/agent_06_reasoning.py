import json
from utils.logger import logger
from utils.groq_client import call_groq_with_retry, GROQ_MODEL_LIGHT
from agents.prompts import reasoning_prompt
from pipeline.state import ThreatState


def agent_6(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 6: REASONING ---")

    if not state.get("huntable", True) or not state.get("detection_angles"):
        return state

    behaviors = state.get("behaviors", [])[:3]
    behavior_summary = json.dumps(
        [
            {
                "id": b.get("behavior_id", "?"),
                "desc": str(b.get("description", ""))[:80],
                "technique": b.get("attack_technique", ""),
            }
            for b in behaviors
        ]
    )

    iocs = state.get("iocs", {})
    ioc_summary = json.dumps(
        {
            "malware": str(iocs.get("malware_name", "Unknown"))[:40],
            "actor": str(iocs.get("threat_actor", "Unknown"))[:40],
            "method": str(iocs.get("attack_method", ""))[:80],
        }
    )

    angles = state.get("detection_angles", [])[:3]
    angle_summary = json.dumps(
        [
            {
                "id": a.get("angle_id", "?"),
                "table": a.get("target_table", "?"),
                "idea": str(a.get("detection_idea", ""))[:80],
            }
            for a in angles
        ]
    )

    prompt = reasoning_prompt(behavior_summary, ioc_summary, angle_summary)
    logger.info(f"[Reasoning] Prompt length: {len(prompt)} chars")

    try:
        resp = call_groq_with_retry(
            agent_name="agent_06_reasoning",
            prompt=prompt,
            model=GROQ_MODEL_LIGHT,
            max_tokens=512,
        )
        state["cot_reasoning"] = resp
        logger.info(f"[Reasoning] Generated {len(resp)} chars of reasoning")
    except Exception as e:
        logger.error(f"[Reasoning] Error: {e}")
        state["cot_reasoning"] = "Reasoning skipped."

    return state
