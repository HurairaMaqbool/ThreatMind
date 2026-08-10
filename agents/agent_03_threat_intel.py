import json
import time
from utils.logger import logger
from utils.groq_client import call_groq_with_retry, safe_parse_json, GROQ_MODEL_LIGHT
from agents.prompts import behaviors_prompt, iocs_prompt
from pipeline.state import ThreatState


def agent_3(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 3: THREAT INTEL ---")

    if not state.get("huntable", True) or not state.get("clean_text"):
        return state

    text = state.get("clean_text", "")[:4000]

    try:
        resp_behaviors = call_groq_with_retry(
            agent_name="agent_03_behaviors",
            prompt=behaviors_prompt(text),
            model=GROQ_MODEL_LIGHT,
            max_tokens=1024,
            response_format={"type": "json_object"},
        )
        parsed = safe_parse_json(resp_behaviors, "dict", "agent_03_behaviors")
        if isinstance(parsed, dict):
            behaviors = parsed.get("behaviors", [])
        elif isinstance(parsed, list):
            behaviors = parsed
        else:
            behaviors = []
        state["behaviors"] = behaviors if isinstance(behaviors, list) else []
        logger.info(f"[Threat Intel] Extracted {len(state['behaviors'])} behaviors")
    except Exception as e:
        logger.error(f"[Threat Intel] Behaviors extraction error: {e}")
        state["behaviors"] = []

    time.sleep(10)

    try:
        resp_iocs = call_groq_with_retry(
            agent_name="agent_03_iocs",
            prompt=iocs_prompt(text[:2000]),
            model=GROQ_MODEL_LIGHT,
            max_tokens=512,
            response_format={"type": "json_object"},
        )
        state["iocs"] = safe_parse_json(resp_iocs, "dict", "agent_03_iocs")
        logger.info(f"[Threat Intel] IOCs extracted: actor={state['iocs'].get('threat_actor', '?')}")
    except Exception as e:
        logger.error(f"[Threat Intel] IOCs extraction error: {e}")
        state["iocs"] = {}

    return state
