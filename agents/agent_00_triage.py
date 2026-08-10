from utils.logger import logger
from utils.groq_client import call_groq_with_retry, safe_parse_json, GROQ_MODEL_LIGHT
from agents.prompts import triage_prompt
from pipeline.state import ThreatState


def agent_0(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 0: TRIAGE ---")
    blog_url = state.get("blog_url", "")
    prompt = triage_prompt(blog_url)

    try:
        response = call_groq_with_retry(
            agent_name="agent_00_triage",
            prompt=prompt,
            model=GROQ_MODEL_LIGHT,
            max_tokens=200,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        parsed = safe_parse_json(response, "dict", "agent_00_triage")
        state["huntable"] = bool(parsed.get("huntable", False))
        state["triage_reason"] = parsed.get("reason", "Parsed response lacked a reason.")
        logger.info(f"[Triage] Huntable: {state['huntable']} - {state['triage_reason']}")
    except Exception as e:
        logger.error(f"[Triage] Error: {e}")
        state["huntable"] = False
        state["triage_reason"] = "Failed to determine huntability; failing closed."

    return state
