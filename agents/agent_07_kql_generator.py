import json
from utils.logger import logger
from utils.groq_client import call_groq_with_retry, safe_parse_json, GROQ_MODEL_LIGHT
from utils.validation import get_min_validation_score
from agents.prompts import kql_generator_prompt
from pipeline.state import ThreatState


def agent_7(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 7: KQL GENERATOR ---")

    if not state.get("huntable", True) or not state.get("detection_angles"):
        return state

    angles = state.get("detection_angles", [])
    schema_snippets = state.get("schema_snippets", {})
    cot_reasoning = state.get("cot_reasoning", "")
    validation_scores = state.get("validation_scores", {})
    existing_queries = {q["angle_id"]: q for q in state.get("generated_queries", [])}
    min_score = get_min_validation_score()

    new_generated = []

    for angle in angles:
        angle_id = angle.get("angle_id")

        if angle_id in validation_scores and validation_scores[angle_id] >= min_score:
            new_generated.append(existing_queries[angle_id])
            continue

        target_table = angle.get("target_table")
        schema_for_table = schema_snippets.get(target_table, [])

        prompt = kql_generator_prompt(
            angle_id=angle_id,
            angle_json=json.dumps(angle, indent=2),
            target_table=target_table,
            schema_json=json.dumps(schema_for_table, indent=2),
            reasoning=cot_reasoning,
        )

        try:
            resp = call_groq_with_retry(
                agent_name="agent_07_kql",
                prompt=prompt,
                model=GROQ_MODEL_LIGHT,
                max_tokens=2048,
                response_format={"type": "json_object"},
            )
            parsed = safe_parse_json(resp, "dict", "agent_07_kql")

            parsed["angle_id"] = angle_id
            parsed.setdefault("blocked", False)
            parsed.setdefault("notes", "")
            parsed.setdefault("kql_detection", f"{target_table}\n| where TimeGenerated >= ago(1d)\n| take 10")
            parsed.setdefault("kql_hunting", f"{target_table}\n| where TimeGenerated >= ago(7d)\n| take 10")

            new_generated.append(parsed)

        except Exception as e:
            logger.error(f"[KQL Generator] Error for angle {angle_id}: {e}")
            new_generated.append(
                {
                    "angle_id": angle_id,
                    "blocked": True,
                    "notes": f"Generation failed: {e}",
                    "kql_detection": "",
                    "kql_hunting": "",
                }
            )

    state["generated_queries"] = new_generated
    return state
