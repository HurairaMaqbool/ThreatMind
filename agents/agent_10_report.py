import os
import uuid
from datetime import datetime, timezone
from utils.logger import logger
from utils.groq_client import call_groq_with_retry, GROQ_MODEL_LIGHT
from utils.platform_converter import convert_to_all_platforms
from agents.prompts import report_prompt
from pipeline.state import ThreatState
from memory.chromadb_client import store_threat_report, store_kql_query
from memory.sqlite_client import save_queries_to_sqlite, _normalize_sentinel_kql


def agent_10(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 10: REPORT GENERATION ---")

    if not state.get("huntable", True):
        return state

    threat_id = "threat_" + str(uuid.uuid4())[:8]
    state["threat_id"] = threat_id

    title = state.get("article_title", "Unknown Threat")
    behaviors = state.get("behaviors", [])
    iocs = state.get("iocs", {})
    validated_queries = state.get("validated_queries", [])
    angles = {a.get("angle_id"): a for a in state.get("detection_angles", [])}
    coverage_report = state.get("coverage_report", {})
    severity = state.get("severity_level", "MEDIUM")
    enable_multi = os.getenv("ENABLE_MULTI_PLATFORM", "true").lower() in ("true", "1", "yes")

    prompt = report_prompt(
        title=title,
        severity=severity,
        behavior_count=len(behaviors),
        ip_count=len(iocs.get("ip_addresses", [])),
        hash_count=len(iocs.get("file_hashes", [])),
        gaps=coverage_report.get("gaps", []),
    )

    try:
        report = call_groq_with_retry(
            agent_name="agent_10_report",
            prompt=prompt,
            model=GROQ_MODEL_LIGHT,
            max_tokens=1024,
        )
        state["final_report"] = report
    except Exception as e:
        logger.error(f"[Report] Error generating report: {e}")
        state["final_report"] = "Report generation failed."

    platform_queries = []
    now_str = datetime.now(timezone.utc).isoformat()

    for q in validated_queries:
        angle_id = q.get("angle_id", "")
        angle = angles.get(angle_id, {})
        behavior_id = angle.get("behavior_id", "")
        behavior_desc = next(
            (b.get("description", "") for b in behaviors if b.get("behavior_id") == behavior_id),
            angle.get("detection_idea", ""),
        )
        technique = next(
            (b.get("attack_technique", "") for b in behaviors if b.get("behavior_id") == behavior_id),
            "",
        )
        target_table = angle.get("target_table", "DeviceProcessEvents")
        kql_text = _normalize_sentinel_kql(q.get("kql_detection", ""), target_table)
        score = state.get("validation_scores", {}).get(angle_id, 0)

        if enable_multi and kql_text.strip():
            try:
                converted = convert_to_all_platforms(
                    kql_text, angle_id, technique, behavior_desc
                )
                converted["validation_score"] = score
                platform_queries.append(converted)
            except Exception as e:
                logger.warning(f"[Report] Multi-platform conversion failed for {angle_id}: {e}")
                platform_queries.append(
                    {"angle_id": angle_id, "sentinel": kql_text, "validation_score": score}
                )
        else:
            platform_queries.append(
                {"angle_id": angle_id, "sentinel": kql_text, "validation_score": score}
            )

    state["platform_queries"] = platform_queries

    try:
        save_queries_to_sqlite(state)
    except Exception as e:
        logger.error(f"[Report] SQLite error: {e}")

    try:
        for pq in platform_queries:
            angle_id = pq.get("angle_id", "")
            angle = angles.get(angle_id, {})
            kql_text = pq.get("sentinel", "")
            score = state.get("validation_scores", {}).get(angle_id, 0)
            behavior_id = angle.get("behavior_id", "")
            behavior_desc = next(
                (b.get("description", "") for b in behaviors if b.get("behavior_id") == behavior_id),
                angle.get("detection_idea", ""),
            )
            technique = next(
                (b.get("attack_technique", "") for b in behaviors if b.get("behavior_id") == behavior_id),
                "",
            )
            meta = {
                "threat_id": threat_id,
                "threat_actor": title,
                "table": angle.get("target_table", "Unknown"),
                "tier": angle.get("tier", "behavioral"),
                "date": now_str[:10],
                "technique": technique,
                "severity": severity,
            }
            if kql_text:
                store_kql_query(angle_id, kql_text, score, behavior_desc, meta)
        logger.info(f"[Report] Saved {len(platform_queries)} queries to ChromaDB kql_library.")
    except Exception as e:
        logger.error(f"[Report] ChromaDB kql_library write error: {e}")

    try:
        clean_text = state.get("clean_text", "")
        url = state.get("blog_url", "")
        if clean_text and url:
            metadata = {
                "title": title,
                "severity": severity,
                "threat_id": threat_id,
                "date": state.get("published_date", ""),
            }
            store_threat_report(url, clean_text[:8000], metadata)
            logger.info("[Report] Successfully saved to ChromaDB.")
    except Exception as e:
        logger.error(f"[Report] ChromaDB error: {e}")

    return state
