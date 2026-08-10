from utils.logger import logger
from pipeline.state import ThreatState
from memory.rag_retriever import (
    find_similar_threats,
    find_historical_kql,
    get_table_schema_snippet,
)


def agent_5(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 5: RAG ---")

    if not state.get("huntable", True) or not state.get("detection_angles"):
        return state

    angles = state.get("detection_angles", [])
    iocs = state.get("iocs", {})
    clean_text = state.get("clean_text", "")

    # Schema grounding via ChromaDB sentinel_schema collection
    schema_snippets = {}
    for angle in angles:
        table = angle.get("target_table")
        if not table:
            continue
        detection_idea = angle.get("detection_idea", "")
        columns = get_table_schema_snippet(table, detection_idea, top_k=8)
        if columns:
            schema_snippets[table] = columns
        elif table not in schema_snippets:
            schema_snippets[table] = []

    state["schema_snippets"] = schema_snippets
    logger.info(f"[RAG] Loaded schema snippets for {len(schema_snippets)} tables")

    # Hybrid retrieval: similar threats + historical KQL
    similar_threats = []
    historical_kqls = []
    try:
        if clean_text:
            similar_threats = find_similar_threats(clean_text[:2000], iocs, top_k=3)
        for angle in angles[:5]:
            idea = angle.get("detection_idea", "")
            if idea:
                historical_kqls.extend(find_historical_kql(idea, iocs, top_k=2))
    except Exception as e:
        logger.error(f"[RAG] Retrieval error: {e}")

    state["similar_threats"] = similar_threats
    state["historical_kqls"] = historical_kqls[:5]

    rag_parts = []
    if similar_threats:
        rag_parts.append("Past Similar Threats:")
        for t in similar_threats:
            meta = t.get("metadata", {}) or {}
            rag_parts.append(f"- {meta.get('title', 'Unknown')}: {t.get('text', '')[:200]}")

    if historical_kqls:
        rag_parts.append("\nHistorical KQL Patterns:")
        for k in historical_kqls[:3]:
            meta = k.get("metadata", {}) or {}
            rag_parts.append(f"- {meta.get('technique', '?')}: {k.get('text', '')[:150]}")

    state["rag_context"] = "\n".join(rag_parts)
    return state
