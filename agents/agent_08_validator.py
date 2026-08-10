import re
from utils.logger import logger
from utils.validation import get_min_validation_score
from pipeline.state import ThreatState

# Known wrong -> correct column name mappings for MDE/Sentinel
COLUMN_FIXES = {
    r'\bCommandLine\b': 'ProcessCommandLine',
    r'\bParentProcessName\b': 'InitiatingProcessFileName',
    r'\bParentProcess\b': 'InitiatingProcessFileName',
    r'\bParentProcessId\b': 'InitiatingProcessId',
    r'\bProcessName\b': 'FileName',
    r'\bUser\b(?=\s*[=!|,])': 'AccountName',
}

def auto_fix_kql(kql: str) -> tuple[str, list]:
    """Auto-correct known wrong column names. Returns (fixed_kql, list_of_fixes)."""
    fixes = []
    for wrong_pattern, correct in COLUMN_FIXES.items():
        new_kql, n = re.subn(wrong_pattern, correct, kql)
        if n > 0:
            fixes.append(f"{wrong_pattern} -> {correct} ({n}x)")
            kql = new_kql
    return kql, fixes

def agent_8(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 8: VALIDATOR ---")

    if not state.get("huntable", True) or not state.get("generated_queries"):
        return state

    queries = state.get("generated_queries", [])
    angles = {a.get("angle_id"): a for a in state.get("detection_angles", [])}
    schema_snippets = state.get("schema_snippets", {})

    scores = state.get("validation_scores", {})
    retry_counts = state.get("retry_counts", {})

    validated = []
    failed = []
    min_score = get_min_validation_score()
    state["validation_threshold_used"] = min_score

    for q in queries:
        angle_id = q.get("angle_id")
        kql = q.get("kql_detection", "")

        if angle_id not in retry_counts:
            retry_counts[angle_id] = 0

        # ── Step 1: Auto-fix known wrong column names ──────────────────────────
        fixed_kql, fixes_applied = auto_fix_kql(kql)
        if fixes_applied:
            logger.warning(f"[Validator] Auto-fixed columns in {angle_id}: {fixes_applied}")
            q["kql_detection"] = fixed_kql
            kql = fixed_kql

        # ── Step 2: Score the query ────────────────────────────────────────────
        score = 100

        if q.get("blocked") or not kql.strip():
            score = 0
            # Mark as permanently exhausted so router never retries it
            retry_counts[angle_id] = 99
            logger.warning(f"[Validator] {angle_id}: blocked/empty query — permanently failed")
        else:
            # Check for pipe operators
            if "|" not in kql:
                score -= 25
                logger.warning(f"[Validator] {angle_id}: Missing pipe operators (-25)")

            # Check for filters
            if "where" not in kql.lower() and "summarize" not in kql.lower():
                score -= 15
                logger.warning(f"[Validator] {angle_id}: Missing where/summarize (-15)")

            # Check for TimeGenerated filter
            if "TimeGenerated" not in kql:
                score -= 20
                logger.warning(f"[Validator] {angle_id}: Missing TimeGenerated filter (-20)")

            # Check for valid schema columns
            target_table = angles.get(angle_id, {}).get("target_table")
            if target_table and target_table in schema_snippets:
                valid_columns = {col.get("column", "") for col in schema_snippets[target_table]}
                # Extract potential column names used in the query
                col_candidates = re.findall(r'\b([A-Z][A-Za-z0-9]+)\b', kql)
                for col in col_candidates:
                    if (col not in valid_columns
                            and col not in {"TimeGenerated", "TenantId", "Type", "true", "false"}
                            and len(col) > 4  # Skip short words like "has", "in"
                            and not col.startswith(("Device", "Account", "Process", "File", "Registry", "Network"))):
                        score -= 5  # Softer penalty — LLM sometimes uses valid sub-names

        scores[angle_id] = max(0, score)

        if score >= min_score:
            validated.append(q)
            logger.info(f"[Validator] Angle {angle_id} PASSED (Score: {score}, threshold={min_score})")
        else:
            failed.append(q)
            retry_counts[angle_id] += 1
            logger.warning(f"[Validator] Angle {angle_id} FAILED (Score: {score}, Retry: {retry_counts[angle_id]})")

    state["validation_scores"] = scores
    state["retry_counts"] = retry_counts
    state["validated_queries"] = validated
    state["failed_queries"] = failed

    return state
