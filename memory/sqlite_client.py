import sqlite3
import datetime
import os
import threading
from utils.logger import logger
from memory.migrations import migrate_legacy_platforms, ensure_indexes

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "autothreat.db")
_db_lock = threading.Lock()

PLATFORMS = ["sentinel", "splunk", "qradar", "elastic", "crowdstrike", "wazuh", "sentinelone"]


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS generated_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT,
            threat_name TEXT,
            angle_id TEXT,
            platform TEXT,
            technique TEXT,
            tier TEXT,
            severity TEXT,
            query_text TEXT,
            validation_score INTEGER,
            created_at TIMESTAMP
        )
    """
    )
    # Migrate older DBs missing validation_score
    cols = {row[1] for row in c.execute("PRAGMA table_info(generated_queries)").fetchall()}
    if "validation_score" not in cols:
        c.execute("ALTER TABLE generated_queries ADD COLUMN validation_score INTEGER")

    migrate_legacy_platforms(conn)
    ensure_indexes(conn)
    conn.commit()
    conn.close()


def get_query_stats() -> dict:
    init_db()
    if not os.path.exists(DB_PATH):
        return {"total": 0, "threats": 0, "platforms": 0}
    conn = sqlite3.connect(DB_PATH)
    try:
        total = conn.execute("SELECT COUNT(*) FROM generated_queries").fetchone()[0]
        threats = conn.execute("SELECT COUNT(DISTINCT threat_id) FROM generated_queries").fetchone()[0]
        platforms = conn.execute("SELECT COUNT(DISTINCT platform) FROM generated_queries").fetchone()[0]
        return {"total": total, "threats": threats, "platforms": platforms}
    finally:
        conn.close()


def list_queries(limit: int = 50, platform: str | None = None, threat_id: str | None = None) -> list:
    init_db()
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        sql = (
            "SELECT id, threat_id, threat_name, angle_id, platform, technique, tier, "
            "severity, query_text, validation_score, created_at FROM generated_queries WHERE 1=1"
        )
        params: list = []
        if platform:
            sql += " AND platform = ?"
            params.append(platform)
        if threat_id:
            sql += " AND threat_id = ?"
            params.append(threat_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _technique_for_angle(angle: dict, behaviors: list) -> str:
    for b in behaviors:
        if b.get("behavior_id") == angle.get("behavior_id"):
            return b.get("attack_technique", "")
    return angle.get("mitre_technique", "")


def _normalize_sentinel_kql(query_text: str, target_table: str) -> str:
    if query_text.strip().startswith("|"):
        return f"{target_table}\n{query_text.strip()}"
    return query_text


def save_queries_to_sqlite(state: dict) -> int:
    """Persist sentinel + multi-platform queries for a completed threat."""
    platform_queries = state.get("platform_queries", [])
    if not platform_queries:
        return 0

    threat_id = state.get("threat_id", "unknown")
    threat_name = state.get("article_title", "Unknown")
    severity = state.get("severity_level", "UNKNOWN")
    angles = state.get("detection_angles", [])
    behaviors = state.get("behaviors", [])
    validation_scores = state.get("validation_scores", {})
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    saved = 0
    init_db()

    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            for p_dict in platform_queries:
                angle_id = p_dict.get("angle_id", "")
                angle = next((a for a in angles if a.get("angle_id") == angle_id), {})
                technique = _technique_for_angle(angle, behaviors)
                tier = angle.get("tier", "unknown")
                score = validation_scores.get(angle_id, p_dict.get("validation_score"))

                for platform in PLATFORMS:
                    query_text = p_dict.get(platform)
                    if not query_text or not str(query_text).strip():
                        continue
                    c.execute(
                        """
                        INSERT INTO generated_queries
                        (threat_id, threat_name, angle_id, platform, technique, tier,
                         severity, query_text, validation_score, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            threat_id,
                            threat_name,
                            angle_id,
                            platform,
                            technique,
                            tier,
                            severity,
                            query_text,
                            score,
                            now,
                        ),
                    )
                    saved += 1
            conn.commit()
        finally:
            conn.close()

    logger.info(f"[SQLite] Saved {saved} multi-platform query rows for {threat_id}.")
    return saved
