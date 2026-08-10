"""SQLite schema migrations and legacy data fixes."""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "autothreat.db")

# MDE table names incorrectly stored as platform before v3.0.1 fix
LEGACY_TABLE_PLATFORMS = {
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "IdentityLogonEvents",
    "DeviceEvents",
    "SecurityEvent",
    "AzureActivity",
    "MDE",
}

VALID_PLATFORMS = {
    "sentinel",
    "splunk",
    "qradar",
    "elastic",
    "crowdstrike",
    "wazuh",
    "sentinelone",
}


def migrate_legacy_platforms(conn: sqlite3.Connection | None = None) -> int:
    """Remap MDE table names stored in platform column → 'sentinel'. Returns rows updated."""
    own_conn = conn is None
    if own_conn:
        if not os.path.exists(DB_PATH):
            return 0
        conn = sqlite3.connect(DB_PATH)

    c = conn.cursor()
    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    if "generated_queries" not in tables:
        if own_conn:
            conn.close()
        return 0

    updated = 0
    for legacy in LEGACY_TABLE_PLATFORMS:
        c.execute(
            "UPDATE generated_queries SET platform = 'sentinel' WHERE platform = ?",
            (legacy,),
        )
        updated += c.rowcount

    if own_conn:
        conn.commit()
        conn.close()

    return updated


def ensure_indexes(conn: sqlite3.Connection | None = None) -> None:
    own_conn = conn is None
    if own_conn:
        if not os.path.exists(DB_PATH):
            return
        conn = sqlite3.connect(DB_PATH)

    c = conn.cursor()
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_queries_threat_id ON generated_queries(threat_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_queries_platform ON generated_queries(platform)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_queries_created ON generated_queries(created_at)"
    )
    if own_conn:
        conn.commit()
        conn.close()


def fix_chroma_config() -> int:
    """Fix legacy empty dict config_json_str in ChromaDB collections."""
    chroma_sqlite = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chroma_db", "chroma.sqlite3")
    if not os.path.exists(chroma_sqlite):
        return 0
    try:
        conn = sqlite3.connect(chroma_sqlite)
        c = conn.cursor()
        c.execute("UPDATE collections SET config_json_str = NULL WHERE config_json_str = '{}'")
        updated = c.rowcount
        conn.commit()
        conn.close()
        return updated
    except Exception:
        return 0


def run_all_migrations() -> dict:
    fix_chroma_config()
    if not os.path.exists(DB_PATH):
        return {"platform_rows_fixed": 0, "indexes": "skipped"}

    conn = sqlite3.connect(DB_PATH)
    fixed = migrate_legacy_platforms(conn)
    ensure_indexes(conn)
    conn.commit()
    conn.close()
    return {"platform_rows_fixed": fixed, "indexes": "ok"}

