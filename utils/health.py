"""Centralized health checks for API, dashboard, and Docker."""
import os
import sqlite3

from utils.system_status import read_status

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(PROJECT_ROOT, "data", "autothreat.db")
CHROMA_PATH = os.path.join(PROJECT_ROOT, "chroma_db")


def check_sqlite() -> dict:
    if not os.path.exists(DB_PATH):
        return {"ok": False, "detail": "database file missing"}
    try:
        conn = sqlite3.connect(DB_PATH)
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "generated_queries" not in tables:
            conn.close()
            return {"ok": False, "detail": "generated_queries table missing"}
        count = conn.execute("SELECT COUNT(*) FROM generated_queries").fetchone()[0]
        threats = conn.execute("SELECT COUNT(DISTINCT threat_id) FROM generated_queries").fetchone()[0]
        conn.close()
        return {"ok": True, "queries": count, "threats": threats}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def check_chromadb() -> dict:
    if not os.path.isdir(CHROMA_PATH):
        return {"ok": False, "detail": "chroma_db directory missing"}
    try:
        from memory.chromadb_client import (
            threat_reports_col,
            kql_library_col,
            processed_urls_col,
            sentinel_schema_col,
        )
        return {
            "ok": True,
            "threat_reports": threat_reports_col.count(),
            "kql_library": kql_library_col.count(),
            "processed_urls": processed_urls_col.count(),
            "sentinel_schema": sentinel_schema_col.count(),
        }
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def check_groq_config() -> dict:
    key = os.getenv("GROQ_API_KEY", "")
    if not key or key.startswith("your_"):
        return {"ok": False, "detail": "GROQ_API_KEY not configured"}
    return {"ok": True}


def full_health(deep: bool = False) -> dict:
    status = read_status()
    result = {
        "status": "ok",
        "version": "3.0",
        "pipeline_status": status.get("pipeline_status", "unknown"),
        "last_crawl_at": status.get("last_crawl_at"),
        "last_crawl_stats": status.get("last_crawl_stats", {}),
        "checks": {
            "groq": check_groq_config(),
            "sqlite": check_sqlite(),
        },
    }

    if deep:
        result["checks"]["chromadb"] = check_chromadb()

    failures = [k for k, v in result["checks"].items() if not v.get("ok")]
    if failures:
        result["status"] = "degraded" if result["checks"]["sqlite"].get("ok") else "unhealthy"
        result["failed_checks"] = failures

    return result
