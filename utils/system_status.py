import json
import os
from datetime import datetime, timezone

STATUS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "system_status.json")


def _ensure_dir():
    os.makedirs(os.path.dirname(STATUS_PATH), exist_ok=True)


def write_status(**fields):
    """Persist operational status for dashboard and health checks."""
    _ensure_dir()
    payload = {}
    if os.path.exists(STATUS_PATH):
        try:
            with open(STATUS_PATH, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (json.JSONDecodeError, OSError):
            payload = {}

    payload.update(fields)
    payload["updated_at"] = datetime.now(timezone.utc).isoformat()

    with open(STATUS_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def read_status() -> dict:
    if not os.path.exists(STATUS_PATH):
        return {
            "pipeline_status": "unknown",
            "last_crawl_at": None,
            "last_crawl_stats": {},
            "api_status": "unknown",
        }
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"pipeline_status": "error", "last_crawl_at": None}
