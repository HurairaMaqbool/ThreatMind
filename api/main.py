import os
import sys
import re
import threading
import traceback
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv(override=True)

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

REQUIRED_ENV = ["GROQ_API_KEY"]
missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
if missing:
    raise RuntimeError(f"STARTUP ERROR: Missing required env vars: {missing}. Set them in .env")

MIN_SCORE = int(os.environ.get("MIN_VALIDATION_SCORE", "70"))
if not (0 <= MIN_SCORE <= 100):
    raise RuntimeError(f"STARTUP ERROR: MIN_VALIDATION_SCORE={MIN_SCORE} must be 0–100")

PRIVATE_IP_RE = re.compile(
    r"^https?://(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|0\.0\.0\.0)"
)

API_KEY = os.environ.get("AUTOTHREAT_API_KEY", "")

from memory.chromadb_client import threat_reports_col, kql_library_col, get_threat_by_id
from memory.sqlite_client import init_db, get_query_stats, list_queries
from memory.migrations import run_all_migrations
from scheduler.crawler import run_pipeline, mark_as_processed
from utils.system_status import write_status, read_status
from utils.health import full_health

_rate_lock = threading.Lock()
_rate_map: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    migration = run_all_migrations()
    write_status(api_status="online", startup_migration=migration)
    yield
    write_status(api_status="offline")


app = FastAPI(
    title="ThreatMind API",
    version="3.0",
    description="Autonomous Cyber Threat Intelligence — REST API for threats, KQL, and pipeline control",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _check_rate_limit(ip: str, max_per_min: int = 5) -> bool:
    import time

    now = time.time()
    with _rate_lock:
        timestamps = [t for t in _rate_map.get(ip, []) if now - t < 60]
        if len(timestamps) >= max_per_min:
            return False
        timestamps.append(now)
        _rate_map[ip] = timestamps
    return True


@app.get("/health")
def health_check():
    return full_health(deep=False)


@app.get("/ready")
def readiness_check():
    """Deep health check for Docker/K8s readiness probes."""
    result = full_health(deep=True)
    if result["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail=result)
    return result


@app.get("/threats")
def list_threats(limit: int = Query(default=50, ge=1, le=500)):
    try:
        results = threat_reports_col.get()
        threats = []
        for i, meta in enumerate(results.get("metadatas", []) or []):
            threats.append(
                {
                    "id": results["ids"][i] if results.get("ids") else None,
                    "metadata": meta,
                }
            )
        threats.sort(key=lambda t: (t.get("metadata") or {}).get("date", ""), reverse=True)
        return {"threats": threats[:limit], "count": len(threats)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/threats/{threat_id}")
def get_threat(threat_id: str):
    try:
        threat = get_threat_by_id(threat_id)
        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat not found: {threat_id}")
        queries = list_queries(limit=100, threat_id=threat_id)
        return {"threat": threat, "queries": queries, "query_count": len(queries)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/queries")
def get_queries(
    limit: int = Query(default=50, ge=1, le=500),
    platform: str | None = None,
    threat_id: str | None = None,
):
    try:
        rows = list_queries(limit=limit, platform=platform, threat_id=threat_id)
        return {"queries": rows, "count": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/kql/{angle_id}")
def get_kql(angle_id: str):
    try:
        results = kql_library_col.get(ids=[angle_id])
        if not results or not results.get("ids"):
            raise HTTPException(status_code=404, detail=f"KQL not found: {angle_id}")
        return {
            "angle_id": angle_id,
            "kql": results["documents"][0] if results.get("documents") else "",
            "metadata": results["metadatas"][0] if results.get("metadatas") else {},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/trigger")
def trigger_pipeline(
    url: str,
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(default=""),
):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")

    if not url:
        raise HTTPException(status_code=422, detail="url parameter is required")

    if not url.startswith("https://"):
        raise HTTPException(status_code=400, detail="URL must start with https://")
    if PRIVATE_IP_RE.match(url):
        raise HTTPException(status_code=400, detail="Private/internal URLs are not allowed")

    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 5 requests per minute")

    def run_and_save(u: str):
        try:
            write_status(pipeline_status="running")
            state = run_pipeline(u)
            huntable = state.get("huntable", False)
            mark_as_processed(u, huntable)
            write_status(
                pipeline_status="idle",
                last_crawl_at=datetime.utcnow().isoformat(),
                last_crawl_stats={
                    "processed": 1,
                    "huntable": 1 if huntable else 0,
                    "errors": 0,
                    "alerts_sent": 0,
                    "source": "api_trigger",
                },
            )
        except Exception:
            import logging

            logging.getLogger("autothreat").error(
                f"Background pipeline FAILED for {u}:\n{traceback.format_exc()}"
            )
            write_status(
                pipeline_status="error",
                last_crawl_stats={"processed": 1, "huntable": 0, "errors": 1, "source": "api_trigger"},
            )

    background_tasks.add_task(run_and_save, url)
    return {"status": "accepted", "message": f"Pipeline triggered for {url}"}


@app.get("/stats")
def get_stats():
    sqlite_stats = get_query_stats()
    status = read_status()
    chroma_count = 0
    try:
        chroma_count = threat_reports_col.count()
    except Exception:
        pass

    return {
        "threats_count": sqlite_stats["threats"] or chroma_count,
        "kql_count": sqlite_stats["total"],
        "platforms_count": sqlite_stats["platforms"],
        "chroma_threats": chroma_count,
        "chroma_kql": kql_library_col.count(),
        "status": "online",
        "pipeline_status": status.get("pipeline_status"),
        "last_crawl_at": status.get("last_crawl_at"),
        "last_crawl_stats": status.get("last_crawl_stats", {}),
        "min_validation_score": MIN_SCORE,
    }
