from utils.logger import logger
from utils.system_status import write_status
import os
import time
import yaml
import feedparser
from datetime import datetime
from memory.chromadb_client import processed_urls_col
from pipeline.state import ThreatState
from pipeline.graph import build_graph
import uuid

ARTICLE_DELAY_SECONDS = int(os.getenv("ARTICLE_DELAY_SECONDS", "90"))  # wait between articles
MAX_ARTICLES_PER_CYCLE = int(os.getenv("MAX_ARTICLES_PER_CYCLE", "3"))  # cap per cycle

# Initialize LangGraph pipeline
app = build_graph()

from alerts.slack_alert import send_slack_alert
from alerts.email_alert import send_email_alert

import hashlib

def is_already_processed(url: str) -> bool:
    try:
        url_hash = hashlib.md5(url.encode()).hexdigest()
        result = processed_urls_col.get(ids=[url_hash])
        return len(result["ids"]) > 0
    except Exception:
        return False

def mark_as_processed(url: str, huntable: bool):
    url_hash = hashlib.md5(url.encode()).hexdigest()
    processed_urls_col.upsert(
        documents=[url],
        metadatas=[{
            "url": url,
            "processed_date": datetime.now().isoformat(),
            "huntable": huntable,
        }],
        ids=[url_hash],
    )

def run_pipeline(url: str) -> ThreatState:
    logger.info(f"\n[PIPELINE] Starting for: {url}")
    state: ThreatState = {
        "blog_url": url,
        "raw_html": "",
        "huntable": True,
        "clean_text": "",
        "behaviors": [],
        "iocs": {},
        "detection_angles": [],
        "similar_threats": [],
        "historical_kqls": [],
        "schema_snippets": {},
        "rag_context": "",
        "cot_reasoning": "",
        "detection_strategy": "",
        "sentinel_tables": [],
        "relevant_columns": {},
        "generated_queries": [],
        "validated_queries": [],
        "failed_queries": [],
        "validation_scores": {},
        "retry_counts": {},
        "coverage_gaps": [],
        "overall_coverage": "",
        "final_report": "",
        "severity_level": "",
        "alert_sent": False,
        "sigma_rules": [],
        "pipeline_run_id": "",
        "pipeline_start_time": datetime.now().isoformat(),
        "auto_fixed_columns": [],
        "validation_threshold_used": 0,
        "platform_queries": [],
        "coverage_report": {},
        "threat_id": "",
    }

    # Generate thread ID for checkpointing
    thread_id = str(uuid.uuid4())
    state["pipeline_run_id"] = thread_id
    config = {"configurable": {"thread_id": thread_id}}
    
    # Run the pipeline through LangGraph
    logger.info(f"Invoking LangGraph pipeline for Thread: {thread_id}")
    result = app.invoke(state, config=config)
    
    return result

def resume_failed_pipeline(thread_id: str):
    logger.info(f"Attempting to resume pipeline thread: {thread_id}")
    state = app.get_state({"configurable": {"thread_id": thread_id}})
    if state: 
        result = app.invoke(None, config={"configurable": {"thread_id": thread_id}})
        return result
    return None

def run_crawler_cycle():
    logger.info("=" * 60)
    logger.info(f" STARTING CRAWLER CYCLE: {datetime.now().isoformat()}")
    logger.info("=" * 60)

    write_status(pipeline_status="running", last_crawl_started_at=datetime.now().isoformat())
    
    # STEP 1: Load RSS URLs
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "feeds.yaml")
    if not os.path.exists(config_path):
        logger.info(f"Error: {config_path} not found.")
        return
        
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        
    feeds = config.get("RSS_FEEDS", [])
    processing_queue = []
    
    # STEP 2 & 3: Parse feeds and extract entry details
    for feed in feeds:
        feed_name = feed["name"]
        feed_url = feed["url"]
        logger.info(f"Checking feed: {feed_name}")
        
        try:
            parsed = feedparser.parse(feed_url)
            for entry in parsed.entries[:5]:  # Limit to top 5 per feed to avoid flooding
                url = getattr(entry, 'link', '')
                
                # STEP 4: Deduplication check
                if is_already_processed(url):
                    logger.info(f"duplicate skipped: {url}")
                else:
                    processing_queue.append({
                        "url": url,
                        "title": getattr(entry, 'title', ''),
                        "feed_name": feed_name
                    })
        except Exception as e:
            logger.info(f"Error parsing feed {feed_name}: {e}")
            
    # STEP 5: Log queue size — cap to MAX_ARTICLES_PER_CYCLE
    if len(processing_queue) > MAX_ARTICLES_PER_CYCLE:
        logger.info(f"Capping queue from {len(processing_queue)} to {MAX_ARTICLES_PER_CYCLE} articles (ARTICLE_DELAY_SECONDS={ARTICLE_DELAY_SECONDS}s each)")
        processing_queue = processing_queue[:MAX_ARTICLES_PER_CYCLE]
    logger.info(f"Found {len(processing_queue)} new articles to process")
    
    report_batch = []
    
    stats = {
        "processed": 0,
        "huntable": 0,
        "errors": 0,
        "alerts_sent": 0
    }
    
    # STEP 6: Process the queue
    for item in processing_queue:
        url = item["url"]
        stats["processed"] += 1
        try:
            state = run_pipeline(url)
            huntable = state.get("huntable", False)
            mark_as_processed(url, huntable)

            if huntable:
                stats["huntable"] += 1
                if state.get("final_report"):
                    report_batch.append({
                        "state": state,
                        "feed_name": item["feed_name"]
                    })
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
            stats["errors"] += 1
            # Do not mark failed URLs — they will be retried on the next crawl cycle

        # ── Wait between articles so Groq token quota resets ────────────────
        remaining = len(processing_queue) - stats["processed"]
        if remaining > 0:
            logger.info(f"[ARTICLE_DELAY] Sleeping {ARTICLE_DELAY_SECONDS}s before next article ({remaining} remaining)...")
            time.sleep(ARTICLE_DELAY_SECONDS)
            
    # STEP 7: Alerts processing
    if report_batch:
        for report in report_batch:
            state = report["state"]
            severity = state.get("severity_level", "LOW")
            
            if severity in ["CRITICAL", "HIGH"]:
                send_slack_alert(state, report["feed_name"])
                stats["alerts_sent"] += 1
                
            if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                send_email_alert(state)

            state["alert_sent"] = True
                
    # STEP 8: Empty queue logging
    if not processing_queue:
        logger.info("No new threats found in this cycle")
        
    logger.info("=" * 60)
    logger.info(f" CRAWLER CYCLE COMPLETE: {datetime.now().isoformat()}")
    logger.info(
        f" Stats: {stats['processed']} Processed | {stats['huntable']} Huntable | "
        f"{stats['alerts_sent']} Alerts Sent | {stats['errors']} Errors"
    )
    logger.info("=" * 60)

    write_status(
        pipeline_status="idle" if stats["errors"] == 0 else "degraded",
        last_crawl_at=datetime.now().isoformat(),
        last_crawl_stats=stats,
    )
