import requests
from utils.logger import logger
from pipeline.state import ThreatState
import time

def agent_1(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 1: DISCOVERY ---")
    
    if not state.get("huntable", True):
        logger.info("[Discovery] Skipping because article is marked non-huntable.")
        return state

    url = state.get("blog_url", "")
    if not url:
        logger.error("[Discovery] No URL provided.")
        state["huntable"] = False
        return state

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Fetching URL: {url} (Attempt {attempt+1}/{max_retries})")
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            state["raw_html"] = response.text
            logger.info("[Discovery] Successfully downloaded HTML.")
            return state
        except Exception as e:
            logger.warning(f"[Discovery] Fetch error: {e}")
            if attempt < max_retries - 1:
                time.sleep(3)
            else:
                logger.error("[Discovery] Failed to fetch URL after max retries.")
                state["huntable"] = False
                state["triage_reason"] = "Failed to fetch URL."
                
    return state