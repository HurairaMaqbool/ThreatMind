import re
from bs4 import BeautifulSoup
from utils.logger import logger
from pipeline.state import ThreatState
from datetime import datetime

def agent_2(state: ThreatState) -> ThreatState:
    logger.info("--- AGENT 2: EXTRACTION ---")
    
    if not state.get("huntable", True) or not state.get("raw_html"):
        return state

    html = state.get("raw_html", "")
    soup = BeautifulSoup(html, "html.parser")
    
    # Extract Title
    title = soup.title.string if soup.title else "Unknown Title"
    state["article_title"] = title.strip()
    
    # Try to find a date
    date_str = "Unknown Date"
    date_meta = soup.find("meta", {"property": "article:published_time"}) or \
                soup.find("meta", {"name": "date"}) or \
                soup.find("time")
    if date_meta:
        date_str = date_meta.get("content") or date_meta.get("datetime") or date_meta.text
    state["published_date"] = date_str.strip()[:50]
    
    # Remove scripts, styles, nav, headers, footers
    for element in soup(["script", "style", "nav", "header", "footer", "aside"]):
        element.decompose()
        
    # Get text
    text = soup.get_text(separator="\n")
    
    # Clean text (collapse multiple newlines/spaces)
    text = re.sub(r'\n+', '\n', text)
    text = re.sub(r' +', ' ', text)
    clean_text = text.strip()
    
    # Truncate to 8000 characters to fit in prompt limits comfortably
    if len(clean_text) > 8000:
        clean_text = clean_text[:8000] + "\n...[TRUNCATED]"
        
    state["clean_text"] = clean_text
    logger.info(f"[Extraction] Title: {state['article_title']}")
    logger.info(f"[Extraction] Clean Text Length: {len(clean_text)}")
    
    return state