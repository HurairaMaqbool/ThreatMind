import sys
import json
from pipeline.state import ThreatState
from agents.agent_01_discovery import agent_1
from agents.agent_02_extraction import agent_2
from agents.agent_03_threat_intel import agent_3

def run_test():
    # BleepingComputer sometimes blocks Python requests (Cloudflare), 
    # so we'll use the proven Midnight Blizzard report from Microsoft.
    test_url = "https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/"
    
    # Initialize a blank state with our target URL
    # (Notice how Agent 1 expects 'blog_url' as input, not raw_html)
    state: ThreatState = {
        "blog_url": test_url,
        "huntable": True, # Pretend Agent 0 already approved it
        "clean_text": "",
        "article_title": "",
        "published_date": "",
        "behaviors": [],
        "iocs": {}
    }
    
    print("="*60)
    print(" STARTING MODULE 4 TEST: CORE EXTRACTION PIPELINE")
    print("="*60)
    
    # 1. Run Discovery Agent
    state = agent_1(state)
    if state.get("huntable") is False:
        print("Pipeline stopped at Agent 1.")
        return
        
    # 2. Run Behavior Extraction Agent
    state = agent_2(state)
    
    # 3. Run Threat Intel Agent
    state = agent_3(state)
    
    # Print the final output to verify Success Criteria
    print("\n" + "="*60)
    print(" FINAL STATE OUTPUT (Behaviors & IOCs)")
    print("="*60)
    
    print(f"\nArticle Title: {state.get('article_title')}")
    print(f"Published: {state.get('published_date')}\n")
    
    print("--- EXTRACTED BEHAVIORS (Agent 2) ---")
    print(json.dumps(state.get("behaviors", []), indent=2))
    
    print("\n--- EXTRACTED IOCs & CONTEXT (Agent 3) ---")
    print(json.dumps(state.get("iocs", {}), indent=2))
    
if __name__ == "__main__":
    run_test()
