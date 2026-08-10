import json
import re
from utils.logger import logger
import os

def safe_parse_json(
    raw_text: str,
    expected_type: str = "dict",
    agent_name: str = "unknown",
    save_failures: bool = True
):
    if not raw_text:
        return {} if expected_type == "dict" else []

    def validate_type(data):
        if expected_type == "dict" and isinstance(data, dict): return data
        if expected_type == "list" and isinstance(data, list): return data
        if expected_type == "dict" and isinstance(data, list): return data[0] if len(data) > 0 and isinstance(data[0], dict) else {}
        if expected_type == "list" and isinstance(data, dict): return [data]
        return data

    try: return validate_type(json.loads(raw_text))
    except: pass

    clean = raw_text.strip()
    if clean.startswith("```json"): clean = clean[7:]
    elif clean.startswith("```"): clean = clean[3:]
    if clean.endswith("```"): clean = clean[:-3]
    try: return validate_type(json.loads(clean.strip()))
    except: pass

    start_idx, end_idx = -1, -1
    for i, char in enumerate(raw_text):
        if char in ("{", "["):
            start_idx = i; break
    if start_idx != -1:
        for i in range(len(raw_text)-1, -1, -1):
            if raw_text[i] in ("}", "]"):
                end_idx = i; break
        if end_idx != -1 and end_idx >= start_idx:
            try: return validate_type(json.loads(raw_text[start_idx:end_idx+1]))
            except: pass

    logger.error(f"JSON parse failed for {agent_name}. Expected {expected_type}")
    if save_failures:
        os.makedirs("data/failures", exist_ok=True)
        with open(f"data/failures/{agent_name}_fail.txt", "a", encoding="utf-8") as f:
            f.write(raw_text + "\n---\n")

    return {} if expected_type == "dict" else []
