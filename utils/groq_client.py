import os
import json
import time
import re
from dotenv import load_dotenv
from groq import Groq
from utils.logger import logger

load_dotenv(override=True)

GROQ_MODEL_LIGHT = "llama-3.1-8b-instant"
GROQ_MODEL_HEAVY = "llama-3.3-70b-versatile"
# Default to LIGHT model for all agents — free tier has strict token limits
GROQ_MODEL_DEFAULT = GROQ_MODEL_LIGHT

def get_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is not set")
    return Groq(api_key=api_key)

def call_groq_with_retry(
    agent_name: str,
    prompt: str,
    model: str = GROQ_MODEL_DEFAULT,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    max_retries: int = 3,
    response_format: dict = None
) -> str:
    client = get_client()
    messages = [{"role": "user", "content": prompt}]
    
    for attempt in range(max_retries):
        try:
            kwargs = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature
            }
            if response_format:
                kwargs["response_format"] = response_format
                
            response = client.chat.completions.create(**kwargs)
            return response.choices[0].message.content
            
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "rate limit" in error_msg.lower() or "413" in error_msg:
                wait_time = 30 * (attempt + 1)
                logger.warning(
                    f"[{agent_name}] Rate/token limit hit. Waiting {wait_time}s... "
                    f"(Attempt {attempt+1}/{max_retries})"
                )
                time.sleep(wait_time)
            elif "502" in error_msg or "503" in error_msg:
                wait_time = 5 * (attempt + 1)
                logger.warning(f"[{agent_name}] Service unavailable. Waiting {wait_time}s... (Attempt {attempt+1}/{max_retries})")
                time.sleep(wait_time)
            else:
                logger.error(f"[{agent_name}] Groq API error: {error_msg}")
                if attempt == max_retries - 1:
                    raise
                time.sleep(2)
                
    raise RuntimeError(f"[{agent_name}] Max retries exceeded")

def safe_parse_json(text: str, expected_type: str = "dict", agent_name: str = "unknown"):
    text = text.strip()
    
    # Strip markdown code blocks
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
        
    text = text.strip()
    
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning(f"[{agent_name}] Direct JSON parsing failed. Attempting regex fallback.")
        
        try:
            if expected_type == "dict":
                match = re.search(r'\{.*\}', text, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
                return {}
            elif expected_type == "list":
                match = re.search(r'\[.*\]', text, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
                return []
        except Exception as e:
            logger.error(f"[{agent_name}] Regex fallback JSON parsing failed: {e}")
            
    return {} if expected_type == "dict" else []
