import os
from dotenv import load_dotenv

load_dotenv()

SCHEMA_VERSION = os.getenv("SCHEMA_VERSION", "v3")

# Pipeline Delays
DELAY_BETWEEN_LIGHT_AGENTS = int(os.getenv("DELAY_BETWEEN_LIGHT_AGENTS", "1"))
DELAY_BETWEEN_HEAVY_AGENTS = int(os.getenv("DELAY_BETWEEN_HEAVY_AGENTS", "5"))
