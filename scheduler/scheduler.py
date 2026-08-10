from utils.logger import logger
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from apscheduler.schedulers.blocking import BlockingScheduler
from scheduler.crawler import run_crawler_cycle
from datetime import datetime
from dotenv import load_dotenv

load_dotenv(override=True)

if not os.environ.get("GROQ_API_KEY"):
    logger.error("STARTUP ERROR: GROQ_API_KEY is not set. Scheduler cannot run.")
    raise SystemExit(1)

CRAWL_INTERVAL_HOURS = int(os.getenv("CRAWL_INTERVAL_HOURS", "6"))


def start_scheduler():
    scheduler = BlockingScheduler()

    scheduler.add_job(
        func=run_crawler_cycle,
        trigger="interval",
        hours=CRAWL_INTERVAL_HOURS,
        id="autothreat_crawler",
        name=f"AutoThreat {CRAWL_INTERVAL_HOURS}-hour crawler",
    )

    scheduler.add_job(
        func=run_crawler_cycle,
        trigger="date",
        run_date=datetime.now(),
        id="autothreat_startup",
    )

    logger.info(f"AutoThreat scheduler started. Crawl interval: every {CRAWL_INTERVAL_HOURS} hours.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    start_scheduler()
