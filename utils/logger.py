import logging
import os
import sys
from logging.handlers import RotatingFileHandler

def setup_logger():
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "autothreat.log")

    logger = logging.getLogger("autothreat")
    logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

    # Avoid duplicate handlers on reimport
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(module)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Rotating file handler — 10 MB max, keep 5 backups
    if os.getenv("LOG_TO_FILE", "True").lower() in ("true", "1", "yes"):
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger

logger = setup_logger()
