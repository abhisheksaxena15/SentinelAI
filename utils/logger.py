# utils/logger.py
# ─── Structured console logger ────────────────────────────────────────────────

import logging
import sys

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=DATE_FORMAT,
    handlers=[logging.StreamHandler(sys.stdout)],
)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
