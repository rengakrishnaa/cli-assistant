"""Logging that cannot leak: every formatted record, tracebacks included, is redacted."""

from __future__ import annotations

import logging
import os

from .redactor import redact_text


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


def get_logger(name: str = "local_ai") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()  # stderr; no log file by default
        handler.setFormatter(RedactingFormatter("local-ai %(levelname)s: %(message)s"))
        logger.addHandler(handler)
        debug = os.environ.get("LOCAL_AI_DEBUG") == "1"
        logger.setLevel(logging.DEBUG if debug else logging.WARNING)
        logger.propagate = False
    return logger
