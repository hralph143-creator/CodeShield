from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path


LOG_NAME = "codeshield.log"
MAX_LOG_BYTES = 3 * 1024 * 1024
LOG_BACKUP_COUNT = 4

_REDACTIONS = (
    (re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)(\s*[:=]\s*)[^\s,;]+"), r"\1\2[MASKED]"),
    (re.compile(r"(?i)(?:mysql|postgresql|postgres|mongodb|redis)://[^\s:/@]+:[^\s/@]+@"), "database://***:***@"),
    (re.compile(r"(?<!\d)[1-9]\d{16}[0-9Xx](?!\d)"), "***ID-MASKED***"),
    (re.compile(r"-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----[\s\S]*?-----END \1-----"), "-----BEGIN PRIVATE KEY----- [MASKED]"),
)


def redact_log_text(value: object) -> str:
    text = str(value)
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


class SafeFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        original_msg, original_args = record.msg, record.args
        try:
            record.msg = redact_log_text(record.getMessage())
            record.args = ()
            return redact_log_text(super().format(record))
        finally:
            record.msg, record.args = original_msg, original_args


def configure_logging(data_dir: Path) -> Path:
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / LOG_NAME
    root = logging.getLogger()
    existing = next(
        (handler for handler in root.handlers if getattr(handler, "baseFilename", None) == str(log_path.resolve())),
        None,
    )
    if existing is None:
        handler = RotatingFileHandler(
            log_path,
            maxBytes=MAX_LOG_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(SafeFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        root.addHandler(handler)
    root.setLevel(logging.INFO)
    return log_path
