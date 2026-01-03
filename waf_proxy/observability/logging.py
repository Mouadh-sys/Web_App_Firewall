"""Structured JSON logging for WAF observability."""
import logging
import json
import sys
from typing import Optional, Dict, Any


class JSONFormatter(logging.Formatter):
    """Formatter that outputs JSON-structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.

        Args:
            record: Python log record

        Returns:
            JSON string
        """
        log_obj: Dict[str, Any] = {
            'level': record.levelname,
            'message': record.getMessage(),
            'timestamp': self.formatTime(record, self.datefmt),
            'logger': record.name,
        }

        # Add exception info if present
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)

        # Add custom fields if present in record
        if hasattr(record, 'request_id'):
            log_obj['request_id'] = record.request_id
        if hasattr(record, 'client_ip'):
            log_obj['client_ip'] = record.client_ip
        if hasattr(record, 'method'):
            log_obj['method'] = record.method
        if hasattr(record, 'path'):
            log_obj['path'] = record.path
        if hasattr(record, 'status'):
            log_obj['status'] = record.status
        if hasattr(record, 'verdict'):
            log_obj['verdict'] = record.verdict
        if hasattr(record, 'score'):
            log_obj['score'] = record.score
        if hasattr(record, 'rule_ids'):
            log_obj['rule_ids'] = record.rule_ids
        if hasattr(record, 'upstream'):
            log_obj['upstream'] = record.upstream
        if hasattr(record, 'latency_ms'):
            log_obj['latency_ms'] = record.latency_ms

        return json.dumps(log_obj)


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure JSON logging for the application.

    Args:
        level: Logging level (default: INFO)
    """
    # Get root logger
    root_logger = logging.getLogger()

    # Remove existing handlers to prevent duplication
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create and configure stream handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root_logger.setLevel(level)
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class RequestContextFilter(logging.Filter):
    """
    Filter that adds request context to log records.

    Use: logger.addFilter(RequestContextFilter(request_id, client_ip, ...))
    """

    def __init__(
        self,
        request_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None
    ):
        super().__init__()
        self.request_id = request_id
        self.client_ip = client_ip
        self.method = method
        self.path = path

    def filter(self, record: logging.LogRecord) -> bool:
        """Add context fields to record."""
        if self.request_id:
            record.request_id = self.request_id
        if self.client_ip:
            record.client_ip = self.client_ip
        if self.method:
            record.method = self.method
        if self.path:
            record.path = self.path
        return True

