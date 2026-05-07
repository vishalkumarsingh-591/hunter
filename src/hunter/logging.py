from __future__ import annotations

import logging
import sys
from contextvars import ContextVar

import structlog

_scan_id: ContextVar[str] = ContextVar("scan_id", default="")
_trace_id: ContextVar[str] = ContextVar("trace_id", default="")


def set_scan_context(*, scan_id: str = "", trace_id: str = "") -> None:
    if scan_id:
        _scan_id.set(scan_id)
    if trace_id:
        _trace_id.set(trace_id)


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        timestamper,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        _inject_ids,
    ]
    if json_logs:
        shared.append(structlog.processors.JSONRenderer())
    else:
        shared.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=shared,
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper(), logging.INFO)),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def _inject_ids(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    sid = _scan_id.get()
    tid = _trace_id.get()
    if sid:
        event_dict["scan_id"] = sid
    if tid:
        event_dict["trace_id"] = tid
    return event_dict


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
