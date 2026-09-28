"""Structured, redacted run probes used by the WebUI pipeline.

The logger remains the live human-readable channel. This module adds a small
machine-readable channel so a failed stage can be located from the run record
without exposing passwords, OTPs, cookies, or bearer tokens.
"""
from __future__ import annotations

import logging
import re
import time
from contextlib import contextmanager
from copy import copy
from functools import wraps
from typing import Any, Iterator, Mapping
from uuid import uuid4

from . import db

logger = logging.getLogger("webui.probes")

_SECRET_KEY = re.compile(
    r"(?:password|passwd|token|secret|cookie|authorization|otp|code|api[_-]?key|refresh)",
    re.IGNORECASE,
)
_NETWORK_MARKERS = (
    "timeout", "timed out", "connection", "proxy", "socks", "dns", "tls", "ssl",
    "cloudflare", "network", "出口", "环境",
)

_OPERATION_HISTORY: list[dict[str, Any]] = []
_OPERATION_HISTORY_LIMIT = 500
_SENSITIVE_ERROR_VALUE = re.compile(
    r"(?i)(?:bearer\s+|\b(?:[\w-]*(?:token|password|passwd|secret|api[_-]?key)|pw|totp|otp|code)"
    r"[\"']?\s*[=:]\s*)(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
_COOKIE_VALUE = re.compile(r"(?i)(?:set-cookie|cookie|authorization)[\"']?\s*[=:]\s*[^\r\n]+")
_URL_CREDENTIALS = re.compile(r"(?i)(https?|socks5h?)://[^/\s@]+@")
_OTP_VALUE = re.compile(r"\b\d{6}\b")
_API_EMAIL_SEGMENT = re.compile(r"^[^/\s@]+@[^/\s@]+$")
_API_HEX_ID_SEGMENT = re.compile(r"^[0-9a-f]{8,64}$", re.IGNORECASE)
_API_LONG_ID_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{20,}$")


def classify_probe_error(error: BaseException | str) -> str:
    text = str(error or "").lower()
    if any(marker in text for marker in _NETWORK_MARKERS):
        return "network"
    return "unknown"


def _redact(value: Any, *, key: str = "") -> Any:
    if key == "status_code" and type(value) is int:
        return value
    if key == "country_code" and isinstance(value, str) and re.fullmatch(r"[A-Za-z]{2}", value):
        return value
    if key.endswith(("_present", "_len")) and isinstance(value, (bool, int)):
        return value
    if _SECRET_KEY.search(key):
        if value in (None, ""):
            return False
        return {"present": True, "length": len(str(value))}
    if isinstance(value, Mapping):
        return {str(k): _redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value[:20]]
    if isinstance(value, str):
        return _redact_error(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return _redact_error(str(value))


def redact_log_message(value: BaseException | str) -> str:
    text = str(value or "")
    text = _COOKIE_VALUE.sub("[redacted]", text)
    text = _URL_CREDENTIALS.sub(r"\1://[redacted]@", text)
    text = _SENSITIVE_ERROR_VALUE.sub("[redacted]", text)
    return _OTP_VALUE.sub("[redacted]", text)


class RedactingFormatter(logging.Formatter):
    """Scrub rendered tracebacks as well as messages without changing shared records."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_log_message(super().format(copy(record)))


def _redact_error(value: BaseException | str) -> str:
    return redact_log_message(value)[:240]


def redact_probe_error(value: BaseException | str) -> str:
    """Return a short error suitable for logs and operation snapshots."""
    return _redact_error(value)


def normalize_api_path(path: str) -> str:
    """Replace dynamic API path values before using a route as an operation key."""
    segments = []
    for segment in str(path or "").split("/"):
        if not segment:
            continue
        if _API_EMAIL_SEGMENT.match(segment):
            segment = "{email}"
        elif _API_HEX_ID_SEGMENT.match(segment) or _API_LONG_ID_SEGMENT.match(segment):
            segment = "{id}"
        segments.append(segment)
    return "/" + "/".join(segments)


class ProbeSession:
    """Append structured stage events for one run."""

    def __init__(self, run_id: str):
        self.run_id = str(run_id or "")
        self._active: dict[str, float] = {}

    def mark(
        self,
        stage: str,
        status: str,
        *,
        duration_ms: int | None = None,
        error: BaseException | str | None = None,
        error_category: str = "",
        **details: Any,
    ) -> dict[str, Any]:
        if status != "started" and duration_ms is None and str(stage) in self._active:
            duration_ms = int((time.perf_counter() - self._active[str(stage)]) * 1000)
        event: dict[str, Any] = {
            "event_id": uuid4().hex[:12],
            "stage": str(stage),
            "status": str(status),
            "timestamp": time.time(),
        }
        if duration_ms is not None:
            event["duration_ms"] = max(0, int(duration_ms))
        if error is not None:
            event["error"] = _redact_error(error)
            event["error_category"] = error_category or classify_probe_error(error)
        if details:
            event["details"] = _redact(details)
        if status == "started":
            self._active[str(stage)] = time.perf_counter()
        elif status in {"ok", "failed", "partial", "skipped", "cancelled"}:
            self._active.pop(str(stage), None)
        if self.run_id:
            try:
                db.record_run_probe(self.run_id, event)
            except Exception as exc:  # noqa: BLE001
                logger.debug("记录探针失败 run=%s stage=%s: %s", self.run_id, stage, exc)
        logger.info(
            "[probe] run=%s stage=%s status=%s duration_ms=%s%s",
            self.run_id or "-",
            stage,
            status,
            event.get("duration_ms", "-"),
            f" error={event['error'][:120]}" if "error" in event else "",
        )
        return event

    @contextmanager
    def step(self, stage: str, **details: Any) -> Iterator[None]:
        started = time.perf_counter()
        self.mark(stage, "started", **details)
        try:
            yield
        except Exception as exc:
            self.mark(
                stage,
                "failed",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=exc,
                **details,
            )
            raise
        else:
            self.mark(
                stage,
                "ok",
                duration_ms=int((time.perf_counter() - started) * 1000),
                **details,
            )

    def fail_open(self, error: BaseException | str = "task ended before stage completion") -> None:
        """Close stages that were started before an unexpected early exit."""
        for stage, started in list(self._active.items()):
            self.mark(
                stage,
                "failed",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=error,
            )


def record_operation_probe(
    operation: str,
    status: str,
    *,
    duration_ms: int | None = None,
    error: BaseException | str | None = None,
    **details: Any,
) -> dict[str, Any]:
    """Log a structured probe for non-run operations (check/export/rebind)."""
    event: dict[str, Any] = {
        "operation": str(operation),
        "status": str(status),
        "timestamp": time.time(),
    }
    if error is not None:
        event["error"] = _redact_error(error)
        event["error_category"] = classify_probe_error(error)
    if duration_ms is not None:
        event["duration_ms"] = max(0, int(duration_ms))
    if details:
        event["details"] = _redact(details)
    _OPERATION_HISTORY.append(dict(event))
    if len(_OPERATION_HISTORY) > _OPERATION_HISTORY_LIMIT:
        del _OPERATION_HISTORY[:-_OPERATION_HISTORY_LIMIT]
    try:
        db.record_operation_probe(event)
    except Exception as exc:  # noqa: BLE001
        # Diagnostics must never break the operation they observe. The in-memory
        # history remains available when a read-only or legacy database fails.
        logger.debug("持久化操作探针失败 operation=%s: %s", operation, exc)
    logger.info("[probe] operation=%s status=%s", operation, status)
    return event


def list_operation_probes(limit: int = 100, operation: str = "") -> list[dict[str, Any]]:
    """Return recent persisted operation probes, with memory as a fallback."""
    count = max(1, min(int(limit or 100), _OPERATION_HISTORY_LIMIT))
    wanted = str(operation or "").strip()
    try:
        persisted = db.list_operation_probes(count, wanted)
    except Exception as exc:  # noqa: BLE001
        logger.debug("读取持久化操作探针失败: %s", exc)
        persisted = []
    if persisted:
        return persisted
    items = _OPERATION_HISTORY
    if wanted:
        items = [item for item in items if item.get("operation") == wanted]
    return [dict(item) for item in items[-count:]]


@contextmanager
def operation_probe(operation: str, **details: Any) -> Iterator[dict[str, Any]]:
    """Emit started/ok/failed events for an operation outside a run row."""
    started = time.perf_counter()
    record_operation_probe(operation, "started", **details)
    try:
        yield details
    except Exception as exc:
        record_operation_probe(
            operation,
            "failed",
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=exc,
            **details,
        )
        raise
    else:
        record_operation_probe(
            operation,
            "ok",
            duration_ms=int((time.perf_counter() - started) * 1000),
            **details,
        )


def instrument_method(
    target: Any,
    method_name: str,
    probe: ProbeSession,
    stage: str,
    *,
    capture_first_arg: bool = False,
    false_is_failure: bool = False,
) -> Any:
    """Wrap one provider callback while preserving its public method shape."""
    original = getattr(target, method_name, None)
    if not callable(original):
        return target
    if getattr(original, "_probe_instrumented", False):
        return target

    @wraps(original)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        details: dict[str, Any] = {}
        if capture_first_arg and args and isinstance(args[0], str):
            details["email"] = args[0]
        probe.mark(stage, "started", **details)
        try:
            result = original(*args, **kwargs)
        except Exception as exc:
            probe.mark(
                stage,
                "failed",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=exc,
                **details,
            )
            raise
        probe.mark(
            stage,
            "failed" if false_is_failure and result is False else "ok",
            duration_ms=int((time.perf_counter() - started) * 1000),
            error="operation returned false" if false_is_failure and result is False else None,
            **details,
        )
        return result

    wrapped._probe_instrumented = True
    setattr(target, method_name, wrapped)
    return target


def probed_operation(operation: str):
    """Decorate a synchronous API operation with started/ok/failed events."""
    def decorator(function: Any) -> Any:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            record_operation_probe(operation, "started")
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                record_operation_probe(
                    operation,
                    "failed",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    error=exc,
                )
                raise
            failed_result = isinstance(result, Mapping) and result.get("ok") is False
            record_operation_probe(
                operation,
                "failed" if failed_result else "ok",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=(
                    result.get("error")
                    or result.get("message")
                    or "operation returned ok=false"
                ) if failed_result else None,
            )
            return result
        return wrapped
    return decorator


__all__ = [
    "ProbeSession",
    "classify_probe_error",
    "instrument_method",
    "list_operation_probes",
    "normalize_api_path",
    "operation_probe",
    "probed_operation",
    "record_operation_probe",
    "redact_probe_error",
    "redact_log_message",
]
