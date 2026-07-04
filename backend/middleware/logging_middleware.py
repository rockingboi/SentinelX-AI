"""
SentinelX AI — Request Logging Middleware
==========================================
Logs every request/response with timing, status, and correlation ID.
Injects X-Request-ID header into responses for traceability.
"""
from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Paths to skip from verbose logging (e.g. k8s liveness probes)
_SKIP_PATHS: frozenset[str] = frozenset({"/health", "/", "/favicon.ico"})


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that:
    - Assigns a unique X-Request-ID to every request
    - Logs method, path, status, duration, and client IP
    - Skips health-check paths from INFO logs (logs them at DEBUG)
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        # Attach request_id to request state for downstream use
        request.state.request_id = request_id

        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "Unhandled exception during request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                },
            )
            raise

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        status_code = response.status_code
        path = request.url.path
        client_ip = request.client.host if request.client else "unknown"

        log_fn = logger.debug if path in _SKIP_PATHS else logger.info
        log_fn(
            "HTTP %s %s → %s  [%.2fms]",
            request.method,
            path,
            status_code,
            duration_ms,
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "client_ip": client_ip,
                "user_agent": request.headers.get("user-agent", ""),
            },
        )

        # Inject tracing headers into response
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = str(duration_ms)

        return response
