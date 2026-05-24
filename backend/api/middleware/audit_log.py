"""
Audit Logging Middleware.
Logs every request/response to structured audit log.
"""
import time
import uuid
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger(__name__)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Middleware to produce structured audit log entries for every request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
        start = time.monotonic()

        response = await call_next(request)

        duration_ms = (time.monotonic() - start) * 1000
        user = getattr(request.state, "user", None)

        logger.info(
            "http_request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round(duration_ms, 2),
            user_id=user.get("id") if user else None,
            tenant_id=user.get("tenant_id") if user else None,
            ip=request.client.host if request.client else None,
        )

        response.headers["X-Request-ID"] = request_id
        return response
