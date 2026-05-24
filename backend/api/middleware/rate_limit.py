"""
Rate Limiting Middleware.
Token bucket algorithm per IP + per user.
"""
import time
from collections import defaultdict
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory token bucket rate limiter."""

    def __init__(self, app, requests_per_minute: int = 300, burst: int = 200):
        super().__init__(app)
        self.rpm = requests_per_minute
        self.burst = burst
        self._buckets: dict = defaultdict(lambda: {"tokens": burst, "last": time.monotonic()})

    def _get_key(self, request: Request) -> str:
        user = getattr(request.state, "user", None)
        if user:
            return f"user:{user['id']}"
        return f"ip:{request.client.host}" if request.client else "ip:unknown"

    async def dispatch(self, request: Request, call_next) -> Response:
        key = self._get_key(request)
        bucket = self._buckets[key]
        now = time.monotonic()
        elapsed = now - bucket["last"]
        bucket["tokens"] = min(self.burst, bucket["tokens"] + elapsed * (self.rpm / 60))
        bucket["last"] = now

        if bucket["tokens"] < 1:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded. Retry after 1 second."},
                headers={"Retry-After": "1", "X-RateLimit-Limit": str(self.rpm)},
            )

        bucket["tokens"] -= 1
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(int(bucket["tokens"]))
        return response
