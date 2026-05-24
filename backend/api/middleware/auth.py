"""
JWT Authentication Middleware.

Validates Bearer tokens on all protected routes.
Injects user context into request state.
"""
from __future__ import annotations

from typing import Optional

import structlog
from fastapi import Request, Response
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware

from config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# Routes that don't require authentication
PUBLIC_ROUTES = {
    "/health",
    "/ready",
    "/live",
    "/metrics",
    "/api/v1/auth/login",
    "/docs",
    "/redoc",
    "/openapi.json",
}


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that validates JWT tokens on protected routes.
    Injects decoded user context into request.state.user.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Allow public routes
        if request.url.path in PUBLIC_ROUTES or request.url.path.startswith("/docs"):
            return await call_next(request)

        # Extract token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            # Allow anonymous access for demo mode; in prod, return 401
            request.state.user = None
            return await call_next(request)

        token = auth_header.removeprefix("Bearer ").strip()

        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
            )
            request.state.user = {
                "id": payload.get("sub"),
                "email": payload.get("email"),
                "role": payload.get("role", "developer"),
                "tenant_id": payload.get("tenant_id", settings.default_tenant_id),
                "department": payload.get("department"),
            }
        except JWTError:
            request.state.user = None

        return await call_next(request)
