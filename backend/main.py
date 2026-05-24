"""
AI Context Firewall — FastAPI Backend
Main application entry point.
"""
from __future__ import annotations

import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure backend package is on path
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS = True
except ImportError:
    PROMETHEUS = False

# ---------------------------------------------------------------------------
# Import routes
# ---------------------------------------------------------------------------

from api.routes import auth, scan, health
from api.routes import policies, audit, admin, gateway, rag, agents

try:
    from api.middleware.audit_log import AuditLogMiddleware
    AUDIT_MW = True
except Exception:
    AUDIT_MW = False

try:
    from api.middleware.rate_limit import RateLimitMiddleware
    RATE_MW = True
except Exception:
    RATE_MW = False

# ---------------------------------------------------------------------------
# Prometheus metrics (optional)
# ---------------------------------------------------------------------------

if PROMETHEUS:
    REQUEST_COUNT = Counter("firewall_requests_total", "Total HTTP requests", ["method", "status"])
    REQUEST_LATENCY = Histogram("firewall_request_duration_seconds", "Request latency", ["endpoint"])
else:
    class _Noop:
        def labels(self, **kw): return self
        def inc(self): pass
        def observe(self, v): pass
    REQUEST_COUNT = REQUEST_LATENCY = _Noop()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[ACF] AI Context Firewall starting up…")
    yield
    print("[ACF] AI Context Firewall shut down.")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    env = os.getenv("ENVIRONMENT", "development")
    debug = env in ("development", "test")

    app = FastAPI(
        title       = "AI Context Firewall",
        description = "Enterprise-grade AI security middleware.",
        version     = "1.0.0",
        docs_url    = "/docs",
        redoc_url   = "/redoc",
        lifespan    = lifespan,
    )

    # CORS
    allowed_origins = os.getenv("CORS_ORIGINS", '["*"]')
    try:
        import json
        origins = json.loads(allowed_origins)
    except Exception:
        origins = ["*"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins     = origins,
        allow_credentials = True,
        allow_methods     = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers     = ["Authorization", "Content-Type", "X-Tenant-ID", "X-Request-ID"],
        expose_headers    = ["X-Request-ID", "X-Risk-Score", "X-Response-Time"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    if RATE_MW:
        try:
            app.add_middleware(RateLimitMiddleware)
        except Exception:
            pass

    if AUDIT_MW:
        try:
            app.add_middleware(AuditLogMiddleware)
        except Exception:
            pass

    # Routers — both bare and /api/v1 prefixed for flexibility
    for prefix in ("", "/api/v1"):
        app.include_router(health.router,    tags=["Health"])
        app.include_router(auth.router,      prefix=f"{prefix}/auth",     tags=["Auth"])
        app.include_router(scan.router,      prefix=f"{prefix}/scan",     tags=["Scan"])
        app.include_router(policies.router,  prefix=f"{prefix}/policies", tags=["Policies"])
        app.include_router(audit.router,     prefix=f"{prefix}/audit",    tags=["Audit"])
        app.include_router(admin.router,     prefix=f"{prefix}/admin",    tags=["Admin"])
        app.include_router(gateway.router,   prefix=f"{prefix}/gateway",  tags=["Gateway"])
        app.include_router(rag.router,       prefix=f"{prefix}/rag",      tags=["RAG"])
        app.include_router(agents.router,    prefix=f"{prefix}/agents",   tags=["Agents"])

    # Prometheus metrics
    if PROMETHEUS:
        @app.get("/metrics", include_in_schema=False)
        async def metrics():
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # Request timing
    @app.middleware("http")
    async def timing_middleware(request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start
        response.headers["X-Response-Time"] = f"{duration * 1000:.1f}ms"
        return response

    # Global error handler
    @app.exception_handler(Exception)
    async def global_error_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(exc) if debug else ""},
        )

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host    = "0.0.0.0",
        port    = 8000,
        reload  = os.getenv("ENVIRONMENT", "development") == "development",
        workers = int(os.getenv("WORKERS", "1")),
    )
