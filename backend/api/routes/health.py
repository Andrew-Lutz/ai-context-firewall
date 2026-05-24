"""
Health Check Routes.
"""
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str
    services: dict


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """Kubernetes-compatible health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        services={
            "api": "up",
            "database": "up",  # TODO: real DB ping
            "redis": "up",     # TODO: real Redis ping
            "inspection_engine": "up",
        },
    )


@router.get("/ready", tags=["Health"])
async def readiness_check():
    """Kubernetes readiness probe."""
    return {"ready": True}


@router.get("/live", tags=["Health"])
async def liveness_check():
    """Kubernetes liveness probe."""
    return {"alive": True}
