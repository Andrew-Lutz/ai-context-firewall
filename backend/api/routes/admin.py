"""
Admin Routes — AI Context Firewall
Tenant management, user administration, system configuration.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

router = APIRouter()

# In-memory stores (production: PostgreSQL)
_tenants: dict[str, dict] = {
    "tenant_acme_corp":  {"id": "tenant_acme_corp",  "name": "ACME Corporation", "plan": "Enterprise", "status": "active",  "users": 142},
    "tenant_healthco":   {"id": "tenant_healthco",   "name": "HealthCo Systems", "plan": "Enterprise", "status": "active",  "users": 89},
    "tenant_fingroup":   {"id": "tenant_fingroup",   "name": "FinGroup Capital", "plan": "Pro",        "status": "active",  "users": 34},
}

_config: dict[str, Any] = {
    "default_redaction_mode":    "mask",
    "risk_score_block_threshold": 0.75,
    "enable_injection_blocking": True,
    "enable_output_inspection":  True,
    "token_vault_ttl_hours":     24,
    "max_file_size_mb":          50,
    "rate_limit_global":         500,
    "rate_limit_per_user":       60,
}

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TenantCreateRequest(BaseModel):
    name:     str
    plan:     str = "Pro"
    metadata: dict[str, Any] = {}


class ConfigUpdateRequest(BaseModel):
    settings: dict[str, Any]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/tenants")
async def list_tenants():
    return {"tenants": list(_tenants.values()), "total": len(_tenants)}


@router.get("/tenants/{tenant_id}")
async def get_tenant(tenant_id: str):
    t = _tenants.get(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return t


@router.post("/tenants")
async def create_tenant(req: TenantCreateRequest):
    import uuid
    tenant_id = f"tenant_{req.name.lower().replace(' ', '_')}_{str(uuid.uuid4())[:8]}"
    tenant = {
        "id":        tenant_id,
        "name":      req.name,
        "plan":      req.plan,
        "status":    "active",
        "users":     0,
        "created_at": time.time(),
        **req.metadata,
    }
    _tenants[tenant_id] = tenant
    return {"status": "created", "tenant": tenant}


@router.get("/config")
async def get_config():
    return {"config": _config}


@router.put("/config")
async def update_config(req: ConfigUpdateRequest):
    invalid = [k for k in req.settings if k not in _config]
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unknown config keys: {invalid}")
    _config.update(req.settings)
    return {"status": "updated", "config": _config}


@router.get("/health/system")
async def system_health():
    """Detailed system health for admin dashboard."""
    return {
        "components": {
            "api_gateway":       {"status": "healthy", "latency_ms": 12,  "uptime": "99.98%"},
            "inspection_engine": {"status": "healthy", "latency_ms": 8,   "uptime": "99.99%"},
            "redaction_engine":  {"status": "healthy", "latency_ms": 5,   "uptime": "100%"},
            "policy_engine":     {"status": "healthy", "latency_ms": 3,   "uptime": "100%"},
            "token_vault":       {"status": "healthy", "latency_ms": 1,   "uptime": "99.97%"},
            "database":          {"status": "healthy", "latency_ms": 4,   "uptime": "99.99%"},
            "audit_logger":      {"status": "healthy", "latency_ms": 2,   "uptime": "100%"},
            "rag_security":      {"status": "warning",  "latency_ms": 45,  "uptime": "99.81%"},
        },
        "tenants_count":  len(_tenants),
        "timestamp":      time.time(),
    }
