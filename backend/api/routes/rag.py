"""
RAG Security Routes — AI Context Firewall
Vector store management, retrieval authorization, poisoning scanning.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter()

# In-memory store registry (production: PostgreSQL)
_stores: dict[str, dict] = {
    "vs_001": {"id": "vs_001", "name": "HR Policy Docs",       "classification": "internal",    "docs": 1240, "status": "healthy"},
    "vs_002": {"id": "vs_002", "name": "Customer Contracts",   "classification": "confidential", "docs": 892,  "status": "healthy"},
    "vs_003": {"id": "vs_003", "name": "Medical Records RAG",  "classification": "restricted",   "docs": 4521, "status": "warning"},
    "vs_004": {"id": "vs_004", "name": "Public Knowledge Base","classification": "public",       "docs": 18000,"status": "healthy"},
}

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RetrievalRequest(BaseModel):
    query:     str
    store_ids: list[str]
    user_role: str = "employee"
    top_k:     int = 5
    tenant_id: str = "default"
    session_id: str | None = None


class PoisoningScanRequest(BaseModel):
    doc_id:  str
    content: str
    store_id: str = "unknown"


# ---------------------------------------------------------------------------
# Access control matrix
# ---------------------------------------------------------------------------

ROLE_CLEARANCE = {"anonymous": 0, "employee": 1, "analyst": 2, "compliance_officer": 3, "admin": 4}
CLS_CLEARANCE  = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


def _can_access(role: str, classification: str) -> bool:
    return ROLE_CLEARANCE.get(role, 0) >= CLS_CLEARANCE.get(classification, 3)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/stores")
async def list_stores():
    return {"stores": list(_stores.values()), "total": len(_stores)}


@router.get("/stores/{store_id}")
async def get_store(store_id: str):
    s = _stores.get(store_id)
    if not s:
        raise HTTPException(status_code=404, detail=f"Store '{store_id}' not found")
    return s


@router.post("/retrieve")
async def authorize_retrieval(req: RetrievalRequest):
    """Authorize a RAG retrieval request."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from core.rag.security import RAGQueryFirewall, RetrievalRequest as CoreRequest

    firewall = RAGQueryFirewall()
    core_req = CoreRequest(
        request_id  = str(uuid.uuid4()),
        session_id  = req.session_id or str(uuid.uuid4()),
        tenant_id   = req.tenant_id,
        user_id     = "api_user",
        user_role   = req.user_role,
        query       = req.query,
        store_ids   = req.store_ids,
        top_k       = req.top_k,
    )
    result = firewall.authorize(core_req)

    # Also check store-level access
    denied_stores = list(result.denied_stores)
    allowed_stores = []
    for sid in result.authorized_stores:
        store = _stores.get(sid)
        if store and not _can_access(req.user_role, store["classification"]):
            denied_stores.append(sid)
        else:
            allowed_stores.append(sid)

    return {
        "request_id":          result.request_id,
        "action":              result.action,
        "allowed":             result.allowed and len(allowed_stores) > 0,
        "authorized_stores":   allowed_stores,
        "denied_stores":       denied_stores,
        "query_risk_score":    result.query_risk_score,
        "injection_detected":  result.injection_detected,
        "block_reason":        result.block_reason,
        "processing_ms":       result.processing_time_ms,
    }


@router.post("/scan/document")
async def scan_document_for_poisoning(req: PoisoningScanRequest):
    """Scan a document for vector store poisoning attacks."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from core.rag.security import VectorStorePoisoningDetector

    detector = VectorStorePoisoningDetector()
    result   = detector.scan(req.doc_id, req.content)
    return {
        "doc_id":      result.doc_id,
        "store_id":    req.store_id,
        "is_poisoned": result.is_poisoned,
        "threats":     result.threats,
        "risk_score":  result.risk_score,
        "explanation": result.explanation,
        "action":      "quarantine" if result.is_poisoned else "allow",
    }


@router.get("/audit")
async def retrieval_audit_log(limit: int = Query(50, ge=1, le=500)):
    """Return recent retrieval authorization events."""
    # In production this queries the audit log store
    return {"events": [], "total": 0, "note": "Connect to audit log backend for live events"}
