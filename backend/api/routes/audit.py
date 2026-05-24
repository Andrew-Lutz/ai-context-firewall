"""
Audit Log Routes — AI Context Firewall
Query, export, and manage the immutable audit trail.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

router = APIRouter()

# In-memory event store (production: PostgreSQL via SQLAlchemy)
_events: list[dict] = []


def record_event(event: dict):
    """Called by other modules to append an audit event."""
    _events.append(event)
    if len(_events) > 10_000:
        _events.pop(0)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AuditExportRequest(BaseModel):
    start_time: str | None = None   # ISO datetime
    end_time:   str | None = None
    format:     Literal["json", "csv"] = "json"
    filters:    dict = {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/")
async def list_events(
    limit:      int   = Query(50,  ge=1,  le=500),
    offset:     int   = Query(0,   ge=0),
    action:     str | None = Query(None),
    risk_level: str | None = Query(None),
    user_id:    str | None = Query(None),
    tenant_id:  str | None = Query(None),
    since_hours: float = Query(168.0),  # default: last 7 days
):
    """Query audit events with filtering and pagination."""
    cutoff = (datetime.utcnow() - timedelta(hours=since_hours)).isoformat()

    results = _events
    if action:
        results = [e for e in results if e.get("action") == action]
    if risk_level:
        results = [e for e in results if e.get("risk_level") == risk_level]
    if user_id:
        results = [e for e in results if e.get("user_id") == user_id]
    if tenant_id:
        results = [e for e in results if e.get("tenant_id") == tenant_id]
    results = [e for e in results if e.get("timestamp", "") >= cutoff]

    total   = len(results)
    page    = results[offset : offset + limit]

    return {
        "events": page,
        "total":  total,
        "offset": offset,
        "limit":  limit,
    }


@router.get("/summary")
async def audit_summary(since_hours: float = Query(24.0)):
    """Aggregated summary of audit events."""
    cutoff = (datetime.utcnow() - timedelta(hours=since_hours)).isoformat()
    recent = [e for e in _events if e.get("timestamp", "") >= cutoff]

    by_action:     dict[str, int] = {}
    by_risk:       dict[str, int] = {}
    by_policy:     dict[str, int] = {}

    for e in recent:
        a = e.get("action", "unknown")
        r = e.get("risk_level", "unknown")
        p = e.get("policy_id")
        by_action[a] = by_action.get(a, 0) + 1
        by_risk[r]   = by_risk.get(r, 0) + 1
        if p:
            by_policy[p] = by_policy.get(p, 0) + 1

    return {
        "period_hours":    since_hours,
        "total_events":    len(recent),
        "by_action":       by_action,
        "by_risk_level":   by_risk,
        "by_policy":       by_policy,
        "blocked_count":   by_action.get("block", 0),
        "redacted_count":  by_action.get("redact", 0),
    }


@router.get("/{event_id}")
async def get_event(event_id: str):
    for e in reversed(_events):
        if e.get("event_id") == event_id:
            return e
    raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found")


@router.post("/export")
async def export_events(req: AuditExportRequest):
    """Export audit events as JSON or CSV."""
    results = list(_events)
    if req.start_time:
        results = [e for e in results if e.get("timestamp", "") >= req.start_time]
    if req.end_time:
        results = [e for e in results if e.get("timestamp", "") <= req.end_time]
    for k, v in req.filters.items():
        results = [e for e in results if e.get(k) == v]

    if req.format == "csv":
        import io, csv
        buf = io.StringIO()
        if results:
            writer = csv.DictWriter(buf, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        return {"format": "csv", "data": buf.getvalue(), "count": len(results)}

    return {"format": "json", "data": results, "count": len(results)}
