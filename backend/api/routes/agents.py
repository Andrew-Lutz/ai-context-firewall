"""
Agent Control Routes — AI Context Firewall
Register agents, evaluate tool calls, manage approval workflows.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

# Shared controller (production: injected via dependency)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.agents.controls import (
    AgentController, AgentProfile, AgentToolCall,
    AgentPermission, AgentActionRisk,
)

_controller = AgentController()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterAgentRequest(BaseModel):
    agent_id:    str
    name:        str
    tenant_id:   str
    permissions: list[str] = []
    max_risk:    str = "medium"
    require_approval_above: str = "high"
    sandbox_mode: bool = False
    metadata:    dict[str, Any] = {}


class ToolCallRequest(BaseModel):
    call_id:    str | None = None
    agent_id:   str
    session_id: str
    tenant_id:  str
    tool_name:  str
    arguments:  dict[str, Any] = {}
    context:    str = ""


class ApprovalRequest(BaseModel):
    call_id:  str
    approved: bool
    reason:   str = ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/register")
async def register_agent(req: RegisterAgentRequest):
    """Register a new AI agent with its permission profile."""
    try:
        perms   = [AgentPermission(p) for p in req.permissions]
        max_r   = AgentActionRisk(req.max_risk)
        appr_r  = AgentActionRisk(req.require_approval_above)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    profile = AgentProfile(
        agent_id    = req.agent_id,
        name        = req.name,
        tenant_id   = req.tenant_id,
        permissions = perms,
        max_risk    = max_r,
        require_approval_above = appr_r,
        sandbox_mode = req.sandbox_mode,
        metadata     = req.metadata,
    )
    _controller.register_agent(profile)
    return {"status": "registered", "agent_id": req.agent_id, "permissions": req.permissions}


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    """Get agent profile."""
    agent = _controller.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {
        "agent_id":    agent.agent_id,
        "name":        agent.name,
        "tenant_id":   agent.tenant_id,
        "permissions": [p.value for p in agent.permissions],
        "max_risk":    agent.max_risk.value,
        "require_approval_above": agent.require_approval_above.value,
        "sandbox_mode": agent.sandbox_mode,
        "is_active":   agent.is_active,
    }


@router.post("/evaluate")
async def evaluate_tool_call(req: ToolCallRequest):
    """Evaluate whether an agent tool call should be allowed."""
    call = AgentToolCall(
        call_id    = req.call_id or str(uuid.uuid4()),
        agent_id   = req.agent_id,
        session_id = req.session_id,
        tenant_id  = req.tenant_id,
        tool_name  = req.tool_name,
        arguments  = req.arguments,
        context    = req.context,
    )
    result = _controller.evaluate_tool_call(call)
    return {
        "call_id":            result.call_id,
        "decision":           result.decision.value,
        "allowed":            result.allowed,
        "risk_level":         result.risk_level.value,
        "reason":             result.reason,
        "requires_approval":  result.requires_approval,
        "approval_reason":    result.approval_reason,
        "sandbox_mode":       result.sandbox_mode,
        "missing_permissions": [p.value for p in result.missing_permissions],
        "processing_ms":      result.processing_time_ms,
    }


@router.get("/audit/log")
async def get_audit_log(limit: int = 100):
    """Get agent tool call audit log."""
    log = _controller.get_audit_log()[-limit:]
    return {
        "entries": [
            {
                "call_id":   r.call_id,
                "decision":  r.decision.value,
                "allowed":   r.allowed,
                "risk_level": r.risk_level.value,
                "tool_name": r.tool_name,
                "reason":    r.reason,
                "timestamp": r.timestamp,
            }
            for r in log
        ],
        "total": len(log),
    }
