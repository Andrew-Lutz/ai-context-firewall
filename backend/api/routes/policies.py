"""
Policy Management Routes — AI Context Firewall
CRUD for compliance policies, policy testing, and hot-reload.
"""
from __future__ import annotations

import os
import yaml
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

POLICIES_DIR = Path(os.getenv("POLICIES_DIR", "/app/policies"))
if not POLICIES_DIR.exists():
    POLICIES_DIR = Path(__file__).parent.parent.parent.parent / "policies"


def _load_all_policies() -> list[dict]:
    policies = []
    for yaml_file in sorted(POLICIES_DIR.rglob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text())
            if data and "policy_id" in data:
                data["_file"] = str(yaml_file.relative_to(POLICIES_DIR))
                policies.append(data)
        except Exception as e:
            policies.append({"policy_id": yaml_file.stem, "_error": str(e), "_file": str(yaml_file)})
    return policies


def _load_policy(policy_id: str) -> dict | None:
    for p in _load_all_policies():
        if p.get("policy_id") == policy_id:
            return p
    return None


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PolicyTestRequest(BaseModel):
    policy_id: str
    text: str
    context: dict[str, Any] = {}


class PolicyCreateRequest(BaseModel):
    policy_id: str
    name: str
    description: str = ""
    rules: list[dict] = []
    frameworks: list[str] = []
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/")
async def list_policies():
    """List all available policies."""
    policies = _load_all_policies()
    return {
        "policies": [
            {
                "policy_id":   p.get("policy_id"),
                "name":        p.get("name", p.get("policy_id")),
                "version":     p.get("version", "1.0.0"),
                "frameworks":  p.get("frameworks", []),
                "severity":    p.get("severity", "medium"),
                "rules_count": len(p.get("rules", [])),
                "file":        p.get("_file"),
            }
            for p in policies if "_error" not in p
        ],
        "total": len([p for p in policies if "_error" not in p]),
    }


@router.get("/{policy_id}")
async def get_policy(policy_id: str):
    """Get full policy definition."""
    policy = _load_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found")
    return policy


@router.post("/test")
async def test_policy(req: PolicyTestRequest):
    """Test a policy against sample text."""
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from core.governance.engine import PolicyEngine, PolicyLoader
        from core.inspection.engine import InputInspectionEngine
        # Inspect the text first
        inspector = InputInspectionEngine()
        insp = inspector.inspect(req.text)
        # Build context dict
        ctx = {
            "entities":          [str(e) for e in insp.entities_detected],
            "risk_score":        insp.risk_score,
            "injection_detected": len(insp.injections_detected) > 0,
            "policy_id":         req.policy_id,
            **req.context,
        }
        loader = PolicyLoader(str(POLICIES_DIR))
        engine = PolicyEngine(loader)
        result = engine.evaluate(ctx)
        return {
            "policy_id":       req.policy_id,
            "final_action":    result.final_action,
            "triggered_rules": [r.__dict__ if hasattr(r,"__dict__") else r for r in result.triggered_rules],
            "risk_score":      result.risk_score,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reload")
async def reload_policies():
    """Hot-reload all policy files from disk."""
    policies = _load_all_policies()
    loaded = [p["policy_id"] for p in policies if "_error" not in p]
    errors = [{"file": p["_file"], "error": p["_error"]} for p in policies if "_error" in p]
    return {
        "reloaded": loaded,
        "count":    len(loaded),
        "errors":   errors,
    }
