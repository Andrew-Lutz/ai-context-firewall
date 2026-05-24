"""
Model Gateway Routes — AI Context Firewall
Proxies LLM requests through the full security pipeline.
Supports OpenAI-compatible and Anthropic API formats.
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class GatewayMessage(BaseModel):
    role:    str
    content: str


class GatewayRequest(BaseModel):
    model:        str
    messages:     list[GatewayMessage]
    system_prompt: str | None = None
    max_tokens:   int  = 1000
    temperature:  float = 0.7
    policy_id:    str | None = None
    tenant_id:    str  = "default"
    user_id:      str  = "api_user"
    session_id:   str | None = None


class GatewayResponse(BaseModel):
    request_id:       str
    model:            str
    content:          str
    input_action:     str
    output_action:    str
    input_risk_score: float
    output_risk_score: float
    entities_redacted: int
    blocked:          bool
    block_reason:     str | None
    processing_ms:    float
    usage:            dict


# ---------------------------------------------------------------------------
# Provider routing
# ---------------------------------------------------------------------------

def _get_provider(model: str) -> str:
    if model.startswith("gpt-") or model.startswith("o1") or model.startswith("o3"):
        return "openai"
    if model.startswith("claude-"):
        return "anthropic"
    if model.startswith("gemini-"):
        return "google"
    return "unknown"


async def _call_openai(model: str, messages: list, system: str | None, max_tokens: int) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return f"[Mock OpenAI response — no API key configured] Model {model} would respond here."
    try:
        import httpx
        payload: dict[str, Any] = {
            "model": model,
            "messages": ([{"role": "system", "content": system}] if system else []) + messages,
            "max_tokens": max_tokens,
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[OpenAI error: {e}]"


async def _call_anthropic(model: str, messages: list, system: str | None, max_tokens: int) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return f"[Mock Anthropic response — no API key configured] Model {model} would respond here."
    try:
        import httpx
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            payload["system"] = system
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            r.raise_for_status()
            return r.json()["content"][0]["text"]
    except Exception as e:
        return f"[Anthropic error: {e}]"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/chat", response_model=GatewayResponse)
async def gateway_chat(req: GatewayRequest):
    """
    Send a chat request through the firewall gateway.
    Input and output are both inspected, redacted, and policy-checked.
    """
    t0 = time.perf_counter()
    request_id  = str(uuid.uuid4())
    session_id  = req.session_id or str(uuid.uuid4())

    # ── Import security pipeline ──────────────────────────────────────────
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    from core.inspection.engine import InputInspectionEngine
    from core.redaction.engine  import RedactionEngine

    inspection = InputInspectionEngine()
    redaction  = RedactionEngine()

    # ── Build full input text for inspection ──────────────────────────────
    full_input = "\n".join(m.content for m in req.messages if m.role != "system")
    if req.system_prompt:
        full_input = req.system_prompt + "\n" + full_input

    input_scan = inspection.inspect(full_input)

    # ── Input decision ────────────────────────────────────────────────────
    input_action = "allow"
    block_reason = None

    if input_scan.injections:
        input_action = "block"
        block_reason = f"Injection detected: {input_scan.injections[0]}"
    elif input_scan.overall_risk_score >= 0.9:
        input_action = "block"
        block_reason = "Risk score exceeds critical threshold"
    elif input_scan.overall_risk_score >= 0.5 or input_scan.entities:
        input_action = "redact"

    if input_action == "block":
        elapsed = (time.perf_counter() - t0) * 1000
        return GatewayResponse(
            request_id        = request_id,
            model             = req.model,
            content           = "",
            input_action      = "block",
            output_action     = "n/a",
            input_risk_score  = input_scan.overall_risk_score,
            output_risk_score = 0.0,
            entities_redacted = 0,
            blocked           = True,
            block_reason      = block_reason,
            processing_ms     = elapsed,
            usage             = {},
        )

    # ── Redact messages before sending to LLM ────────────────────────────
    redacted_messages = []
    total_redacted = 0
    for msg in req.messages:
        if input_scan.entities and msg.role != "system":
            # Re-inspect individual message for accurate entity positions
            msg_scan = inspection.inspect(msg.content)
            if msg_scan.entities:
                rr = redaction.redact(msg.content, msg_scan)
                redacted_content = rr.redacted_text
                total_redacted += rr.redaction_count
            else:
                redacted_content = msg.content
            redacted_messages.append({"role": msg.role, "content": redacted_content})
        else:
            redacted_messages.append({"role": msg.role, "content": msg.content})

    # ── Call LLM ──────────────────────────────────────────────────────────
    provider = _get_provider(req.model)
    if provider == "openai":
        llm_response = await _call_openai(req.model, redacted_messages, req.system_prompt, req.max_tokens)
    elif provider == "anthropic":
        llm_response = await _call_anthropic(req.model, redacted_messages, req.system_prompt, req.max_tokens)
    else:
        llm_response = f"[Gateway mock] Provider '{provider}' for model '{req.model}' not configured."

    # ── Output inspection ─────────────────────────────────────────────────
    output_scan    = inspection.inspect(llm_response)
    output_action  = "deliver"
    output_redacted = llm_response

    if output_scan.entities:
        output_redacted, _ = redaction.redact(
            llm_response,
            [e.__dict__ if hasattr(e, "__dict__") else e for e in output_scan.entities],
        )
        output_action = "redact"

    elapsed = (time.perf_counter() - t0) * 1000

    return GatewayResponse(
        request_id        = request_id,
        model             = req.model,
        content           = output_redacted,
        input_action      = input_action,
        output_action     = output_action,
        input_risk_score  = input_scan.overall_risk_score,
        output_risk_score = output_scan.overall_risk_score,
        entities_redacted = total_redacted + len(output_scan.entities),
        blocked           = False,
        block_reason      = None,
        processing_ms     = elapsed,
        usage             = {"prompt_tokens": len(full_input) // 4, "completion_tokens": len(llm_response) // 4},
    )


@router.get("/models")
async def list_models():
    """List available models and their providers."""
    return {
        "models": [
            {"id": "gpt-4o",            "provider": "openai",    "context_window": 128000},
            {"id": "gpt-4-turbo",       "provider": "openai",    "context_window": 128000},
            {"id": "gpt-3.5-turbo",     "provider": "openai",    "context_window": 16000},
            {"id": "claude-opus-4-5",   "provider": "anthropic", "context_window": 200000},
            {"id": "claude-sonnet-4-5", "provider": "anthropic", "context_window": 200000},
            {"id": "claude-haiku-4-5",  "provider": "anthropic", "context_window": 200000},
            {"id": "gemini-1.5-pro",    "provider": "google",    "context_window": 1000000},
            {"id": "gemini-1.5-flash",  "provider": "google",    "context_window": 1000000},
        ]
    }
