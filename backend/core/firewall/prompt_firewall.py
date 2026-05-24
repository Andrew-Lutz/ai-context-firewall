"""
Prompt Firewall — AI Context Firewall
Intercepts, inspects, and governs all prompts before they reach LLMs.
Provides context isolation, session boundaries, and zero-trust prompt validation.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..inspection.engine import InspectionEngine, InspectionResult
from ..redaction.engine import RedactionEngine, RedactionResult
from ..governance.engine import GovernanceEngine, PolicyEvaluationResult


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class FirewallAction(str, Enum):
    ALLOW   = "allow"
    BLOCK   = "block"
    REDACT  = "redact"
    ALERT   = "alert"
    QUARANTINE = "quarantine"


class PromptRisk(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    NONE     = "none"


@dataclass
class PromptContext:
    """Full context of a prompt request."""
    prompt_id:    str
    session_id:   str
    tenant_id:    str
    user_id:      str
    user_role:    str
    department:   str
    model:        str
    messages:     list[dict[str, str]]       # [{role, content}, …]
    system_prompt: str | None = None
    policy_ids:   list[str]   = field(default_factory=list)
    metadata:     dict[str, Any] = field(default_factory=dict)
    timestamp:    float        = field(default_factory=time.time)


@dataclass
class FirewallResult:
    """Decision and full audit record from the prompt firewall."""
    prompt_id:      str
    session_id:     str
    action:         FirewallAction
    risk_level:     PromptRisk
    risk_score:     float
    allowed:        bool

    # Original vs processed content
    original_messages:  list[dict[str, str]]
    processed_messages: list[dict[str, str]]

    # Sub-engine results
    inspection:    InspectionResult  | None = None
    redaction:     RedactionResult   | None = None
    policy_eval:   PolicyEvaluationResult | None = None

    # Explanation
    block_reason:  str | None = None
    violations:    list[str]  = field(default_factory=list)
    explanation:   str        = ""

    # Audit fingerprint (SHA-256 of content — never stores raw PII)
    content_hash:  str        = ""

    # Performance
    processing_time_ms: float = 0.0
    timestamp:          float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Context Isolation
# ---------------------------------------------------------------------------

class SessionIsolationLayer:
    """
    Maintains zero-trust session boundaries.
    Prevents cross-session context leakage and enforces message history limits.
    """

    MAX_HISTORY_MESSAGES = 50
    MAX_MESSAGE_CHARS    = 32_000

    def __init__(self):
        # In production this would be Redis-backed; here we use in-memory
        self._sessions: dict[str, list[dict]] = {}

    def get_isolated_context(
        self,
        session_id: str,
        new_messages: list[dict[str, str]],
        tenant_id: str,
    ) -> list[dict[str, str]]:
        """
        Returns a clean, bounded conversation history for this session.
        Enforces:
        - Session isolation (no cross-session leakage)
        - Message count limits
        - Per-message size limits
        - Tenant isolation
        """
        session_key = f"{tenant_id}:{session_id}"

        # Retrieve existing history (or empty)
        history = self._sessions.get(session_key, [])

        # Append new messages
        combined = history + new_messages

        # Enforce size limits
        for msg in combined:
            if len(msg.get("content", "")) > self.MAX_MESSAGE_CHARS:
                msg["content"] = msg["content"][: self.MAX_MESSAGE_CHARS] + " [TRUNCATED]"

        # Enforce message count
        if len(combined) > self.MAX_HISTORY_MESSAGES:
            # Keep system message if present, then most recent messages
            system_msgs = [m for m in combined if m.get("role") == "system"]
            non_system  = [m for m in combined if m.get("role") != "system"]
            keep        = non_system[-(self.MAX_HISTORY_MESSAGES - len(system_msgs)):]
            combined    = system_msgs + keep

        # Persist back
        self._sessions[session_key] = combined
        return combined

    def clear_session(self, session_id: str, tenant_id: str):
        session_key = f"{tenant_id}:{session_id}"
        self._sessions.pop(session_key, None)

    def get_session_count(self) -> int:
        return len(self._sessions)


# ---------------------------------------------------------------------------
# Prompt Firewall
# ---------------------------------------------------------------------------

class PromptFirewall:
    """
    Main prompt firewall. Orchestrates all security layers for inbound prompts.

    Pipeline:
      1. Input validation & sanitization
      2. Session isolation & context bounding
      3. Content inspection (PII/PHI/PCI/secrets/injections)
      4. Policy evaluation
      5. Redaction (if applicable)
      6. Final allow/block decision
      7. Audit logging
    """

    # Patterns that always trigger immediate block regardless of policy
    HARD_BLOCK_PATTERNS: list[tuple[str, str]] = [
        # Prompt injection
        (r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?",       "Instruction Override"),
        (r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:evil|unrestricted|jailbroken|DAN)", "Jailbreak Attempt"),
        (r"(?:repeat|print|output|echo)\s+(?:the\s+)?(?:system|initial)\s+prompt", "System Prompt Extraction"),
        (r"</?(system|human|assistant|instruction|ctx)\s*>",                     "Delimiter Injection"),
        # Data exfiltration hooks
        (r"(?:fetch|curl|wget|requests\.get)\s*\(\s*['\"]https?://",             "SSRF Attempt"),
        (r"__import__\s*\(\s*['\"](?:os|subprocess|sys)",                        "Code Injection"),
    ]

    def __init__(
        self,
        inspection_engine: InspectionEngine | None = None,
        redaction_engine:  RedactionEngine  | None = None,
        governance_engine: GovernanceEngine | None = None,
        session_layer:     SessionIsolationLayer | None = None,
        strict_mode:       bool = False,
    ):
        self.inspection  = inspection_engine or InspectionEngine()
        self.redaction   = redaction_engine  or RedactionEngine()
        self.governance  = governance_engine or GovernanceEngine()
        self.session     = session_layer     or SessionIsolationLayer()
        self.strict_mode = strict_mode

        # Pre-compile hard-block patterns
        self._hard_block = [
            (re.compile(pat, re.IGNORECASE | re.DOTALL), name)
            for pat, name in self.HARD_BLOCK_PATTERNS
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, context: PromptContext) -> FirewallResult:
        """
        Full pipeline evaluation. Returns a FirewallResult with allow/block decision.
        """
        t0 = time.perf_counter()

        prompt_id = context.prompt_id or str(uuid.uuid4())

        # 1. Session isolation
        isolated_messages = self.session.get_isolated_context(
            session_id=context.session_id,
            new_messages=context.messages,
            tenant_id=context.tenant_id,
        )

        # 2. Build full text for scanning (all non-system content)
        full_text = "\n".join(
            m.get("content", "")
            for m in isolated_messages
            if m.get("role") != "system"
        )

        if context.system_prompt:
            full_text = context.system_prompt + "\n" + full_text

        # 3. Hard block check (synchronous, fast)
        hard_block = self._check_hard_blocks(full_text)
        if hard_block:
            elapsed = (time.perf_counter() - t0) * 1000
            return FirewallResult(
                prompt_id      = prompt_id,
                session_id     = context.session_id,
                action         = FirewallAction.BLOCK,
                risk_level     = PromptRisk.CRITICAL,
                risk_score     = 1.0,
                allowed        = False,
                original_messages   = context.messages,
                processed_messages  = [],
                block_reason   = f"Hard block: {hard_block}",
                violations     = [hard_block],
                explanation    = f"Request blocked by immutable firewall rule: {hard_block}",
                content_hash   = self._hash(full_text),
                processing_time_ms = elapsed,
            )

        # 4. Inspection
        inspection_result = self.inspection.inspect(full_text)

        # 5. Redaction pass on messages
        processed_messages = []
        redaction_result   = None
        if inspection_result.entities_detected:
            redacted_text, redaction_result = self.redaction.redact(
                full_text,
                entities=[e.__dict__ if hasattr(e, "__dict__") else e for e in inspection_result.entities_detected],
            )
            # Apply redaction per-message
            processed_messages = self._redact_messages(isolated_messages, inspection_result)
        else:
            processed_messages = isolated_messages

        # 6. Policy evaluation
        policy_context = {
            "user_role":       context.user_role,
            "department":      context.department,
            "tenant_id":       context.tenant_id,
            "model":           context.model,
            "risk_score":      inspection_result.risk_score,
            "injection_detected": bool(inspection_result.injections_detected),
            "entities_detected":  [str(e) for e in inspection_result.entities_detected],
        }
        policy_result = self.governance.evaluate(full_text, policy_context, context.policy_ids)

        # 7. Final decision
        action, risk_level, violations, block_reason = self._decide(
            inspection_result, policy_result
        )

        allowed = action not in (FirewallAction.BLOCK, FirewallAction.QUARANTINE)

        elapsed = (time.perf_counter() - t0) * 1000

        return FirewallResult(
            prompt_id          = prompt_id,
            session_id         = context.session_id,
            action             = action,
            risk_level         = risk_level,
            risk_score         = inspection_result.risk_score,
            allowed            = allowed,
            original_messages  = context.messages,
            processed_messages = processed_messages if allowed else [],
            inspection         = inspection_result,
            redaction          = redaction_result,
            policy_eval        = policy_result,
            block_reason       = block_reason,
            violations         = violations,
            explanation        = self._build_explanation(action, inspection_result, policy_result, block_reason),
            content_hash       = self._hash(full_text),
            processing_time_ms = elapsed,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_hard_blocks(self, text: str) -> str | None:
        for pattern, name in self._hard_block:
            if pattern.search(text):
                return name
        return None

    def _decide(
        self,
        inspection: InspectionResult,
        policy_eval: PolicyEvaluationResult,
    ) -> tuple[FirewallAction, PromptRisk, list[str], str | None]:
        violations: list[str] = []
        block_reason: str | None = None

        # Injection = immediate block
        if inspection.injections_detected:
            inj_names = [str(i) for i in inspection.injections_detected]
            violations += inj_names
            block_reason = f"Injection detected: {', '.join(inj_names[:2])}"
            return FirewallAction.BLOCK, PromptRisk.CRITICAL, violations, block_reason

        # Policy block
        if policy_eval and policy_eval.final_action == "block":
            violations += [r.get("rule_name", "policy_rule") for r in policy_eval.triggered_rules]
            block_reason = f"Policy block: {policy_eval.policy_id}"
            return FirewallAction.BLOCK, PromptRisk.CRITICAL, violations, block_reason

        # Score-based risk
        score = inspection.risk_score

        if score >= 0.9:
            return FirewallAction.BLOCK, PromptRisk.CRITICAL, violations, "Risk score exceeds critical threshold"

        if score >= 0.7 or (policy_eval and policy_eval.final_action == "redact"):
            return FirewallAction.REDACT, PromptRisk.HIGH, violations, None

        if score >= 0.4 or (policy_eval and policy_eval.final_action == "alert"):
            return FirewallAction.ALERT, PromptRisk.MEDIUM, violations, None

        if score >= 0.1:
            return FirewallAction.ALLOW, PromptRisk.LOW, violations, None

        return FirewallAction.ALLOW, PromptRisk.NONE, violations, None

    def _redact_messages(
        self,
        messages: list[dict[str, str]],
        inspection: InspectionResult,
    ) -> list[dict[str, str]]:
        result = []
        for msg in messages:
            content = msg.get("content", "")
            redacted, _ = self.redaction.redact(
                content,
                entities=[e.__dict__ if hasattr(e, "__dict__") else e for e in inspection.entities_detected],
            )
            result.append({**msg, "content": redacted})
        return result

    def _build_explanation(
        self,
        action: FirewallAction,
        inspection: InspectionResult,
        policy_eval: PolicyEvaluationResult,
        block_reason: str | None,
    ) -> str:
        parts = [f"Decision: {action.value.upper()}"]

        if block_reason:
            parts.append(f"Reason: {block_reason}")

        if inspection.entities_detected:
            entity_types = list({str(e) for e in inspection.entities_detected})[:5]
            parts.append(f"Entities: {', '.join(entity_types)}")

        if inspection.injections_detected:
            parts.append(f"Injections: {len(inspection.injections_detected)} pattern(s) detected")

        parts.append(f"Risk score: {inspection.risk_score:.2f}")

        if policy_eval and policy_eval.triggered_rules:
            rule_names = [r.get("rule_name", "?") for r in policy_eval.triggered_rules[:3]]
            parts.append(f"Policy rules triggered: {', '.join(rule_names)}")

        return " | ".join(parts)

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]
