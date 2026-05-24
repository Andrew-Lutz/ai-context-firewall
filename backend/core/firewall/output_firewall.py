"""
Output Firewall — AI Context Firewall
Inspects, filters, and governs LLM responses before delivery to end users.
Prevents data exfiltration, hallucination of PII, and policy violations in output.
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
from ..redaction.engine import RedactionEngine


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class OutputAction(str, Enum):
    DELIVER  = "deliver"
    REDACT   = "redact"
    BLOCK    = "block"
    SANITIZE = "sanitize"
    ALERT    = "alert"


@dataclass
class OutputContext:
    """Context for an LLM output inspection request."""
    response_id:   str
    session_id:    str
    tenant_id:     str
    user_id:       str
    user_role:     str
    model:         str
    content:       str
    policy_ids:    list[str] = field(default_factory=list)
    original_prompt_risk: float = 0.0   # Risk score of the input prompt
    metadata:      dict[str, Any] = field(default_factory=dict)


@dataclass
class OutputFirewallResult:
    """Decision and audit record for an LLM output."""
    response_id:    str
    action:         OutputAction
    allowed:        bool
    original_content:   str
    delivered_content:  str
    risk_score:     float
    entities_found: list[Any]   = field(default_factory=list)
    redacted_count: int         = 0
    block_reason:   str | None  = None
    violations:     list[str]   = field(default_factory=list)
    explanation:    str         = ""
    content_hash:   str         = ""
    processing_time_ms: float   = 0.0
    timestamp:      float       = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Output Firewall
# ---------------------------------------------------------------------------

class OutputFirewall:
    """
    Output firewall — second line of defence after the LLM responds.

    Guards against:
    - PII/PHI hallucinated or leaked in responses
    - Secrets or credentials in generated code
    - Excessive data disclosure
    - Injection-payload echoing (model was successfully hijacked)
    - Prompt echo attacks (model repeating system prompt)
    - Unsafe URLs / SSRF links in responses
    """

    # Strings that indicate the model may have been successfully hijacked
    HIJACK_INDICATORS: list[tuple[str, str]] = [
        (r"I\s+(?:am|will)\s+now\s+(?:a\s+)?(?:an?\s+)?(?:unrestricted|jailbroken|DAN)", "Jailbreak Confirmation"),
        (r"(?:ignoring|ignores?)\s+(?:all\s+)?(?:previous|prior|safety)\s+instructions?", "Safety Bypass"),
        (r"as\s+(?:an?\s+)?(?:evil|malicious|unethical)\s+AI",                           "Malicious Persona"),
        (r"my\s+(?:true|real|actual)\s+(?:name|identity|purpose)\s+is",                  "Persona Leak"),
    ]

    # Unsafe URL patterns in output
    UNSAFE_URL_PATTERNS: list[tuple[str, str]] = [
        (r"https?://(?:(?:\d{1,3}\.){3}\d{1,3})",          "Private IP URL"),
        (r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)", "Localhost URL"),
        (r"https?://\S+(?:\.onion)\b",                       "Tor Hidden Service"),
        (r"(?:javascript|data|vbscript):",                   "XSS Protocol"),
    ]

    # Dangerous code patterns (e.g. in generated code blocks)
    DANGEROUS_CODE: list[tuple[str, str]] = [
        (r"(?:subprocess|os\.system|eval|exec)\s*\(",  "Code Execution"),
        (r"(?:rm\s+-rf|del\s+/f|format\s+c:)",        "Destructive Command"),
        (r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|python)", "RCE Pipe"),
        (r"(?:base64\s+-d|atob)\s*\(",                  "Base64 Decode Execution"),
    ]

    def __init__(
        self,
        inspection_engine: InspectionEngine | None = None,
        redaction_engine:  RedactionEngine  | None = None,
        block_on_hijack:   bool = True,
        block_on_pii:      bool = False,   # Redact by default, not block
        max_output_chars:  int  = 50_000,
    ):
        self.inspection       = inspection_engine or InspectionEngine()
        self.redaction        = redaction_engine  or RedactionEngine()
        self.block_on_hijack  = block_on_hijack
        self.block_on_pii     = block_on_pii
        self.max_output_chars = max_output_chars

        self._hijack_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), n)
            for p, n in self.HIJACK_INDICATORS
        ]
        self._unsafe_url_patterns = [
            (re.compile(p, re.IGNORECASE), n)
            for p, n in self.UNSAFE_URL_PATTERNS
        ]
        self._code_patterns = [
            (re.compile(p, re.IGNORECASE | re.MULTILINE), n)
            for p, n in self.DANGEROUS_CODE
        ]

    def evaluate(self, context: OutputContext) -> OutputFirewallResult:
        t0 = time.perf_counter()
        content = context.content

        # 0. Size limit
        if len(content) > self.max_output_chars:
            content = content[: self.max_output_chars] + "\n\n[OUTPUT TRUNCATED BY FIREWALL]"

        # 1. Hijack / jailbreak confirmation check
        hijack = self._check_hijack(content)
        if hijack and self.block_on_hijack:
            elapsed = (time.perf_counter() - t0) * 1000
            return OutputFirewallResult(
                response_id       = context.response_id,
                action            = OutputAction.BLOCK,
                allowed           = False,
                original_content  = context.content,
                delivered_content = "[RESPONSE BLOCKED: Model compromise detected]",
                risk_score        = 1.0,
                block_reason      = f"Model hijack detected: {hijack}",
                violations        = [hijack],
                explanation       = f"Response blocked — model appears to have been successfully jailbroken: {hijack}",
                content_hash      = self._hash(content),
                processing_time_ms= elapsed,
            )

        # 2. Unsafe URL check
        url_violations = self._check_urls(content)
        sanitized_content = content
        for _, match_text in url_violations:
            sanitized_content = sanitized_content.replace(match_text, "[URL REMOVED]")

        # 3. PII/PHI inspection
        inspection_result = self.inspection.inspect(sanitized_content)

        # 4. Redact entities in output
        delivered = sanitized_content
        redacted_count = 0
        if inspection_result.entities_detected:
            delivered, redaction_result = self.redaction.redact(
                sanitized_content,
                entities=[e.__dict__ if hasattr(e, "__dict__") else e for e in inspection_result.entities_detected],
            )
            redacted_count = len(inspection_result.entities_detected)
            if self.block_on_pii and redacted_count > 0:
                elapsed = (time.perf_counter() - t0) * 1000
                return OutputFirewallResult(
                    response_id       = context.response_id,
                    action            = OutputAction.BLOCK,
                    allowed           = False,
                    original_content  = context.content,
                    delivered_content = "[RESPONSE BLOCKED: PII detected in LLM output]",
                    risk_score        = inspection_result.risk_score,
                    entities_found    = list(inspection_result.entities_detected),
                    redacted_count    = redacted_count,
                    block_reason      = f"PII in output: {redacted_count} entity/-ies",
                    violations        = [str(e) for e in inspection_result.entities_detected],
                    content_hash      = self._hash(content),
                    processing_time_ms= elapsed,
                )

        # 5. Dangerous code check
        code_violations = self._check_dangerous_code(delivered)

        # 6. Determine final action
        risk  = inspection_result.risk_score
        violations = [n for _, n in url_violations] + [n for _, n in code_violations]

        if code_violations:
            action = OutputAction.SANITIZE
            for _, match_text in code_violations:
                delivered = delivered.replace(match_text, "[CODE SANITIZED]")
        elif redacted_count > 0:
            action = OutputAction.REDACT
        elif url_violations:
            action = OutputAction.SANITIZE
        elif risk > 0.5:
            action = OutputAction.ALERT
        else:
            action = OutputAction.DELIVER

        allowed = action != OutputAction.BLOCK

        elapsed = (time.perf_counter() - t0) * 1000

        return OutputFirewallResult(
            response_id       = context.response_id,
            action            = action,
            allowed           = allowed,
            original_content  = context.content,
            delivered_content = delivered,
            risk_score        = risk,
            entities_found    = list(inspection_result.entities_detected),
            redacted_count    = redacted_count,
            violations        = violations,
            explanation       = self._explain(action, inspection_result, url_violations, code_violations, redacted_count),
            content_hash      = self._hash(content),
            processing_time_ms= elapsed,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_hijack(self, text: str) -> str | None:
        for pattern, name in self._hijack_patterns:
            if pattern.search(text):
                return name
        return None

    def _check_urls(self, text: str) -> list[tuple[str, str]]:
        found = []
        for pattern, name in self._unsafe_url_patterns:
            for m in pattern.finditer(text):
                found.append((name, m.group()))
        return found

    def _check_dangerous_code(self, text: str) -> list[tuple[str, str]]:
        """Only check inside code blocks to avoid false positives in prose."""
        code_block_re = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL)
        found = []
        code_blocks = code_block_re.findall(text)
        code_text = "\n".join(code_blocks) if code_blocks else ""
        if code_text:
            for pattern, name in self._code_patterns:
                for m in pattern.finditer(code_text):
                    found.append((name, m.group()))
        return found

    def _explain(
        self,
        action: OutputAction,
        inspection: InspectionResult,
        url_violations: list,
        code_violations: list,
        redacted_count: int,
    ) -> str:
        parts = [f"Output action: {action.value.upper()}"]
        if redacted_count:
            parts.append(f"{redacted_count} entity/-ies redacted")
        if url_violations:
            parts.append(f"Unsafe URLs removed: {len(url_violations)}")
        if code_violations:
            parts.append(f"Dangerous code sanitized: {len(code_violations)}")
        parts.append(f"Output risk score: {inspection.risk_score:.2f}")
        return " | ".join(parts)

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]
