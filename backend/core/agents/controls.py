"""
Agent Controls — AI Context Firewall
Permission boundaries, tool-use governance, approval workflows,
and sandboxing for autonomous AI agents.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class AgentPermission(str, Enum):
    """Coarse-grained permissions for agent capabilities."""
    READ_FILES       = "read_files"
    WRITE_FILES      = "write_files"
    DELETE_FILES     = "delete_files"
    EXECUTE_CODE     = "execute_code"
    NETWORK_ACCESS   = "network_access"
    DATABASE_READ    = "database_read"
    DATABASE_WRITE   = "database_write"
    EMAIL_SEND       = "email_send"
    API_CALL         = "api_call"
    SYSTEM_COMMAND   = "system_command"
    MEMORY_READ      = "memory_read"
    MEMORY_WRITE     = "memory_write"


class AgentActionRisk(str, Enum):
    CRITICAL   = "critical"
    HIGH       = "high"
    MEDIUM     = "medium"
    LOW        = "low"
    SAFE       = "safe"


class AgentDecision(str, Enum):
    ALLOW    = "allow"
    DENY     = "deny"
    ESCALATE = "escalate"   # Requires human approval
    SANDBOX  = "sandbox"    # Allow in sandboxed environment only


@dataclass
class AgentToolCall:
    """A single tool/function call requested by an agent."""
    call_id:    str
    agent_id:   str
    session_id: str
    tenant_id:  str
    tool_name:  str
    arguments:  dict[str, Any]
    context:    str = ""    # Natural language explanation from agent
    timestamp:  float = field(default_factory=time.time)


@dataclass
class AgentControlResult:
    """Decision on whether an agent tool call is permitted."""
    call_id:    str
    decision:   AgentDecision
    allowed:    bool
    risk_level: AgentActionRisk
    tool_name:  str
    reason:     str
    required_permissions: list[AgentPermission] = field(default_factory=list)
    missing_permissions:  list[AgentPermission] = field(default_factory=list)
    requires_approval:    bool   = False
    approval_reason:      str    = ""
    sandbox_mode:         bool   = False
    audit_note:           str    = ""
    processing_time_ms:   float  = 0.0
    timestamp:            float  = field(default_factory=time.time)


@dataclass
class AgentProfile:
    """Security profile for a registered agent."""
    agent_id:    str
    name:        str
    tenant_id:   str
    permissions: list[AgentPermission] = field(default_factory=list)
    max_risk:    AgentActionRisk = AgentActionRisk.MEDIUM
    require_approval_above: AgentActionRisk = AgentActionRisk.HIGH
    sandbox_mode:  bool = False
    is_active:     bool = True
    created_at:    float = field(default_factory=time.time)
    metadata:      dict  = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tool Risk Registry
# ---------------------------------------------------------------------------

# Maps tool name patterns to (required_permissions, risk_level, escalate_flag)
TOOL_RISK_REGISTRY: list[tuple[str, list[AgentPermission], AgentActionRisk, bool]] = [
    # pattern,                     required perms,                          risk,                         escalate?
    (r"^read_file$",               [AgentPermission.READ_FILES],            AgentActionRisk.LOW,          False),
    (r"^list_files?$",             [AgentPermission.READ_FILES],            AgentActionRisk.LOW,          False),
    (r"^write_file$",              [AgentPermission.WRITE_FILES],           AgentActionRisk.MEDIUM,       False),
    (r"^delete_file$",             [AgentPermission.DELETE_FILES],          AgentActionRisk.HIGH,         True),
    (r"^execute_(?:code|script)$", [AgentPermission.EXECUTE_CODE],          AgentActionRisk.CRITICAL,     True),
    (r"^run_(?:bash|shell|cmd)$",  [AgentPermission.SYSTEM_COMMAND,
                                    AgentPermission.EXECUTE_CODE],          AgentActionRisk.CRITICAL,     True),
    (r"^http_(?:get|post|put)$",   [AgentPermission.NETWORK_ACCESS,
                                    AgentPermission.API_CALL],              AgentActionRisk.MEDIUM,       False),
    (r"^db_(?:query|select)$",     [AgentPermission.DATABASE_READ],         AgentActionRisk.MEDIUM,       False),
    (r"^db_(?:insert|update)$",    [AgentPermission.DATABASE_WRITE],        AgentActionRisk.HIGH,         True),
    (r"^db_delete$",               [AgentPermission.DATABASE_WRITE,
                                    AgentPermission.DELETE_FILES],          AgentActionRisk.CRITICAL,     True),
    (r"^send_email$",              [AgentPermission.EMAIL_SEND],            AgentActionRisk.HIGH,         True),
    (r"^memory_(?:read|recall)$",  [AgentPermission.MEMORY_READ],          AgentActionRisk.LOW,          False),
    (r"^memory_(?:write|store)$",  [AgentPermission.MEMORY_WRITE],         AgentActionRisk.MEDIUM,       False),
]

# Pre-compile
_COMPILED_REGISTRY = [
    (re.compile(pat, re.IGNORECASE), perms, risk, escalate)
    for pat, perms, risk, escalate in TOOL_RISK_REGISTRY
]

RISK_ORDER = [
    AgentActionRisk.SAFE,
    AgentActionRisk.LOW,
    AgentActionRisk.MEDIUM,
    AgentActionRisk.HIGH,
    AgentActionRisk.CRITICAL,
]


def _risk_gte(a: AgentActionRisk, b: AgentActionRisk) -> bool:
    """True if risk a >= risk b."""
    return RISK_ORDER.index(a) >= RISK_ORDER.index(b)


def _lookup_tool(tool_name: str) -> tuple[list[AgentPermission], AgentActionRisk, bool]:
    """Returns (required_perms, risk_level, needs_escalation) for a tool name."""
    for pattern, perms, risk, escalate in _COMPILED_REGISTRY:
        if pattern.match(tool_name):
            return perms, risk, escalate
    # Unknown tool — treat as high risk requiring approval
    return [], AgentActionRisk.HIGH, True


# ---------------------------------------------------------------------------
# Argument Scanner (detect dangerous argument values)
# ---------------------------------------------------------------------------

DANGEROUS_ARG_PATTERNS: list[tuple[str, str, AgentActionRisk]] = [
    (r"(?:rm\s+-rf|del\s+/f\s+/s|format)",           "Destructive command",      AgentActionRisk.CRITICAL),
    (r"\.\./\.\./",                                    "Path traversal",           AgentActionRisk.CRITICAL),
    (r"(?:0\.0\.0\.0|127\.0\.0\.1|localhost)\b",      "Localhost access",         AgentActionRisk.HIGH),
    (r"(?:DROP|TRUNCATE|DELETE\s+FROM)\s+",            "Destructive SQL",          AgentActionRisk.CRITICAL),
    (r"(?:eval|exec|__import__|subprocess)\s*\(",     "Code injection",           AgentActionRisk.CRITICAL),
    (r"\$\(|`[^`]+`",                                  "Command substitution",     AgentActionRisk.CRITICAL),
    (r"(?:sk-|rk-|api_key)[A-Za-z0-9]{16,}",          "Credential in argument",   AgentActionRisk.HIGH),
]

_ARG_PATTERNS = [
    (re.compile(p, re.IGNORECASE | re.MULTILINE), n, r)
    for p, n, r in DANGEROUS_ARG_PATTERNS
]


def scan_arguments(arguments: dict[str, Any]) -> list[tuple[str, str, AgentActionRisk]]:
    """Returns list of (field_name, threat_name, risk_level) for dangerous argument values."""
    threats = []
    arg_text = str(arguments)
    for pattern, name, risk in _ARG_PATTERNS:
        if pattern.search(arg_text):
            threats.append(("*", name, risk))
    return threats


# ---------------------------------------------------------------------------
# Agent Controller
# ---------------------------------------------------------------------------

class AgentController:
    """
    Central controller for AI agent tool-use governance.

    Enforces:
    - Permission boundary checks
    - Risk-based approval workflows
    - Argument-level threat detection
    - Rate limiting per agent
    - Audit trail of all tool calls
    """

    def __init__(self, approval_callback: Callable | None = None):
        self._agents:   dict[str, AgentProfile] = {}
        self._approval_callback = approval_callback
        self._call_log: list[AgentControlResult] = []

        # Rate limiting: agent_id -> list of timestamps
        self._rate_windows: dict[str, list[float]] = {}
        self.RATE_LIMIT_WINDOW = 60     # seconds
        self.RATE_LIMIT_MAX    = 100    # calls per window

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_agent(self, profile: AgentProfile):
        self._agents[profile.agent_id] = profile

    def get_agent(self, agent_id: str) -> AgentProfile | None:
        return self._agents.get(agent_id)

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate_tool_call(self, call: AgentToolCall) -> AgentControlResult:
        t0 = time.perf_counter()

        agent = self._agents.get(call.agent_id)
        if not agent or not agent.is_active:
            return self._deny(call, "Agent not registered or inactive", AgentActionRisk.CRITICAL, t0)

        # Rate limit
        if self._is_rate_limited(call.agent_id):
            return self._deny(call, "Rate limit exceeded", AgentActionRisk.MEDIUM, t0)

        # Look up tool risk
        required_perms, tool_risk, needs_escalation = _lookup_tool(call.tool_name)

        # Check arguments for threats
        arg_threats = scan_arguments(call.arguments)
        if arg_threats:
            max_risk = max((r for _, _, r in arg_threats), default=AgentActionRisk.MEDIUM)
            if _risk_gte(max_risk, AgentActionRisk.CRITICAL):
                return self._deny(
                    call,
                    f"Dangerous argument detected: {', '.join(n for _, n, _ in arg_threats[:2])}",
                    AgentActionRisk.CRITICAL, t0,
                )
            tool_risk = max_risk if _risk_gte(max_risk, tool_risk) else tool_risk

        # Permission check
        missing = [p for p in required_perms if p not in agent.permissions]
        if missing:
            return self._deny(
                call,
                f"Missing permissions: {', '.join(p.value for p in missing)}",
                tool_risk, t0,
                required_permissions=required_perms,
                missing_permissions=missing,
            )

        # Risk ceiling check
        if _risk_gte(tool_risk, AgentActionRisk.CRITICAL) and agent.max_risk != AgentActionRisk.CRITICAL:
            return self._deny(call, f"Tool risk ({tool_risk.value}) exceeds agent ceiling ({agent.max_risk.value})", tool_risk, t0)

        # Escalation / approval
        requires_approval = needs_escalation or _risk_gte(tool_risk, agent.require_approval_above)
        if requires_approval:
            decision = AgentDecision.ESCALATE
            allowed  = False  # Hold until approved
            reason   = f"Human approval required for {call.tool_name} (risk: {tool_risk.value})"
        elif agent.sandbox_mode:
            decision = AgentDecision.SANDBOX
            allowed  = True
            reason   = "Permitted in sandbox mode"
        else:
            decision = AgentDecision.ALLOW
            allowed  = True
            reason   = f"Permitted: all checks passed (risk: {tool_risk.value})"

        elapsed = (time.perf_counter() - t0) * 1000
        self._record_call(call.agent_id)

        result = AgentControlResult(
            call_id              = call.call_id,
            decision             = decision,
            allowed              = allowed,
            risk_level           = tool_risk,
            tool_name            = call.tool_name,
            reason               = reason,
            required_permissions = required_perms,
            missing_permissions  = [],
            requires_approval    = requires_approval,
            approval_reason      = reason if requires_approval else "",
            sandbox_mode         = agent.sandbox_mode,
            processing_time_ms   = elapsed,
        )

        self._call_log.append(result)

        # Trigger approval callback if configured
        if requires_approval and self._approval_callback:
            self._approval_callback(call, result)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _deny(
        self,
        call: AgentToolCall,
        reason: str,
        risk: AgentActionRisk,
        t0: float,
        required_permissions: list | None = None,
        missing_permissions:  list | None = None,
    ) -> AgentControlResult:
        elapsed = (time.perf_counter() - t0) * 1000
        result = AgentControlResult(
            call_id              = call.call_id,
            decision             = AgentDecision.DENY,
            allowed              = False,
            risk_level           = risk,
            tool_name            = call.tool_name,
            reason               = reason,
            required_permissions = required_permissions or [],
            missing_permissions  = missing_permissions or [],
            requires_approval    = False,
            processing_time_ms   = elapsed,
        )
        self._call_log.append(result)
        return result

    def _is_rate_limited(self, agent_id: str) -> bool:
        now = time.time()
        window = [t for t in self._rate_windows.get(agent_id, []) if now - t < self.RATE_LIMIT_WINDOW]
        self._rate_windows[agent_id] = window
        return len(window) >= self.RATE_LIMIT_MAX

    def _record_call(self, agent_id: str):
        self._rate_windows.setdefault(agent_id, []).append(time.time())

    def get_audit_log(self) -> list[AgentControlResult]:
        return list(self._call_log)

    def clear_audit_log(self):
        self._call_log.clear()
