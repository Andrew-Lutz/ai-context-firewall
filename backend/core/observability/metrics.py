"""
Observability & Metrics — AI Context Firewall
Prometheus metrics, structured logging, and telemetry for the firewall platform.
"""

from __future__ import annotations

import logging
import time
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("ai_context_firewall.metrics")

# ---------------------------------------------------------------------------
# Prometheus metrics (with graceful fallback if prometheus_client unavailable)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Summary,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client not installed — metrics will be no-op")


class _NoOpMetric:
    """No-op metric for when prometheus_client is unavailable."""
    def labels(self, **kwargs): return self
    def inc(self, *a, **kw): pass
    def observe(self, *a, **kw): pass
    def set(self, *a, **kw): pass
    def time(self): return _NoOpTimer()


class _NoOpTimer:
    def __enter__(self): return self
    def __exit__(self, *a): pass


def _make_counter(name, desc, labels=None):
    if PROMETHEUS_AVAILABLE:
        return Counter(name, desc, labels or [])
    return _NoOpMetric()


def _make_histogram(name, desc, labels=None, buckets=None):
    if PROMETHEUS_AVAILABLE:
        kwargs = {"labelnames": labels or []}
        if buckets:
            kwargs["buckets"] = buckets
        return Histogram(name, desc, **kwargs)
    return _NoOpMetric()


def _make_gauge(name, desc, labels=None):
    if PROMETHEUS_AVAILABLE:
        return Gauge(name, desc, labels or [])
    return _NoOpMetric()


# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

# Request counters
REQUESTS_TOTAL = _make_counter(
    "acf_requests_total",
    "Total requests processed by the firewall",
    ["tenant_id", "action", "endpoint"],
)

# Decision counters
DECISIONS = _make_counter(
    "acf_decisions_total",
    "Firewall decisions by action type",
    ["action", "risk_level", "tenant_id"],
)

# Entity detections
ENTITIES_DETECTED = _make_counter(
    "acf_entities_detected_total",
    "Total entities detected across all scans",
    ["entity_type", "severity", "tenant_id"],
)

# Injection attempts
INJECTION_ATTEMPTS = _make_counter(
    "acf_injection_attempts_total",
    "Total injection attempts detected",
    ["injection_type", "tenant_id"],
)

# Policy violations
POLICY_VIOLATIONS = _make_counter(
    "acf_policy_violations_total",
    "Policy rule violations triggered",
    ["policy_id", "rule_id", "action"],
)

# Processing latency
PROCESSING_LATENCY = _make_histogram(
    "acf_processing_latency_ms",
    "Firewall processing latency in milliseconds",
    ["component"],
    buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500],
)

# Risk score distribution
RISK_SCORE = _make_histogram(
    "acf_risk_score",
    "Distribution of risk scores",
    ["tenant_id"],
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

# Active sessions
ACTIVE_SESSIONS = _make_gauge(
    "acf_active_sessions",
    "Number of active firewall sessions",
    ["tenant_id"],
)

# Token vault size
TOKEN_VAULT_SIZE = _make_gauge(
    "acf_token_vault_entries",
    "Number of entries in the token vault",
    ["tenant_id"],
)

# Agent tool calls
AGENT_TOOL_CALLS = _make_counter(
    "acf_agent_tool_calls_total",
    "Agent tool call decisions",
    ["agent_id", "tool_name", "decision"],
)

# RAG retrieval
RAG_RETRIEVALS = _make_counter(
    "acf_rag_retrievals_total",
    "RAG retrieval authorization decisions",
    ["store_id", "action", "tenant_id"],
)


# ---------------------------------------------------------------------------
# Structured event logging
# ---------------------------------------------------------------------------

@dataclass
class FirewallEvent:
    """Structured audit event for the firewall."""
    event_id:    str
    event_type:  str
    tenant_id:   str
    user_id:     str
    session_id:  str
    action:      str
    risk_score:  float
    timestamp:   float = field(default_factory=time.time)
    metadata:    dict  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id":   self.event_id,
            "event_type": self.event_type,
            "tenant_id":  self.tenant_id,
            "user_id":    self.user_id,
            "session_id": self.session_id,
            "action":     self.action,
            "risk_score": round(self.risk_score, 4),
            "timestamp":  self.timestamp,
            **self.metadata,
        }


class MetricsCollector:
    """
    Central metrics collector for the AI Context Firewall.
    Records all security events, updates Prometheus metrics,
    and emits structured log lines for SIEM/SOAR integration.
    """

    def __init__(self, enable_structured_logging: bool = True):
        self._enable_logging = enable_structured_logging
        self._event_buffer:  list[FirewallEvent] = []
        self._max_buffer     = 1000

    # ------------------------------------------------------------------
    # Record helpers
    # ------------------------------------------------------------------

    def record_scan(
        self,
        tenant_id:    str,
        user_id:      str,
        session_id:   str,
        action:       str,
        risk_score:   float,
        risk_level:   str,
        entities:     list[dict],
        injections:   list[dict],
        processing_ms: float,
        endpoint:     str = "scan",
    ):
        """Record a prompt/file scan result."""
        REQUESTS_TOTAL.labels(tenant_id=tenant_id, action=action, endpoint=endpoint).inc()
        DECISIONS.labels(action=action, risk_level=risk_level, tenant_id=tenant_id).inc()
        PROCESSING_LATENCY.labels(component="inspection").observe(processing_ms)
        RISK_SCORE.labels(tenant_id=tenant_id).observe(risk_score)

        for entity in entities:
            ENTITIES_DETECTED.labels(
                entity_type=entity.get("type", "unknown"),
                severity=entity.get("severity", "unknown"),
                tenant_id=tenant_id,
            ).inc()

        for injection in injections:
            INJECTION_ATTEMPTS.labels(
                injection_type=injection.get("type", "unknown"),
                tenant_id=tenant_id,
            ).inc()

        self._emit_event(FirewallEvent(
            event_id   = self._gen_id(),
            event_type = "scan",
            tenant_id  = tenant_id,
            user_id    = user_id,
            session_id = session_id,
            action     = action,
            risk_score = risk_score,
            metadata   = {
                "entities_count":  len(entities),
                "injections_count": len(injections),
                "processing_ms":   processing_ms,
                "endpoint":        endpoint,
            },
        ))

    def record_policy_violation(
        self,
        tenant_id:  str,
        policy_id:  str,
        rule_id:    str,
        action:     str,
        user_id:    str = "",
        session_id: str = "",
    ):
        POLICY_VIOLATIONS.labels(policy_id=policy_id, rule_id=rule_id, action=action).inc()
        self._emit_event(FirewallEvent(
            event_id   = self._gen_id(),
            event_type = "policy_violation",
            tenant_id  = tenant_id,
            user_id    = user_id,
            session_id = session_id,
            action     = action,
            risk_score = 1.0,
            metadata   = {"policy_id": policy_id, "rule_id": rule_id},
        ))

    def record_agent_call(
        self,
        agent_id:  str,
        tool_name: str,
        decision:  str,
        tenant_id: str = "",
    ):
        AGENT_TOOL_CALLS.labels(agent_id=agent_id, tool_name=tool_name, decision=decision).inc()

    def record_rag_retrieval(
        self,
        store_id:  str,
        action:    str,
        tenant_id: str,
    ):
        RAG_RETRIEVALS.labels(store_id=store_id, action=action, tenant_id=tenant_id).inc()

    def set_active_sessions(self, tenant_id: str, count: int):
        ACTIVE_SESSIONS.labels(tenant_id=tenant_id).set(count)

    def set_vault_size(self, tenant_id: str, count: int):
        TOKEN_VAULT_SIZE.labels(tenant_id=tenant_id).set(count)

    # ------------------------------------------------------------------
    # Prometheus export
    # ------------------------------------------------------------------

    def get_prometheus_output(self) -> tuple[bytes, str]:
        if PROMETHEUS_AVAILABLE:
            return generate_latest(), CONTENT_TYPE_LATEST
        return b"# prometheus_client not installed\n", "text/plain"

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_event(self, event: FirewallEvent):
        if len(self._event_buffer) >= self._max_buffer:
            self._event_buffer.pop(0)
        self._event_buffer.append(event)

        if self._enable_logging:
            import json
            logger.info(json.dumps(event.to_dict()))

    def get_recent_events(self, n: int = 100) -> list[dict]:
        return [e.to_dict() for e in self._event_buffer[-n:]]

    def flush_events(self) -> list[dict]:
        events = [e.to_dict() for e in self._event_buffer]
        self._event_buffer.clear()
        return events

    @staticmethod
    def _gen_id() -> str:
        import uuid
        return str(uuid.uuid4())[:8]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_collector: MetricsCollector | None = None


def get_metrics_collector() -> MetricsCollector:
    global _collector
    if _collector is None:
        _collector = MetricsCollector(
            enable_structured_logging=os.getenv("STRUCTURED_LOGGING", "true").lower() == "true"
        )
    return _collector
