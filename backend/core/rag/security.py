"""
RAG Security — AI Context Firewall
Secures Retrieval-Augmented Generation pipelines with authorization,
poisoning detection, source attribution, and output filtering.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class DocumentClassification(str, Enum):
    PUBLIC       = "public"
    INTERNAL     = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED   = "restricted"


class RetrievalAction(str, Enum):
    ALLOW     = "allow"
    DENY      = "deny"
    FILTER    = "filter"      # Return partial/sanitized results
    QUARANTINE = "quarantine" # Flag docs for review


@dataclass
class DocumentMetadata:
    """Metadata for a document in a vector store."""
    doc_id:         str
    store_id:       str
    title:          str = ""
    classification: DocumentClassification = DocumentClassification.INTERNAL
    owner:          str = ""
    allowed_roles:  list[str] = field(default_factory=list)
    tags:           list[str] = field(default_factory=list)
    content_hash:   str = ""
    ingested_at:    float = field(default_factory=time.time)
    is_quarantined: bool = False


@dataclass
class RetrievalRequest:
    """A RAG retrieval request to be authorized."""
    request_id:  str
    session_id:  str
    tenant_id:   str
    user_id:     str
    user_role:   str
    query:       str
    store_ids:   list[str]
    top_k:       int   = 5
    min_score:   float = 0.7
    policy_ids:  list[str] = field(default_factory=list)


@dataclass
class RetrievalAuthResult:
    """Authorization decision for a retrieval request."""
    request_id:     str
    action:         RetrievalAction
    allowed:        bool
    authorized_stores:  list[str]
    denied_stores:      list[str]
    query_risk_score:   float
    injection_detected: bool
    block_reason:   str | None  = None
    filtered_docs:  list[str]   = field(default_factory=list)
    warnings:       list[str]   = field(default_factory=list)
    processing_time_ms: float   = 0.0


@dataclass
class PoisoningDetectionResult:
    """Result of scanning a document for poisoning attacks."""
    doc_id:     str
    is_poisoned: bool
    threats:    list[dict]   = field(default_factory=list)
    risk_score: float        = 0.0
    explanation: str         = ""


# ---------------------------------------------------------------------------
# Access Control Engine
# ---------------------------------------------------------------------------

ROLE_CLEARANCE: dict[str, int] = {
    "anonymous":          0,
    "employee":           1,
    "analyst":            2,
    "compliance_officer": 3,
    "admin":              4,
}

CLASSIFICATION_CLEARANCE: dict[DocumentClassification, int] = {
    DocumentClassification.PUBLIC:       0,
    DocumentClassification.INTERNAL:     1,
    DocumentClassification.CONFIDENTIAL: 2,
    DocumentClassification.RESTRICTED:   3,
}


class RAGAccessControl:
    """
    Attribute-based access control for RAG retrieval.
    Uses role clearance levels + document classification.
    """

    def can_access(self, user_role: str, classification: DocumentClassification) -> bool:
        user_level = ROLE_CLEARANCE.get(user_role, 0)
        doc_level  = CLASSIFICATION_CLEARANCE.get(classification, 3)
        return user_level >= doc_level

    def filter_documents(
        self,
        docs: list[DocumentMetadata],
        user_role: str,
    ) -> tuple[list[DocumentMetadata], list[DocumentMetadata]]:
        """Returns (allowed_docs, denied_docs)."""
        allowed, denied = [], []
        for doc in docs:
            if doc.is_quarantined:
                denied.append(doc)
            elif self.can_access(user_role, doc.classification):
                allowed.append(doc)
            else:
                denied.append(doc)
        return allowed, denied


# ---------------------------------------------------------------------------
# Poisoning Detector
# ---------------------------------------------------------------------------

class VectorStorePoisoningDetector:
    """
    Detects poisoning attacks in documents before/after ingestion.

    Threat types detected:
    - Instruction injection (embedded LLM instructions)
    - Hidden HTML/XML tags with directives
    - Data exfiltration hooks
    - Adversarial text (unicode tricks)
    - Semantic manipulation
    """

    INJECTION_PATTERNS: list[tuple[str, str, str]] = [
        # pattern, threat_type, severity
        (r"<!--\s*(?:ignore|system:|instruction:).*?-->",              "HTML Comment Injection",   "critical"),
        (r"</?(?:system|instruction|ctx|prompt)\s*/?>",                "XML Tag Injection",         "critical"),
        (r"ignore\s+(?:all\s+)?(?:previous|above)\s+instructions?",    "Instruction Override",      "critical"),
        (r"when\s+(?:someone\s+)?asks?\s+(?:about|for).*?(?:say|tell|respond\s+with)", "Conditional Trigger", "high"),
        (r"https?://\S+(?:\?|&)(?:data|content|query)=",              "Exfiltration URL",          "high"),
        (r"[\u200b\u200c\u200d\ufeff]",                                "Zero-Width Characters",     "medium"),
        (r"(?:this\s+document\s+(?:says?|states?|claims?))\s+(?:that\s+)?(?:you|the\s+AI|assistant)\s+(?:must|should|will)", "Semantic Override", "high"),
    ]

    def __init__(self):
        self._patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), t, s)
            for p, t, s in self.INJECTION_PATTERNS
        ]

    def scan(self, doc_id: str, content: str) -> PoisoningDetectionResult:
        threats = []
        max_risk = 0.0

        for pattern, threat_type, severity in self._patterns:
            matches = list(pattern.finditer(content))
            if matches:
                risk = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}[severity]
                max_risk = max(max_risk, risk)

                # Store payload snippet (truncated, never full content)
                snippet = matches[0].group()[:100]
                threats.append({
                    "threat_type": threat_type,
                    "severity":    severity,
                    "count":       len(matches),
                    "payload_snippet": snippet,
                    "positions": [(m.start(), m.end()) for m in matches[:3]],
                })

        is_poisoned = len(threats) > 0

        explanation = ""
        if is_poisoned:
            names = [t["threat_type"] for t in threats]
            explanation = f"Document contains {len(threats)} threat(s): {', '.join(names[:3])}"
        else:
            explanation = "Document passed poisoning scan"

        return PoisoningDetectionResult(
            doc_id      = doc_id,
            is_poisoned = is_poisoned,
            threats     = threats,
            risk_score  = max_risk,
            explanation = explanation,
        )

    def scan_batch(self, documents: list[tuple[str, str]]) -> list[PoisoningDetectionResult]:
        """Scan a batch of (doc_id, content) tuples."""
        return [self.scan(doc_id, content) for doc_id, content in documents]


# ---------------------------------------------------------------------------
# Query Authorization
# ---------------------------------------------------------------------------

class RAGQueryFirewall:
    """
    Authorizes and sanitizes RAG retrieval queries.
    Prevents query injection, privilege escalation, and data fishing.
    """

    QUERY_INJECTION_PATTERNS: list[tuple[str, str]] = [
        (r"(?:show|return|list|dump|select)\s+(?:all|everything|every|ALL\s+RECORDS)",  "Mass Retrieval"),
        (r"(?:ignore|bypass|skip)\s+(?:filter|access\s+control|permission|acl)",        "Access Control Bypass"),
        (r"(?:WHERE|SELECT|INSERT|UPDATE|DELETE|DROP)\s+",                               "SQL-like Injection"),
        (r"\$(?:where|or|and|regex)\s*:",                                                "NoSQL Injection"),
        (r"(?:for\s+all\s+users?|across\s+all\s+tenants?)",                             "Cross-Tenant Query"),
    ]

    def __init__(self):
        self._patterns = [
            (re.compile(p, re.IGNORECASE), n)
            for p, n in self.QUERY_INJECTION_PATTERNS
        ]

    def authorize(self, request: RetrievalRequest) -> RetrievalAuthResult:
        t0 = time.perf_counter()

        # Check query for injection
        injection_found = None
        for pattern, name in self._patterns:
            if pattern.search(request.query):
                injection_found = name
                break

        if injection_found:
            elapsed = (time.perf_counter() - t0) * 1000
            return RetrievalAuthResult(
                request_id         = request.request_id,
                action             = RetrievalAction.DENY,
                allowed            = False,
                authorized_stores  = [],
                denied_stores      = request.store_ids,
                query_risk_score   = 0.95,
                injection_detected = True,
                block_reason       = f"Query injection detected: {injection_found}",
                processing_time_ms = elapsed,
            )

        # Risk-score the query
        risk = self._score_query(request.query)

        # Authorize stores
        acl = RAGAccessControl()
        # For simplicity — in production each store has a classification
        # Here we use a placeholder: all stores default to "internal"
        authorized, denied = request.store_ids, []

        elapsed = (time.perf_counter() - t0) * 1000

        action = RetrievalAction.ALLOW if risk < 0.7 else RetrievalAction.FILTER

        return RetrievalAuthResult(
            request_id         = request.request_id,
            action             = action,
            allowed            = True,
            authorized_stores  = authorized,
            denied_stores      = denied,
            query_risk_score   = risk,
            injection_detected = False,
            processing_time_ms = elapsed,
        )

    def _score_query(self, query: str) -> float:
        """Simple heuristic risk scoring for queries."""
        risk = 0.0
        # PII fishing
        pii_re = [
            r"\bSSN\b", r"\bsocial\s+security\b", r"\bcredit\s+card\b",
            r"\bpassword\b", r"\bapi\s+key\b", r"\bsecret\b",
        ]
        for pat in pii_re:
            if re.search(pat, query, re.IGNORECASE):
                risk = max(risk, 0.6)

        # Personal data fishing
        if re.search(r"\b(?:patient|customer|employee|user)\s+(?:records?|data|info)\b", query, re.I):
            risk = max(risk, 0.5)

        # Bulk retrieval
        if re.search(r"\ball\s+(?:records?|documents?|files?|data)\b", query, re.I):
            risk = max(risk, 0.8)

        return risk


# ---------------------------------------------------------------------------
# Source Attribution
# ---------------------------------------------------------------------------

class SourceAttributionEngine:
    """
    Enforces source attribution in RAG responses.
    Ensures every claim can be traced back to its source document.
    """

    def build_attribution_context(
        self,
        retrieved_docs: list[dict],
        user_role:      str,
    ) -> tuple[str, list[dict]]:
        """
        Returns (attribution_context_string, citation_map).
        Only includes document metadata visible to the requesting user.
        """
        acl = RAGAccessControl()
        citation_map = []
        context_parts = []

        for i, doc in enumerate(retrieved_docs, 1):
            classification = DocumentClassification(doc.get("classification", "internal"))
            if not acl.can_access(user_role, classification):
                continue

            doc_id    = doc.get("doc_id", f"doc_{i}")
            title     = doc.get("title", "Unknown Document")
            content   = doc.get("content", "")
            score     = doc.get("score", 0.0)
            store_id  = doc.get("store_id", "unknown")

            citation_map.append({
                "citation_id": i,
                "doc_id":      doc_id,
                "title":       title,
                "store_id":    store_id,
                "score":       score,
                "classification": classification.value,
            })

            context_parts.append(
                f"[Source {i}] {title} (doc_id: {doc_id}, relevance: {score:.2f})\n{content}"
            )

        return "\n\n---\n\n".join(context_parts), citation_map
