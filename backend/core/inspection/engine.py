"""
Input Context Inspection Engine.

Analyzes prompts, files, and documents for:
- PII (Personally Identifiable Information)
- PHI (Protected Health Information)
- PCI data (Payment Card Industry)
- API keys and credentials
- Toxic/harmful content
- Prompt injection and jailbreak attempts

Uses: regex patterns, NER, embeddings, and rule-based scanning.
Produces confidence scores and full explainability output.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Entity Types
# ---------------------------------------------------------------------------

class EntityType(str, Enum):
    """Categories of sensitive entities the inspector can detect."""
    # PII
    PERSON_NAME = "person_name"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    NATIONAL_ID = "national_id"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    IP_ADDRESS = "ip_address"
    # PHI
    SSN = "ssn"
    MEDICAL_RECORD_NUMBER = "medical_record_number"
    HEALTH_PLAN_BENEFICIARY = "health_plan_beneficiary"
    DIAGNOSIS_CODE = "diagnosis_code"
    PRESCRIPTION = "prescription"
    # PCI
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    ROUTING_NUMBER = "routing_number"
    CVV = "cvv"
    # Secrets
    API_KEY = "api_key"
    AWS_KEY = "aws_key"
    JWT_TOKEN = "jwt_token"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    # Threats
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    UNICODE_ATTACK = "unicode_attack"
    INDIRECT_INJECTION = "indirect_injection"
    TOXIC_CONTENT = "toxic_content"


class ThreatCategory(str, Enum):
    """High-level category for threat classification."""
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    SECRET = "secret"
    INJECTION = "injection"
    TOXICITY = "toxicity"
    COMPLIANCE = "compliance"


# ---------------------------------------------------------------------------
# Detection Result Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class DetectedEntity:
    """A single detected sensitive entity within text."""
    entity_type: EntityType
    category: ThreatCategory
    value_masked: str            # Masked representation (never raw value)
    start: int                   # Character offset start
    end: int                     # Character offset end
    confidence: float            # 0.0–1.0
    detection_method: str        # regex | ner | rule | embedding
    policy_reference: Optional[str] = None
    explanation: Optional[str] = None


@dataclass
class InjectionAttempt:
    """A detected prompt injection or jailbreak attempt."""
    attack_type: str
    severity: str                # critical | high | medium | low
    pattern_matched: str
    location: str                # prompt | system | context | rag_doc
    confidence: float
    explanation: str
    remediation: str


@dataclass
class InspectionResult:
    """
    Comprehensive result from the Input Inspection Engine.
    Contains all detected entities, threats, and scoring.
    """
    # Input metadata
    content_hash: str
    content_type: str            # prompt | file | rag_doc
    scan_duration_ms: float

    # Detection results
    entities: List[DetectedEntity] = field(default_factory=list)
    injections: List[InjectionAttempt] = field(default_factory=list)

    # Flags
    pii_detected: bool = False
    phi_detected: bool = False
    pci_detected: bool = False
    secrets_detected: bool = False
    injection_detected: bool = False
    toxicity_detected: bool = False

    # Scoring
    overall_risk_score: float = 0.0
    confidence_scores: Dict[str, float] = field(default_factory=dict)

    # Explainability
    explanation_summary: str = ""
    triggered_rules: List[str] = field(default_factory=list)
    remediation_recommendations: List[str] = field(default_factory=list)

    # Decision
    action: str = "allow"        # allow | redact | block
    block_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Regex Pattern Library
# ---------------------------------------------------------------------------

PATTERNS: Dict[EntityType, List[Tuple[str, str]]] = {
    # --- PII ---
    EntityType.EMAIL: [
        (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "RFC 5322 email pattern"),
    ],
    EntityType.PHONE: [
        (r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "US phone pattern"),
        (r"\b\+?[1-9]\d{1,14}\b", "E.164 international phone"),
    ],
    EntityType.IP_ADDRESS: [
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IPv4 address"),
        (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", "IPv6 address"),
    ],
    # --- PHI ---
    EntityType.SSN: [
        (r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", "SSN with dashes"),
        (r"\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b", "SSN without dashes"),
    ],
    EntityType.MEDICAL_RECORD_NUMBER: [
        (r"\bMRN[:\s#]?\s*\d{6,10}\b", "MRN prefix pattern"),
        (r"\bmedical record[:\s#]?\s*\d{6,10}\b", "Medical record prefix", ),
    ],
    # --- PCI ---
    EntityType.CREDIT_CARD: [
        (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Visa card"),
        (r"\b5[1-5][0-9]{14}\b", "Mastercard"),
        (r"\b3[47][0-9]{13}\b", "Amex"),
        (r"\b6(?:011|5[0-9]{2})[0-9]{12}\b", "Discover"),
        (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b", "Generic card Luhn"),
    ],
    EntityType.CVV: [
        (r"\bcvv[:\s]?\d{3,4}\b", "CVV prefix", ),
        (r"\bcvc[:\s]?\d{3,4}\b", "CVC prefix"),
        (r"\bsecurity code[:\s]?\d{3,4}\b", "Security code prefix"),
    ],
    EntityType.BANK_ACCOUNT: [
        (r"\baccount\s*(?:number|#|no)[:\s]?\s*\d{8,17}\b", "Bank account prefix"),
    ],
    EntityType.ROUTING_NUMBER: [
        (r"\b(?:routing|aba)[:\s]?\s*\d{9}\b", "ABA routing number"),
    ],
    # --- Secrets ---
    EntityType.API_KEY: [
        (r"\bsk-[A-Za-z0-9]{32,}\b", "OpenAI/Anthropic API key"),
        (r"\b[A-Za-z0-9]{32,}[_\-][A-Za-z0-9]{32,}\b", "Generic long API key"),
        (r"(?i)api[_\-]?key[\"'\s:=]+[A-Za-z0-9_\-]{20,}", "Generic API key assignment"),
        (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", "Bearer token"),
    ],
    EntityType.AWS_KEY: [
        (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key ID"),
        (r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"'\s:=]+[A-Za-z0-9/+=]{40}", "AWS Secret Key"),
    ],
    EntityType.JWT_TOKEN: [
        (r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "JWT token pattern"),
    ],
    EntityType.PRIVATE_KEY: [
        (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "PEM private key header"),
        (r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", "OpenSSH private key header"),
    ],
    EntityType.PASSWORD: [
        (r"(?i)password[\"'\s:=]+[^\s\"']{8,}", "Password assignment"),
        (r"(?i)passwd[\"'\s:=]+[^\s\"']{8,}", "Passwd assignment"),
        (r"(?i)pwd[\"'\s:=]+[^\s\"']{8,}", "Pwd assignment"),
    ],
}

# ---------------------------------------------------------------------------
# Prompt Injection Patterns
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "ignore_instructions",
        "pattern": r"(?i)(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier)?\s*(instructions?|prompts?|rules?|guidelines?|constraints?)",
        "severity": "critical",
        "explanation": "Classic prompt injection: attempts to override system instructions",
        "remediation": "Block this prompt. Do not process. Notify security team.",
    },
    {
        "name": "jailbreak_dan",
        "pattern": r"(?i)(DAN|do\s+anything\s+now|jailbreak|jail\s+break|unrestricted\s+mode|developer\s+mode|god\s+mode)",
        "severity": "critical",
        "explanation": "DAN/jailbreak attempt: tries to activate unrestricted persona",
        "remediation": "Block immediately. Log attempt with full context.",
    },
    {
        "name": "role_confusion",
        "pattern": r"(?i)(you\s+are\s+now|pretend\s+you\s+are|act\s+as\s+if\s+you\s+are|your\s+new\s+(role|persona|identity)\s+is)",
        "severity": "high",
        "explanation": "Role confusion attack: attempts to redefine AI identity",
        "remediation": "Sanitize prompt. Remove role-overriding instructions.",
    },
    {
        "name": "system_prompt_leak",
        "pattern": r"(?i)(repeat\s+your\s+(instructions?|prompt|system)|print\s+your\s+system\s+prompt|what\s+(are|were)\s+your\s+instructions?|reveal\s+your\s+prompt)",
        "severity": "high",
        "explanation": "System prompt extraction attempt",
        "remediation": "Block response. Never expose system instructions.",
    },
    {
        "name": "indirect_injection",
        "pattern": r"(?i)(when\s+you\s+read\s+this|hidden\s+instruction|this\s+text\s+contains\s+(a\s+)?(?:hidden\s+)?command|execute\s+the\s+following\s+instruction)",
        "severity": "critical",
        "explanation": "Indirect injection via RAG context or documents",
        "remediation": "Quarantine source document. Block retrieval. Alert.",
    },
    {
        "name": "unicode_attack",
        "pattern": r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
        "severity": "high",
        "explanation": "Hidden Unicode characters detected (zero-width, bidirectional overrides)",
        "remediation": "Strip all non-printable Unicode before processing.",
    },
    {
        "name": "prompt_delimiter_escape",
        "pattern": r"(?i)(</?(system|human|assistant|user|instruction)>|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>)",
        "severity": "high",
        "explanation": "Prompt delimiter injection: exploits token boundary confusion",
        "remediation": "Sanitize all delimiter tokens before forwarding to LLM.",
    },
    {
        "name": "code_execution_trigger",
        "pattern": r"(?i)(execute\s+this\s+(code|script|command)|run\s+(the\s+following|this)\s+(bash|python|shell|command)|eval\s*\(|__import__)",
        "severity": "critical",
        "explanation": "Code execution attempt embedded in prompt",
        "remediation": "Block. Sandbox any code processing. Log for forensics.",
    },
    {
        "name": "data_exfiltration",
        "pattern": r"(?i)(send\s+(all|the|my)\s+(data|files|documents|emails)\s+to|exfiltrate|exfil\s+data|upload\s+(to|all)\s+to\s+https?://)",
        "severity": "critical",
        "explanation": "Data exfiltration instruction detected",
        "remediation": "Block immediately. Disable agent actions for session.",
    },
]

# ---------------------------------------------------------------------------
# Toxicity Keywords (simplified - production should use a classifier)
# ---------------------------------------------------------------------------

TOXICITY_INDICATORS = [
    r"(?i)\b(how\s+to\s+(make|build|create|synthesize)\s+(bomb|explosive|poison|malware|virus|ransomware))\b",
    r"(?i)\b(step[\s\-]by[\s\-]step\s+(guide|instructions?)\s+(to|for)\s+(hack|attack|exploit|murder|kill))\b",
    r"(?i)\b(generate\s+(child|minors?|underage)\s+(sexual|porn|nude|explicit))\b",
]


# ---------------------------------------------------------------------------
# Main Inspection Engine
# ---------------------------------------------------------------------------

class InputInspectionEngine:
    """
    Core inspection engine that analyzes any text content for sensitive data
    and security threats. Produces structured InspectionResult with full
    explainability output.

    Usage:
        engine = InputInspectionEngine()
        result = engine.inspect(text="Hello, my SSN is 123-45-6789", content_type="prompt")
    """

    def __init__(
        self,
        pii_threshold: float = 0.75,
        injection_threshold: float = 0.60,
        toxicity_threshold: float = 0.70,
    ):
        self.pii_threshold = pii_threshold
        self.injection_threshold = injection_threshold
        self.toxicity_threshold = toxicity_threshold
        self._compiled_patterns = self._compile_patterns()
        self._compiled_injections = self._compile_injections()
        self._compiled_toxicity = self._compile_toxicity()
        logger.info("InputInspectionEngine initialized")

    def _compile_patterns(self) -> Dict[EntityType, List[Tuple[re.Pattern, str]]]:
        """Pre-compile all entity regex patterns for performance."""
        compiled: Dict[EntityType, List[Tuple[re.Pattern, str]]] = {}
        for entity_type, pattern_list in PATTERNS.items():
            compiled[entity_type] = [
                (re.compile(p, re.IGNORECASE | re.MULTILINE), desc)
                for p, desc in pattern_list
            ]
        return compiled

    def _compile_injections(self) -> List[Dict[str, Any]]:
        """Pre-compile injection detection patterns."""
        compiled = []
        for item in INJECTION_PATTERNS:
            compiled.append({
                **item,
                "compiled": re.compile(item["pattern"], re.IGNORECASE | re.MULTILINE | re.UNICODE),
            })
        return compiled

    def _compile_toxicity(self) -> List[re.Pattern]:
        """Pre-compile toxicity detection patterns."""
        return [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in TOXICITY_INDICATORS
        ]

    def _content_hash(self, text: str) -> str:
        """Compute SHA-256 hash of content (stored instead of raw content)."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _mask_value(self, value: str, entity_type: EntityType) -> str:
        """Create a masked representation for audit logs (never store raw values)."""
        if entity_type in (EntityType.CREDIT_CARD, EntityType.BANK_ACCOUNT):
            return f"****-****-****-{value[-4:]}" if len(value) >= 4 else "****"
        elif entity_type == EntityType.SSN:
            return "***-**-" + value[-4:] if len(value) >= 4 else "***-**-****"
        elif entity_type == EntityType.EMAIL:
            parts = value.split("@")
            return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "***@***"
        elif entity_type in (EntityType.API_KEY, EntityType.JWT_TOKEN, EntityType.AWS_KEY):
            return value[:8] + "..." + value[-4:] if len(value) > 12 else "****"
        elif entity_type == EntityType.PHONE:
            return value[:3] + "***" + value[-2:] if len(value) > 5 else "***"
        else:
            return value[:3] + "*" * max(0, len(value) - 3) if len(value) > 3 else "***"

    def _entity_to_category(self, entity_type: EntityType) -> ThreatCategory:
        """Map entity type to threat category."""
        pii_types = {EntityType.EMAIL, EntityType.PHONE, EntityType.IP_ADDRESS,
                     EntityType.PERSON_NAME, EntityType.ADDRESS, EntityType.DATE_OF_BIRTH,
                     EntityType.NATIONAL_ID, EntityType.PASSPORT, EntityType.DRIVERS_LICENSE}
        phi_types = {EntityType.SSN, EntityType.MEDICAL_RECORD_NUMBER,
                     EntityType.HEALTH_PLAN_BENEFICIARY, EntityType.DIAGNOSIS_CODE,
                     EntityType.PRESCRIPTION}
        pci_types = {EntityType.CREDIT_CARD, EntityType.BANK_ACCOUNT,
                     EntityType.ROUTING_NUMBER, EntityType.CVV}
        secret_types = {EntityType.API_KEY, EntityType.AWS_KEY, EntityType.JWT_TOKEN,
                        EntityType.PRIVATE_KEY, EntityType.PASSWORD}

        if entity_type in pii_types:
            return ThreatCategory.PII
        elif entity_type in phi_types:
            return ThreatCategory.PHI
        elif entity_type in pci_types:
            return ThreatCategory.PCI
        elif entity_type in secret_types:
            return ThreatCategory.SECRET
        elif entity_type in (EntityType.PROMPT_INJECTION, EntityType.JAILBREAK,
                              EntityType.UNICODE_ATTACK, EntityType.INDIRECT_INJECTION):
            return ThreatCategory.INJECTION
        return ThreatCategory.COMPLIANCE

    def _scan_entities(self, text: str) -> List[DetectedEntity]:
        """
        Scan text for PII, PHI, PCI, and secret entities using regex patterns.
        Returns list of DetectedEntity instances.
        """
        entities: List[DetectedEntity] = []

        for entity_type, pattern_list in self._compiled_patterns.items():
            for pattern, description in pattern_list:
                for match in pattern.finditer(text):
                    # Assign confidence based on pattern specificity
                    confidence = 0.90 if entity_type in (
                        EntityType.CREDIT_CARD, EntityType.SSN, EntityType.AWS_KEY,
                        EntityType.JWT_TOKEN, EntityType.PRIVATE_KEY
                    ) else 0.80

                    entity = DetectedEntity(
                        entity_type=entity_type,
                        category=self._entity_to_category(entity_type),
                        value_masked=self._mask_value(match.group(), entity_type),
                        start=match.start(),
                        end=match.end(),
                        confidence=confidence,
                        detection_method="regex",
                        explanation=f"Detected via {description}",
                    )
                    entities.append(entity)

        return entities

    def _scan_injections(self, text: str) -> List[InjectionAttempt]:
        """
        Scan text for prompt injection, jailbreak, and Unicode attacks.
        Returns list of InjectionAttempt instances.
        """
        attempts: List[InjectionAttempt] = []

        for pattern_def in self._compiled_injections:
            matches = list(pattern_def["compiled"].finditer(text))
            if matches:
                # Unicode attacks - each match is separate
                if pattern_def["name"] == "unicode_attack":
                    confidence = 0.99  # Unicode zero-width chars are unambiguous
                else:
                    confidence = 0.85

                attempt = InjectionAttempt(
                    attack_type=pattern_def["name"],
                    severity=pattern_def["severity"],
                    pattern_matched=f"Pattern: {pattern_def['name']} ({len(matches)} match(es))",
                    location="prompt",
                    confidence=confidence,
                    explanation=pattern_def["explanation"],
                    remediation=pattern_def["remediation"],
                )
                attempts.append(attempt)

        return attempts

    def _scan_toxicity(self, text: str) -> bool:
        """Check for toxic/harmful content using pattern matching."""
        for pattern in self._compiled_toxicity:
            if pattern.search(text):
                return True
        return False

    def _calculate_risk_score(
        self,
        entities: List[DetectedEntity],
        injections: List[InjectionAttempt],
        toxicity: bool,
    ) -> float:
        """
        Calculate overall risk score (0.0–1.0).
        Weighted combination of entity severity and injection/toxicity flags.
        """
        score = 0.0

        # Entity-based scoring
        category_weights = {
            ThreatCategory.SECRET: 0.95,
            ThreatCategory.PHI: 0.85,
            ThreatCategory.PCI: 0.85,
            ThreatCategory.PII: 0.65,
            ThreatCategory.INJECTION: 0.90,
            ThreatCategory.TOXICITY: 0.90,
            ThreatCategory.COMPLIANCE: 0.50,
        }
        for entity in entities:
            weight = category_weights.get(entity.category, 0.50)
            score = max(score, weight * entity.confidence)

        # Injection scoring
        severity_weights = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.40}
        for injection in injections:
            weight = severity_weights.get(injection.severity, 0.50)
            score = max(score, weight * injection.confidence)

        # Toxicity scoring
        if toxicity:
            score = max(score, 0.90)

        return round(min(score, 1.0), 4)

    def _determine_action(
        self,
        risk_score: float,
        entities: List[DetectedEntity],
        injections: List[InjectionAttempt],
        toxicity: bool,
    ) -> Tuple[str, Optional[str]]:
        """
        Determine recommended action: allow | redact | block
        Returns (action, block_reason).
        """
        # Always block injections with critical severity
        for injection in injections:
            if injection.severity == "critical":
                return "block", f"Critical injection detected: {injection.attack_type}"

        # Always block toxicity
        if toxicity:
            return "block", "Harmful/toxic content detected"

        # Always block exposed secrets/credentials
        for entity in entities:
            if entity.category == ThreatCategory.SECRET and entity.confidence >= 0.85:
                return "block", f"Sensitive credential detected: {entity.entity_type.value}"

        # Redact PII/PHI/PCI above threshold
        needs_redaction = any(
            e.category in (ThreatCategory.PII, ThreatCategory.PHI, ThreatCategory.PCI)
            and e.confidence >= self.pii_threshold
            for e in entities
        )
        if needs_redaction:
            return "redact", None

        # High risk score warrants redaction
        if risk_score >= 0.70:
            return "redact", None

        return "allow", None

    def inspect(self, text: str, content_type: str = "prompt") -> InspectionResult:
        """
        Main inspection entry point. Analyzes text for all sensitive data
        and security threats.

        Args:
            text: The content to inspect
            content_type: 'prompt' | 'file' | 'rag_doc' | 'output'

        Returns:
            InspectionResult with full detection and scoring details
        """
        start_time = time.monotonic()

        if not text or not text.strip():
            return InspectionResult(
                content_hash="",
                content_type=content_type,
                scan_duration_ms=0,
                action="allow",
                explanation_summary="Empty content — no scan required",
            )

        content_hash = self._content_hash(text)

        # Run all detectors
        entities = self._scan_entities(text)
        injections = self._scan_injections(text)
        toxicity = self._scan_toxicity(text)

        # Compute flags
        pii_detected = any(e.category == ThreatCategory.PII for e in entities)
        phi_detected = any(e.category == ThreatCategory.PHI for e in entities)
        pci_detected = any(e.category == ThreatCategory.PCI for e in entities)
        secrets_detected = any(e.category == ThreatCategory.SECRET for e in entities)
        injection_detected = len(injections) > 0

        # Compute scores
        risk_score = self._calculate_risk_score(entities, injections, toxicity)
        confidence_scores = {
            "pii": max((e.confidence for e in entities if e.category == ThreatCategory.PII), default=0.0),
            "phi": max((e.confidence for e in entities if e.category == ThreatCategory.PHI), default=0.0),
            "pci": max((e.confidence for e in entities if e.category == ThreatCategory.PCI), default=0.0),
            "secrets": max((e.confidence for e in entities if e.category == ThreatCategory.SECRET), default=0.0),
            "injection": max((inj.confidence for inj in injections), default=0.0),
            "toxicity": 0.90 if toxicity else 0.0,
        }

        # Determine action
        action, block_reason = self._determine_action(risk_score, entities, injections, toxicity)

        # Build triggered rules list
        triggered_rules = []
        for e in entities:
            triggered_rules.append(f"{e.category.value.upper()}: {e.entity_type.value}")
        for inj in injections:
            triggered_rules.append(f"INJECTION: {inj.attack_type} [{inj.severity}]")
        if toxicity:
            triggered_rules.append("TOXICITY: harmful_content_detected")

        # Build remediation recommendations
        remediations = []
        if pii_detected:
            remediations.append("Redact all PII before forwarding to LLM (GDPR Art.5, CCPA §1798.100)")
        if phi_detected:
            remediations.append("Mask PHI immediately — HIPAA Safe Harbor required (45 CFR §164.514)")
        if pci_detected:
            remediations.append("Mask payment card data — PCI-DSS Requirement 3.4 mandates PAN masking")
        if secrets_detected:
            remediations.append("Rotate any exposed credentials immediately. Block this request.")
        for inj in injections:
            remediations.append(inj.remediation)

        # Build explanation summary
        flags = []
        if pii_detected:
            flags.append(f"PII ({sum(1 for e in entities if e.category == ThreatCategory.PII)} entity/ies)")
        if phi_detected:
            flags.append(f"PHI ({sum(1 for e in entities if e.category == ThreatCategory.PHI)} entity/ies)")
        if pci_detected:
            flags.append(f"PCI data ({sum(1 for e in entities if e.category == ThreatCategory.PCI)} entity/ies)")
        if secrets_detected:
            flags.append("SECRETS/CREDENTIALS")
        if injection_detected:
            flags.append(f"INJECTION ATTEMPT ({len(injections)} pattern(s))")
        if toxicity:
            flags.append("TOXIC/HARMFUL CONTENT")

        explanation = (
            f"Scan completed. Action: {action.upper()}. "
            + (f"Detected: {', '.join(flags)}. " if flags else "No threats detected. ")
            + f"Overall risk score: {risk_score:.2%}."
        )

        scan_duration_ms = (time.monotonic() - start_time) * 1000

        result = InspectionResult(
            content_hash=content_hash,
            content_type=content_type,
            scan_duration_ms=round(scan_duration_ms, 2),
            entities=entities,
            injections=injections,
            pii_detected=pii_detected,
            phi_detected=phi_detected,
            pci_detected=pci_detected,
            secrets_detected=secrets_detected,
            injection_detected=injection_detected,
            toxicity_detected=toxicity,
            overall_risk_score=risk_score,
            confidence_scores=confidence_scores,
            explanation_summary=explanation,
            triggered_rules=list(set(triggered_rules)),
            remediation_recommendations=remediations,
            action=action,
            block_reason=block_reason,
        )

        logger.info(
            "inspection_complete",
            content_hash=content_hash[:16],
            action=action,
            risk_score=risk_score,
            entity_count=len(entities),
            injection_count=len(injections),
            duration_ms=scan_duration_ms,
        )

        return result
