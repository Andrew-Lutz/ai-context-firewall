"""
Governance & Policy Engine.

Loads, validates, and evaluates YAML-based compliance policies.
Supports HIPAA, GDPR, PCI-DSS, SOC2, FINRA, SEC, NIST, and custom rules.

Policy evaluation is deterministic and fully explainable:
- Every decision includes which rule triggered
- Confidence score and remediation recommendation
- Full audit trail
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import structlog
import yaml

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Policy Rule Types
# ---------------------------------------------------------------------------

class RuleAction(str, Enum):
    BLOCK = "block"
    REDACT = "redact"
    ALERT = "alert"
    AUDIT = "audit"
    ALLOW = "allow"


class RuleConditionType(str, Enum):
    ENTITY_DETECTED = "entity_detected"
    RISK_SCORE_ABOVE = "risk_score_above"
    INJECTION_DETECTED = "injection_detected"
    KEYWORD_MATCH = "keyword_match"
    CONTENT_TYPE = "content_type"
    USER_ROLE = "user_role"
    DATA_CATEGORY = "data_category"
    MODEL_NAME = "model_name"
    DEPARTMENT = "department"
    REGION = "region"


# ---------------------------------------------------------------------------
# Policy Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PolicyRule:
    """A single evaluatable rule within a policy."""
    id: str
    name: str
    description: str
    condition_type: RuleConditionType
    condition_value: Any          # entity type, threshold, keywords, etc.
    action: RuleAction
    severity: str                 # critical | high | medium | low
    explanation_template: str
    remediation: str
    enabled: bool = True
    applies_to: List[str] = field(default_factory=list)  # roles/depts/regions
    exceptions: List[str] = field(default_factory=list)  # allowed exceptions


@dataclass
class PolicyDefinition:
    """A complete policy containing multiple rules."""
    id: str
    name: str
    framework: str               # hipaa | gdpr | pci_dss | soc2 | finra | custom
    version: str
    description: str
    industry: Optional[str]
    tenant_id: Optional[str]
    rules: List[PolicyRule]
    enforce_mode: bool = True    # False = audit-only
    active: bool = True


@dataclass
class RuleEvaluationResult:
    """Result of evaluating a single rule against a context."""
    rule_id: str
    rule_name: str
    framework: str
    triggered: bool
    action: RuleAction
    severity: str
    explanation: str
    remediation: str
    confidence: float


@dataclass
class PolicyEvaluationResult:
    """Result of evaluating all active policies against a context."""
    # Overall decision
    final_action: str            # allow | redact | block | alert
    blocked: bool
    redact_required: bool
    alert_required: bool

    # All triggered rules
    triggered_rules: List[RuleEvaluationResult] = field(default_factory=list)
    all_rules_evaluated: int = 0
    policies_evaluated: List[str] = field(default_factory=list)

    # Explainability
    explanation_summary: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    compliance_frameworks_triggered: Set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# YAML Policy Loader
# ---------------------------------------------------------------------------

class PolicyLoader:
    """
    Loads and validates YAML policy files from the policies/ directory.
    Supports hot-reload in development environments.
    """

    REQUIRED_POLICY_FIELDS = {"id", "name", "framework", "version", "rules"}
    REQUIRED_RULE_FIELDS = {"id", "name", "condition_type", "condition_value", "action", "severity"}

    def __init__(self, policies_dir: str = "policies"):
        self.policies_dir = Path(policies_dir)
        self._cache: Dict[str, PolicyDefinition] = {}
        logger.info("PolicyLoader initialized", dir=str(self.policies_dir))

    def load_all(self) -> Dict[str, PolicyDefinition]:
        """
        Load all YAML policy files from the policies directory.
        Returns dict of {policy_id: PolicyDefinition}.
        """
        if not self.policies_dir.exists():
            logger.warning("policies_dir_not_found", path=str(self.policies_dir))
            return {}

        policies = {}
        for yaml_file in self.policies_dir.rglob("*.yaml"):
            try:
                policy = self.load_file(yaml_file)
                if policy:
                    policies[policy.id] = policy
                    logger.debug("policy_loaded", id=policy.id, file=str(yaml_file))
            except Exception as e:
                logger.error("policy_load_error", file=str(yaml_file), error=str(e))

        self._cache = policies
        logger.info("policies_loaded", count=len(policies))
        return policies

    def load_file(self, path: Path) -> Optional[PolicyDefinition]:
        """Load and parse a single YAML policy file."""
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        self._validate_structure(raw, path)
        return self._parse_policy(raw)

    def _validate_structure(self, raw: Dict, path: Path) -> None:
        """Raise ValueError if required fields are missing."""
        missing = self.REQUIRED_POLICY_FIELDS - set(raw.keys())
        if missing:
            raise ValueError(f"Policy {path} missing required fields: {missing}")

        for i, rule in enumerate(raw.get("rules", [])):
            missing_rule = self.REQUIRED_RULE_FIELDS - set(rule.keys())
            if missing_rule:
                raise ValueError(f"Policy {path} rule[{i}] missing: {missing_rule}")

    def _parse_policy(self, raw: Dict) -> PolicyDefinition:
        """Parse raw YAML dict into PolicyDefinition."""
        rules = []
        for r in raw.get("rules", []):
            rule = PolicyRule(
                id=r["id"],
                name=r["name"],
                description=r.get("description", ""),
                condition_type=RuleConditionType(r["condition_type"]),
                condition_value=r["condition_value"],
                action=RuleAction(r["action"]),
                severity=r.get("severity", "medium"),
                explanation_template=r.get("explanation", f"Rule {r['id']} triggered"),
                remediation=r.get("remediation", "Review and remediate."),
                enabled=r.get("enabled", True),
                applies_to=r.get("applies_to", []),
                exceptions=r.get("exceptions", []),
            )
            rules.append(rule)

        return PolicyDefinition(
            id=raw["id"],
            name=raw["name"],
            framework=raw["framework"],
            version=raw.get("version", "1.0.0"),
            description=raw.get("description", ""),
            industry=raw.get("industry"),
            tenant_id=raw.get("tenant_id"),
            rules=rules,
            enforce_mode=raw.get("enforce_mode", True),
            active=raw.get("active", True),
        )


# ---------------------------------------------------------------------------
# Policy Evaluator
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluates input/output context against all active policies.

    Takes an inspection result and evaluation context, applies all
    matching policy rules, and returns a PolicyEvaluationResult with
    full explainability.

    Usage:
        engine = PolicyEngine(policies_dir="policies")
        result = engine.evaluate(inspection_result, context)
    """

    def __init__(
        self,
        policies_dir: str = "policies",
        tenant_id: Optional[str] = None,
    ):
        self.loader = PolicyLoader(policies_dir)
        self.policies: Dict[str, PolicyDefinition] = self.loader.load_all()
        self.tenant_id = tenant_id
        logger.info("PolicyEngine ready", policies=len(self.policies))

    def reload_policies(self) -> int:
        """Hot-reload all policies from disk. Returns count loaded."""
        self.policies = self.loader.load_all()
        return len(self.policies)

    def get_active_policies(self, tenant_id: Optional[str] = None) -> List[PolicyDefinition]:
        """Return all active policies, optionally filtered by tenant."""
        return [
            p for p in self.policies.values()
            if p.active and (p.tenant_id is None or p.tenant_id == tenant_id)
        ]

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        context: Dict[str, Any],
        framework: str,
    ) -> RuleEvaluationResult:
        """
        Evaluate a single rule against the provided context dict.

        Context keys:
        - entities: list of detected entity type strings
        - risk_score: float 0.0-1.0
        - injection_detected: bool
        - content_type: str
        - user_role: str
        - department: str
        - region: str
        - model_name: str
        - keywords: list of strings found in text
        - data_categories: list of category strings
        """
        triggered = False
        confidence = 0.0

        ct = rule.condition_type
        cv = rule.condition_value

        if ct == RuleConditionType.ENTITY_DETECTED:
            # cv is a list of entity type strings or a single string
            target_entities = [cv] if isinstance(cv, str) else cv
            detected = set(context.get("entities", []))
            triggered = bool(detected.intersection(set(target_entities)))
            confidence = 0.90 if triggered else 0.0

        elif ct == RuleConditionType.RISK_SCORE_ABOVE:
            risk = context.get("risk_score", 0.0)
            triggered = risk >= float(cv)
            confidence = risk if triggered else 0.0

        elif ct == RuleConditionType.INJECTION_DETECTED:
            triggered = context.get("injection_detected", False)
            confidence = context.get("injection_confidence", 0.0) if triggered else 0.0

        elif ct == RuleConditionType.KEYWORD_MATCH:
            keywords = [cv] if isinstance(cv, str) else cv
            text_lower = context.get("text_lower", "")
            matched = [kw for kw in keywords if kw.lower() in text_lower]
            triggered = bool(matched)
            confidence = 0.85 if triggered else 0.0

        elif ct == RuleConditionType.DATA_CATEGORY:
            target_cats = [cv] if isinstance(cv, str) else cv
            detected_cats = set(context.get("data_categories", []))
            triggered = bool(detected_cats.intersection(set(target_cats)))
            confidence = 0.90 if triggered else 0.0

        elif ct == RuleConditionType.USER_ROLE:
            user_role = context.get("user_role", "")
            allowed_roles = [cv] if isinstance(cv, str) else cv
            triggered = user_role not in allowed_roles
            confidence = 1.0 if triggered else 0.0

        elif ct == RuleConditionType.MODEL_NAME:
            model = context.get("model_name", "")
            blocked_models = [cv] if isinstance(cv, str) else cv
            triggered = model in blocked_models
            confidence = 1.0 if triggered else 0.0

        elif ct == RuleConditionType.CONTENT_TYPE:
            content_type = context.get("content_type", "")
            allowed_types = [cv] if isinstance(cv, str) else cv
            triggered = content_type not in allowed_types
            confidence = 1.0 if triggered else 0.0

        elif ct == RuleConditionType.DEPARTMENT:
            dept = context.get("department", "")
            restricted_depts = [cv] if isinstance(cv, str) else cv
            triggered = dept in restricted_depts
            confidence = 1.0 if triggered else 0.0

        elif ct == RuleConditionType.REGION:
            region = context.get("region", "")
            restricted_regions = [cv] if isinstance(cv, str) else cv
            triggered = region in restricted_regions
            confidence = 1.0 if triggered else 0.0

        # Build explanation
        explanation = rule.explanation_template
        if triggered:
            explanation = f"[{framework.upper()}] {rule.name}: {rule.explanation_template}"

        return RuleEvaluationResult(
            rule_id=rule.id,
            rule_name=rule.name,
            framework=framework,
            triggered=triggered,
            action=rule.action,
            severity=rule.severity,
            explanation=explanation,
            remediation=rule.remediation,
            confidence=confidence,
        )

    def evaluate(
        self,
        context: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate all active policies against the provided context.

        Args:
            context: Dict containing inspection results and request metadata.
                Required keys: entities, risk_score, injection_detected
                Optional: user_role, department, region, model_name, content_type
            tenant_id: Tenant to filter policies for

        Returns:
            PolicyEvaluationResult with final action and full explainability
        """
        active_policies = self.get_active_policies(tenant_id)
        triggered_rules: List[RuleEvaluationResult] = []
        policies_evaluated = []
        total_rules = 0

        for policy in active_policies:
            policies_evaluated.append(f"{policy.framework}:{policy.name}")
            for rule in policy.rules:
                if not rule.enabled:
                    continue
                total_rules += 1
                result = self._evaluate_rule(rule, context, policy.framework)
                if result.triggered:
                    triggered_rules.append(result)

        # Determine final action (most severe wins)
        final_action = "allow"
        blocked = False
        redact_required = False
        alert_required = False

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        triggered_rules.sort(
            key=lambda r: severity_order.get(r.severity, 0), reverse=True
        )

        for rule_result in triggered_rules:
            if rule_result.action == RuleAction.BLOCK:
                final_action = "block"
                blocked = True
                break
            elif rule_result.action == RuleAction.REDACT:
                final_action = "redact"
                redact_required = True
            elif rule_result.action == RuleAction.ALERT:
                alert_required = True
                if final_action == "allow":
                    final_action = "alert"

        # Build explanation summary
        if triggered_rules:
            top = triggered_rules[0]
            explanation = (
                f"Policy evaluation: {final_action.upper()}. "
                f"{len(triggered_rules)} rule(s) triggered across "
                f"{len(set(r.framework for r in triggered_rules))} framework(s). "
                f"Highest severity: {top.severity} ({top.framework.upper()} — {top.rule_name})."
            )
        else:
            explanation = f"Policy evaluation: ALLOW. {total_rules} rules evaluated, none triggered."

        remediation_steps = list({r.remediation for r in triggered_rules if r.triggered})
        frameworks_triggered = {r.framework for r in triggered_rules}

        return PolicyEvaluationResult(
            final_action=final_action,
            blocked=blocked,
            redact_required=redact_required,
            alert_required=alert_required,
            triggered_rules=triggered_rules,
            all_rules_evaluated=total_rules,
            policies_evaluated=policies_evaluated,
            explanation_summary=explanation,
            remediation_steps=remediation_steps,
            compliance_frameworks_triggered=frameworks_triggered,
        )
