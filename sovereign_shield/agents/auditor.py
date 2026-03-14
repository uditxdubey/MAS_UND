"""
sovereign_shield/agents/auditor.py

Sovereign Shield — Auditor Agent
Classifies and records every Shield decision with EU AI Act article mapping.

The Auditor is the first agent in the pipeline. It receives the raw
violation or pass event from the guards and enriches it with:
- EU AI Act article reference
- Severity level
- Recommended action
- Structured audit entry

Depends on: audit/logger.py, symbolic/enums.py
"""

from dataclasses import dataclass, field
from datetime    import datetime, timezone

from sovereign_shield.symbolic.enums  import Verdict, EnforcedArticle
from sovereign_shield.audit.logger    import audit_logger


# ── Severity levels ───────────────────────────────────────────────────────────
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"


# ── Audit Decision — structured output of the Auditor ─────────────────────────
@dataclass
class AuditDecision:
    """
    Structured record produced by the Auditor for every Shield event.
    Passed to the Verifier for cross-checking.
    """
    verdict         : Verdict
    guard           : str
    url             : str
    reason          : str
    article         : str
    severity        : str
    recommended_act : str
    ts_utc          : str        = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    extra           : dict       = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "verdict"         : self.verdict.name,
            "guard"           : self.guard,
            "url"             : self.url,
            "reason"          : self.reason,
            "article"         : self.article,
            "severity"        : self.severity,
            "recommended_act" : self.recommended_act,
            "ts_utc"          : self.ts_utc,
            **self.extra,
        }


# ── Article mapping — guard name → EU AI Act article ─────────────────────────
GUARD_ARTICLE_MAP: dict[str, str] = {
    "GeoGuard"     : EnforcedArticle.ART_53.value,
    "PIIGuard"     : EnforcedArticle.ART_10.value,
    "NeuralAdvisor": EnforcedArticle.ART_13.value,
    "Shield"       : EnforcedArticle.ART_17.value,
}

# ── Severity mapping — guard name → severity level ────────────────────────────
GUARD_SEVERITY_MAP: dict[str, str] = {
    "GeoGuard"     : SEVERITY_CRITICAL,
    "PIIGuard"     : SEVERITY_CRITICAL,
    "NeuralAdvisor": SEVERITY_MEDIUM,
    "Shield"       : SEVERITY_HIGH,
}

# ── Recommended actions per guard ─────────────────────────────────────────────
GUARD_ACTION_MAP: dict[str, str] = {
    "GeoGuard"     : "Block request. Review destination. Update allowlist if legitimate.",
    "PIIGuard"     : "Block request. Identify PII source. Notify Datenschutzbeauftragter.",
    "NeuralAdvisor": "Flag for human review. No automatic block.",
    "Shield"       : "Investigate Shield error. Check logs. Restart if necessary.",
}


# ── Auditor Agent ─────────────────────────────────────────────────────────────
class AuditorAgent:
    """
    Classifies every Shield event and produces a structured AuditDecision.

    Flow:
        1. Receive verdict + context from guard
        2. Map to EU AI Act article, severity, recommended action
        3. Write enriched entry to audit log
        4. Return AuditDecision to Verifier
    """

    def process_halt(
        self,
        guard  : str,
        url    : str,
        reason : str,
        **extra,
    ) -> AuditDecision:
        """
        Process a HALT verdict from any guard.
        Called immediately when a guard raises a violation.

        Args:
            guard:  Name of the guard that issued the HALT
            url:    Destination URL that was blocked
            reason: Human-readable reason for the block
            extra:  Additional context (country, pii_type, etc.)

        Returns:
            AuditDecision — passed to Verifier
        """
        decision = AuditDecision(
            verdict         = Verdict.HALT,
            guard           = guard,
            url             = url,
            reason          = reason,
            article         = GUARD_ARTICLE_MAP.get(guard, "Art.Unknown"),
            severity        = GUARD_SEVERITY_MAP.get(guard, SEVERITY_HIGH),
            recommended_act = GUARD_ACTION_MAP.get(
                guard, "Block and investigate."
            ),
            extra           = extra,
        )

        audit_logger.log_halt(
    url    = url,
    guard  = guard,
    reason = reason,
    **{k: v for k, v in decision.to_dict().items()
       if k not in ("url", "guard", "reason", "verdict")},
)

        return decision

    def process_pass(
        self,
        guard  : str,
        url    : str,
        **extra,
    ) -> AuditDecision:
        """
        Process a PASS verdict from any guard.

        Args:
            guard: Name of the guard that issued the PASS
            url:   Destination URL allowed through
            extra: Additional context (country, etc.)

        Returns:
            AuditDecision — passed to Verifier
        """
        decision = AuditDecision(
            verdict         = Verdict.PASS,
            guard           = guard,
            url             = url,
            reason          = "Request passed all policy checks.",
            article         = GUARD_ARTICLE_MAP.get(guard, "Art.Unknown"),
            severity        = SEVERITY_LOW,
            recommended_act = "No action required.",
            extra           = extra,
        )

        audit_logger.log_pass(
    url   = url,
    guard = guard,
    **{k: v for k, v in decision.to_dict().items()
       if k not in ("url", "guard", "verdict")},
)

        return decision

    def process_error(
        self,
        guard  : str,
        reason : str,
        **extra,
    ) -> AuditDecision:
        """
        Process a Shield internal error.
        Shield fails CLOSED — errors are treated as HALT.

        Args:
            guard:  Name of the guard where error occurred
            reason: Description of the error
        """
        decision = AuditDecision(
            verdict         = Verdict.UNKNOWN,
            guard           = guard,
            url             = extra.get("url", "UNKNOWN"),
            reason          = f"Shield error (fail-closed): {reason}",
            article         = EnforcedArticle.ART_17.value,
            severity        = SEVERITY_CRITICAL,
            recommended_act = "Investigate Shield internals immediately.",
            extra           = extra,
        )

        audit_logger.log_error(
    guard  = guard,
    reason = reason,
    **{k: v for k, v in decision.to_dict().items()
       if k not in ("guard", "reason", "verdict")},
)

        return decision