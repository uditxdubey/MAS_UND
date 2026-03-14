"""
sovereign_shield/agents/verifier.py

Sovereign Shield — Verifier Agent
Second layer of the agent pipeline. Cross-checks every AuditDecision
produced by the Auditor before it becomes final.

The Verifier answers one question:
"Is this decision consistent, complete, and legally defensible?"

If the Verifier finds an inconsistency it escalates to CRITICAL
and flags for human review. It never downgrades a HALT to a PASS.

Depends on: agents/auditor.py, audit/logger.py, symbolic/enums.py
"""

from dataclasses import dataclass, field
from datetime    import datetime, timezone

from sovereign_shield.agents.auditor  import AuditDecision
from sovereign_shield.symbolic.enums  import Verdict
from sovereign_shield.audit.logger    import audit_logger


# ── Verification result ───────────────────────────────────────────────────────
@dataclass
class VerificationResult:
    """
    Final output of the Verifier.
    This is the last record before a decision is enforced.
    """
    decision          : AuditDecision
    verified          : bool
    confidence        : str        # HIGH / MEDIUM / LOW
    flags             : list       = field(default_factory=list)
    escalate          : bool       = False
    ts_utc            : str        = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "verified"   : self.verified,
            "confidence" : self.confidence,
            "flags"      : self.flags,
            "escalate"   : self.escalate,
            "ts_utc"     : self.ts_utc,
        }


# ── Verification rules ────────────────────────────────────────────────────────
# Each rule is a function that takes an AuditDecision and returns
# a flag string if the rule fails, or None if it passes.
# Add new rules here without touching any other file.

def _rule_halt_has_reason(d: AuditDecision) -> str | None:
    """Every HALT must have a non-empty reason."""
    if d.verdict == Verdict.HALT and not d.reason.strip():
        return "HALT_MISSING_REASON"
    return None

def _rule_halt_has_article(d: AuditDecision) -> str | None:
    """Every HALT must reference an EU AI Act article."""
    if d.verdict == Verdict.HALT and "Art." not in d.article:
        return "HALT_MISSING_ARTICLE"
    return None

def _rule_halt_has_url(d: AuditDecision) -> str | None:
    """Every HALT must have a destination URL."""
    if d.verdict == Verdict.HALT and not d.url.strip():
        return "HALT_MISSING_URL"
    return None

def _rule_unknown_treated_as_halt(d: AuditDecision) -> str | None:
    """UNKNOWN verdict must be treated as HALT — fail closed."""
    if d.verdict == Verdict.UNKNOWN and d.severity != "CRITICAL":
        return "UNKNOWN_NOT_ESCALATED"
    return None

def _rule_pass_has_guard(d: AuditDecision) -> str | None:
    """Every PASS must identify the guard that approved it."""
    if d.verdict == Verdict.PASS and not d.guard.strip():
        return "PASS_MISSING_GUARD"
    return None


# Registry — add new rules to this list only
VERIFICATION_RULES = [
    _rule_halt_has_reason,
    _rule_halt_has_article,
    _rule_halt_has_url,
    _rule_unknown_treated_as_halt,
    _rule_pass_has_guard,
]


# ── Verifier Agent ────────────────────────────────────────────────────────────
class VerifierAgent:
    """
    Cross-checks every AuditDecision for completeness and consistency.

    Flow:
        1. Receive AuditDecision from Auditor
        2. Run all verification rules against it
        3. Collect any flags (rule failures)
        4. Determine confidence level and escalation
        5. Write verification result to audit log
        6. Return VerificationResult

    Invariants:
        - Never downgrades HALT to PASS
        - Never suppresses flags
        - Always writes to audit log
        - Fails CLOSED on internal error
    """

    def verify(self, decision: AuditDecision) -> VerificationResult:
        """
        Main entry point. Verifies any AuditDecision.

        Args:
            decision: AuditDecision produced by AuditorAgent

        Returns:
            VerificationResult — final record of the Shield decision
        """
        try:
            return self._run_verification(decision)
        except Exception as e:
            # Internal verifier error — fail closed, escalate
            audit_logger.log_error(
                guard  = "VerifierAgent",
                reason = f"Verification internal error: {e}",
                url    = decision.url,
            )
            return VerificationResult(
                decision   = decision,
                verified   = False,
                confidence = "LOW",
                flags      = ["VERIFIER_INTERNAL_ERROR"],
                escalate   = True,
            )

    def _run_verification(
        self, decision: AuditDecision
    ) -> VerificationResult:
        """Run all rules and assemble the VerificationResult."""

        flags = []
        for rule in VERIFICATION_RULES:
            flag = rule(decision)
            if flag:
                flags.append(flag)

        verified   = len(flags) == 0
        escalate   = len(flags) > 0 or decision.verdict == Verdict.UNKNOWN
        confidence = self._confidence(flags)

        result = VerificationResult(
            decision   = decision,
            verified   = verified,
            confidence = confidence,
            flags      = flags,
            escalate   = escalate,
        )

        self._write_to_log(decision, result)
        return result

    def _confidence(self, flags: list) -> str:
        """Derive confidence level from number of flags."""
        if len(flags) == 0:
            return "HIGH"
        if len(flags) == 1:
            return "MEDIUM"
        return "LOW"

    def _write_to_log(
        self,
        decision : AuditDecision,
        result   : VerificationResult,
    ) -> None:
        """Write verification result to audit log."""
        if result.verified:
            audit_logger.log_pass(
                url        = decision.url,
                guard      = "VerifierAgent",
                confidence = result.confidence,
                **result.to_dict(),
            )
        else:
            audit_logger.log_halt(
                url        = decision.url,
                guard      = "VerifierAgent",
                reason     = f"Verification failed — flags: {result.flags}",
                confidence = result.confidence,
                **result.to_dict(),
            )