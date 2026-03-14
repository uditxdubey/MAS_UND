"""
sovereign_shield/interceptor.py

Sovereign Shield — Main Interceptor
The single entry point that connects every module into one working Shield.

This file does ONE thing:
Wrap requests.post() at import time so every outbound HTTP POST
from any AI agent is inspected before execution.

Architecture:
    requests.post() call
        → GeoGuard     (Art.53 — destination country check)
        → PIIGuard     (Art.10 — payload PII scan)
        → AuditorAgent (classify + enrich decision)
        → VerifierAgent(cross-check decision)
        → NeuralAdvisor(async tag — never blocks)
        → Original requests.post() executes (only if all guards PASS)

Fail-closed: ANY exception inside the Shield = HALT.
Read-only:   Zero changes to client codebase required.

Depends on: all symbolic guards, all agents, neural advisor, audit logger
"""

import requests
from typing import Callable, Optional

from sovereign_shield.symbolic.shield_policy  import ShieldPolicy
from sovereign_shield.symbolic.geo_guard      import GeoGuard, DataSovereigntyViolation
from sovereign_shield.symbolic.pii_guard      import PIIGuard, PIILeakViolation
from sovereign_shield.agents.auditor          import AuditorAgent
from sovereign_shield.agents.verifier         import VerifierAgent
from sovereign_shield.neural.advisor          import NeuralAdvisor
from sovereign_shield.audit.logger            import audit_logger


class SovereignShield:
    """
    The Sovereign Shield interceptor.

    Install once at agent bootstrap. Wraps requests.post() transparently.
    All AI agent outbound POST requests flow through this chokepoint.

    Usage:
        from sovereign_shield.interceptor import activate
        activate()                                    # EU standard defaults
        activate(ShieldPolicy.german_mittelstand())   # strictest preset
    """

    def __init__(self, policy: Optional[ShieldPolicy] = None):
        self.policy   = policy or ShieldPolicy()

        # ── Guards (symbolic — deterministic) ─────────────────────────────
        self.geo_guard = GeoGuard(self.policy.sovereignty)
        self.pii_guard = PIIGuard(self.policy.pii)

        # ── Agents ────────────────────────────────────────────────────────
        self.auditor  = AuditorAgent()
        self.verifier = VerifierAgent()

        # ── Neural advisor (async — never blocks) ─────────────────────────
        self.advisor  = NeuralAdvisor(self.policy.neural)

        # ── Original requests.post reference ──────────────────────────────
        self._original_post: Callable = requests.post
        self._installed: bool         = False

    def install(self) -> None:
        """
        Patch requests.post at module level.
        Idempotent — safe to call multiple times.
        """
        if self._installed:
            return
        requests.post   = self._intercepted_post
        self._installed = True
        audit_logger.log_shield_event(
            "shield_installed",
            f"policy='{self.policy.__class__.__name__}' "
            f"fail_closed={self.policy.fail_closed}",
        )

    def uninstall(self) -> None:
        """
        Restore original requests.post.
        Use in tests only — never in production.
        """
        requests.post   = self._original_post
        self._installed = False
        audit_logger.log_shield_event("shield_uninstalled", "")

    def _intercepted_post(self, url: str, **kwargs) -> requests.Response:
        """
        THE CHOKEPOINT — every outbound POST flows through here.

        Flow:
            1. GeoGuard  — check destination country (Art.53)
            2. PIIGuard  — scan payload for PII (Art.10)
            3. Auditor   — classify and enrich decision
            4. Verifier  — cross-check decision
            5. Advisor   — async neural tag (non-blocking)
            6. Execute   — call original requests.post()

        Any guard raising an exception = immediate HALT.
        Any unexpected error = fail closed = HALT.
        """
        # ── STEP 1: Geo check ─────────────────────────────────────────────
        try:
            self.geo_guard.evaluate(url)
        except DataSovereigntyViolation as e:
            self.auditor.process_halt(
                guard   = "GeoGuard",
                url     = url,
                reason  = e.reason,
                country = e.country,
            )
            raise

        except Exception as e:
            self.auditor.process_error(
                guard  = "GeoGuard",
                reason = str(e),
                url    = url,
            )
            raise DataSovereigntyViolation(
                url     = url,
                country = "ERROR",
                reason  = f"GeoGuard internal error (fail-closed): {e}",
            )

        # ── STEP 2: PII scan ──────────────────────────────────────────────
        try:
            self.pii_guard.evaluate(url, **kwargs)
        except PIILeakViolation as e:
            self.auditor.process_halt(
                guard    = "PIIGuard",
                url      = url,
                reason   = e.reason,
                pii_type = e.pii_type,
            )
            raise

        except Exception as e:
            self.auditor.process_error(
                guard  = "PIIGuard",
                reason = str(e),
                url    = url,
            )
            raise DataSovereigntyViolation(
                url     = url,
                country = "ERROR",
                reason  = f"PIIGuard internal error (fail-closed): {e}",
            )

        # ── STEP 3 + 4: Audit + Verify ────────────────────────────────────
        decision = self.auditor.process_pass(
            guard = "GeoGuard+PIIGuard",
            url   = url,
        )
        self.verifier.verify(decision)

        # ── STEP 5: Async neural tag ──────────────────────────────────────
        payload_preview = str(kwargs.get("json", kwargs.get("data", "")))
        self.advisor.tag_async(url, payload_preview[:200])

        # ── STEP 6: Execute original request ─────────────────────────────
        return self._original_post(url, **kwargs)


# ── Module-level singleton and bootstrap helper ───────────────────────────────
_shield_instance: Optional[SovereignShield] = None


def activate(
    policy: Optional[ShieldPolicy] = None,
) -> SovereignShield:
    """
    Activate Sovereign Shield. Call once in agent bootstrap.

    Args:
        policy: ShieldPolicy preset. Defaults to EU standard.
                Use ShieldPolicy.german_mittelstand() for strictest mode.

    Returns:
        The installed SovereignShield instance.

    Example:
        from sovereign_shield.interceptor import activate
        from sovereign_shield.symbolic.shield_policy import ShieldPolicy
        activate(ShieldPolicy.german_mittelstand())
    """
    global _shield_instance
    if _shield_instance is None:
        _shield_instance = SovereignShield(policy=policy)
        _shield_instance.install()
    return _shield_instance


def deactivate() -> None:
    """Remove the Shield. For testing only."""
    global _shield_instance
    if _shield_instance:
        _shield_instance.uninstall()
        _shield_instance = None