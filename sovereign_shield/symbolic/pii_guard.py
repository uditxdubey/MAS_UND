"""
sovereign_shield/symbolic/pii_guard.py
PII Guard — scans outbound request payloads for personal data leakage.
Enforces EU AI Act Art. 10 — Data Governance.

Depends on: pii_policy.py, enums.py
Edit this file only if regex patterns or scan logic changes.
Add new PII types in pii_policy.py, not here.
"""
import json
import re


from .enums      import Verdict
from .pii_policy import PIIPolicy


# ── Violation signal ──────────────────────────────────────────────────────────
class PIILeakViolation(PermissionError):
    """
    Raised when outbound payload contains detected PII.
    Subclasses PermissionError for graceful agent-level handling.
    """
    def __init__(self, url: str, pii_type: str, reason: str):
        self.url      = url
        self.pii_type = pii_type
        self.reason   = reason
        super().__init__(
            f"[SOVEREIGN SHIELD — HALT] "
            f"PII detected in payload. "
            f"url='{url}' pii_type='{pii_type}' reason='{reason}'"
        )


# ── Regex patterns per PII type ───────────────────────────────────────────────
# Add new patterns here when pii_policy.py adds new pattern names.
PII_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    ),
    "iban": re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
    ),
    "phone_de": re.compile(
        # Must start with +49 or 0049 or 0 followed by 15/16/17
        # (German mobile prefixes) — not just any digit sequence
        r"(\+49|0049)([\s\-]?)(15|16|17|30|40|69|89)\d{6,10}"
        r"|(\b0(15|16|17|30|40|69|89)\d{6,10}\b)",
    ),
    "passport": re.compile(
        # German passport: letter(s) followed by alphanumeric mix, 8-9 chars total
        r"\b[A-Z]{1,2}[0-9A-Z]{6,8}\b",
    ),
    "steuer_id": re.compile(
        # German Steuer-ID: exactly 11 digits, never starts with 0
        r"\b[1-9]\d{10}\b",
    ),
    "sozialversicherung": re.compile(
        r"\b\d{2}[0-9]{6}[A-Z]\d{3}\b",
    ),
}

# ── PII Guard ─────────────────────────────────────────────────────────────────
class PIIGuard:
    """
    Scans outbound request body for PII before transmission.

    Flow:
        1. Extract text payload from request kwargs (json, data, params)
        2. Run enabled regex patterns against payload text
        3. Return Verdict.PASS or raise PIILeakViolation

    Fails CLOSED if payload cannot be parsed.
    """

    def __init__(self, policy: PIIPolicy):
        self.policy   = policy
        self._active_patterns = self._build_active_patterns()

    def _build_active_patterns(self) -> dict[str, re.Pattern]:
        """Only compile patterns that are enabled in policy."""
        return {
            name: pattern
            for name, pattern in PII_PATTERNS.items()
            if name in self.policy.patterns
        }

    def _extract_text(self, **kwargs) -> str:
        """
        Converts request payload to a flat string for scanning.
        Handles json=, data=, and params= kwargs from requests.post().
        """
        parts = []

        if "json" in kwargs and kwargs["json"] is not None:
            try:
                parts.append(json.dumps(kwargs["json"]))
            except (TypeError, ValueError):
                parts.append(str(kwargs["json"]))

        if "data" in kwargs and kwargs["data"] is not None:
            parts.append(str(kwargs["data"]))

        if "params" in kwargs and kwargs["params"] is not None:
            parts.append(str(kwargs["params"]))

        return " ".join(parts)

    def evaluate(self, url: str, **kwargs) -> Verdict:
        """
        Main entry point. Called by interceptor for every outbound request.

        Returns:
            Verdict.PASS — no PII detected, allow request
        Raises:
            PIILeakViolation — PII found in payload, HALT execution
        """
        if not self.policy.scan_enabled:
            return Verdict.PASS

        payload_text = self._extract_text(**kwargs)

        if not payload_text:
            return Verdict.PASS  # empty payload — nothing to scan

        for pii_type, pattern in self._active_patterns.items():
            if pattern.search(payload_text):
                if self.policy.block_on_detection:
                    raise PIILeakViolation(
                        url=url,
                        pii_type=pii_type,
                        reason=f"Pattern '{pii_type}' matched in outbound payload (Art.10)",
                    )

        return Verdict.PASS