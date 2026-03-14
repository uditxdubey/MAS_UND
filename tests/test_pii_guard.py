"""
tests/test_pii_guard.py

Sovereign Shield — PIIGuard Test Suite
Formally verifies PII detection in outbound request payloads.
Enforces EU AI Act Art.10 — Data Governance.

Coverage:
    - German Steuer-ID detection
    - German Sozialversicherungsnummer detection
    - IBAN detection
    - Email detection
    - German phone number detection
    - Passport number detection
    - Clean payloads pass
    - Empty payloads pass
    - Multiple PII types in one payload
    - Scan disabled in policy
    - Block disabled in policy
"""

import pytest
from sovereign_shield.symbolic.pii_guard import PIIGuard, PIILeakViolation
from sovereign_shield.symbolic.pii_policy import PIIPolicy


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def guard():
    """Standard PIIGuard with all patterns enabled."""
    return PIIGuard(PIIPolicy())


@pytest.fixture
def guard_scan_disabled():
    """PIIGuard with scanning disabled — nothing should block."""
    return PIIGuard(PIIPolicy(scan_enabled=False))


@pytest.fixture
def guard_block_disabled():
    """PIIGuard that scans but does not block."""
    return PIIGuard(PIIPolicy(
        scan_enabled=True,
        block_on_detection=False,
    ))


# ── HALT tests — these payloads must always be blocked ───────────────────────

class TestPIIDetected:

    def test_email_in_json_halts(self, guard):
        """Email address in JSON payload — must HALT."""
        with pytest.raises(PIILeakViolation) as exc:
            guard.evaluate(
                url="https://api.example.de",
                json={"user": "hans.mueller@example.de"}
            )
        assert exc.value.pii_type == "email"

    def test_iban_in_json_halts(self, guard):
        """German IBAN in JSON payload — must HALT."""
        with pytest.raises(PIILeakViolation) as exc:
            guard.evaluate(
                url="https://api.example.de",
                json={"account": "DE89370400440532013000"}
            )
        assert exc.value.pii_type == "iban"

    def test_german_phone_in_data_halts(self, guard):
        """German phone number in data payload — must HALT."""
        with pytest.raises(PIILeakViolation) as exc:
            guard.evaluate(
                url="https://api.example.de",
                data={"phone": "+4915112345678"}
            )
        assert exc.value.pii_type == "phone_de"

    def test_steuer_id_in_json_halts(self, guard):
        """German Steueridentifikationsnummer — must HALT."""
        with pytest.raises(PIILeakViolation) as exc:
            guard.evaluate(
                url="https://api.example.de",
                json={"tax_id": "86095742719"}
            )
        assert exc.value.pii_type == "steuer_id"

    def test_passport_in_json_halts(self, guard):
        """Passport number in JSON payload — must HALT."""
        with pytest.raises(PIILeakViolation) as exc:
            guard.evaluate(
                url="https://api.example.de",
                json={"passport": "C01X00T47"}
            )
        assert exc.value.pii_type == "passport"

    def test_multiple_pii_types_halts_on_first(self, guard):
        """Multiple PII types — must HALT on first detection."""
        with pytest.raises(PIILeakViolation):
            guard.evaluate(
                url="https://api.example.de",
                json={
                    "email"   : "hans@example.de",
                    "account" : "DE89370400440532013000",
                }
            )

    def test_pii_in_params_halts(self, guard):
        """PII in URL params — must HALT."""
        with pytest.raises(PIILeakViolation):
            guard.evaluate(
                url    = "https://api.example.de",
                params = {"email": "hans@example.de"},
            )


# ── PASS tests — clean payloads must always pass ─────────────────────────────

class TestCleanPayloads:

    def test_clean_json_passes(self, guard):
        """Clean JSON payload — must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        verdict = guard.evaluate(
            url  = "https://api.example.de",
            json = {"action": "get_report", "report_id": "Q3-2026"},
        )
        assert verdict == Verdict.PASS

    def test_empty_payload_passes(self, guard):
        """No payload at all — must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        verdict = guard.evaluate(url="https://api.example.de")
        assert verdict == Verdict.PASS

    def test_numeric_only_payload_passes(self, guard):
        """Numbers only — no PII pattern match — must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        verdict = guard.evaluate(
            url  = "https://api.example.de",
            json = {"value": 42, "count": 100},
        )
        assert verdict == Verdict.PASS

    def test_german_company_name_passes(self, guard):
        """Company name — not PII — must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        verdict = guard.evaluate(
            url  = "https://api.example.de",
            json = {"company": "Siemens AG", "city": "Erlangen"},
        )
        assert verdict == Verdict.PASS


# ── Policy control tests ──────────────────────────────────────────────────────

class TestPolicyControl:

    def test_scan_disabled_allows_pii(self, guard_scan_disabled):
        """Scan disabled — PII payload must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        verdict = guard_scan_disabled.evaluate(
            url  = "https://api.example.de",
            json = {"email": "hans@example.de"},
        )
        assert verdict == Verdict.PASS

    def test_block_disabled_allows_pii(self, guard_block_disabled):
        """Block disabled — PII detected but must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        verdict = guard_block_disabled.evaluate(
            url  = "https://api.example.de",
            json = {"email": "hans@example.de"},
        )
        assert verdict == Verdict.PASS