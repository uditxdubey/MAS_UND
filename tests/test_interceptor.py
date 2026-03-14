"""
tests/test_interceptor.py

Sovereign Shield — Full Pipeline Integration Test
End-to-end verification of the complete interception layer.

This is the DEMO TEST. Run this in front of clients.
It proves the entire pipeline works from requests.post() to HALT.
"""

import pytest
import requests
from unittest.mock import patch, MagicMock

from sovereign_shield.interceptor            import activate, deactivate, SovereignShield
from sovereign_shield.symbolic.shield_policy import ShieldPolicy
from sovereign_shield.symbolic.geo_guard     import DataSovereigntyViolation
from sovereign_shield.symbolic.pii_guard     import PIILeakViolation


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_shield():
    deactivate()
    yield
    deactivate()


def mock_geo(country: str):
    return patch(
        "sovereign_shield.symbolic.geo_guard.GeoGuard._resolve_ip",
        return_value="1.2.3.4",
    ), patch(
        "sovereign_shield.symbolic.geo_guard.GeoGuard._country_for_ip",
        return_value=country,
    )


# ── Full pipeline HALT tests ──────────────────────────────────────────────────

class TestFullPipelineHalt:

    def test_chinese_destination_halted(self):
        """DEMO TEST 1 — AI agent blocked from posting to China."""
        activate(ShieldPolicy.eu_standard())
        p1, p2 = mock_geo("CN")
        with p1, p2:
            with pytest.raises(DataSovereigntyViolation) as exc:
                requests.post(
                    "https://api.cn-server.com",
                    json={"data": "business_report"}
                )
        assert exc.value.country == "CN"
        assert "Art.53" in exc.value.reason

    def test_russian_destination_halted(self):
        """RU destination blocked end-to-end."""
        activate(ShieldPolicy.eu_standard())
        p1, p2 = mock_geo("RU")
        with p1, p2:
            with pytest.raises(DataSovereigntyViolation) as exc:
                requests.post("https://api.ru-server.com")
        assert exc.value.country == "RU"

    def test_pii_blocked_before_transmission(self):
        """DEMO TEST 2 — PII in payload blocked before transmission."""
        activate(ShieldPolicy.eu_standard())
        p1, p2 = mock_geo("DE")
        with p1, p2:
            with pytest.raises(PIILeakViolation) as exc:
                requests.post(
                    "https://api.example.de",
                    json={"customer_email": "kunde@beispiel.de"}
                )
        assert exc.value.pii_type == "email"
        assert "Art.10" in exc.value.reason

    def test_iban_blocked_before_transmission(self):
        """IBAN in payload blocked end-to-end."""
        activate(ShieldPolicy.eu_standard())
        p1, p2 = mock_geo("DE")
        with p1, p2:
            with pytest.raises(PIILeakViolation):
                requests.post(
                    "https://api.example.de",
                    json={"account": "DE89370400440532013000"}
                )


# ── Full pipeline PASS tests ──────────────────────────────────────────────────

class TestFullPipelinePass:

    def test_clean_german_request_passes(self):
        """DEMO TEST 3 — Clean request to Germany flows through."""
        activate(ShieldPolicy.eu_standard())
        p1, p2 = mock_geo("DE")
        mock_response = MagicMock()
        mock_response.status_code = 200
        with p1, p2:
            with patch(
                "sovereign_shield.interceptor.requests.post",
                return_value=mock_response,
            ):
                response = requests.post(
                    "https://api.example.de",
                    json={"report": "Q3-2026", "department": "Finance"}
                )
        assert response.status_code == 200

    def test_swiss_destination_passes(self):
        """CH has EC adequacy decision — must pass end-to-end."""
        activate(ShieldPolicy.eu_standard())
        p1, p2 = mock_geo("CH")
        mock_response = MagicMock()
        mock_response.status_code = 200
        with p1, p2:
            with patch(
                "sovereign_shield.interceptor.requests.post",
                return_value=mock_response,
            ):
                response = requests.post(
                    "https://api.example.ch",
                    json={"action": "sync"}
                )
        assert response.status_code == 200


# ── Shield lifecycle tests ────────────────────────────────────────────────────

class TestShieldLifecycle:

    def test_shield_installs_and_intercepts(self):
        """Shield install patches requests.post correctly."""
        original = requests.post
        shield   = activate()
        assert requests.post != original
        assert requests.post == shield._intercepted_post

    def test_shield_uninstalls_cleanly(self):
        """Shield uninstall restores original requests.post."""
        original = requests.post
        activate()
        deactivate()
        assert requests.post == original

    def test_shield_idempotent_install(self):
        """Calling activate() twice does not double-wrap."""
        shield1 = activate()
        shield2 = activate()
        assert shield1 is shield2

    def test_multiple_requests_in_sequence(self):
        """Shield handles CN block then DE pass in sequence."""
        activate(ShieldPolicy.eu_standard())

        p1, p2 = mock_geo("CN")
        with p1, p2:
            with pytest.raises(DataSovereigntyViolation):
                requests.post("https://api.cn-server.com")

        p1, p2 = mock_geo("DE")
        mock_response = MagicMock()
        mock_response.status_code = 200
        with p1, p2:
            with patch(
                "sovereign_shield.interceptor.requests.post",
                return_value=mock_response,
            ):
                response = requests.post(
                    "https://api.example.de",
                    json={"action": "report"}
                )
        assert response.status_code == 200


# ── German Mittelstand preset tests ──────────────────────────────────────────

class TestGermanMittelstandPreset:

    def test_japan_blocked_under_mittelstand(self):
        """JP passes EU standard but blocked under german_mittelstand."""
        activate(ShieldPolicy.german_mittelstand())
        p1, p2 = mock_geo("JP")
        with p1, p2:
            with pytest.raises(DataSovereigntyViolation) as exc:
                requests.post("https://api.example.jp")
        assert exc.value.country == "JP"

    def test_germany_passes_under_mittelstand(self):
        """DE always passes under german_mittelstand preset."""
        activate(ShieldPolicy.german_mittelstand())
        p1, p2 = mock_geo("DE")
        mock_response = MagicMock()
        mock_response.status_code = 200
        with p1, p2:
            with patch(
                "sovereign_shield.interceptor.requests.post",
                return_value=mock_response,
            ):
                response = requests.post(
                    "https://api.example.de",
                    json={"action": "report"}
                )
        assert response.status_code == 200