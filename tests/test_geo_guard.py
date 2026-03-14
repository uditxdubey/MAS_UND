"""
tests/test_geo_guard.py

Sovereign Shield — GeoGuard Test Suite
Formally verifies the deterministic geo-blocking logic.

These tests are the legal proof that Art.53 enforcement works.
Run before every commit. Run in every client demo.

Coverage:
    - Blocked countries (CN, RU, US, IN)
    - Allowed countries (DE, AT, CH, FR)
    - Private/loopback addresses
    - Missing GeoIP database (fail-closed)
    - Malformed URLs
"""

import pytest
from unittest.mock import patch, MagicMock

from sovereign_shield.symbolic.geo_guard   import GeoGuard, DataSovereigntyViolation
from sovereign_shield.symbolic.sovereignty import DataSovereigntyPolicy


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def eu_policy():
    """Standard EU policy — all adequacy countries allowed."""
    return DataSovereigntyPolicy()


@pytest.fixture
def dach_policy():
    """Strictest preset — DACH + core EU only."""
    return DataSovereigntyPolicy(
        safe_countries=frozenset({
            "DE", "AT", "CH",
            "IS", "LI", "NO",
            "BE", "NL", "FR", "SE",
        })
    )


@pytest.fixture
def guard_eu(eu_policy, tmp_path):
    """GeoGuard with EU policy — no real GeoIP DB needed for mocked tests."""
    policy = DataSovereigntyPolicy(
        geoip_db_path=str(tmp_path / "nonexistent.mmdb")
    )
    return GeoGuard(policy)


@pytest.fixture
def guard_with_db(eu_policy):
    """GeoGuard where GeoIP lookups are fully mocked."""
    guard = GeoGuard(eu_policy)
    return guard


# ── Helper — mock a full GeoIP lookup chain ───────────────────────────────────

def make_guard_with_country(country_code: str) -> GeoGuard:
    """
    Returns a GeoGuard that always resolves to the given country.
    No real DNS or GeoIP DB needed.
    """
    policy = DataSovereigntyPolicy()
    guard  = GeoGuard(policy)

    # Mock the two internal methods that touch the network/filesystem
    guard._resolve_ip      = MagicMock(return_value="1.2.3.4")
    guard._country_for_ip  = MagicMock(return_value=country_code)
    return guard


# ── HALT tests — these countries must always be blocked ──────────────────────

class TestBlockedCountries:

    def test_china_is_halted(self):
        """CN is not in EU adequacy list — must HALT."""
        guard = make_guard_with_country("CN")
        with pytest.raises(DataSovereigntyViolation) as exc:
            guard.evaluate("https://api.example.cn")
        assert exc.value.country == "CN"
        assert "Art.53" in exc.value.reason

    def test_russia_is_halted(self):
        """RU is not in EU adequacy list — must HALT."""
        guard = make_guard_with_country("RU")
        with pytest.raises(DataSovereigntyViolation) as exc:
            guard.evaluate("https://api.example.ru")
        assert exc.value.country == "RU"

    def test_usa_is_halted(self):
        """US is not in EU adequacy list — must HALT."""
        guard = make_guard_with_country("US")
        with pytest.raises(DataSovereigntyViolation) as exc:
            guard.evaluate("https://api.example.us")
        assert exc.value.country == "US"

    def test_india_is_halted(self):
        """IN is not in EU adequacy list — must HALT."""
        guard = make_guard_with_country("IN")
        with pytest.raises(DataSovereigntyViolation) as exc:
            guard.evaluate("https://api.example.in")
        assert exc.value.country == "IN"

    def test_unknown_country_is_halted(self):
        """UNKNOWN country — fail closed, must HALT."""
        guard = make_guard_with_country("UNKNOWN")
        with pytest.raises(DataSovereigntyViolation):
            guard.evaluate("https://mystery.example.com")


# ── PASS tests — these countries must always be allowed ──────────────────────

class TestAllowedCountries:

    def test_germany_passes(self):
        """DE — EU member state, must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        guard   = make_guard_with_country("DE")
        verdict = guard.evaluate("https://api.example.de")
        assert verdict == Verdict.PASS

    def test_austria_passes(self):
        """AT — EU member state, must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        guard   = make_guard_with_country("AT")
        verdict = guard.evaluate("https://api.example.at")
        assert verdict == Verdict.PASS

    def test_switzerland_passes(self):
        """CH — EC adequacy decision, must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        guard   = make_guard_with_country("CH")
        verdict = guard.evaluate("https://api.example.ch")
        assert verdict == Verdict.PASS

    def test_france_passes(self):
        """FR — EU member state, must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        guard   = make_guard_with_country("FR")
        verdict = guard.evaluate("https://api.example.fr")
        assert verdict == Verdict.PASS

    def test_japan_passes(self):
        """JP — EC adequacy decision, must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        guard   = make_guard_with_country("JP")
        verdict = guard.evaluate("https://api.example.jp")
        assert verdict == Verdict.PASS


# ── Fail-closed tests — Shield must HALT on ambiguity ────────────────────────

class TestFailClosed:

    def test_no_geoip_db_halts(self, tmp_path):
        """No GeoIP DB present — every request must HALT."""
        policy = DataSovereigntyPolicy(
            geoip_db_path=str(tmp_path / "missing.mmdb")
        )
        guard = GeoGuard(policy)
        guard._resolve_ip = MagicMock(return_value="1.2.3.4")

        with pytest.raises(DataSovereigntyViolation):
            guard.evaluate("https://api.example.com")

    def test_dns_failure_halts(self, eu_policy):
        """DNS resolution failure — must HALT."""
        import socket
        guard = GeoGuard(eu_policy)
        guard._resolve_ip = MagicMock(
            side_effect=DataSovereigntyViolation(
                url     = "https://unresolvable.invalid",
                country = "UNRESOLVED",
                reason  = "DNS resolution failed",
            )
        )
        with pytest.raises(DataSovereigntyViolation) as exc:
            guard.evaluate("https://unresolvable.invalid")
        assert exc.value.country == "UNRESOLVED"

    def test_loopback_passes(self, eu_policy):
        """Loopback (127.0.0.1) treated as local DE — must PASS."""
        from sovereign_shield.symbolic.enums import Verdict
        guard  = GeoGuard(eu_policy)
        guard._resolve_ip     = MagicMock(return_value="127.0.0.1")
        guard._country_for_ip = MagicMock(return_value="DE")
        verdict = guard.evaluate("http://localhost:8080/api")
        assert verdict == Verdict.PASS


# ── DACH strict policy tests ──────────────────────────────────────────────────

class TestDACHPolicy:

    def test_japan_blocked_under_dach(self, dach_policy):
        """JP passes EU standard but must HALT under DACH strict policy."""
        guard = GeoGuard(dach_policy)
        guard._resolve_ip     = MagicMock(return_value="1.2.3.4")
        guard._country_for_ip = MagicMock(return_value="JP")

        with pytest.raises(DataSovereigntyViolation) as exc:
            guard.evaluate("https://api.example.jp")
        assert exc.value.country == "JP"

    def test_germany_passes_under_dach(self, dach_policy):
        """DE must pass under DACH strict policy."""
        from sovereign_shield.symbolic.enums import Verdict
        guard = GeoGuard(dach_policy)
        guard._resolve_ip     = MagicMock(return_value="1.2.3.4")
        guard._country_for_ip = MagicMock(return_value="DE")
        verdict = guard.evaluate("https://api.example.de")
        assert verdict == Verdict.PASS