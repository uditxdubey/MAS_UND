"""
sovereign_shield/symbolic/geo_guard.py
Geo Guard — resolves destination IP and checks against safe country list.
This is the primary enforcement module for EU AI Act Art. 53.

Depends on: sovereignty.py, enums.py
Edit this file only if DNS resolution or GeoIP lookup logic changes.
"""
import ipaddress
import socket
from pathlib import Path
from typing import Optional

import maxminddb

from .enums       import Verdict
from .sovereignty import DataSovereigntyPolicy


# ── Violation signal ──────────────────────────────────────────────────────────
class DataSovereigntyViolation(PermissionError):
    """
    Raised when an outbound request targets a non-approved country.
    Subclasses PermissionError so agent frameworks catch it gracefully.
    """
    def __init__(self, url: str, country: str, reason: str):
        self.url     = url
        self.country = country
        self.reason  = reason
        super().__init__(
            f"[SOVEREIGN SHIELD — HALT] "
            f"url='{url}' country='{country}' reason='{reason}'"
        )


# ── Geo Guard ─────────────────────────────────────────────────────────────────
class GeoGuard:
    """
    Deterministic geographic enforcement.

    Flow:
        1. Resolve hostname → IP address
        2. Lookup IP → ISO country code (local GeoIP DB, no cloud)
        3. Check country against DataSovereigntyPolicy.safe_countries
        4. Return Verdict.PASS or raise DataSovereigntyViolation

    All branches are handled. Fails CLOSED on any ambiguity.
    """

    def __init__(self, policy: DataSovereigntyPolicy):
        self.policy = policy
        self._db: Optional[maxminddb.Reader] = None
        self._load_db()

    def _load_db(self) -> None:
        path = Path(self.policy.geoip_db_path)
        if path.exists():
            self._db = maxminddb.open_database(str(path))
        else:
            # No DB = fail closed. Every request will HALT until DB is present.
            self._db = None

    def _resolve_ip(self, url: str) -> str:
        """Resolve hostname to IP. Raises DataSovereigntyViolation on failure."""
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ""
        try:
            return socket.getaddrinfo(
                hostname,
                None,
                proto=socket.IPPROTO_TCP,
            )[0][4][0]
        except (socket.gaierror, socket.timeout) as exc:
            raise DataSovereigntyViolation(
                url=url,
                country="UNRESOLVED",
                reason=f"DNS resolution failed: {exc}",
            )

    def _country_for_ip(self, ip_str: str) -> str:
        """Returns ISO-3166-1 alpha-2 country code or 'UNKNOWN'."""
        try:
            addr = ipaddress.ip_address(ip_str)

            if addr.is_loopback:
                return "DE"  # loopback = local = safe

            if addr.is_private:
                return "PRIVATE"

            if self._db is None:
                return "UNKNOWN"  # no DB → fail closed downstream

            record = self._db.get(ip_str)
            if record and "country" in record:
                return record["country"].get("iso_code", "UNKNOWN")
            return "UNKNOWN"

        except ValueError:
            return "UNKNOWN"

    def evaluate(self, url: str) -> Verdict:
        """
        Main entry point. Called by interceptor for every outbound request.

        Returns:
            Verdict.PASS  — country is in safe list, allow request
        Raises:
            DataSovereigntyViolation — country not approved, HALT execution
        """
        ip_str  = self._resolve_ip(url)
        country = self._country_for_ip(ip_str)

        if self.policy.block_private_ranges and country == "PRIVATE":
            raise DataSovereigntyViolation(
                url=url,
                country="PRIVATE",
                reason="Private IP ranges blocked under zero-trust policy",
            )

        if country in self.policy.safe_countries or country == "PRIVATE":
            return Verdict.PASS

        raise DataSovereigntyViolation(
            url=url,
            country=country,
            reason="Destination country not in EU adequacy allowlist (Art.53)",
        )