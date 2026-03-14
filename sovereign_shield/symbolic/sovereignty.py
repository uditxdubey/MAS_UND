"""
sovereign_shield/symbolic/sovereignty.py
Data Sovereignty Policy — country allowlist and GeoIP configuration.
Edit this file when EU adequacy decisions are added or revoked.
"""
from dataclasses import dataclass, field


@dataclass
class DataSovereigntyPolicy:
    safe_countries: frozenset = field(default_factory=lambda: frozenset({
        # EU Member States
        "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
        "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
        "NL", "PL", "PT", "RO", "SE", "SI", "SK",
        # EEA
        "IS", "LI", "NO",
        # EC Adequacy Decisions (valid 2025)
        "CH", "GB", "JP", "KR", "CA", "NZ", "IL", "UY", "AR",
    }))
    geoip_db_path: str        = "./data/GeoLite2-Country.mmdb"
    block_private_ranges: bool = False
    dns_timeout_sec: float    = 2.0