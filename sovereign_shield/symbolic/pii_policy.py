"""
sovereign_shield/symbolic/pii_policy.py
PII Detection Policy — controls what gets scanned in outbound payloads.
Edit this file to add new PII pattern types (e.g. Sozialversicherungsnummer).
"""
from dataclasses import dataclass, field


@dataclass
class PIIPolicy:
    scan_enabled: bool       = True
    block_on_detection: bool = True
    patterns: list           = field(default_factory=lambda: [
        "email",
        "iban",
        "phone_de",
        "passport",
        "steuer_id",          # German tax ID
        "sozialversicherung",  # German social security number
    ])