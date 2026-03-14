"""
sovereign_shield/symbolic/enums.py
Enumerations for EU AI Act risk levels, verdicts, and enforced articles.
These values are stable — only change if the AI Act itself is amended.
"""
from enum import Enum, auto


class RiskLevel(Enum):
    UNACCEPTABLE = auto()  # Art. 5  — banned outright
    HIGH         = auto()  # Art. 6  — conformity assessment required
    LIMITED      = auto()  # Art. 52 — transparency obligations
    MINIMAL      = auto()  # No specific obligations


class Verdict(Enum):
    PASS    = auto()  # Compliant — allow execution
    HALT    = auto()  # Violation — block execution
    REVIEW  = auto()  # Ambiguous — flag for human review
    UNKNOWN = auto()  # Shield error — fail closed


class EnforcedArticle(Enum):
    ART_10 = "Art.10  — Data Governance & PII Protection"
    ART_13 = "Art.13  — Transparency & Logging"
    ART_17 = "Art.17  — Quality Management"
    ART_53 = "Art.53  — Data Sovereignty & Cross-Border Transfer"