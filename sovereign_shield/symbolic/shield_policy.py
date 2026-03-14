"""
sovereign_shield/symbolic/shield_policy.py
Master Shield Policy — assembles all sub-policies into one config object.
This is the ONLY file other modules import for configuration.
"""
from dataclasses import dataclass, field
from .sovereignty   import DataSovereigntyPolicy
from .pii_policy    import PIIPolicy
from .neural_policy import NeuralAdvisorPolicy


@dataclass
class ShieldPolicy:
    """
    Single config object passed to SovereignShield on activation.

    Usage:
        from sovereign_shield.symbolic.shield_policy import ShieldPolicy
        policy = ShieldPolicy.german_mittelstand()
        policy = ShieldPolicy.eu_standard()
        policy = ShieldPolicy.minimal()          # testing only
    """
    sovereignty    : DataSovereigntyPolicy = field(
        default_factory=DataSovereigntyPolicy
    )
    pii            : PIIPolicy             = field(
        default_factory=PIIPolicy
    )
    neural         : NeuralAdvisorPolicy   = field(
        default_factory=NeuralAdvisorPolicy
    )
    audit_log_path : str  = "./shield_audit.log"
    fail_closed    : bool = True


    @classmethod
    def german_mittelstand(cls) -> "ShieldPolicy":
        """DACH-only preset. Strictest option for German SME clients."""
        return cls(
            sovereignty=DataSovereigntyPolicy(
                safe_countries=frozenset({
                    "DE", "AT", "CH",
                    "IS", "LI", "NO",
                    "BE", "NL", "FR", "SE",
                }),
            ),
            pii=PIIPolicy(scan_enabled=True, block_on_detection=True),
            fail_closed=True,
        )

    @classmethod
    def eu_standard(cls) -> "ShieldPolicy":
        """All adequacy-approved countries. Standard enterprise preset."""
        return cls()

    @classmethod
    def minimal(cls) -> "ShieldPolicy":
        """Local testing only. Never deploy to production."""
        return cls(
            pii=PIIPolicy(scan_enabled=False, block_on_detection=False),
            neural=NeuralAdvisorPolicy(enabled=False),
            fail_closed=False,
        )