"""AI-Cyber OS canonical runtime package.

This initializer must stay lightweight: the canonical CLI verifies integrity before
loading the large HYDRA implementation. Public historical exports are resolved lazily.
"""
from __future__ import annotations

from importlib import import_module as _import_module

__all__ = [
    "PHASE",
    "PHASE_NAME",
    "THREAT_INTELLIGENCE_VERSION",
    "utc_now",
    "ensure_utc",
    "deterministic_id",
    "IOCType",
    "ConfidenceLevel",
    "Reputation",
    "EntityType",
    "RelationshipType",
    "ThreatIntelError",
    "ThreatIntelValidationError",
    "ThreatIntelSecurityError",
    "ThreatIntelProviderError",
    "ThreatIntelProviderConflictError",
    "IOCNormalizer",
    "ThreatIntelProvenance",
    "IOC",
    "IOCInput",
    "ThreatActor",
    "Campaign",
    "Malware",
    "ATTACKTechnique",
    "ThreatRelationship",
    "ThreatIntelRecord",
    "FreshnessResult",
    "FreshnessCalculator",
    "ThreatScore",
    "ThreatIntelScorer",
    "ThreatIntelProvider",
    "ThreatIntelProviderRegistry",
    "SimulatedThreatIntelProvider",
    "TenantSafeThreatIntelProvider",
    "ThreatIntelRepository",
    "ThreatIntelService",
    "ThreatIntelBulkIngestor",
    "BulkIngestionResult",
    "ATTACKRegistry",
    "CyberThreatIntelligence",
    "run_phase5_tests",
    "verify_phase5"
]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = _import_module(".hydra", __name__)
    try:
        return getattr(module, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def __dir__():
    return sorted(set(globals()) | set(__all__))
