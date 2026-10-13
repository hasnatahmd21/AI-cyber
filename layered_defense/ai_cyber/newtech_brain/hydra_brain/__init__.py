"""
hydra_brain - the useful "New Tech" engines (phases 4-16), split into
independent modules and wired together.

    from hydra_brain import HydraBrain
    brain = HydraBrain()

Layout
------
    hydra_brain/core/      phases 4-16, wired by HydraBrain
    hydra_brain/optional/  phases 17-22, fixed + tested, NOT wired
    hydra_brain/brain.py   the wiring (adapters between engines)
    hydra_brain/audit.py   hash-chained decision log
    hydra_brain/bridge.py  adapter for the platform's CyberEvent / EventBus
"""

from .audit import AuditChain
from .brain import (
    AttackPathReport,
    AttributionReport,
    AuthorizationDecision,
    BrainConfig,
    HydraBrain,
    IngestResult,
    ResponsePlan,
    ResponseReport,
)
from .bridge import PlatformBridge

__all__ = [
    "AttackPathReport",
    "AttributionReport",
    "AuditChain",
    "AuthorizationDecision",
    "BrainConfig",
    "HydraBrain",
    "IngestResult",
    "PlatformBridge",
    "ResponsePlan",
    "ResponseReport",
]
__version__ = "1.0.0"
