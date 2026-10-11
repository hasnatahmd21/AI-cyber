"""Plug datasets into the canonical system via runtime.build_system (no bypass, no 'test mode')."""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from ..runtime import System, build_system
from .dataset_loader import DatasetIntegrityError, load_verified
from .dataset_rules import DatasetLayer1, compile_rules


def build_system_with_datasets(dataset_dirs: Iterable[str], config: Optional[Dict[str, Any]] = None,
                               key_provider=None) -> System:
    s = build_system(config, key_provider=key_provider)
    rules = []
    for d in dataset_dirs:
        try:
            ds = load_verified(d)
            rules += compile_rules(ds)
        except DatasetIntegrityError as e:
            s.audit.record("dataset_rejected", dir=str(d), reason=str(e))
            s.shutdown()
            raise                                   # fail closed: refuse to start with unverified data
        s.audit.record("dataset_loaded", dir=str(d), files=len(ds.files))
    s.orchestrator.l1 = DatasetLayer1(rules)        # the same orchestrator, same order: barrier->...->L3
    return s
