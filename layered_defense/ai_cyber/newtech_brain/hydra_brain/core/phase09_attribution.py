"""
HYDRA™ — Phase 9
Adversary Identity & Attribution Engine

STRICT SCOPE
------------
Phase 9 ONLY:

    - Adversary hypotheses
    - Infrastructure correlation
    - TTP correlation
    - Campaign correlation
    - Temporal correlation
    - Attribution confidence
    - Alternative attribution hypotheses
    - Evidence lineage
    - Attribution assessment
    - Attribution validation

NOT IMPLEMENTED
---------------
    - Intervention optimization
    - Security invariants
    - Dynamic authority graph
    - Security intent compiler
    - Continuous replanning
    - Cyber experiments
    - Cyber regeneration
    - Adaptive defense

Safety boundary:
    Attribution is probabilistic and evidence-backed.
    The engine MUST NOT claim certainty when evidence is insufficient.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
import hashlib
import unittest


# ============================================================================
# HELPERS
# ============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value


def stable_id(*parts: str) -> str:
    material = "|".join(parts)
    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMERATIONS
# ============================================================================

class AdversaryHypothesisStatus(str, Enum):
    OPEN = "OPEN"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    REJECTED = "REJECTED"


class AttributionEvidenceType(str, Enum):
    INFRASTRUCTURE = "INFRASTRUCTURE"
    TTP = "TTP"
    CAMPAIGN = "CAMPAIGN"
    TEMPORAL = "TEMPORAL"
    BEHAVIORAL = "BEHAVIORAL"
    IDENTITY = "IDENTITY"
    VICTIM_PATTERN = "VICTIM_PATTERN"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"


class CorrelationType(str, Enum):
    INFRASTRUCTURE = "INFRASTRUCTURE"
    TTP = "TTP"
    CAMPAIGN = "CAMPAIGN"
    TEMPORAL = "TEMPORAL"
    BEHAVIORAL = "BEHAVIORAL"


class AttributionConfidence(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


# ============================================================================
# TEMPORAL WINDOW
# ============================================================================

@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        ensure_aware(self.start)
        ensure_aware(self.end)

        if self.end < self.start:
            raise ValueError("time window end must not precede start")

    def overlaps(self, other: "TimeWindow") -> bool:
        return (
            self.start <= other.end
            and other.start <= self.end
        )


# ============================================================================
# ATTRIBUTION EVIDENCE
# ============================================================================

@dataclass(frozen=True)
class AttributionEvidence:
    """
    Evidence supporting or weakening an adversary hypothesis.

    Evidence is scored for:
        - reliability
        - relevance
        - direction

    direction:
        +1.0 => supports hypothesis
        -1.0 => contradicts hypothesis
         0.0 => neutral
    """

    evidence_id: str
    scope_id: str
    evidence_type: AttributionEvidenceType
    source_id: str
    observed_at: datetime
    description: str

    reliability: float = 1.0
    relevance: float = 1.0
    direction: float = 1.0

    infrastructure_ids: FrozenSet[str] = frozenset()
    ttp_ids: FrozenSet[str] = frozenset()
    campaign_ids: FrozenSet[str] = frozenset()

    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        ensure_aware(self.observed_at)

        if not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if not self.source_id.strip():
            raise ValueError("source_id must not be empty")

        if not self.description.strip():
            raise ValueError("description must not be empty")

        if not 0.0 <= self.reliability <= 1.0:
            raise ValueError("reliability must be between 0 and 1")

        if not 0.0 <= self.relevance <= 1.0:
            raise ValueError("relevance must be between 0 and 1")

        if not -1.0 <= self.direction <= 1.0:
            raise ValueError("direction must be between -1 and 1")


# ============================================================================
# INFRASTRUCTURE
# ============================================================================

@dataclass(frozen=True)
class AdversaryInfrastructure:
    infrastructure_id: str
    scope_id: str
    infrastructure_type: str
    identifier: str
    first_seen: datetime
    last_seen: datetime
    confidence: float = 1.0

    def __post_init__(self) -> None:
        ensure_aware(self.first_seen)
        ensure_aware(self.last_seen)

        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")

        if not self.infrastructure_id.strip():
            raise ValueError("infrastructure_id must not be empty")

        if not self.identifier.strip():
            raise ValueError("identifier must not be empty")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


# ============================================================================
# TTP
# ============================================================================

@dataclass(frozen=True)
class AdversaryTTP:
    ttp_id: str
    scope_id: str
    technique_id: str
    observed_at: datetime
    confidence: float = 1.0

    def __post_init__(self) -> None:
        ensure_aware(self.observed_at)

        if not self.ttp_id.strip():
            raise ValueError("ttp_id must not be empty")

        if not self.technique_id.strip():
            raise ValueError("technique_id must not be empty")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


# ============================================================================
# CAMPAIGN
# ============================================================================

@dataclass(frozen=True)
class AdversaryCampaign:
    campaign_id: str
    scope_id: str
    name: str
    window: TimeWindow
    infrastructure_ids: FrozenSet[str] = frozenset()
    ttp_ids: FrozenSet[str] = frozenset()
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.campaign_id.strip():
            raise ValueError("campaign_id must not be empty")

        if not self.name.strip():
            raise ValueError("campaign name must not be empty")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


# ============================================================================
# ADVERSARY HYPOTHESIS
# ============================================================================

@dataclass
class AdversaryHypothesis:
    hypothesis_id: str
    scope_id: str

    # This is a hypothesis label, not a claim of confirmed identity.
    adversary_label: str

    status: AdversaryHypothesisStatus = (
        AdversaryHypothesisStatus.OPEN
    )

    evidence_ids: FrozenSet[str] = frozenset()
    infrastructure_ids: FrozenSet[str] = frozenset()
    ttp_ids: FrozenSet[str] = frozenset()
    campaign_ids: FrozenSet[str] = frozenset()

    alternative_hypothesis_ids: FrozenSet[str] = frozenset()

    confidence_score: float = 0.0
    confidence_level: AttributionConfidence = (
        AttributionConfidence.VERY_LOW
    )

    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)
        ensure_aware(self.updated_at)

        if not self.hypothesis_id.strip():
            raise ValueError("hypothesis_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if not self.adversary_label.strip():
            raise ValueError("adversary_label must not be empty")

        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError(
                "confidence_score must be between 0 and 1"
            )


# ============================================================================
# CORRELATION RESULT
# ============================================================================

@dataclass(frozen=True)
class CorrelationResult:
    correlation_id: str
    hypothesis_id: str
    correlation_type: CorrelationType
    matched_items: Tuple[str, ...]
    score: float
    explanation: str

    def __post_init__(self) -> None:
        if not self.correlation_id.strip():
            raise ValueError("correlation_id must not be empty")

        if not self.hypothesis_id.strip():
            raise ValueError("hypothesis_id must not be empty")

        if not 0.0 <= self.score <= 1.0:
            raise ValueError("correlation score must be between 0 and 1")

        if not self.explanation.strip():
            raise ValueError("explanation must not be empty")


# ============================================================================
# ATTRIBUTION ASSESSMENT
# ============================================================================

@dataclass(frozen=True)
class AttributionAssessment:
    assessment_id: str
    hypothesis_id: str
    assessed_at: datetime

    confidence_score: float
    confidence_level: AttributionConfidence

    supporting_evidence_ids: FrozenSet[str]
    contradicting_evidence_ids: FrozenSet[str]

    correlation_results: Tuple[CorrelationResult, ...]

    limitations: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        ensure_aware(self.assessed_at)

        if not self.assessment_id.strip():
            raise ValueError("assessment_id must not be empty")

        if not self.hypothesis_id.strip():
            raise ValueError("hypothesis_id must not be empty")

        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError(
                "confidence_score must be between 0 and 1"
            )


# ============================================================================
# ENGINE
# ============================================================================

class AdversaryAttributionEngine:
    """
    Phase 9 attribution engine.

    Design principles:
        1. Attribution is hypothesis-based.
        2. Evidence must be scoped.
        3. Multiple alternatives are preserved.
        4. Correlation is not treated as proof.
        5. Confidence is explicit.
        6. Contradictory evidence reduces confidence.
        7. No automatic attacker identity certainty.
    """

    def __init__(self):
        self._evidence: Dict[str, AttributionEvidence] = {}
        self._infrastructure: Dict[str, AdversaryInfrastructure] = {}
        self._ttps: Dict[str, AdversaryTTP] = {}
        self._campaigns: Dict[str, AdversaryCampaign] = {}

        self._hypotheses: Dict[str, AdversaryHypothesis] = {}
        self._assessments: Dict[str, AttributionAssessment] = {}

        self._lock = RLock()

    # ========================================================================
    # EVIDENCE
    # ========================================================================

    def add_evidence(
        self,
        evidence: AttributionEvidence,
    ) -> None:

        with self._lock:
            if evidence.evidence_id in self._evidence:
                raise ValueError(
                    f"duplicate evidence: {evidence.evidence_id}"
                )

            self._evidence[evidence.evidence_id] = evidence

    def get_evidence(
        self,
        evidence_id: str,
    ) -> AttributionEvidence:

        with self._lock:
            try:
                return self._evidence[evidence_id]
            except KeyError:
                raise KeyError(
                    f"evidence not found: {evidence_id}"
                )

    # ========================================================================
    # INFRASTRUCTURE
    # ========================================================================

    def add_infrastructure(
        self,
        infrastructure: AdversaryInfrastructure,
    ) -> None:

        with self._lock:
            if infrastructure.infrastructure_id in self._infrastructure:
                raise ValueError(
                    "duplicate infrastructure"
                )

            self._infrastructure[
                infrastructure.infrastructure_id
            ] = infrastructure

    # ========================================================================
    # TTP
    # ========================================================================

    def add_ttp(
        self,
        ttp: AdversaryTTP,
    ) -> None:

        with self._lock:
            if ttp.ttp_id in self._ttps:
                raise ValueError(
                    "duplicate TTP"
                )

            self._ttps[ttp.ttp_id] = ttp

    # ========================================================================
    # CAMPAIGN
    # ========================================================================

    def add_campaign(
        self,
        campaign: AdversaryCampaign,
    ) -> None:

        with self._lock:
            if campaign.campaign_id in self._campaigns:
                raise ValueError(
                    "duplicate campaign"
                )

            self._campaigns[
                campaign.campaign_id
            ] = campaign

    # ========================================================================
    # HYPOTHESIS
    # ========================================================================

    def create_hypothesis(
        self,
        hypothesis: AdversaryHypothesis,
    ) -> None:

        with self._lock:
            if hypothesis.hypothesis_id in self._hypotheses:
                raise ValueError(
                    "duplicate hypothesis"
                )

            self._validate_scope_links(
                hypothesis
            )

            self._hypotheses[
                hypothesis.hypothesis_id
            ] = hypothesis

    def get_hypothesis(
        self,
        hypothesis_id: str,
    ) -> AdversaryHypothesis:

        with self._lock:
            try:
                return self._hypotheses[hypothesis_id]
            except KeyError:
                raise KeyError(
                    f"hypothesis not found: {hypothesis_id}"
                )

    # ========================================================================
    # EVIDENCE ATTACHMENT
    # ========================================================================

    def attach_evidence(
        self,
        hypothesis_id: str,
        evidence_id: str,
    ) -> None:

        with self._lock:
            hypothesis = self.get_hypothesis(
                hypothesis_id
            )

            evidence = self.get_evidence(
                evidence_id
            )

            if evidence.scope_id != hypothesis.scope_id:
                raise ValueError(
                    "evidence scope does not match hypothesis"
                )

            hypothesis.evidence_ids = (
                hypothesis.evidence_ids
                | {evidence_id}
            )

            hypothesis.updated_at = utc_now()

    # ========================================================================
    # INFRASTRUCTURE CORRELATION
    # ========================================================================

    def correlate_infrastructure(
        self,
        hypothesis_id: str,
        observed_ids: Iterable[str],
    ) -> CorrelationResult:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        observed = set(observed_ids)

        if not observed:
            return CorrelationResult(
                correlation_id=stable_id(
                    hypothesis_id,
                    "infrastructure",
                    "empty",
                ),
                hypothesis_id=hypothesis_id,
                correlation_type=CorrelationType.INFRASTRUCTURE,
                matched_items=(),
                score=0.0,
                explanation="no infrastructure overlap",
            )

        known = (
            hypothesis.infrastructure_ids
        )

        matched = tuple(
            sorted(observed & known)
        )

        score = (
            len(matched) / len(observed)
            if observed
            else 0.0
        )

        return CorrelationResult(
            correlation_id=stable_id(
                hypothesis_id,
                "infrastructure",
                *sorted(observed),
            ),
            hypothesis_id=hypothesis_id,
            correlation_type=CorrelationType.INFRASTRUCTURE,
            matched_items=matched,
            score=score,
            explanation=(
                "infrastructure overlap correlation"
            ),
        )

    # ========================================================================
    # TTP CORRELATION
    # ========================================================================

    def correlate_ttp(
        self,
        hypothesis_id: str,
        observed_ttp_ids: Iterable[str],
    ) -> CorrelationResult:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        observed = set(observed_ttp_ids)

        known = set(
            hypothesis.ttp_ids
        )

        matched = tuple(
            sorted(observed & known)
        )

        score = (
            len(matched) / len(observed)
            if observed
            else 0.0
        )

        return CorrelationResult(
            correlation_id=stable_id(
                hypothesis_id,
                "ttp",
                *sorted(observed),
            ),
            hypothesis_id=hypothesis_id,
            correlation_type=CorrelationType.TTP,
            matched_items=matched,
            score=score,
            explanation="TTP overlap correlation",
        )

    # ========================================================================
    # CAMPAIGN CORRELATION
    # ========================================================================

    def correlate_campaign(
        self,
        hypothesis_id: str,
        observed_campaign_ids: Iterable[str],
    ) -> CorrelationResult:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        observed = set(
            observed_campaign_ids
        )

        known = set(
            hypothesis.campaign_ids
        )

        matched = tuple(
            sorted(observed & known)
        )

        score = (
            len(matched) / len(observed)
            if observed
            else 0.0
        )

        return CorrelationResult(
            correlation_id=stable_id(
                hypothesis_id,
                "campaign",
                *sorted(observed),
            ),
            hypothesis_id=hypothesis_id,
            correlation_type=CorrelationType.CAMPAIGN,
            matched_items=matched,
            score=score,
            explanation="campaign overlap correlation",
        )

    # ========================================================================
    # TEMPORAL CORRELATION
    # ========================================================================

    def correlate_temporal(
        self,
        hypothesis_id: str,
        observed_window: TimeWindow,
    ) -> CorrelationResult:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        matched: List[str] = []

        for campaign_id in hypothesis.campaign_ids:
            campaign = self._campaigns.get(
                campaign_id
            )

            if campaign is None:
                continue

            if campaign.window.overlaps(
                observed_window
            ):
                matched.append(campaign_id)

        score = (
            1.0 if matched else 0.0
        )

        return CorrelationResult(
            correlation_id=stable_id(
                hypothesis_id,
                "temporal",
                observed_window.start.isoformat(),
                observed_window.end.isoformat(),
            ),
            hypothesis_id=hypothesis_id,
            correlation_type=CorrelationType.TEMPORAL,
            matched_items=tuple(
                sorted(matched)
            ),
            score=score,
            explanation="temporal campaign-window correlation",
        )

    # ========================================================================
    # BEHAVIORAL CORRELATION
    # ========================================================================

    def correlate_behavior(
        self,
        hypothesis_id: str,
        observed_ttp_ids: Iterable[str],
        observed_infrastructure_ids: Iterable[str],
    ) -> CorrelationResult:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        observed_ttp = set(
            observed_ttp_ids
        )

        observed_infra = set(
            observed_infrastructure_ids
        )

        ttp_match = (
            observed_ttp
            & set(hypothesis.ttp_ids)
        )

        infra_match = (
            observed_infra
            & set(hypothesis.infrastructure_ids)
        )

        matched = tuple(
            sorted(
                set(ttp_match)
                | set(infra_match)
            )
        )

        total = (
            len(observed_ttp)
            + len(observed_infra)
        )

        score = (
            len(matched) / total
            if total
            else 0.0
        )

        return CorrelationResult(
            correlation_id=stable_id(
                hypothesis_id,
                "behavior",
                *sorted(matched),
            ),
            hypothesis_id=hypothesis_id,
            correlation_type=CorrelationType.BEHAVIORAL,
            matched_items=matched,
            score=min(score, 1.0),
            explanation="behavioral overlap correlation",
        )

    # ========================================================================
    # TEMPORAL EVIDENCE CORRELATION
    # ========================================================================

    def correlate_evidence_temporal(
        self,
        hypothesis_id: str,
        observed_window: TimeWindow,
    ) -> CorrelationResult:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        matched = []

        for evidence_id in hypothesis.evidence_ids:
            evidence = self._evidence.get(
                evidence_id
            )

            if evidence is None:
                continue

            if (
                observed_window.start
                <= evidence.observed_at
                <= observed_window.end
            ):
                matched.append(evidence_id)

        score = (
            1.0 if matched else 0.0
        )

        return CorrelationResult(
            correlation_id=stable_id(
                hypothesis_id,
                "evidence-temporal",
                observed_window.start.isoformat(),
                observed_window.end.isoformat(),
            ),
            hypothesis_id=hypothesis_id,
            correlation_type=CorrelationType.TEMPORAL,
            matched_items=tuple(
                sorted(matched)
            ),
            score=score,
            explanation="evidence temporal correlation",
        )

    # ========================================================================
    # ASSESSMENT
    # ========================================================================

    def assess(
        self,
        hypothesis_id: str,
        correlation_results: Iterable[CorrelationResult],
    ) -> AttributionAssessment:

        with self._lock:
            hypothesis = self.get_hypothesis(
                hypothesis_id
            )

            correlations = tuple(
                correlation_results
            )

            for correlation in correlations:
                if correlation.hypothesis_id != hypothesis_id:
                    raise ValueError(
                        "correlation belongs to another hypothesis"
                    )

            supporting = []
            contradicting = []

            weighted_total = 0.0
            weighted_score = 0.0

            for evidence_id in hypothesis.evidence_ids:
                evidence = self.get_evidence(
                    evidence_id
                )

                weight = (
                    evidence.reliability
                    * evidence.relevance
                )

                weighted_total += weight

                weighted_score += (
                    weight
                    * evidence.direction
                )

                if evidence.direction > 0:
                    supporting.append(evidence_id)

                elif evidence.direction < 0:
                    contradicting.append(evidence_id)

            evidence_score = 0.0

            if weighted_total > 0:
                normalized = (
                    weighted_score
                    / weighted_total
                )

                evidence_score = (
                    normalized + 1.0
                ) / 2.0

            if correlations:
                correlation_score = sum(
                    item.score
                    for item in correlations
                ) / len(correlations)
            else:
                correlation_score = 0.0

            if weighted_total > 0:
                confidence = (
                    evidence_score * 0.70
                    + correlation_score * 0.30
                )
            else:
                confidence = (
                    correlation_score * 0.30
                )

            confidence = max(
                0.0,
                min(1.0, confidence),
            )

            confidence_level = (
                self._confidence_level(confidence)
            )

            limitations = []

            if not supporting:
                limitations.append(
                    "no supporting evidence registered"
                )

            if contradicting:
                limitations.append(
                    "contradicting evidence exists"
                )

            if not correlations:
                limitations.append(
                    "no correlation results supplied"
                )

            assessment = AttributionAssessment(
                assessment_id=stable_id(
                    hypothesis_id,
                    str(len(self._assessments)),
                    str(round(confidence, 8)),
                ),
                hypothesis_id=hypothesis_id,
                assessed_at=utc_now(),
                confidence_score=confidence,
                confidence_level=confidence_level,
                supporting_evidence_ids=frozenset(
                    supporting
                ),
                contradicting_evidence_ids=frozenset(
                    contradicting
                ),
                correlation_results=correlations,
                limitations=tuple(limitations),
            )

            self._assessments[
                assessment.assessment_id
            ] = assessment

            hypothesis.confidence_score = confidence
            hypothesis.confidence_level = confidence_level
            hypothesis.updated_at = assessment.assessed_at

            if confidence >= 0.80:
                hypothesis.status = (
                    AdversaryHypothesisStatus.SUPPORTED
                )

            elif confidence <= 0.20:
                hypothesis.status = (
                    AdversaryHypothesisStatus.WEAKENED
                )

            else:
                hypothesis.status = (
                    AdversaryHypothesisStatus.OPEN
                )

            return assessment

    # ========================================================================
    # ALTERNATIVE HYPOTHESES
    # ========================================================================

    def link_alternative(
        self,
        hypothesis_id: str,
        alternative_id: str,
    ) -> None:

        with self._lock:
            primary = self.get_hypothesis(
                hypothesis_id
            )

            alternative = self.get_hypothesis(
                alternative_id
            )

            if primary.scope_id != alternative.scope_id:
                raise ValueError(
                    "alternative hypothesis scope mismatch"
                )

            if hypothesis_id == alternative_id:
                raise ValueError(
                    "hypothesis cannot be its own alternative"
                )

            primary.alternative_hypothesis_ids = (
                primary.alternative_hypothesis_ids
                | {alternative_id}
            )

            alternative.alternative_hypothesis_ids = (
                alternative.alternative_hypothesis_ids
                | {hypothesis_id}
            )

            primary.updated_at = utc_now()
            alternative.updated_at = utc_now()

    def get_alternatives(
        self,
        hypothesis_id: str,
    ) -> Tuple[AdversaryHypothesis, ...]:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        return tuple(
            self.get_hypothesis(item)
            for item in sorted(
                hypothesis.alternative_hypothesis_ids
            )
        )

    # ========================================================================
    # CONFIDENCE
    # ========================================================================

    @staticmethod
    def _confidence_level(
        score: float,
    ) -> AttributionConfidence:

        if score < 0.20:
            return AttributionConfidence.VERY_LOW

        if score < 0.40:
            return AttributionConfidence.LOW

        if score < 0.60:
            return AttributionConfidence.MODERATE

        if score < 0.80:
            return AttributionConfidence.HIGH

        return AttributionConfidence.VERY_HIGH

    # ========================================================================
    # SCOPE VALIDATION
    # ========================================================================

    def _validate_scope_links(
        self,
        hypothesis: AdversaryHypothesis,
    ) -> None:

        for evidence_id in hypothesis.evidence_ids:
            evidence = self.get_evidence(
                evidence_id
            )

            if evidence.scope_id != hypothesis.scope_id:
                raise ValueError(
                    f"evidence scope mismatch: {evidence_id}"
                )

        for infrastructure_id in hypothesis.infrastructure_ids:
            infrastructure = self._infrastructure.get(
                infrastructure_id
            )

            if infrastructure is None:
                raise KeyError(
                    f"infrastructure not found: {infrastructure_id}"
                )

            if infrastructure.scope_id != hypothesis.scope_id:
                raise ValueError(
                    "infrastructure scope mismatch"
                )

        for ttp_id in hypothesis.ttp_ids:
            ttp = self._ttps.get(
                ttp_id
            )

            if ttp is None:
                raise KeyError(
                    f"TTP not found: {ttp_id}"
                )

            if ttp.scope_id != hypothesis.scope_id:
                raise ValueError(
                    "TTP scope mismatch"
                )

        for campaign_id in hypothesis.campaign_ids:
            campaign = self._campaigns.get(
                campaign_id
            )

            if campaign is None:
                raise KeyError(
                    f"campaign not found: {campaign_id}"
                )

            if campaign.scope_id != hypothesis.scope_id:
                raise ValueError(
                    "campaign scope mismatch"
                )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for evidence_id, evidence in self._evidence.items():
                if evidence_id != evidence.evidence_id:
                    errors.append(
                        f"evidence key mismatch: {evidence_id}"
                    )

            for hypothesis_id, hypothesis in self._hypotheses.items():

                if hypothesis_id != hypothesis.hypothesis_id:
                    errors.append(
                        f"hypothesis key mismatch: {hypothesis_id}"
                    )

                try:
                    self._validate_scope_links(
                        hypothesis
                    )
                except (KeyError, ValueError) as exc:
                    errors.append(
                        f"{hypothesis_id}: {exc}"
                    )

                for alternative_id in (
                    hypothesis.alternative_hypothesis_ids
                ):
                    if alternative_id not in self._hypotheses:
                        errors.append(
                            f"missing alternative: {alternative_id}"
                        )

                if not (
                    0.0
                    <= hypothesis.confidence_score
                    <= 1.0
                ):
                    errors.append(
                        f"invalid confidence: {hypothesis_id}"
                    )

        return errors

    # ========================================================================
    # EXPORT
    # ========================================================================

    def export_hypothesis(
        self,
        hypothesis_id: str,
    ) -> dict:

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        return {
            "hypothesis_id": hypothesis.hypothesis_id,
            "scope_id": hypothesis.scope_id,
            "adversary_label": hypothesis.adversary_label,
            "status": hypothesis.status.value,
            "confidence_score": hypothesis.confidence_score,
            "confidence_level": (
                hypothesis.confidence_level.value
            ),
            "evidence_ids": sorted(
                hypothesis.evidence_ids
            ),
            "infrastructure_ids": sorted(
                hypothesis.infrastructure_ids
            ),
            "ttp_ids": sorted(
                hypothesis.ttp_ids
            ),
            "campaign_ids": sorted(
                hypothesis.campaign_ids
            ),
            "alternative_hypothesis_ids": sorted(
                hypothesis.alternative_hypothesis_ids
            ),
            "created_at": (
                hypothesis.created_at.isoformat()
            ),
            "updated_at": (
                hypothesis.updated_at.isoformat()
            ),
        }


# ============================================================================
# TESTS
# ============================================================================

class Phase9Tests(unittest.TestCase):

    def setUp(self):

        self.engine = AdversaryAttributionEngine()

        now = utc_now()

        self.infrastructure = AdversaryInfrastructure(
            infrastructure_id="infra-1",
            scope_id="scope-a",
            infrastructure_type="network",
            identifier="example-infra",
            first_seen=now,
            last_seen=now,
        )

        self.ttp = AdversaryTTP(
            ttp_id="ttp-1",
            scope_id="scope-a",
            technique_id="TECH-001",
            observed_at=now,
        )

        self.campaign = AdversaryCampaign(
            campaign_id="campaign-1",
            scope_id="scope-a",
            name="campaign-alpha",
            window=TimeWindow(
                start=now,
                end=now,
            ),
            infrastructure_ids=frozenset(
                {"infra-1"}
            ),
            ttp_ids=frozenset(
                {"ttp-1"}
            ),
        )

        self.engine.add_infrastructure(
            self.infrastructure
        )

        self.engine.add_ttp(
            self.ttp
        )

        self.engine.add_campaign(
            self.campaign
        )

        self.evidence_supporting = AttributionEvidence(
            evidence_id="ev-support",
            scope_id="scope-a",
            evidence_type=AttributionEvidenceType.TTP,
            source_id="sensor-1",
            observed_at=now,
            description="observed technique match",
            reliability=0.9,
            relevance=0.9,
            direction=1.0,
            ttp_ids=frozenset({"ttp-1"}),
        )

        self.evidence_contradicting = AttributionEvidence(
            evidence_id="ev-contradict",
            scope_id="scope-a",
            evidence_type=AttributionEvidenceType.IDENTITY,
            source_id="intel-1",
            observed_at=now,
            description="alternative identity evidence",
            reliability=0.8,
            relevance=0.8,
            direction=-1.0,
        )

        self.engine.add_evidence(
            self.evidence_supporting
        )

        self.engine.add_evidence(
            self.evidence_contradicting
        )

    def create_hypothesis(
        self,
        hypothesis_id="hyp-1",
        *,
        evidence_ids=frozenset(),
    ):

        hypothesis = AdversaryHypothesis(
            hypothesis_id=hypothesis_id,
            scope_id="scope-a",
            adversary_label="adversary-alpha",
            evidence_ids=evidence_ids,
            infrastructure_ids=frozenset(
                {"infra-1"}
            ),
            ttp_ids=frozenset(
                {"ttp-1"}
            ),
            campaign_ids=frozenset(
                {"campaign-1"}
            ),
        )

        self.engine.create_hypothesis(
            hypothesis
        )

    # ========================================================================
    # Evidence
    # ========================================================================

    def test_evidence_registration(self):

        self.assertEqual(
            self.engine.get_evidence(
                "ev-support"
            ).evidence_id,
            "ev-support",
        )

    def test_duplicate_evidence_rejected(self):

        with self.assertRaises(ValueError):
            self.engine.add_evidence(
                self.evidence_supporting
            )

    # ========================================================================
    # Hypothesis
    # ========================================================================

    def test_hypothesis_creation(self):

        self.create_hypothesis()

        hypothesis = self.engine.get_hypothesis(
            "hyp-1"
        )

        self.assertEqual(
            hypothesis.status,
            AdversaryHypothesisStatus.OPEN,
        )

    def test_scope_mismatch_rejected(self):

        bad = AttributionEvidence(
            evidence_id="bad-scope",
            scope_id="scope-b",
            evidence_type=AttributionEvidenceType.TTP,
            source_id="sensor",
            observed_at=utc_now(),
            description="wrong scope",
        )

        self.engine.add_evidence(
            bad
        )

        with self.assertRaises(ValueError):
            self.create_hypothesis(
                evidence_ids=frozenset(
                    {"bad-scope"}
                )
            )

    # ========================================================================
    # Correlation
    # ========================================================================

    def test_infrastructure_correlation(self):

        self.create_hypothesis()

        result = self.engine.correlate_infrastructure(
            "hyp-1",
            ["infra-1"],
        )

        self.assertEqual(
            result.score,
            1.0,
        )

    def test_ttp_correlation(self):

        self.create_hypothesis()

        result = self.engine.correlate_ttp(
            "hyp-1",
            ["ttp-1"],
        )

        self.assertEqual(
            result.score,
            1.0,
        )

    def test_campaign_correlation(self):

        self.create_hypothesis()

        result = self.engine.correlate_campaign(
            "hyp-1",
            ["campaign-1"],
        )

        self.assertEqual(
            result.score,
            1.0,
        )

    def test_temporal_correlation(self):

        self.create_hypothesis()

        now = utc_now()

        # Observed window gets a small margin: the fixture campaign window is
        # [setUp-time, setUp-time], so a zero-width window created later
        # would never overlap it.
        result = self.engine.correlate_temporal(
            "hyp-1",
            TimeWindow(
                start=now - timedelta(seconds=5),
                end=now + timedelta(seconds=5),
            ),
        )

        self.assertEqual(
            result.score,
            1.0,
        )

    # ========================================================================
    # Evidence Attachment
    # ========================================================================

    def test_attach_evidence(self):

        self.create_hypothesis()

        self.engine.attach_evidence(
            "hyp-1",
            "ev-support",
        )

        hypothesis = self.engine.get_hypothesis(
            "hyp-1"
        )

        self.assertIn(
            "ev-support",
            hypothesis.evidence_ids,
        )

    # ========================================================================
    # Assessment
    # ========================================================================

    def test_supported_assessment(self):

        self.create_hypothesis(
            evidence_ids=frozenset(
                {"ev-support"}
            )
        )

        correlation = self.engine.correlate_ttp(
            "hyp-1",
            ["ttp-1"],
        )

        assessment = self.engine.assess(
            "hyp-1",
            [correlation],
        )

        self.assertGreater(
            assessment.confidence_score,
            0.5,
        )

        self.assertIn(
            "ev-support",
            assessment.supporting_evidence_ids,
        )

    def test_contradicting_evidence_is_preserved(self):

        self.create_hypothesis(
            evidence_ids=frozenset(
                {
                    "ev-support",
                    "ev-contradict",
                }
            )
        )

        correlation = self.engine.correlate_ttp(
            "hyp-1",
            ["ttp-1"],
        )

        assessment = self.engine.assess(
            "hyp-1",
            [correlation],
        )

        self.assertIn(
            "ev-contradict",
            assessment.contradicting_evidence_ids,
        )

        self.assertIn(
            "contradicting evidence exists",
            assessment.limitations,
        )

    # ========================================================================
    # Alternatives
    # ========================================================================

    def test_alternative_hypotheses(self):

        self.create_hypothesis(
            "hyp-primary"
        )

        self.create_hypothesis(
            "hyp-alternative"
        )

        self.engine.link_alternative(
            "hyp-primary",
            "hyp-alternative",
        )

        alternatives = self.engine.get_alternatives(
            "hyp-primary"
        )

        self.assertEqual(
            len(alternatives),
            1,
        )

        self.assertEqual(
            alternatives[0].hypothesis_id,
            "hyp-alternative",
        )

    # ========================================================================
    # Safety properties
    # ========================================================================

    def test_no_evidence_means_low_confidence(self):

        self.create_hypothesis()

        assessment = self.engine.assess(
            "hyp-1",
            [],
        )

        self.assertLessEqual(
            assessment.confidence_score,
            0.30,
        )

        self.assertIn(
            "no supporting evidence registered",
            assessment.limitations,
        )

    def test_confidence_is_bounded(self):

        self.create_hypothesis(
            evidence_ids=frozenset(
                {"ev-support"}
            )
        )

        assessment = self.engine.assess(
            "hyp-1",
            [],
        )

        self.assertGreaterEqual(
            assessment.confidence_score,
            0.0,
        )

        self.assertLessEqual(
            assessment.confidence_score,
            1.0,
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation_clean(self):

        self.create_hypothesis()

        self.assertEqual(
            self.engine.validate(),
            [],
        )

    # ========================================================================
    # Export
    # ========================================================================

    def test_export(self):

        self.create_hypothesis()

        exported = self.engine.export_hypothesis(
            "hyp-1"
        )

        self.assertEqual(
            exported["hypothesis_id"],
            "hyp-1",
        )

        self.assertEqual(
            exported["status"],
            "OPEN",
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase9_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase9Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 9 verification failed"
        )


if __name__ == "__main__":
    run_phase9_tests()
