"""
HYDRA™ — Phase 21
Resource & Availability Resilience

SCOPE
-----
- Resource quotas
- Resource budgets
- Rate limits
- Circuit breakers
- Bounded reasoning
- Safe degradation
- Emergency safe mode
- Resource usage tracking
- Availability protection
- Failure containment at resource layer
- Phase 21 validation and tests

EXCLUDED
--------
Phase 22+ functionality is intentionally NOT implemented:
- Full Autonomous Security Control Loop
- Adversarial Validation
- Scientific Benchmarking
- Enterprise Hardening
- Production Validation
- IP / Novelty / Final Validation

This module does not execute external security actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
import hashlib
import time
import unittest


# ============================================================================
# HELPERS
# ============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")


def stable_hash(*parts: object) -> str:
    material = "|".join(str(part) for part in parts)
    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMS
# ============================================================================

class ResourceType(str, Enum):
    CPU = "CPU"
    MEMORY = "MEMORY"
    STORAGE = "STORAGE"
    NETWORK = "NETWORK"
    API_REQUEST = "API_REQUEST"
    MODEL_INFERENCE = "MODEL_INFERENCE"
    REASONING_STEP = "REASONING_STEP"
    TOOL_CALL = "TOOL_CALL"
    CONCURRENT_TASK = "CONCURRENT_TASK"


class ResourceState(str, Enum):
    AVAILABLE = "AVAILABLE"
    LIMITED = "LIMITED"
    EXHAUSTED = "EXHAUSTED"
    UNKNOWN = "UNKNOWN"


class LimitType(str, Enum):
    QUOTA = "QUOTA"
    BUDGET = "BUDGET"
    RATE = "RATE"
    CONCURRENCY = "CONCURRENCY"


class EnforcementAction(str, Enum):
    ALLOW = "ALLOW"
    THROTTLE = "THROTTLE"
    DEFER = "DEFER"
    REJECT = "REJECT"
    SAFE_DEGRADE = "SAFE_DEGRADE"
    SAFE_MODE = "SAFE_MODE"


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class DegradationLevel(str, Enum):
    NONE = "NONE"
    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_3 = "LEVEL_3"
    EMERGENCY = "EMERGENCY"


class SafeModeState(str, Enum):
    NORMAL = "NORMAL"
    ACTIVE = "ACTIVE"


class ResourceEventType(str, Enum):
    CONSUMPTION = "CONSUMPTION"
    QUOTA_REACHED = "QUOTA_REACHED"
    BUDGET_REACHED = "BUDGET_REACHED"
    RATE_LIMITED = "RATE_LIMITED"
    CIRCUIT_OPENED = "CIRCUIT_OPENED"
    CIRCUIT_CLOSED = "CIRCUIT_CLOSED"
    DEGRADATION_CHANGED = "DEGRADATION_CHANGED"
    SAFE_MODE_ENTERED = "SAFE_MODE_ENTERED"
    SAFE_MODE_EXITED = "SAFE_MODE_EXITED"


# ============================================================================
# RESOURCE QUOTA
# ============================================================================

@dataclass(frozen=True)
class ResourceQuota:

    quota_id: str
    scope_id: str
    resource_type: ResourceType

    maximum: float
    warning_threshold: float

    created_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.quota_id.strip():
            raise ValueError("quota_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if self.maximum <= 0:
            raise ValueError("maximum must be positive")

        if not 0.0 < self.warning_threshold <= 1.0:
            raise ValueError(
                "warning_threshold must be between 0 and 1"
            )


# ============================================================================
# RESOURCE BUDGET
# ============================================================================

@dataclass(frozen=True)
class ResourceBudget:

    budget_id: str
    scope_id: str
    resource_type: ResourceType

    maximum: float
    consumed: float = 0.0

    created_at: datetime = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.budget_id.strip():
            raise ValueError("budget_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if self.maximum <= 0:
            raise ValueError("maximum must be positive")

        if self.consumed < 0:
            raise ValueError("consumed cannot be negative")


# ============================================================================
# RATE LIMIT
# ============================================================================

@dataclass(frozen=True)
class RateLimit:

    limit_id: str
    scope_id: str
    resource_type: ResourceType

    maximum_events: int
    window_seconds: float

    created_at: datetime = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.limit_id.strip():
            raise ValueError("limit_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if self.maximum_events <= 0:
            raise ValueError(
                "maximum_events must be positive"
            )

        if self.window_seconds <= 0:
            raise ValueError(
                "window_seconds must be positive"
            )


# ============================================================================
# RESOURCE CONSUMPTION
# ============================================================================

@dataclass(frozen=True)
class ResourceConsumption:

    event_id: str
    scope_id: str
    resource_type: ResourceType

    amount: float

    source_reference: str
    occurred_at: datetime

    def __post_init__(self) -> None:

        ensure_aware(self.occurred_at)

        if not self.event_id.strip():
            raise ValueError("event_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if self.amount <= 0:
            raise ValueError("amount must be positive")

        if not self.source_reference.strip():
            raise ValueError(
                "source_reference required"
            )


# ============================================================================
# CIRCUIT BREAKER
# ============================================================================

@dataclass
class CircuitBreaker:

    circuit_id: str
    scope_id: str
    resource_type: ResourceType

    failure_threshold: int
    recovery_timeout_seconds: float

    state: CircuitState = CircuitState.CLOSED

    consecutive_failures: int = 0
    opened_at: Optional[datetime] = None

    def __post_init__(self) -> None:

        if not self.circuit_id.strip():
            raise ValueError("circuit_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if self.failure_threshold <= 0:
            raise ValueError(
                "failure_threshold must be positive"
            )

        if self.recovery_timeout_seconds <= 0:
            raise ValueError(
                "recovery_timeout_seconds must be positive"
            )

    def record_success(
        self,
    ) -> None:

        self.consecutive_failures = 0
        self.state = CircuitState.CLOSED
        self.opened_at = None

    def record_failure(
        self,
    ) -> None:

        self.consecutive_failures += 1

        if (
            self.consecutive_failures
            >= self.failure_threshold
        ):
            self.state = CircuitState.OPEN
            self.opened_at = utc_now()

    def can_attempt(
        self,
        now: Optional[datetime] = None,
    ) -> bool:

        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:

            if self.opened_at is None:
                return False

            moment = now or utc_now()
            ensure_aware(moment)

            elapsed = (
                moment - self.opened_at
            ).total_seconds()

            if (
                elapsed
                >= self.recovery_timeout_seconds
            ):
                self.state = (
                    CircuitState.HALF_OPEN
                )
                return True

            return False

        return True


# ============================================================================
# DEGRADATION POLICY
# ============================================================================

@dataclass(frozen=True)
class DegradationPolicy:

    policy_id: str
    scope_id: str

    thresholds: Tuple[
        Tuple[float, DegradationLevel],
        ...]

    created_at: datetime = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.policy_id.strip():
            raise ValueError("policy_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if not self.thresholds:
            raise ValueError(
                "at least one threshold required"
            )

        previous = 1.1

        for threshold, _level in self.thresholds:

            if not 0.0 <= threshold <= 1.0:
                raise ValueError(
                    "threshold must be between 0 and 1"
                )

            if threshold >= previous:
                raise ValueError(
                    "thresholds must be descending"
                )

            previous = threshold

    def level_for(
        self,
        utilization: float,
    ) -> DegradationLevel:

        utilization = max(
            0.0,
            min(1.0, utilization),
        )

        for threshold, level in self.thresholds:

            if utilization >= threshold:
                return level

        return DegradationLevel.NONE


# ============================================================================
# ENFORCEMENT DECISION
# ============================================================================

@dataclass(frozen=True)
class ResourceDecision:

    decision_id: str
    scope_id: str

    resource_type: ResourceType
    action: EnforcementAction

    utilization: float
    reason: str

    created_at: datetime

    decision_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.decision_id.strip():
            raise ValueError("decision_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if not 0.0 <= self.utilization:
            raise ValueError(
                "utilization cannot be negative"
            )

        if not self.reason.strip():
            raise ValueError("reason required")

        if not self.decision_hash.strip():
            raise ValueError(
                "decision_hash required"
            )


# ============================================================================
# RESOURCE EVENT
# ============================================================================

@dataclass(frozen=True)
class ResourceEvent:

    event_id: str
    scope_id: str

    event_type: ResourceEventType
    resource_type: ResourceType

    description: str
    created_at: datetime

    event_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.event_id.strip():
            raise ValueError("event_id required")

        if not self.scope_id.strip():
            raise ValueError("scope_id required")

        if not self.description.strip():
            raise ValueError(
                "description required"
            )

        if not self.event_hash.strip():
            raise ValueError("event_hash required")


# ============================================================================
# RESOURCE RESILIENCE ENGINE
# ============================================================================

class ResourceAvailabilityResilienceEngine:

    def __init__(
        self,
        *,
        safe_mode_threshold: float = 0.95,
    ) -> None:

        if not 0.0 < safe_mode_threshold <= 1.0:
            raise ValueError(
                "safe_mode_threshold must be between 0 and 1"
            )

        self.safe_mode_threshold = (
            safe_mode_threshold
        )

        self._quotas: Dict[
            str,
            ResourceQuota,
        ] = {}

        self._budgets: Dict[
            str,
            ResourceBudget,
        ] = {}

        self._rate_limits: Dict[
            str,
            RateLimit,
        ] = {}

        self._circuits: Dict[
            str,
            CircuitBreaker,
        ] = {}

        self._degradation: Dict[
            str,
            DegradationPolicy,
        ] = {}

        self._consumption: Dict[
            str,
            ResourceConsumption,
        ] = {}

        self._decisions: Dict[
            str,
            ResourceDecision,
        ] = {}

        self._events: Dict[
            str,
            ResourceEvent,
        ] = {}

        self._rate_history: Dict[
            str,
            List[float],
        ] = {}

        self._safe_modes: Dict[
            str,
            SafeModeState,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # QUOTAS
    # ========================================================================

    def add_quota(
        self,
        quota: ResourceQuota,
    ) -> None:

        with self._lock:

            if quota.quota_id in self._quotas:
                raise ValueError(
                    "duplicate quota"
                )

            self._quotas[
                quota.quota_id
            ] = quota

    # ========================================================================
    # BUDGETS
    # ========================================================================

    def add_budget(
        self,
        budget: ResourceBudget,
    ) -> None:

        with self._lock:

            if budget.budget_id in self._budgets:
                raise ValueError(
                    "duplicate budget"
                )

            self._budgets[
                budget.budget_id
            ] = budget

    # ========================================================================
    # RATE LIMITS
    # ========================================================================

    def add_rate_limit(
        self,
        rate_limit: RateLimit,
    ) -> None:

        with self._lock:

            if rate_limit.limit_id in (
                self._rate_limits
            ):
                raise ValueError(
                    "duplicate rate limit"
                )

            self._rate_limits[
                rate_limit.limit_id
            ] = rate_limit

            self._rate_history[
                rate_limit.limit_id
            ] = []

    # ========================================================================
    # CIRCUITS
    # ========================================================================

    def add_circuit_breaker(
        self,
        circuit: CircuitBreaker,
    ) -> None:

        with self._lock:

            if circuit.circuit_id in self._circuits:
                raise ValueError(
                    "duplicate circuit breaker"
                )

            self._circuits[
                circuit.circuit_id
            ] = circuit

    # ========================================================================
    # DEGRADATION
    # ========================================================================

    def add_degradation_policy(
        self,
        policy: DegradationPolicy,
    ) -> None:

        with self._lock:

            if policy.policy_id in (
                self._degradation
            ):
                raise ValueError(
                    "duplicate degradation policy"
                )

            self._degradation[
                policy.policy_id
            ] = policy

    # ========================================================================
    # CONSUMPTION
    # ========================================================================

    def record_consumption(
        self,
        consumption: ResourceConsumption,
    ) -> None:

        with self._lock:

            if consumption.event_id in (
                self._consumption
            ):
                raise ValueError(
                    "duplicate consumption event"
                )

            self._consumption[
                consumption.event_id
            ] = consumption

            self._apply_budget_consumption(
                consumption
            )

            self._record_event(
                scope_id=consumption.scope_id,
                resource_type=consumption.resource_type,
                event_type=(
                    ResourceEventType.CONSUMPTION
                ),
                description=(
                    f"{consumption.resource_type.value} "
                    f"consumption recorded"
                ),
            )

    def _apply_budget_consumption(
        self,
        consumption: ResourceConsumption,
    ) -> None:

        for budget_id, budget in list(
            self._budgets.items()
        ):

            if (
                budget.scope_id
                != consumption.scope_id
            ):
                continue

            if (
                budget.resource_type
                != consumption.resource_type
            ):
                continue

            updated = ResourceBudget(
                budget_id=budget.budget_id,
                scope_id=budget.scope_id,
                resource_type=budget.resource_type,
                maximum=budget.maximum,
                consumed=(
                    budget.consumed
                    + consumption.amount
                ),
                created_at=budget.created_at,
            )

            self._budgets[
                budget_id
            ] = updated

    # ========================================================================
    # UTILIZATION
    # ========================================================================

    def utilization(
        self,
        *,
        scope_id: str,
        resource_type: ResourceType,
    ) -> float:

        with self._lock:

            quota_values = [
                quota.maximum
                for quota
                in self._quotas.values()
                if quota.scope_id == scope_id
                and quota.resource_type
                == resource_type
            ]

            consumed = sum(
                event.amount
                for event
                in self._consumption.values()
                if event.scope_id == scope_id
                and event.resource_type
                == resource_type
            )

            if not quota_values:

                budget_values = [
                    budget.maximum
                    for budget
                    in self._budgets.values()
                    if budget.scope_id == scope_id
                    and budget.resource_type
                    == resource_type
                ]

                if not budget_values:
                    return 0.0

                maximum = min(
                    budget_values
                )

            else:

                maximum = min(
                    quota_values
                )

            if maximum <= 0:
                return 1.0

            return min(
                1.0,
                consumed / maximum,
            )

    # ========================================================================
    # QUOTA / BUDGET CHECK
    # ========================================================================

    def evaluate_limits(
        self,
        *,
        scope_id: str,
        resource_type: ResourceType,
    ) -> ResourceDecision:

        with self._lock:

            utilization = self.utilization(
                scope_id=scope_id,
                resource_type=resource_type,
            )

            quota_exhausted = any(
                quota.scope_id == scope_id
                and quota.resource_type
                == resource_type
                and utilization >= 1.0
                for quota
                in self._quotas.values()
            )

            budget_exhausted = any(
                budget.scope_id == scope_id
                and budget.resource_type
                == resource_type
                and budget.consumed
                >= budget.maximum
                for budget
                in self._budgets.values()
            )

            if (
                quota_exhausted
                or budget_exhausted
            ):

                action = (
                    EnforcementAction.REJECT
                )

                reason = (
                    "resource quota or budget "
                    "exhausted"
                )

            elif (
                utilization
                >= self.safe_mode_threshold
            ):

                action = (
                    EnforcementAction.SAFE_DEGRADE
                )

                reason = (
                    "resource utilization reached "
                    "safe-degradation threshold"
                )

            elif utilization >= 0.80:

                action = (
                    EnforcementAction.THROTTLE
                )

                reason = (
                    "resource utilization is high"
                )

            else:

                action = (
                    EnforcementAction.ALLOW
                )

                reason = (
                    "resource capacity available"
                )

            decision_hash = stable_hash(
                "resource-decision",
                scope_id,
                resource_type.value,
                action.value,
                utilization,
                reason,
            )

            decision = ResourceDecision(
                decision_id=stable_hash(
                    "decision",
                    decision_hash,
                ),
                scope_id=scope_id,
                resource_type=resource_type,
                action=action,
                utilization=utilization,
                reason=reason,
                created_at=utc_now(),
                decision_hash=decision_hash,
            )

            self._decisions[
                decision.decision_id
            ] = decision

            if action == EnforcementAction.REJECT:

                self._record_event(
                    scope_id=scope_id,
                    resource_type=resource_type,
                    event_type=(
                        ResourceEventType.QUOTA_REACHED
                    ),
                    description=reason,
                )

            return decision

    # ========================================================================
    # RATE LIMITING
    # ========================================================================

    def check_rate_limit(
        self,
        limit_id: str,
        *,
        now: Optional[float] = None,
    ) -> EnforcementAction:

        with self._lock:

            limit = self._rate_limits.get(
                limit_id
            )

            if limit is None:
                raise KeyError(
                    "rate limit not found"
                )

            current = (
                time.monotonic()
                if now is None
                else now
            )

            history = self._rate_history[
                limit_id
            ]

            cutoff = (
                current
                - limit.window_seconds
            )

            history[:] = [
                timestamp
                for timestamp
                in history
                if timestamp > cutoff
            ]

            if len(history) >= (
                limit.maximum_events
            ):

                self._record_event(
                    scope_id=limit.scope_id,
                    resource_type=(
                        limit.resource_type
                    ),
                    event_type=(
                        ResourceEventType.RATE_LIMITED
                    ),
                    description=(
                        "rate limit exceeded"
                    ),
                )

                return EnforcementAction.THROTTLE

            history.append(current)

            return EnforcementAction.ALLOW

    # ========================================================================
    # CIRCUIT BREAKERS
    # ========================================================================

    def record_circuit_failure(
        self,
        circuit_id: str,
    ) -> CircuitState:

        with self._lock:

            circuit = self._circuits.get(
                circuit_id
            )

            if circuit is None:
                raise KeyError(
                    "circuit breaker not found"
                )

            circuit.record_failure()

            if (
                circuit.state
                == CircuitState.OPEN
            ):

                self._record_event(
                    scope_id=circuit.scope_id,
                    resource_type=(
                        circuit.resource_type
                    ),
                    event_type=(
                        ResourceEventType.CIRCUIT_OPENED
                    ),
                    description=(
                        "circuit breaker opened "
                        "after repeated failures"
                    ),
                )

            return circuit.state

    def record_circuit_success(
        self,
        circuit_id: str,
    ) -> CircuitState:

        with self._lock:

            circuit = self._circuits.get(
                circuit_id
            )

            if circuit is None:
                raise KeyError(
                    "circuit breaker not found"
                )

            previous = circuit.state

            circuit.record_success()

            if previous != CircuitState.CLOSED:

                self._record_event(
                    scope_id=circuit.scope_id,
                    resource_type=(
                        circuit.resource_type
                    ),
                    event_type=(
                        ResourceEventType.CIRCUIT_CLOSED
                    ),
                    description=(
                        "circuit breaker closed "
                        "after successful recovery"
                    ),
                )

            return circuit.state

    def circuit_can_attempt(
        self,
        circuit_id: str,
        *,
        now: Optional[datetime] = None,
    ) -> bool:

        with self._lock:

            circuit = self._circuits.get(
                circuit_id
            )

            if circuit is None:
                raise KeyError(
                    "circuit breaker not found"
                )

            return circuit.can_attempt(
                now
            )

    # ========================================================================
    # BOUNDED REASONING
    # ========================================================================

    @staticmethod
    def bounded_reasoning_budget(
        *,
        requested_steps: int,
        maximum_steps: int,
    ) -> int:

        if requested_steps < 0:
            raise ValueError(
                "requested_steps cannot be negative"
            )

        if maximum_steps <= 0:
            raise ValueError(
                "maximum_steps must be positive"
            )

        return min(
            requested_steps,
            maximum_steps,
        )

    @staticmethod
    def bounded_concurrency(
        *,
        requested_tasks: int,
        maximum_tasks: int,
    ) -> int:

        if requested_tasks < 0:
            raise ValueError(
                "requested_tasks cannot be negative"
            )

        if maximum_tasks <= 0:
            raise ValueError(
                "maximum_tasks must be positive"
            )

        return min(
            requested_tasks,
            maximum_tasks,
        )

    # ========================================================================
    # SAFE DEGRADATION
    # ========================================================================

    def degradation_level(
        self,
        policy_id: str,
        *,
        utilization: float,
    ) -> DegradationLevel:

        with self._lock:

            policy = self._degradation.get(
                policy_id
            )

            if policy is None:
                raise KeyError(
                    "degradation policy not found"
                )

            level = policy.level_for(
                utilization
            )

            return level

    # ========================================================================
    # SAFE MODE
    # ========================================================================

    def enter_safe_mode(
        self,
        scope_id: str,
        *,
        reason: str,
    ) -> None:

        if not reason.strip():
            raise ValueError(
                "safe mode reason required"
            )

        with self._lock:

            self._safe_modes[
                scope_id
            ] = SafeModeState.ACTIVE

            self._record_event(
                scope_id=scope_id,
                resource_type=(
                    ResourceType.CONCURRENT_TASK
                ),
                event_type=(
                    ResourceEventType.SAFE_MODE_ENTERED
                ),
                description=reason,
            )

    def exit_safe_mode(
        self,
        scope_id: str,
        *,
        reason: str,
    ) -> None:

        if not reason.strip():
            raise ValueError(
                "safe mode exit reason required"
            )

        with self._lock:

            self._safe_modes[
                scope_id
            ] = SafeModeState.NORMAL

            self._record_event(
                scope_id=scope_id,
                resource_type=(
                    ResourceType.CONCURRENT_TASK
                ),
                event_type=(
                    ResourceEventType.SAFE_MODE_EXITED
                ),
                description=reason,
            )

    def safe_mode_state(
        self,
        scope_id: str,
    ) -> SafeModeState:

        with self._lock:

            return self._safe_modes.get(
                scope_id,
                SafeModeState.NORMAL,
            )

    # ========================================================================
    # INTERNAL EVENT
    # ========================================================================

    def _record_event(
        self,
        *,
        scope_id: str,
        resource_type: ResourceType,
        event_type: ResourceEventType,
        description: str,
    ) -> ResourceEvent:

        created_at = utc_now()

        event_hash = stable_hash(
            "resource-event",
            scope_id,
            resource_type.value,
            event_type.value,
            description,
            created_at.isoformat(),
        )

        event = ResourceEvent(
            event_id=stable_hash(
                "event",
                event_hash,
            ),
            scope_id=scope_id,
            event_type=event_type,
            resource_type=resource_type,
            description=description,
            created_at=created_at,
            event_hash=event_hash,
        )

        self._events[
            event.event_id
        ] = event

        return event

    # ========================================================================
    # LOOKUPS
    # ========================================================================

    def decisions_for_scope(
        self,
        scope_id: str,
    ) -> Tuple[
        ResourceDecision,
        ...,
    ]:

        with self._lock:

            return tuple(
                decision
                for decision
                in self._decisions.values()
                if decision.scope_id == scope_id
            )

    def events_for_scope(
        self,
        scope_id: str,
    ) -> Tuple[
        ResourceEvent,
        ...,
    ]:

        with self._lock:

            return tuple(
                event
                for event
                in self._events.values()
                if event.scope_id == scope_id
            )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for quota_id, quota in (
                self._quotas.items()
            ):
                if quota_id != quota.quota_id:
                    errors.append(
                        "quota key mismatch"
                    )

            for budget_id, budget in (
                self._budgets.items()
            ):
                if budget_id != budget.budget_id:
                    errors.append(
                        "budget key mismatch"
                    )

                if budget.consumed < 0:
                    errors.append(
                        f"negative budget consumption: "
                        f"{budget_id}"
                    )

            for limit_id, limit in (
                self._rate_limits.items()
            ):

                if limit_id != limit.limit_id:
                    errors.append(
                        "rate limit key mismatch"
                    )

                if limit_id not in (
                    self._rate_history
                ):
                    errors.append(
                        f"missing rate history: "
                        f"{limit_id}"
                    )

            for circuit_id, circuit in (
                self._circuits.items()
            ):

                if circuit_id != circuit.circuit_id:
                    errors.append(
                        "circuit key mismatch"
                    )

                if circuit.consecutive_failures < 0:
                    errors.append(
                        f"negative failure count: "
                        f"{circuit_id}"
                    )

                if (
                    circuit.state
                    == CircuitState.OPEN
                    and circuit.opened_at is None
                ):
                    errors.append(
                        f"open circuit missing "
                        f"opened_at: {circuit_id}"
                    )

            for event_id, event in (
                self._events.items()
            ):

                if event_id != event.event_id:
                    errors.append(
                        "event key mismatch"
                    )

            for decision_id, decision in (
                self._decisions.items()
            ):

                if (
                    decision_id
                    != decision.decision_id
                ):
                    errors.append(
                        "decision key mismatch"
                    )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase21Tests(unittest.TestCase):

    def setUp(self):

        self.scope = "tenant-a"

        self.engine = (
            ResourceAvailabilityResilienceEngine()
        )

        self.engine.add_quota(
            ResourceQuota(
                quota_id="cpu-quota",
                scope_id=self.scope,
                resource_type=ResourceType.CPU,
                maximum=100.0,
                warning_threshold=0.80,
                created_at=utc_now(),
            )
        )

        self.engine.add_budget(
            ResourceBudget(
                budget_id="reasoning-budget",
                scope_id=self.scope,
                resource_type=(
                    ResourceType.REASONING_STEP
                ),
                maximum=100.0,
            )
        )

    # ========================================================================
    # Quota
    # ========================================================================

    def test_quota_allows_available_capacity(self):

        decision = (
            self.engine.evaluate_limits(
                scope_id=self.scope,
                resource_type=ResourceType.CPU,
            )
        )

        self.assertEqual(
            decision.action,
            EnforcementAction.ALLOW,
        )

    # ========================================================================
    # Consumption
    # ========================================================================

    def test_consumption_updates_budget(self):

        self.engine.record_consumption(
            ResourceConsumption(
                event_id="usage-1",
                scope_id=self.scope,
                resource_type=(
                    ResourceType.REASONING_STEP
                ),
                amount=25.0,
                source_reference="reasoning-engine",
                occurred_at=utc_now(),
            )
        )

        utilization = (
            self.engine.utilization(
                scope_id=self.scope,
                resource_type=(
                    ResourceType.REASONING_STEP
                ),
            )
        )

        self.assertEqual(
            utilization,
            0.25,
        )

    # ========================================================================
    # Exhaustion
    # ========================================================================

    def test_exhausted_budget_rejected(self):

        for index in range(4):

            self.engine.record_consumption(
                ResourceConsumption(
                    event_id=f"usage-{index}",
                    scope_id=self.scope,
                    resource_type=(
                        ResourceType.REASONING_STEP
                    ),
                    amount=25.0,
                    source_reference="reasoning-engine",
                    occurred_at=utc_now(),
                )
            )

        decision = (
            self.engine.evaluate_limits(
                scope_id=self.scope,
                resource_type=(
                    ResourceType.REASONING_STEP
                ),
            )
        )

        self.assertEqual(
            decision.action,
            EnforcementAction.REJECT,
        )

    # ========================================================================
    # Rate limit
    # ========================================================================

    def test_rate_limit(self):

        limit = RateLimit(
            limit_id="api-rate",
            scope_id=self.scope,
            resource_type=ResourceType.API_REQUEST,
            maximum_events=2,
            window_seconds=60.0,
        )

        self.engine.add_rate_limit(
            limit
        )

        self.assertEqual(
            self.engine.check_rate_limit(
                "api-rate",
                now=100.0,
            ),
            EnforcementAction.ALLOW,
        )

        self.assertEqual(
            self.engine.check_rate_limit(
                "api-rate",
                now=101.0,
            ),
            EnforcementAction.ALLOW,
        )

        self.assertEqual(
            self.engine.check_rate_limit(
                "api-rate",
                now=102.0,
            ),
            EnforcementAction.THROTTLE,
        )

    # ========================================================================
    # Circuit breaker
    # ========================================================================

    def test_circuit_breaker_opens(self):

        circuit = CircuitBreaker(
            circuit_id="model-circuit",
            scope_id=self.scope,
            resource_type=(
                ResourceType.MODEL_INFERENCE
            ),
            failure_threshold=2,
            recovery_timeout_seconds=30.0,
        )

        self.engine.add_circuit_breaker(
            circuit
        )

        self.engine.record_circuit_failure(
            "model-circuit"
        )

        self.assertEqual(
            circuit.state,
            CircuitState.CLOSED,
        )

        self.engine.record_circuit_failure(
            "model-circuit"
        )

        self.assertEqual(
            circuit.state,
            CircuitState.OPEN,
        )

        self.assertFalse(
            self.engine.circuit_can_attempt(
                "model-circuit",
                now=utc_now(),
            )
        )

    # ========================================================================
    # Bounded reasoning
    # ========================================================================

    def test_reasoning_is_bounded(self):

        result = (
            self.engine.bounded_reasoning_budget(
                requested_steps=1000,
                maximum_steps=100,
            )
        )

        self.assertEqual(
            result,
            100,
        )

    # ========================================================================
    # Bounded concurrency
    # ========================================================================

    def test_concurrency_is_bounded(self):

        result = (
            self.engine.bounded_concurrency(
                requested_tasks=50,
                maximum_tasks=8,
            )
        )

        self.assertEqual(
            result,
            8,
        )

    # ========================================================================
    # Degradation
    # ========================================================================

    def test_safe_degradation(self):

        policy = DegradationPolicy(
            policy_id="default-degradation",
            scope_id=self.scope,
            thresholds=(
                (0.95, DegradationLevel.EMERGENCY),
                (0.85, DegradationLevel.LEVEL_3),
                (0.70, DegradationLevel.LEVEL_2),
                (0.50, DegradationLevel.LEVEL_1),
            ),
        )

        self.engine.add_degradation_policy(
            policy
        )

        level = (
            self.engine.degradation_level(
                "default-degradation",
                utilization=0.90,
            )
        )

        self.assertEqual(
            level,
            DegradationLevel.LEVEL_3,
        )

    # ========================================================================
    # Safe mode
    # ========================================================================

    def test_safe_mode(self):

        self.engine.enter_safe_mode(
            self.scope,
            reason="resource exhaustion",
        )

        self.assertEqual(
            self.engine.safe_mode_state(
                self.scope
            ),
            SafeModeState.ACTIVE,
        )

        self.engine.exit_safe_mode(
            self.scope,
            reason="capacity restored",
        )

        self.assertEqual(
            self.engine.safe_mode_state(
                self.scope
            ),
            SafeModeState.NORMAL,
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation(self):

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase21_tests() -> None:

    suite = (
        unittest.defaultTestLoader
        .loadTestsFromTestCase(
            Phase21Tests
        )
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 21 tests failed"
        )


if __name__ == "__main__":
    run_phase21_tests()
