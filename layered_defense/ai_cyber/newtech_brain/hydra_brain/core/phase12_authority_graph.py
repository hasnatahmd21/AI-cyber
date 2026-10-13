"""
HYDRA™ — Phase 12
Dynamic Authority Graph

SCOPE
-----
Phase 12 ONLY:

    - Agent identities
    - Authority nodes
    - Tool authority
    - Delegation relationships
    - Authority graph
    - Privilege drift detection
    - Authority anomaly detection
    - Authority revocation state
    - Scope isolation
    - Validation
    - Tests

NOT IMPLEMENTED
---------------
Phase 13 -> Security Intent Compiler
Phase 14 -> Independent Verification
Phase 15 -> Continuous Replanning
Phase 16 -> Cyber Experiment Engine
Phase 17 -> Cyber Regeneration
Phase 18 -> Adaptive Defense

This engine models and evaluates authority.
It does NOT execute tools.
It does NOT perform authorization of real actions.
It does NOT implement identity infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
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


def stable_id(*parts: object) -> str:
    material = "|".join(str(part) for part in parts)
    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMS
# ============================================================================

class AuthorityNodeType(str, Enum):
    HUMAN = "HUMAN"
    AGENT = "AGENT"
    SERVICE = "SERVICE"
    TOOL = "TOOL"
    RESOURCE = "RESOURCE"


class AuthorityEdgeType(str, Enum):
    DIRECT_GRANT = "DIRECT_GRANT"
    DELEGATION = "DELEGATION"
    TOOL_ACCESS = "TOOL_ACCESS"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"


class AuthorityState(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class DriftType(str, Enum):
    UNEXPECTED_GRANT = "UNEXPECTED_GRANT"
    PRIVILEGE_EXPANSION = "PRIVILEGE_EXPANSION"
    UNEXPECTED_DELEGATION = "UNEXPECTED_DELEGATION"
    SCOPE_EXPANSION = "SCOPE_EXPANSION"
    TOOL_ACCESS_EXPANSION = "TOOL_ACCESS_EXPANSION"
    REVOKED_ACCESS_REAPPEARED = "REVOKED_ACCESS_REAPPEARED"


class AnomalySeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ============================================================================
# AUTHORITY NODE
# ============================================================================

@dataclass(frozen=True)
class AuthorityNode:
    node_id: str
    scope_id: str
    node_type: AuthorityNodeType
    name: str

    authority_state: AuthorityState = AuthorityState.ACTIVE

    metadata: Tuple[Tuple[str, str], ...] = ()

    created_at: datetime = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if not self.node_id.strip():
            raise ValueError("node_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if not self.name.strip():
            raise ValueError("name must not be empty")


# ============================================================================
# AUTHORITY EDGE
# ============================================================================

@dataclass(frozen=True)
class AuthorityEdge:
    edge_id: str
    scope_id: str

    source_node_id: str
    target_node_id: str

    edge_type: AuthorityEdgeType

    permissions: FrozenSet[str] = frozenset()

    state: AuthorityState = AuthorityState.ACTIVE

    created_at: datetime = field(
        default_factory=utc_now
    )

    expires_at: Optional[datetime] = None

    delegation_depth: int = 0

    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if self.expires_at is not None:
            ensure_aware(self.expires_at)

        if not self.edge_id.strip():
            raise ValueError("edge_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if not self.source_node_id.strip():
            raise ValueError(
                "source_node_id must not be empty"
            )

        if not self.target_node_id.strip():
            raise ValueError(
                "target_node_id must not be empty"
            )

        if self.source_node_id == self.target_node_id:
            raise ValueError(
                "authority edge cannot self-reference"
            )

        if self.delegation_depth < 0:
            raise ValueError(
                "delegation_depth cannot be negative"
            )

    def is_active(
        self,
        moment: Optional[datetime] = None,
    ) -> bool:

        moment = moment or utc_now()
        ensure_aware(moment)

        if self.state != AuthorityState.ACTIVE:
            return False

        if (
            self.expires_at is not None
            and moment >= self.expires_at
        ):
            return False

        return True


# ============================================================================
# AUTHORITY BASELINE
# ============================================================================

@dataclass(frozen=True)
class AuthorityBaseline:
    """
    Expected authority configuration.

    This is the reference used for drift detection.
    """

    baseline_id: str
    scope_id: str

    allowed_edges: FrozenSet[str] = frozenset()

    allowed_permissions: FrozenSet[str] = frozenset()

    maximum_delegation_depth: int = 8

    allowed_tools: FrozenSet[str] = frozenset()

    created_at: datetime = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:
        ensure_aware(self.created_at)

        if self.maximum_delegation_depth < 0:
            raise ValueError(
                "maximum_delegation_depth cannot be negative"
            )


# ============================================================================
# AUTHORITY DRIFT
# ============================================================================

@dataclass(frozen=True)
class AuthorityDrift:
    drift_id: str
    scope_id: str

    detected_at: datetime

    drift_type: DriftType
    severity: AnomalySeverity

    node_id: Optional[str] = None
    edge_id: Optional[str] = None

    expected_permissions: FrozenSet[str] = frozenset()
    observed_permissions: FrozenSet[str] = frozenset()

    description: str = ""

    def __post_init__(self) -> None:
        ensure_aware(self.detected_at)

        if not self.drift_id.strip():
            raise ValueError(
                "drift_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )


# ============================================================================
# REVOCATION RECORD
# ============================================================================

@dataclass(frozen=True)
class AuthorityRevocation:
    revocation_id: str
    scope_id: str

    target_node_id: Optional[str]
    target_edge_id: Optional[str]

    reason: str

    revoked_at: datetime

    revoked_by: str

    def __post_init__(self) -> None:
        ensure_aware(self.revoked_at)

        if not self.reason.strip():
            raise ValueError(
                "revocation reason must not be empty"
            )

        if not self.revoked_by.strip():
            raise ValueError(
                "revoked_by must not be empty"
            )

        if (
            self.target_node_id is None
            and self.target_edge_id is None
        ):
            raise ValueError(
                "revocation must target node or edge"
            )


# ============================================================================
# AUTHORITY GRAPH
# ============================================================================

class DynamicAuthorityGraph:
    """
    Phase 12 authority graph.

    The graph represents who/what has authority over what.

    It is intentionally separate from actual execution.
    """

    def __init__(self) -> None:

        self._nodes: Dict[
            str,
            AuthorityNode,
        ] = {}

        self._edges: Dict[
            str,
            AuthorityEdge,
        ] = {}

        self._baselines: Dict[
            str,
            AuthorityBaseline,
        ] = {}

        self._drifts: Dict[
            str,
            AuthorityDrift,
        ] = {}

        self._revocations: Dict[
            str,
            AuthorityRevocation,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # NODE MANAGEMENT
    # ========================================================================

    def add_node(
        self,
        node: AuthorityNode,
    ) -> None:

        with self._lock:

            if node.node_id in self._nodes:
                raise ValueError(
                    f"duplicate authority node: "
                    f"{node.node_id}"
                )

            self._nodes[
                node.node_id
            ] = node

    def get_node(
        self,
        node_id: str,
    ) -> AuthorityNode:

        with self._lock:

            if node_id not in self._nodes:
                raise KeyError(
                    f"authority node not found: "
                    f"{node_id}"
                )

            return self._nodes[node_id]

    # ========================================================================
    # EDGE MANAGEMENT
    # ========================================================================

    def add_edge(
        self,
        edge: AuthorityEdge,
    ) -> None:

        with self._lock:

            if edge.edge_id in self._edges:
                raise ValueError(
                    f"duplicate authority edge: "
                    f"{edge.edge_id}"
                )

            source = self._nodes.get(
                edge.source_node_id
            )

            target = self._nodes.get(
                edge.target_node_id
            )

            if source is None:
                raise ValueError(
                    "edge source node does not exist"
                )

            if target is None:
                raise ValueError(
                    "edge target node does not exist"
                )

            if (
                source.scope_id
                != edge.scope_id
                or target.scope_id
                != edge.scope_id
            ):
                raise ValueError(
                    "authority edge scope mismatch"
                )

            self._edges[
                edge.edge_id
            ] = edge

    def get_edge(
        self,
        edge_id: str,
    ) -> AuthorityEdge:

        with self._lock:

            if edge_id not in self._edges:
                raise KeyError(
                    f"authority edge not found: "
                    f"{edge_id}"
                )

            return self._edges[edge_id]

    # ========================================================================
    # ACTIVE EDGES
    # ========================================================================

    def active_edges(
        self,
        scope_id: Optional[str] = None,
        moment: Optional[datetime] = None,
    ) -> Tuple[AuthorityEdge, ...]:

        with self._lock:

            result = []

            for edge in self._edges.values():

                if (
                    scope_id is not None
                    and edge.scope_id != scope_id
                ):
                    continue

                if edge.is_active(moment):
                    result.append(edge)

            return tuple(result)

    # ========================================================================
    # AUTHORITY QUERIES
    # ========================================================================

    def outgoing_authority(
        self,
        node_id: str,
        moment: Optional[datetime] = None,
    ) -> Tuple[AuthorityEdge, ...]:

        with self._lock:

            self.get_node(node_id)

            return tuple(
                edge
                for edge in self._edges.values()
                if (
                    edge.source_node_id == node_id
                    and edge.is_active(moment)
                )
            )

    def incoming_authority(
        self,
        node_id: str,
        moment: Optional[datetime] = None,
    ) -> Tuple[AuthorityEdge, ...]:

        with self._lock:

            self.get_node(node_id)

            return tuple(
                edge
                for edge in self._edges.values()
                if (
                    edge.target_node_id == node_id
                    and edge.is_active(moment)
                )
            )

    def permissions_for(
        self,
        node_id: str,
        moment: Optional[datetime] = None,
    ) -> FrozenSet[str]:

        permissions = set()

        for edge in self.outgoing_authority(
            node_id,
            moment,
        ):
            permissions.update(
                edge.permissions
            )

        return frozenset(permissions)

    # ========================================================================
    # DELEGATION CHAIN
    # ========================================================================

    def delegation_chain(
        self,
        source_node_id: str,
        target_node_id: str,
        *,
        maximum_depth: int = 32,
    ) -> Optional[Tuple[AuthorityEdge, ...]]:

        if maximum_depth < 1:
            raise ValueError(
                "maximum_depth must be positive"
            )

        with self._lock:

            self.get_node(source_node_id)
            self.get_node(target_node_id)

            queue = [
                (
                    source_node_id,
                    (),
                    0,
                )
            ]

            visited = {
                source_node_id
            }

            while queue:

                current, path, depth = queue.pop(0)

                if current == target_node_id:
                    return path

                if depth >= maximum_depth:
                    continue

                for edge in self.outgoing_authority(
                    current
                ):

                    if (
                        edge.target_node_id
                        in visited
                    ):
                        continue

                    visited.add(
                        edge.target_node_id
                    )

                    queue.append(
                        (
                            edge.target_node_id,
                            path + (edge,),
                            depth + 1,
                        )
                    )

            return None

    # ========================================================================
    # BASELINES
    # ========================================================================

    def add_baseline(
        self,
        baseline: AuthorityBaseline,
    ) -> None:

        with self._lock:

            if baseline.baseline_id in self._baselines:
                raise ValueError(
                    f"duplicate baseline: "
                    f"{baseline.baseline_id}"
                )

            self._baselines[
                baseline.baseline_id
            ] = baseline

    # ========================================================================
    # DRIFT DETECTION
    # ========================================================================

    @staticmethod
    def _severity_for_drift(
        drift_type: DriftType,
    ) -> AnomalySeverity:

        if drift_type in {
            DriftType.PRIVILEGE_EXPANSION,
            DriftType.SCOPE_EXPANSION,
            DriftType.REVOKED_ACCESS_REAPPEARED,
        }:
            return AnomalySeverity.HIGH

        if drift_type in {
            DriftType.UNEXPECTED_GRANT,
            DriftType.UNEXPECTED_DELEGATION,
            DriftType.TOOL_ACCESS_EXPANSION,
        }:
            return AnomalySeverity.MODERATE

        return AnomalySeverity.LOW

    def detect_drift(
        self,
        baseline_id: str,
        *,
        moment: Optional[datetime] = None,
    ) -> Tuple[AuthorityDrift, ...]:

        with self._lock:

            if baseline_id not in self._baselines:
                raise KeyError(
                    f"baseline not found: "
                    f"{baseline_id}"
                )

            baseline = self._baselines[
                baseline_id
            ]

            observed_edges = self.active_edges(
                baseline.scope_id,
                moment,
            )

            observed_by_id = {
                edge.edge_id: edge
                for edge in observed_edges
            }

            drifts = []

            # ---------------------------------------------------------------
            # Unexpected edges
            # ---------------------------------------------------------------

            for edge in observed_edges:

                if (
                    edge.edge_id
                    not in baseline.allowed_edges
                ):

                    drift_type = (
                        DriftType.UNEXPECTED_GRANT
                    )

                    if (
                        edge.edge_type
                        == AuthorityEdgeType.DELEGATION
                    ):
                        drift_type = (
                            DriftType.UNEXPECTED_DELEGATION
                        )

                    if edge.permissions:
                        drift_type = (
                            DriftType.PRIVILEGE_EXPANSION
                        )

                    drift = AuthorityDrift(
                        drift_id=stable_id(
                            baseline_id,
                            edge.edge_id,
                            drift_type.value,
                        ),
                        scope_id=baseline.scope_id,
                        detected_at=utc_now(),
                        drift_type=drift_type,
                        severity=self._severity_for_drift(
                            drift_type
                        ),
                        edge_id=edge.edge_id,
                        observed_permissions=(
                            edge.permissions
                        ),
                        description=(
                            "authority edge exists "
                            "outside the configured baseline"
                        ),
                    )

                    self._drifts[
                        drift.drift_id
                    ] = drift

                    drifts.append(drift)

                # -----------------------------------------------------------
                # Permission expansion
                # -----------------------------------------------------------

                unexpected_permissions = (
                    edge.permissions
                    - baseline.allowed_permissions
                )

                if unexpected_permissions:

                    drift = AuthorityDrift(
                        drift_id=stable_id(
                            baseline_id,
                            edge.edge_id,
                            "permission-expansion",
                        ),
                        scope_id=baseline.scope_id,
                        detected_at=utc_now(),
                        drift_type=(
                            DriftType.PRIVILEGE_EXPANSION
                        ),
                        severity=(
                            AnomalySeverity.HIGH
                        ),
                        edge_id=edge.edge_id,
                        expected_permissions=(
                            baseline.allowed_permissions
                        ),
                        observed_permissions=(
                            edge.permissions
                        ),
                        description=(
                            "edge contains permissions "
                            "outside the configured baseline"
                        ),
                    )

                    self._drifts[
                        drift.drift_id
                    ] = drift

                    drifts.append(drift)

                # -----------------------------------------------------------
                # Delegation depth
                # -----------------------------------------------------------

                if (
                    edge.delegation_depth
                    > baseline.maximum_delegation_depth
                ):

                    drift = AuthorityDrift(
                        drift_id=stable_id(
                            baseline_id,
                            edge.edge_id,
                            "delegation-depth",
                        ),
                        scope_id=baseline.scope_id,
                        detected_at=utc_now(),
                        drift_type=(
                            DriftType.SCOPE_EXPANSION
                        ),
                        severity=(
                            AnomalySeverity.HIGH
                        ),
                        edge_id=edge.edge_id,
                        description=(
                            "delegation depth exceeds "
                            "configured maximum"
                        ),
                    )

                    self._drifts[
                        drift.drift_id
                    ] = drift

                    drifts.append(drift)

            # ---------------------------------------------------------------
            # Expected edges that disappeared are NOT automatically treated
            # as drift. Missing authority may represent deliberate removal.
            # ---------------------------------------------------------------

            return tuple(drifts)

    # ========================================================================
    # REVOKE
    # ========================================================================

    def revoke_edge(
        self,
        edge_id: str,
        *,
        reason: str,
        revoked_by: str,
    ) -> AuthorityRevocation:

        with self._lock:

            edge = self.get_edge(edge_id)

            revocation = AuthorityRevocation(
                revocation_id=stable_id(
                    "revocation",
                    edge_id,
                    utc_now().isoformat(),
                ),
                scope_id=edge.scope_id,
                target_node_id=None,
                target_edge_id=edge_id,
                reason=reason,
                revoked_at=utc_now(),
                revoked_by=revoked_by,
            )

            self._revocations[
                revocation.revocation_id
            ] = revocation

            self._edges[
                edge_id
            ] = AuthorityEdge(
                edge_id=edge.edge_id,
                scope_id=edge.scope_id,
                source_node_id=edge.source_node_id,
                target_node_id=edge.target_node_id,
                edge_type=edge.edge_type,
                permissions=edge.permissions,
                state=AuthorityState.REVOKED,
                created_at=edge.created_at,
                expires_at=edge.expires_at,
                delegation_depth=edge.delegation_depth,
                metadata=edge.metadata,
            )

            return revocation

    def revoke_node(
        self,
        node_id: str,
        *,
        reason: str,
        revoked_by: str,
    ) -> AuthorityRevocation:

        with self._lock:

            node = self.get_node(node_id)

            revocation = AuthorityRevocation(
                revocation_id=stable_id(
                    "node-revocation",
                    node_id,
                    utc_now().isoformat(),
                ),
                scope_id=node.scope_id,
                target_node_id=node_id,
                target_edge_id=None,
                reason=reason,
                revoked_at=utc_now(),
                revoked_by=revoked_by,
            )

            self._revocations[
                revocation.revocation_id
            ] = revocation

            self._nodes[
                node_id
            ] = AuthorityNode(
                node_id=node.node_id,
                scope_id=node.scope_id,
                node_type=node.node_type,
                name=node.name,
                authority_state=AuthorityState.REVOKED,
                metadata=node.metadata,
                created_at=node.created_at,
            )

            return revocation

    # ========================================================================
    # REVOCATION LOOKUP
    # ========================================================================

    def revocations(
        self,
        scope_id: Optional[str] = None,
    ) -> Tuple[AuthorityRevocation, ...]:

        with self._lock:

            values = tuple(
                revocation
                for revocation in (
                    self._revocations.values()
                )
                if (
                    scope_id is None
                    or revocation.scope_id == scope_id
                )
            )

            return values

    # ========================================================================
    # DRIFT LOOKUP
    # ========================================================================

    def drifts(
        self,
        scope_id: Optional[str] = None,
    ) -> Tuple[AuthorityDrift, ...]:

        with self._lock:

            return tuple(
                drift
                for drift in self._drifts.values()
                if (
                    scope_id is None
                    or drift.scope_id == scope_id
                )
            )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for node_id, node in self._nodes.items():

                if node_id != node.node_id:
                    errors.append(
                        f"node key mismatch: {node_id}"
                    )

            for edge_id, edge in self._edges.items():

                if edge_id != edge.edge_id:
                    errors.append(
                        f"edge key mismatch: {edge_id}"
                    )

                if edge.source_node_id not in self._nodes:
                    errors.append(
                        f"edge source missing: {edge_id}"
                    )

                if edge.target_node_id not in self._nodes:
                    errors.append(
                        f"edge target missing: {edge_id}"
                    )

                if (
                    edge.source_node_id in self._nodes
                    and edge.target_node_id in self._nodes
                ):
                    source = self._nodes[
                        edge.source_node_id
                    ]

                    target = self._nodes[
                        edge.target_node_id
                    ]

                    if source.scope_id != edge.scope_id:
                        errors.append(
                            f"edge source scope mismatch: "
                            f"{edge_id}"
                        )

                    if target.scope_id != edge.scope_id:
                        errors.append(
                            f"edge target scope mismatch: "
                            f"{edge_id}"
                        )

            for baseline_id, baseline in (
                self._baselines.items()
            ):

                if baseline_id != baseline.baseline_id:
                    errors.append(
                        f"baseline key mismatch: "
                        f"{baseline_id}"
                    )

                for edge_id in baseline.allowed_edges:

                    if edge_id not in self._edges:
                        errors.append(
                            f"baseline references "
                            f"unknown edge: {edge_id}"
                        )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase12Tests(unittest.TestCase):

    def setUp(self):

        self.graph = DynamicAuthorityGraph()

        self.agent = AuthorityNode(
            node_id="agent-1",
            scope_id="tenant-a",
            node_type=AuthorityNodeType.AGENT,
            name="Security Agent",
        )

        self.tool = AuthorityNode(
            node_id="tool-1",
            scope_id="tenant-a",
            node_type=AuthorityNodeType.TOOL,
            name="Network Control Tool",
        )

        self.resource = AuthorityNode(
            node_id="resource-1",
            scope_id="tenant-a",
            node_type=AuthorityNodeType.RESOURCE,
            name="Protected Resource",
        )

        self.graph.add_node(self.agent)
        self.graph.add_node(self.tool)
        self.graph.add_node(self.resource)

    # ========================================================================
    # Nodes
    # ========================================================================

    def test_node_registration(self):

        node = self.graph.get_node(
            "agent-1"
        )

        self.assertEqual(
            node.node_type,
            AuthorityNodeType.AGENT,
        )

    def test_duplicate_node_rejected(self):

        with self.assertRaises(ValueError):
            self.graph.add_node(
                self.agent
            )

    # ========================================================================
    # Edges
    # ========================================================================

    def test_edge_registration(self):

        edge = AuthorityEdge(
            edge_id="edge-1",
            scope_id="tenant-a",
            source_node_id="agent-1",
            target_node_id="tool-1",
            edge_type=AuthorityEdgeType.TOOL_ACCESS,
            permissions=frozenset(
                {"network.read"}
            ),
        )

        self.graph.add_edge(edge)

        self.assertEqual(
            len(
                self.graph.outgoing_authority(
                    "agent-1"
                )
            ),
            1,
        )

    def test_missing_node_rejected(self):

        edge = AuthorityEdge(
            edge_id="edge-bad",
            scope_id="tenant-a",
            source_node_id="unknown",
            target_node_id="tool-1",
            edge_type=AuthorityEdgeType.TOOL_ACCESS,
        )

        with self.assertRaises(ValueError):
            self.graph.add_edge(edge)

    # ========================================================================
    # Permissions
    # ========================================================================

    def test_permissions_for_agent(self):

        self.graph.add_edge(
            AuthorityEdge(
                edge_id="edge-perm",
                scope_id="tenant-a",
                source_node_id="agent-1",
                target_node_id="tool-1",
                edge_type=AuthorityEdgeType.TOOL_ACCESS,
                permissions=frozenset(
                    {
                        "network.read",
                        "network.block",
                    }
                ),
            )
        )

        permissions = (
            self.graph.permissions_for(
                "agent-1"
            )
        )

        self.assertEqual(
            permissions,
            frozenset(
                {
                    "network.read",
                    "network.block",
                }
            ),
        )

    # ========================================================================
    # Delegation
    # ========================================================================

    def test_delegation_chain(self):

        service = AuthorityNode(
            node_id="service-1",
            scope_id="tenant-a",
            node_type=AuthorityNodeType.SERVICE,
            name="Security Service",
        )

        self.graph.add_node(service)

        self.graph.add_edge(
            AuthorityEdge(
                edge_id="delegate-1",
                scope_id="tenant-a",
                source_node_id="agent-1",
                target_node_id="service-1",
                edge_type=AuthorityEdgeType.DELEGATION,
                permissions=frozenset(
                    {"security.read"}
                ),
            )
        )

        self.graph.add_edge(
            AuthorityEdge(
                edge_id="delegate-2",
                scope_id="tenant-a",
                source_node_id="service-1",
                target_node_id="tool-1",
                edge_type=AuthorityEdgeType.TOOL_ACCESS,
                permissions=frozenset(
                    {"network.read"}
                ),
            )
        )

        path = self.graph.delegation_chain(
            "agent-1",
            "tool-1",
        )

        self.assertIsNotNone(path)
        self.assertEqual(
            len(path),
            2,
        )

    # ========================================================================
    # Temporal expiry
    # ========================================================================

    def test_expired_edge_inactive(self):

        expired = (
            utc_now()
        )

        from datetime import timedelta

        edge = AuthorityEdge(
            edge_id="expired-edge",
            scope_id="tenant-a",
            source_node_id="agent-1",
            target_node_id="tool-1",
            edge_type=AuthorityEdgeType.TOOL_ACCESS,
            expires_at=(
                expired - timedelta(seconds=1)
            ),
        )

        self.graph.add_edge(edge)

        self.assertEqual(
            self.graph.active_edges(
                "tenant-a"
            ),
            (),
        )

    # ========================================================================
    # Baseline / drift
    # ========================================================================

    def test_unexpected_edge_detected(self):

        edge = AuthorityEdge(
            edge_id="unexpected",
            scope_id="tenant-a",
            source_node_id="agent-1",
            target_node_id="tool-1",
            edge_type=AuthorityEdgeType.TOOL_ACCESS,
            permissions=frozenset(
                {"network.block"}
            ),
        )

        self.graph.add_edge(edge)

        baseline = AuthorityBaseline(
            baseline_id="baseline-1",
            scope_id="tenant-a",
            allowed_edges=frozenset(),
            allowed_permissions=frozenset(),
        )

        self.graph.add_baseline(
            baseline
        )

        drifts = self.graph.detect_drift(
            "baseline-1"
        )

        self.assertTrue(
            len(drifts) >= 1
        )

    def test_permission_expansion_detected(self):

        edge = AuthorityEdge(
            edge_id="permission-expansion",
            scope_id="tenant-a",
            source_node_id="agent-1",
            target_node_id="tool-1",
            edge_type=AuthorityEdgeType.TOOL_ACCESS,
            permissions=frozenset(
                {
                    "network.read",
                    "network.block",
                }
            ),
        )

        self.graph.add_edge(edge)

        baseline = AuthorityBaseline(
            baseline_id="baseline-perm",
            scope_id="tenant-a",
            allowed_edges=frozenset(
                {"permission-expansion"}
            ),
            allowed_permissions=frozenset(
                {"network.read"}
            ),
        )

        self.graph.add_baseline(
            baseline
        )

        drifts = self.graph.detect_drift(
            "baseline-perm"
        )

        self.assertTrue(
            any(
                drift.drift_type
                == DriftType.PRIVILEGE_EXPANSION
                for drift in drifts
            )
        )

    # ========================================================================
    # Revocation
    # ========================================================================

    def test_edge_revocation(self):

        edge = AuthorityEdge(
            edge_id="revoke-edge",
            scope_id="tenant-a",
            source_node_id="agent-1",
            target_node_id="tool-1",
            edge_type=AuthorityEdgeType.TOOL_ACCESS,
        )

        self.graph.add_edge(edge)

        revocation = self.graph.revoke_edge(
            "revoke-edge",
            reason="authority no longer required",
            revoked_by="security-control",
        )

        self.assertEqual(
            revocation.target_edge_id,
            "revoke-edge",
        )

        self.assertEqual(
            self.graph.active_edges(
                "tenant-a"
            ),
            (),
        )

    def test_node_revocation(self):

        revocation = self.graph.revoke_node(
            "agent-1",
            reason="agent compromised",
            revoked_by="security-control",
        )

        self.assertEqual(
            revocation.target_node_id,
            "agent-1",
        )

        self.assertEqual(
            self.graph.get_node(
                "agent-1"
            ).authority_state,
            AuthorityState.REVOKED,
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_cross_scope_edge_rejected(self):

        foreign = AuthorityNode(
            node_id="foreign-tool",
            scope_id="tenant-b",
            node_type=AuthorityNodeType.TOOL,
            name="Foreign Tool",
        )

        self.graph.add_node(
            foreign
        )

        edge = AuthorityEdge(
            edge_id="cross-scope",
            scope_id="tenant-a",
            source_node_id="agent-1",
            target_node_id="foreign-tool",
            edge_type=AuthorityEdgeType.TOOL_ACCESS,
        )

        with self.assertRaises(ValueError):
            self.graph.add_edge(edge)

    # ========================================================================
    # Validation
    # ========================================================================

    def test_validation_clean(self):

        self.assertEqual(
            self.graph.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase12_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase12Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 12 verification failed"
        )


if __name__ == "__main__":
    run_phase12_tests()
