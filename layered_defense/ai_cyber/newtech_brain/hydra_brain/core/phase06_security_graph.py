"""
HYDRA™
PHASE 6 — SECURITY GRAPH & ATTACK-PATH RECONSTRUCTION

Scope ONLY:
    - Temporal security graph
    - Security graph nodes
    - Security graph edges
    - Temporal relationships
    - Attack-path representation
    - Attack-path reconstruction
    - Path scoring
    - Intervention-point identification
    - Validation
    - Tests

No Phase 7+ functionality is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Optional
import copy
import heapq
import threading
import unittest
import uuid


# ============================================================================
# ENUMS
# ============================================================================


class GraphNodeType(str, Enum):
    ASSET = "asset"
    ENDPOINT = "endpoint"
    SERVER = "server"
    APPLICATION = "application"
    DATABASE = "database"
    NETWORK = "network"
    CLOUD = "cloud"
    CONTAINER = "container"
    IDENTITY = "identity"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class GraphEdgeType(str, Enum):
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    AUTHENTICATES_TO = "authenticates_to"
    ACCESSES = "accesses"
    EXECUTES_ON = "executes_on"
    COMMUNICATES_WITH = "communicates_with"
    TRUSTS = "trusts"
    CONTAINS = "contains"
    LEADS_TO = "leads_to"


class PathStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_FOUND = "not_found"


# ============================================================================
# EXCEPTIONS
# ============================================================================


class SecurityGraphError(Exception):
    """Base Phase-6 exception."""


class GraphNodeNotFound(SecurityGraphError):
    """Requested graph node does not exist."""


class GraphEdgeNotFound(SecurityGraphError):
    """Requested graph edge does not exist."""


class InvalidGraphOperation(SecurityGraphError):
    """Graph operation violates Phase-6 rules."""


# ============================================================================
# TIME HELPERS
# ============================================================================


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise InvalidGraphOperation(
            "Graph timestamps must be timezone-aware"
        )

    return value.astimezone(timezone.utc)


# ============================================================================
# GRAPH NODE
# ============================================================================


@dataclass(frozen=True)
class SecurityGraphNode:
    node_id: str
    node_type: GraphNodeType
    scope_id: str
    attributes: Mapping[str, Any] = field(
        default_factory=dict
    )
    valid_from: datetime = field(
        default_factory=utc_now
    )
    valid_until: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.node_id:
            raise InvalidGraphOperation(
                "node_id cannot be empty"
            )

        if not self.scope_id:
            raise InvalidGraphOperation(
                "scope_id cannot be empty"
            )

        valid_from = ensure_aware(self.valid_from)

        if self.valid_until is not None:
            valid_until = ensure_aware(
                self.valid_until
            )

            if valid_until < valid_from:
                raise InvalidGraphOperation(
                    "valid_until cannot precede valid_from"
                )

        object.__setattr__(
            self,
            "valid_from",
            valid_from,
        )

        object.__setattr__(
            self,
            "attributes",
            copy.deepcopy(dict(self.attributes)),
        )

    def active_at(self, moment: datetime) -> bool:
        moment = ensure_aware(moment)

        if moment < self.valid_from:
            return False

        if (
            self.valid_until is not None
            and moment > self.valid_until
        ):
            return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "scope_id": self.scope_id,
            "attributes": copy.deepcopy(
                dict(self.attributes)
            ),
            "valid_from": self.valid_from.isoformat(),
            "valid_until": (
                self.valid_until.isoformat()
                if self.valid_until
                else None
            ),
        }


# ============================================================================
# GRAPH EDGE
# ============================================================================


@dataclass(frozen=True)
class SecurityGraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: GraphEdgeType
    scope_id: str
    weight: float = 1.0
    attributes: Mapping[str, Any] = field(
        default_factory=dict
    )
    valid_from: datetime = field(
        default_factory=utc_now
    )
    valid_until: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.edge_id:
            raise InvalidGraphOperation(
                "edge_id cannot be empty"
            )

        if not self.source_id:
            raise InvalidGraphOperation(
                "source_id cannot be empty"
            )

        if not self.target_id:
            raise InvalidGraphOperation(
                "target_id cannot be empty"
            )

        if not self.scope_id:
            raise InvalidGraphOperation(
                "scope_id cannot be empty"
            )

        if self.weight < 0:
            raise InvalidGraphOperation(
                "edge weight cannot be negative"
            )

        valid_from = ensure_aware(
            self.valid_from
        )

        if self.valid_until is not None:
            valid_until = ensure_aware(
                self.valid_until
            )

            if valid_until < valid_from:
                raise InvalidGraphOperation(
                    "valid_until cannot precede valid_from"
                )

        object.__setattr__(
            self,
            "valid_from",
            valid_from,
        )

        object.__setattr__(
            self,
            "attributes",
            copy.deepcopy(dict(self.attributes)),
        )

    def active_at(self, moment: datetime) -> bool:
        moment = ensure_aware(moment)

        if moment < self.valid_from:
            return False

        if (
            self.valid_until is not None
            and moment > self.valid_until
        ):
            return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "scope_id": self.scope_id,
            "weight": self.weight,
            "attributes": copy.deepcopy(
                dict(self.attributes)
            ),
            "valid_from": self.valid_from.isoformat(),
            "valid_until": (
                self.valid_until.isoformat()
                if self.valid_until
                else None
            ),
        }


# ============================================================================
# ATTACK PATH
# ============================================================================


@dataclass(frozen=True)
class AttackPathStep:
    node_id: str
    edge_id: Optional[str]
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "edge_id": self.edge_id,
            "sequence": self.sequence,
        }


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    scope_id: str
    source_node_id: str
    target_node_id: str
    steps: tuple[AttackPathStep, ...]
    total_score: float
    status: PathStatus
    reconstructed_at: datetime

    @property
    def node_ids(self) -> tuple[str, ...]:
        return tuple(
            step.node_id
            for step in self.steps
        )

    @property
    def edge_ids(self) -> tuple[str, ...]:
        return tuple(
            step.edge_id
            for step in self.steps
            if step.edge_id is not None
        )

    @property
    def hop_count(self) -> int:
        return max(0, len(self.steps) - 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "scope_id": self.scope_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "steps": [
                step.to_dict()
                for step in self.steps
            ],
            "total_score": self.total_score,
            "status": self.status.value,
            "reconstructed_at": (
                self.reconstructed_at.isoformat()
            ),
        }


# ============================================================================
# INTERVENTION POINT
# ============================================================================


@dataclass(frozen=True)
class InterventionPoint:
    node_id: str
    path_position: int
    reason: str
    blocking_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "path_position": self.path_position,
            "reason": self.reason,
            "blocking_score": self.blocking_score,
        }


# ============================================================================
# TEMPORAL SECURITY GRAPH
# ============================================================================


class TemporalSecurityGraph:
    """
    Phase-6 temporal graph.

    Nodes and edges are valid only during their defined temporal intervals.
    """

    def __init__(self, scope_id: str) -> None:
        if not scope_id:
            raise InvalidGraphOperation(
                "scope_id cannot be empty"
            )

        self.scope_id = scope_id

        self._nodes: dict[
            str,
            SecurityGraphNode,
        ] = {}

        self._edges: dict[
            str,
            SecurityGraphEdge,
        ] = {}

        self._lock = threading.RLock()

    # ------------------------------------------------------------------------
    # NODE MANAGEMENT
    # ------------------------------------------------------------------------

    def add_node(
        self,
        node: SecurityGraphNode,
    ) -> None:

        if node.scope_id != self.scope_id:
            raise InvalidGraphOperation(
                "Node scope does not match graph scope"
            )

        with self._lock:
            if node.node_id in self._nodes:
                raise InvalidGraphOperation(
                    f"Node already exists: {node.node_id}"
                )

            self._nodes[node.node_id] = node

    def get_node(
        self,
        node_id: str,
    ) -> SecurityGraphNode:

        try:
            return self._nodes[node_id]
        except KeyError as exc:
            raise GraphNodeNotFound(
                f"Node not found: {node_id}"
            ) from exc

    # ------------------------------------------------------------------------
    # EDGE MANAGEMENT
    # ------------------------------------------------------------------------

    def add_edge(
        self,
        edge: SecurityGraphEdge,
    ) -> None:

        if edge.scope_id != self.scope_id:
            raise InvalidGraphOperation(
                "Edge scope does not match graph scope"
            )

        with self._lock:
            self.get_node(edge.source_id)
            self.get_node(edge.target_id)

            if edge.edge_id in self._edges:
                raise InvalidGraphOperation(
                    f"Edge already exists: {edge.edge_id}"
                )

            self._edges[edge.edge_id] = edge

    def get_edge(
        self,
        edge_id: str,
    ) -> SecurityGraphEdge:

        try:
            return self._edges[edge_id]
        except KeyError as exc:
            raise GraphEdgeNotFound(
                f"Edge not found: {edge_id}"
            ) from exc

    # ------------------------------------------------------------------------
    # TEMPORAL QUERIES
    # ------------------------------------------------------------------------

    def active_nodes(
        self,
        moment: Optional[datetime] = None,
    ) -> tuple[SecurityGraphNode, ...]:

        moment = ensure_aware(
            moment or utc_now()
        )

        with self._lock:
            return tuple(
                node
                for node in self._nodes.values()
                if node.active_at(moment)
            )

    def active_edges(
        self,
        moment: Optional[datetime] = None,
    ) -> tuple[SecurityGraphEdge, ...]:

        moment = ensure_aware(
            moment or utc_now()
        )

        with self._lock:
            return tuple(
                edge
                for edge in self._edges.values()
                if edge.active_at(moment)
                and self.get_node(
                    edge.source_id
                ).active_at(moment)
                and self.get_node(
                    edge.target_id
                ).active_at(moment)
            )

    # ------------------------------------------------------------------------
    # NEIGHBORS
    # ------------------------------------------------------------------------

    def outgoing_edges(
        self,
        node_id: str,
        moment: Optional[datetime] = None,
    ) -> tuple[SecurityGraphEdge, ...]:

        self.get_node(node_id)

        return tuple(
            edge
            for edge in self.active_edges(moment)
            if edge.source_id == node_id
        )

    # ------------------------------------------------------------------------
    # PATH RECONSTRUCTION
    # ------------------------------------------------------------------------

    def reconstruct_attack_path(
        self,
        source_node_id: str,
        target_node_id: str,
        *,
        moment: Optional[datetime] = None,
    ) -> AttackPath:

        self.get_node(source_node_id)
        self.get_node(target_node_id)

        moment = ensure_aware(
            moment or utc_now()
        )

        if not self.get_node(
            source_node_id
        ).active_at(moment):

            return AttackPath(
                path_id=str(uuid.uuid4()),
                scope_id=self.scope_id,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                steps=(),
                total_score=0.0,
                status=PathStatus.NOT_FOUND,
                reconstructed_at=utc_now(),
            )

        if not self.get_node(
            target_node_id
        ).active_at(moment):

            return AttackPath(
                path_id=str(uuid.uuid4()),
                scope_id=self.scope_id,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                steps=(),
                total_score=0.0,
                status=PathStatus.NOT_FOUND,
                reconstructed_at=utc_now(),
            )

        if source_node_id == target_node_id:
            return AttackPath(
                path_id=str(uuid.uuid4()),
                scope_id=self.scope_id,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                steps=(
                    AttackPathStep(
                        node_id=source_node_id,
                        edge_id=None,
                        sequence=0,
                    ),
                ),
                total_score=0.0,
                status=PathStatus.COMPLETE,
                reconstructed_at=utc_now(),
            )

        edges = self.active_edges(moment)

        adjacency: dict[
            str,
            list[SecurityGraphEdge],
        ] = {}

        for edge in edges:
            adjacency.setdefault(
                edge.source_id,
                [],
            ).append(edge)

        # Dijkstra-style shortest weighted path.
        queue: list[
            tuple[
                float,
                str,
                tuple[AttackPathStep, ...],
            ]
        ] = [
            (
                0.0,
                source_node_id,
                (
                    AttackPathStep(
                        node_id=source_node_id,
                        edge_id=None,
                        sequence=0,
                    ),
                ),
            )
        ]

        best_cost: dict[str, float] = {
            source_node_id: 0.0
        }

        while queue:
            cost, node_id, steps = heapq.heappop(queue)

            if node_id == target_node_id:
                return AttackPath(
                    path_id=str(uuid.uuid4()),
                    scope_id=self.scope_id,
                    source_node_id=source_node_id,
                    target_node_id=target_node_id,
                    steps=steps,
                    total_score=cost,
                    status=PathStatus.COMPLETE,
                    reconstructed_at=utc_now(),
                )

            if cost > best_cost.get(
                node_id,
                float("inf"),
            ):
                continue

            for edge in adjacency.get(
                node_id,
                [],
            ):
                next_cost = cost + edge.weight

                if next_cost >= best_cost.get(
                    edge.target_id,
                    float("inf"),
                ):
                    continue

                best_cost[edge.target_id] = next_cost

                next_steps = steps + (
                    AttackPathStep(
                        node_id=edge.target_id,
                        edge_id=edge.edge_id,
                        sequence=len(steps),
                    ),
                )

                heapq.heappush(
                    queue,
                    (
                        next_cost,
                        edge.target_id,
                        next_steps,
                    ),
                )

        return AttackPath(
            path_id=str(uuid.uuid4()),
            scope_id=self.scope_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            steps=(),
            total_score=0.0,
            status=PathStatus.NOT_FOUND,
            reconstructed_at=utc_now(),
        )

    # ------------------------------------------------------------------------
    # PATH SCORING
    # ------------------------------------------------------------------------

    def score_path(
        self,
        path: AttackPath,
    ) -> float:

        if path.scope_id != self.scope_id:
            raise InvalidGraphOperation(
                "Path scope does not match graph scope"
            )

        if path.status != PathStatus.COMPLETE:
            return 0.0

        if not path.edge_ids:
            return 0.0

        return sum(
            self.get_edge(edge_id).weight
            for edge_id in path.edge_ids
        )

    # ------------------------------------------------------------------------
    # INTERVENTION POINTS
    # ------------------------------------------------------------------------

    def identify_intervention_points(
        self,
        path: AttackPath,
        *,
        minimum_blocking_score: float = 0.0,
    ) -> tuple[InterventionPoint, ...]:

        if path.scope_id != self.scope_id:
            raise InvalidGraphOperation(
                "Path scope does not match graph scope"
            )

        if minimum_blocking_score < 0:
            raise InvalidGraphOperation(
                "minimum_blocking_score cannot be negative"
            )

        if path.status != PathStatus.COMPLETE:
            return ()

        points: list[InterventionPoint] = []

        for position, step in enumerate(
            path.steps
        ):
            node = self.get_node(step.node_id)

            raw_score = float(
                node.attributes.get(
                    "intervention_score",
                    1.0,
                )
            )

            score = max(
                0.0,
                min(1.0, raw_score),
            )

            if score < minimum_blocking_score:
                continue

            if position == 0:
                reason = "path-origin"
            elif position == len(path.steps) - 1:
                reason = "path-target"
            else:
                reason = "path-intermediate-node"

            points.append(
                InterventionPoint(
                    node_id=step.node_id,
                    path_position=position,
                    reason=reason,
                    blocking_score=score,
                )
            )

        return tuple(
            sorted(
                points,
                key=lambda item: (
                    -item.blocking_score,
                    item.path_position,
                ),
            )
        )

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    def validate(self) -> tuple[str, ...]:

        issues: list[str] = []

        with self._lock:
            for edge in self._edges.values():

                if edge.scope_id != self.scope_id:
                    issues.append(
                        f"edge-scope:{edge.edge_id}"
                    )

                if edge.source_id not in self._nodes:
                    issues.append(
                        f"missing-source:{edge.edge_id}"
                    )

                if edge.target_id not in self._nodes:
                    issues.append(
                        f"missing-target:{edge.edge_id}"
                    )

                if edge.weight < 0:
                    issues.append(
                        f"negative-weight:{edge.edge_id}"
                    )

        return tuple(issues)


# ============================================================================
# TESTS
# ============================================================================


class TestTemporalSecurityGraph(unittest.TestCase):

    def setUp(self) -> None:
        self.scope = "scope-A"

        self.graph = TemporalSecurityGraph(
            self.scope
        )

        self.now = datetime(
            2026,
            9,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

    def node(
        self,
        node_id: str,
        *,
        intervention_score: float = 1.0,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
    ) -> SecurityGraphNode:

        return SecurityGraphNode(
            node_id=node_id,
            node_type=GraphNodeType.ASSET,
            scope_id=self.scope,
            attributes={
                "intervention_score":
                    intervention_score,
            },
            valid_from=valid_from or (
                self.now - timedelta(hours=1)
            ),
            valid_until=valid_until,
        )

    def edge(
        self,
        edge_id: str,
        source: str,
        target: str,
        weight: float = 1.0,
        *,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
    ) -> SecurityGraphEdge:

        return SecurityGraphEdge(
            edge_id=edge_id,
            source_id=source,
            target_id=target,
            edge_type=GraphEdgeType.LEADS_TO,
            scope_id=self.scope,
            weight=weight,
            valid_from=valid_from or (
                self.now - timedelta(hours=1)
            ),
            valid_until=valid_until,
        )

    def test_add_node(self) -> None:
        node = self.node("A")

        self.graph.add_node(node)

        self.assertEqual(
            self.graph.get_node("A").node_id,
            "A",
        )

    def test_add_edge_requires_existing_nodes(self) -> None:
        self.graph.add_node(
            self.node("A")
        )

        edge = self.edge(
            "E1",
            "A",
            "B",
        )

        with self.assertRaises(
            GraphNodeNotFound
        ):
            self.graph.add_edge(edge)

    def test_temporal_node_activity(self) -> None:
        node = self.node(
            "A",
            valid_from=self.now
            - timedelta(minutes=10),
            valid_until=self.now
            + timedelta(minutes=10),
        )

        self.graph.add_node(node)

        self.assertEqual(
            len(
                self.graph.active_nodes(
                    self.now
                )
            ),
            1,
        )

        future = self.now + timedelta(
            minutes=20
        )

        self.assertEqual(
            len(
                self.graph.active_nodes(
                    future
                )
            ),
            0,
        )

    def test_reconstruct_simple_path(self) -> None:
        for node_id in ("A", "B", "C"):
            self.graph.add_node(
                self.node(node_id)
            )

        self.graph.add_edge(
            self.edge(
                "E1",
                "A",
                "B",
                1.0,
            )
        )

        self.graph.add_edge(
            self.edge(
                "E2",
                "B",
                "C",
                2.0,
            )
        )

        path = self.graph.reconstruct_attack_path(
            "A",
            "C",
            moment=self.now,
        )

        self.assertEqual(
            path.status,
            PathStatus.COMPLETE,
        )

        self.assertEqual(
            path.node_ids,
            ("A", "B", "C"),
        )

        self.assertEqual(
            path.edge_ids,
            ("E1", "E2"),
        )

    def test_weighted_path_selection(self) -> None:
        for node_id in (
            "A",
            "B",
            "C",
            "D",
        ):
            self.graph.add_node(
                self.node(node_id)
            )

        self.graph.add_edge(
            self.edge(
                "E1",
                "A",
                "B",
                10.0,
            )
        )

        self.graph.add_edge(
            self.edge(
                "E2",
                "B",
                "D",
                10.0,
            )
        )

        self.graph.add_edge(
            self.edge(
                "E3",
                "A",
                "C",
                1.0,
            )
        )

        self.graph.add_edge(
            self.edge(
                "E4",
                "C",
                "D",
                1.0,
            )
        )

        path = self.graph.reconstruct_attack_path(
            "A",
            "D",
            moment=self.now,
        )

        self.assertEqual(
            path.node_ids,
            ("A", "C", "D"),
        )

        self.assertEqual(
            path.total_score,
            2.0,
        )

    def test_path_not_found(self) -> None:
        self.graph.add_node(
            self.node("A")
        )

        self.graph.add_node(
            self.node("B")
        )

        path = self.graph.reconstruct_attack_path(
            "A",
            "B",
            moment=self.now,
        )

        self.assertEqual(
            path.status,
            PathStatus.NOT_FOUND,
        )

    def test_path_score(self) -> None:
        self.graph.add_node(
            self.node("A")
        )

        self.graph.add_node(
            self.node("B")
        )

        self.graph.add_edge(
            self.edge(
                "E1",
                "A",
                "B",
                3.5,
            )
        )

        path = self.graph.reconstruct_attack_path(
            "A",
            "B",
            moment=self.now,
        )

        self.assertEqual(
            self.graph.score_path(path),
            3.5,
        )

    def test_intervention_points(self) -> None:
        self.graph.add_node(
            self.node(
                "A",
                intervention_score=0.2,
            )
        )

        self.graph.add_node(
            self.node(
                "B",
                intervention_score=0.9,
            )
        )

        self.graph.add_node(
            self.node(
                "C",
                intervention_score=0.5,
            )
        )

        self.graph.add_edge(
            self.edge(
                "E1",
                "A",
                "B",
            )
        )

        self.graph.add_edge(
            self.edge(
                "E2",
                "B",
                "C",
            )
        )

        path = self.graph.reconstruct_attack_path(
            "A",
            "C",
            moment=self.now,
        )

        points = (
            self.graph.identify_intervention_points(
                path,
                minimum_blocking_score=0.5,
            )
        )

        self.assertEqual(
            [p.node_id for p in points],
            ["B", "C"],
        )

        self.assertEqual(
            points[0].blocking_score,
            0.9,
        )

    def test_temporal_edge_exclusion(self) -> None:
        self.graph.add_node(
            self.node("A")
        )

        self.graph.add_node(
            self.node("B")
        )

        self.graph.add_edge(
            self.edge(
                "E1",
                "A",
                "B",
                valid_from=self.now
                - timedelta(hours=2),
                valid_until=self.now
                - timedelta(hours=1),
            )
        )

        path = self.graph.reconstruct_attack_path(
            "A",
            "B",
            moment=self.now,
        )

        self.assertEqual(
            path.status,
            PathStatus.NOT_FOUND,
        )

    def test_scope_isolation(self) -> None:
        foreign_node = SecurityGraphNode(
            node_id="foreign",
            node_type=GraphNodeType.ASSET,
            scope_id="scope-B",
            valid_from=self.now,
        )

        with self.assertRaises(
            InvalidGraphOperation
        ):
            self.graph.add_node(
                foreign_node
            )

    def test_graph_validation(self) -> None:
        self.graph.add_node(
            self.node("A")
        )

        self.graph.add_node(
            self.node("B")
        )

        self.graph.add_edge(
            self.edge(
                "E1",
                "A",
                "B",
            )
        )

        self.assertEqual(
            self.graph.validate(),
            (),
        )

    def test_same_source_target(self) -> None:
        self.graph.add_node(
            self.node("A")
        )

        path = self.graph.reconstruct_attack_path(
            "A",
            "A",
            moment=self.now,
        )

        self.assertEqual(
            path.status,
            PathStatus.COMPLETE,
        )

        self.assertEqual(
            path.hop_count,
            0,
        )


# ============================================================================
# TEST RUNNER
# ============================================================================


def run_phase6_tests() -> unittest.result.TestResult:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestTemporalSecurityGraph
    )

    runner = unittest.TextTestRunner(
        verbosity=2
    )

    return runner.run(suite)


if __name__ == "__main__":
    run_phase6_tests()
