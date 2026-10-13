"""Integration tests for the wired HydraBrain (stdlib unittest)."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from hydra_brain import BrainConfig, HydraBrain, PlatformBridge
from hydra_brain.core.phase11_invariants import (
    InvariantCondition,
    InvariantConditionType,
    InvariantSeverity,
    SecurityInvariant,
)
from hydra_brain.core.phase13_intent_compiler import (
    ConstraintType,
    IntentConstraint,
    SecurityIntent,
)


def now():
    return datetime.now(timezone.utc)


def make_brain(**cfg) -> HydraBrain:
    brain = HydraBrain(BrainConfig(**cfg))
    brain.ingest(source_id="edr", payload={"fw": "on", "maintenance": False})
    brain.add_asset("ext", "external")
    brain.add_asset("web", "server")
    brain.add_asset("db", "database")
    brain.link_assets("ext", "web", "connects_to", weight=0.9)
    brain.link_assets("web", "db", "accesses", weight=0.8)
    brain.add_authority_node("soc", "agent", "soc-agent")
    brain.add_authority_node("fw", "resource", "firewall")
    brain.grant(
        "g1", "soc", "fw", {"isolate", "restrict", "monitor"},
        edge_type="RESOURCE_ACCESS",
    )
    return brain


class IngestTests(unittest.TestCase):
    def test_valid_telemetry_updates_state_and_is_trusted(self):
        b = HydraBrain()
        r = b.ingest(source_id="edr", payload={"fw": "on"})
        self.assertTrue(r.accepted)
        self.assertEqual(r.integrity_status, "VALID")
        self.assertEqual(r.trust_state, "TRUSTED")
        self.assertIsNotNone(r.state_id)

    def test_state_is_merged_across_events(self):
        b = HydraBrain()
        b.ingest(source_id="edr", payload={"a": 1})
        r = b.ingest(source_id="edr", payload={"b": 2})
        data = b.state.get_state(r.state_id).data
        self.assertEqual(dict(data), {"a": 1, "b": 2})

    def test_duplicate_event_id_is_dropped_as_replay(self):
        b = HydraBrain()
        first = b.ingest(source_id="edr", payload={"a": 1}, telemetry_id="e1")
        again = b.ingest(source_id="edr", payload={"a": 9}, telemetry_id="e1")
        self.assertTrue(first.accepted)
        self.assertFalse(again.accepted)
        self.assertTrue(again.deduplicated)
        self.assertEqual(
            dict(b.state.get_state(first.state_id).data), {"a": 1}
        )

    def test_stale_telemetry_does_not_update_state_and_is_not_trusted(self):
        b = HydraBrain(BrainConfig(stale_after_seconds=60))
        good = b.ingest(source_id="edr", payload={"a": 1})
        old = b.ingest(
            source_id="edr", payload={"a": 2},
            observed_at=now() - timedelta(hours=3),
        )
        self.assertFalse(old.accepted)
        self.assertNotEqual(old.trust_state, "TRUSTED")
        self.assertEqual(
            dict(b.state.get_state(good.state_id).data), {"a": 1}
        )

    def test_contradictory_telemetry_is_quarantined(self):
        b = HydraBrain(BrainConfig(
            mutually_exclusive=(("fw", "on", "fw_disabled", True),)
        ))
        r = b.ingest(
            source_id="edr", payload={"fw": "on", "fw_disabled": True}
        )
        self.assertFalse(r.accepted)
        self.assertEqual(r.trust_state, "QUARANTINED")
        self.assertFalse(b.trust.is_usable_for_trusted_decision(r.memory_id))

    def test_causation_creates_causal_link(self):
        b = HydraBrain()
        b.ingest(source_id="edr", payload={"a": 1}, telemetry_id="cause")
        b.ingest(
            source_id="edr", payload={"b": 1}, telemetry_id="effect",
            causation_id="cause",
        )
        chain = [m.memory_id for m in b.memory.causal_chain("cause")]
        self.assertIn("effect", chain)

    def test_scopes_are_isolated(self):
        b = HydraBrain()
        a = b.ingest(source_id="x", payload={"k": 1}, scope_id="t1")
        c = b.ingest(source_id="x", payload={"k": 2}, scope_id="t2")
        self.assertNotEqual(a.state_id, c.state_id)


class InvariantTests(unittest.TestCase):
    def inv(self, iid, key, value, scope="default"):
        return SecurityInvariant(
            invariant_id=iid, scope_id=scope, name=iid, description=iid,
            conditions=(InvariantCondition(
                key=key, condition_type=InvariantConditionType.EQUALS,
                expected_value=value),),
            severity=InvariantSeverity.HIGH,
        )

    def test_posture_invariant_violation_is_reported_on_ingest(self):
        b = HydraBrain()
        b.add_invariant(self.inv("fw-on", "fw", "on"))
        ok = b.ingest(source_id="edr", payload={"fw": "on"})
        bad = b.ingest(source_id="edr", payload={"fw": "off"})
        self.assertEqual(ok.violated_invariants, ())
        self.assertEqual(bad.violated_invariants, ("fw-on",))

    def test_gate_invariant_blocks_response(self):
        b = make_brain()
        b.add_invariant(self.inv("no-freeze", "maintenance", False), gate=True)
        b.ingest(source_id="edr", payload={"maintenance": True})
        rep = b.attack_path("ext", "db")
        result = b.respond(rep, actor_id="soc")
        self.assertEqual(result.status, "BLOCKED_BY_INVARIANT")

    def test_gate_invariant_allows_when_satisfied(self):
        b = make_brain()
        b.add_invariant(self.inv("no-freeze", "maintenance", False), gate=True)
        rep = b.attack_path("ext", "db")
        self.assertEqual(b.respond(rep, actor_id="soc").status, "PLANNED")

    def test_intent_constraints_become_invariants(self):
        b = HydraBrain()
        b.define_intent(
            SecurityIntent(
                intent_id="i1", scope_id="default", name="fw policy",
                objective="Firewall must stay on",
            ),
            constraints=[IntentConstraint(
                constraint_id="c1", intent_id="i1", key="fw",
                constraint_type=ConstraintType.MUST, value="on")],
        )
        result = b.activate_intent("i1")
        self.assertFalse(result.errors)
        bad = b.ingest(source_id="edr", payload={"fw": "off"})
        self.assertEqual(len(bad.violated_invariants), 1)
        self.assertTrue(bad.violated_invariants[0].startswith("inv:i1:"))


class ResponseLoopTests(unittest.TestCase):
    def test_dry_run_stops_at_planned(self):
        b = make_brain()
        r = b.respond(b.attack_path("ext", "db"), actor_id="soc")
        self.assertEqual(r.status, "PLANNED")
        self.assertEqual(r.simulation_status, "SKIPPED")
        self.assertIsNotNone(r.cycle_id)

    def test_simulator_veto_stops_the_action(self):
        b = make_brain()
        called = []
        r = b.respond(
            b.attack_path("ext", "db"), actor_id="soc",
            simulator=lambda c: False,
            executor=lambda c: called.append(1) or {"x": 1},
            expected={"x": 1},
        )
        self.assertEqual(r.status, "SIMULATION_FAILED")
        self.assertEqual(r.simulation_status, "NOT_VIABLE")
        self.assertEqual(called, [])

    def test_simulator_approval_continues(self):
        b = make_brain()
        r = b.respond(
            b.attack_path("ext", "db"), actor_id="soc",
            simulator=lambda c: True,
        )
        self.assertEqual(r.status, "PLANNED")
        self.assertEqual(r.simulation_status, "VIABLE")

    def test_builtin_experiment_simulator_returns_bool(self):
        b = make_brain()
        plan = b.recommend_response(b.attack_path("ext", "db"))
        cand = plan.candidates[plan.selectable_ids[0]]
        self.assertIsInstance(b.experiment_simulator(cand), bool)

    def test_successful_execution_is_verified(self):
        b = make_brain()
        r = b.respond(
            b.attack_path("ext", "db"), actor_id="soc",
            executor=lambda c: {"contained": True},
            expected={"contained": True},
            independent_observer=lambda c: {"contained": True},
        )
        self.assertEqual(r.status, "VERIFIED")
        self.assertEqual(r.replan_decision, "CONTINUE")

    def test_failed_verification_triggers_replan(self):
        b = make_brain()
        r = b.respond(
            b.attack_path("ext", "db"), actor_id="soc",
            executor=lambda c: {"contained": False},
            expected={"contained": True},
            independent_observer=lambda c: {"contained": False},
        )
        self.assertEqual(r.status, "NEEDS_REPLAN")
        self.assertEqual(r.verification_status, "FAILED")

    def test_executor_requires_expected(self):
        b = make_brain()
        with self.assertRaises(ValueError):
            b.respond(
                b.attack_path("ext", "db"), actor_id="soc",
                executor=lambda c: {},
            )

    def test_unknown_actor_is_denied_and_executor_never_called(self):
        b = make_brain()
        called = []
        r = b.respond(
            b.attack_path("ext", "db"), actor_id="ghost",
            executor=lambda c: called.append(1) or {"x": 1},
            expected={"x": 1},
        )
        self.assertEqual(r.status, "DENIED")
        self.assertEqual(called, [])

    def test_actor_without_permission_is_denied(self):
        b = make_brain()
        b.add_authority_node("intern", "agent", "intern")
        b.grant("gi", "intern", "fw", {"monitor"}, edge_type="RESOURCE_ACCESS")
        d = b.authorize("intern", "isolate")
        self.assertFalse(d.allowed)

    def test_authority_drift_blocks_actor(self):
        b = make_brain()
        b.set_authority_baseline(
            "base", allowed_edges={"g1"},
            allowed_permissions={"isolate", "restrict", "monitor"},
        )
        self.assertTrue(b.authorize("soc", "isolate").allowed)
        b.grant("g2", "soc", "fw", {"delete"}, edge_type="RESOURCE_ACCESS")
        d = b.authorize("soc", "isolate")
        self.assertFalse(d.allowed)
        self.assertTrue(any("drift" in r for r in d.reasons))

    def test_no_path_gives_no_candidates(self):
        b = make_brain()
        b.add_asset("island", "server")
        rep = b.attack_path("ext", "island")
        self.assertFalse(rep.found)
        self.assertEqual(
            b.respond(rep, actor_id="soc").status, "NO_CANDIDATE"
        )


class AttributionTests(unittest.TestCase):
    def test_only_trusted_memory_is_used_as_evidence(self):
        b = HydraBrain(BrainConfig(
            mutually_exclusive=(("fw", "on", "fw_disabled", True),)
        ))
        good = b.ingest(source_id="edr", payload={"proc": "powershell"})
        poisoned = b.ingest(
            source_id="edr", payload={"fw": "on", "fw_disabled": True}
        )
        b.register_adversary(
            "APT-X", techniques=["T1059"], infrastructure=["1.2.3.4"]
        )
        rep = b.attribute(
            "APT-X",
            observed_techniques=["T1059", "T9999"],
            observed_infrastructure=["1.2.3.4"],
            evidence_memory_ids=[good.memory_id, poisoned.memory_id],
        )
        self.assertEqual(rep.used_evidence_memory_ids, (good.memory_id,))
        self.assertIn(poisoned.memory_id, rep.excluded_evidence_memory_ids)
        self.assertEqual(len(rep.unmatched_ttps), 1)

    def test_evidence_raises_confidence(self):
        b = HydraBrain()
        mem = b.ingest(source_id="edr", payload={"p": 1}).memory_id
        b.register_adversary("A", techniques=["T1"], infrastructure=["9.9.9.9"])
        without = b.attribute(
            "A", observed_techniques=["T1"], observed_infrastructure=["9.9.9.9"]
        )
        with_ev = b.attribute(
            "A", observed_techniques=["T1"],
            observed_infrastructure=["9.9.9.9"], evidence_memory_ids=[mem],
        )
        self.assertGreater(
            with_ev.assessment.confidence_score,
            without.assessment.confidence_score,
        )


class AuditAndHealthTests(unittest.TestCase):
    def test_audit_chain_is_intact_and_detects_tampering(self):
        b = make_brain()
        b.respond(b.attack_path("ext", "db"), actor_id="soc")
        self.assertEqual(b.audit.verify(), [])
        self.assertGreater(len(b.audit), 5)
        entry = b.audit.entries()[2]
        object.__setattr__(entry, "kind", "tampered")
        self.assertTrue(b.audit.verify())

    def test_all_engines_validate_clean_after_full_flow(self):
        b = make_brain()
        b.respond(
            b.attack_path("ext", "db"), actor_id="soc",
            executor=lambda c: {"ok": True}, expected={"ok": True},
        )
        self.assertTrue(b.healthy(), b.validate_all())


class BridgeTests(unittest.TestCase):
    def test_platform_style_event_dict_is_ingested(self):
        b = HydraBrain()
        bridge = PlatformBridge(b)
        res = bridge.handle_event({
            "event_id": "ev-1", "tenant_id": "acme", "source": "siem",
            "timestamp": now().isoformat().replace("+00:00", "Z"),
            "payload": {"alert": "login"}, "causation_id": None,
        })
        self.assertTrue(res.accepted)
        self.assertEqual(res.scope_id, "acme")

    def test_attribute_style_event_and_bus_subscription(self):
        class Evt:
            event_id = "ev-2"; tenant_id = "acme"; source = "edr"
            timestamp = now().isoformat(); payload = {"k": 1}
            causation_id = None

        class Bus:
            def __init__(self): self.h = {}
            def subscribe(self, t, fn): self.h[t] = fn

        b = HydraBrain()
        bridge = PlatformBridge(b)
        bus = Bus(); bridge.subscribe_to(bus, "*")
        bus.h["*"](Evt())
        self.assertEqual(len(bridge.results), 1)

    def test_bad_event_never_raises(self):
        bridge = PlatformBridge(HydraBrain())
        self.assertIsNone(bridge.handle_event({"payload": "not-a-dict"}))
        self.assertTrue(bridge.errors)


if __name__ == "__main__":
    unittest.main()
