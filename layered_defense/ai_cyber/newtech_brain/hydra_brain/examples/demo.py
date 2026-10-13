"""End-to-end demo:  python -m hydra_brain.examples.demo  (from repo root)"""

from __future__ import annotations

from hydra_brain import BrainConfig, HydraBrain


def main() -> None:
    brain = HydraBrain(BrainConfig(
        mutually_exclusive=(("fw", "on", "fw_disabled", True),),
    ))

    # 1. telemetry: good, replayed, and contradictory (poisoned) data
    good = brain.ingest(source_id="edr", payload={"fw": "on", "host": "web"})
    dup = brain.ingest(source_id="edr", payload={"fw": "off"},
                       telemetry_id=good.telemetry_id)
    bad = brain.ingest(source_id="edr",
                       payload={"fw": "on", "fw_disabled": True})
    print("good :", good.integrity_status, good.trust_state)
    print("dup  :", dup.deduplicated, dup.issues)
    print("bad  :", bad.integrity_status, bad.trust_state, bad.issues)

    # 2. topology + attack path
    brain.add_asset("internet", "external")
    brain.add_asset("web", "server")
    brain.add_asset("db", "database")
    brain.link_assets("internet", "web", "connects_to", weight=0.9)
    brain.link_assets("web", "db", "accesses", weight=0.8)
    path = brain.attack_path("internet", "db")
    print("path :", path.path.status.name,
          [p.node_id for p in path.intervention_points])

    # 3. who may act?
    brain.add_authority_node("soc", "agent", "soc-agent")
    brain.add_authority_node("fw", "resource", "firewall")
    brain.grant("g1", "soc", "fw", {"isolate", "restrict", "monitor"},
                edge_type="RESOURCE_ACCESS")

    # 4. respond (your executor does the real work; here it is simulated)
    result = brain.respond(
        path, actor_id="soc",
        executor=lambda cand: {"contained": True},
        expected={"contained": True},
        independent_observer=lambda cand: {"contained": True},
    )
    print("resp :", result.status, result.intervention, "->",
          result.target_id, "| verify:", result.verification_status)

    # 5. attribution: poisoned memory is excluded automatically
    brain.register_adversary("APT-X", techniques=["T1059"],
                             infrastructure=["203.0.113.7"])
    attr = brain.attribute(
        "APT-X", observed_techniques=["T1059"],
        observed_infrastructure=["203.0.113.7"],
        evidence_memory_ids=[good.memory_id, bad.memory_id],
    )
    print("attr :", attr.assessment.confidence_level.name,
          "used", len(attr.used_evidence_memory_ids),
          "excluded", dict(attr.excluded_evidence_memory_ids))

    print("audit:", len(brain.audit), "entries, intact =",
          not brain.audit.verify(), "| healthy =", brain.healthy())


if __name__ == "__main__":
    main()
