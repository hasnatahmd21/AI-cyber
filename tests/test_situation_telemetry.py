"""Contract tests for the evidence-first runtime telemetry/event stream."""
from __future__ import annotations

from ai_cyber_os import telemetry


def setup_function() -> None:
    telemetry.reset()


def teardown_function() -> None:
    telemetry.reset()


def test_begin_and_complete_emit_monotonic_events_and_close_run() -> None:
    started = telemetry.begin("dataset-ingest", phase="stage-6")
    completed = telemetry.complete(
        "dataset-ingest",
        success=True,
        phase="stage-6",
        evidence={"records_ingested": 3, "verified": True},
    )

    assert started["id"] == 1
    assert started["type"] == "operation_started"
    assert started["status"] == "RUNNING"
    assert completed["id"] == 2
    assert completed["type"] == "operation_completed"
    assert completed["status"] == "PASS"

    state = telemetry.snapshot()
    assert state["next_id"] == 2
    assert [event["id"] for event in state["events"]] == [1, 2]
    assert state["run"]["active"] is False
    assert state["run"]["status"] == "PASS"
    assert state["events"][1]["evidence"] == {"records_ingested": 3, "verified": True}


def test_failure_and_error_are_distinguishable() -> None:
    failed = telemetry.complete(
        "evaluation", success=False, message="evaluation did not meet threshold"
    )
    errored = telemetry.error(
        "evaluation", "fixture failure", details={"error_type": "RuntimeError"}
    )

    assert failed["status"] == "FAIL"
    assert failed["type"] == "operation_completed"
    assert errored["status"] == "ERROR"
    assert errored["type"] == "operation_error"
    assert errored["details"] == {"error_type": "RuntimeError"}
    assert telemetry.snapshot()["run"]["active"] is False
    assert telemetry.snapshot()["run"]["status"] == "ERROR"


def test_snapshot_cursor_and_limit_return_only_newest_matching_events() -> None:
    for index in range(5):
        telemetry.emit("fixture_event", f"event {index}", status="INFO")

    page = telemetry.snapshot(since=2, limit=2)
    assert [event["id"] for event in page["events"]] == [4, 5]
    assert page["next_id"] == 5


def test_event_payload_is_copied_at_top_level_and_defaults_details() -> None:
    details = {"source": "fixture"}
    event = telemetry.emit("fixture_event", "observed", details=details)
    details["source"] = "mutated"

    assert event["details"] == {"source": "fixture"}
    assert event["id"] == 1
    assert event["source"] == "runtime"
    assert event["status"] == "INFO"


def test_event_history_is_bounded_and_ids_remain_monotonic() -> None:
    for index in range(505):
        telemetry.emit("fixture_event", f"event {index}")

    state = telemetry.snapshot(limit=500)
    assert len(state["events"]) == 500
    assert state["events"][0]["id"] == 6
    assert state["events"][-1]["id"] == 505
    assert state["next_id"] == 505
