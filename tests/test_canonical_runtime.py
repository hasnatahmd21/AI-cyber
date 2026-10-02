from datetime import datetime, timezone


def test_canonical_hydra_import_and_clock():
    from ai_cyber_os.hydra import FrozenClock, SubjectId

    now = datetime.now(timezone.utc)
    clock = FrozenClock(now)
    assert clock.now() == now
    assert isinstance(SubjectId("subject-1"), SubjectId)
