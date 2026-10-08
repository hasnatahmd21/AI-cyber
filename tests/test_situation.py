from pathlib import Path
import json, sqlite3, pytest
from ai_cyber_os.situation import SituationError,SituationStore,TelemetryEvent

def ev(**x):
    p={"event_type":"authentication","observed_at":"2026-10-08T10:00:00Z","source":"sensor-a","external_id":"auth-1","severity":"HIGH","subject_type":"asset","subject_id":"host-1","action":"login","outcome":"failure","evidence_refs":["sensor-a:auth-1"],"related_record_ids":["r-1"],"payload":{"ip":"10.0.0.1"}}
    p.update(x); return TelemetryEvent(**p)

def test_identity_and_utc():
    assert ev(observed_at="2026-10-08T12:00:00+02:00").event_id==ev(observed_at="2026-10-08T10:00:00Z").event_id
    assert ev().observed_at=="2026-10-08T10:00:00.000000Z"

def test_validation():
    with pytest.raises(SituationError): ev(observed_at="2026-10-08T10:00:00")
    with pytest.raises(SituationError): ev(severity="urgent")
    with pytest.raises(SituationError): ev(payload={"x":float("nan")})

def test_idempotent_and_query(tmp_path):
    s=SituationStore(tmp_path/"s.sqlite"); e=ev(); s.ingest(e); s.ingest(e)
    assert s.count()==1 and s.query(subject_type="asset",subject_id="host-1",limit=1)[0]["event_id"]==e.event_id

def test_batch_atomic(tmp_path):
    s=SituationStore(tmp_path/"s.sqlite"); good=ev()
    with pytest.raises(SituationError): s.ingest_many([good,ev(event_id="bad",payload={"x":float("nan")})])
    assert s.count()==0

def test_payload_is_data(tmp_path):
    s=SituationStore(tmp_path/"s.sqlite"); e=ev(payload={"value":"quoted input; table name text"})
    s.ingest(e); assert s.count()==1 and s.get(e.event_id)["payload"]["value"].startswith("quoted")

def test_correlation_and_snapshot(tmp_path):
    s=SituationStore(tmp_path/"s.sqlite"); s.ingest(ev()); s.ingest(ev(external_id="auth-2",observed_at="2026-10-08T10:02:00Z",severity="CRITICAL")); s.ingest(ev(external_id="proc-1",event_type="process",observed_at="2026-10-08T10:03:00Z",severity="MEDIUM"))
    assert len(s.correlate(s.query(subject_id="host-1",limit=1)[0]["event_id"],window_seconds=180))==2
    snap=s.situation(subject_type="asset",subject_id="host-1",start="2026-10-08T09:59:00Z",end="2026-10-08T10:05:00Z")
    assert snap["event_count"]==3 and snap["severity_counts"]["CRITICAL"]==1 and snap["evidence_only"]

def test_tamper_detection(tmp_path):
    s=SituationStore(tmp_path/"s.sqlite"); e=ev(); s.ingest(e)
    with sqlite3.connect(tmp_path/"s.sqlite") as db: db.execute("UPDATE situation_events SET payload_json=?",(json.dumps({"changed":True}),))
    assert s.verify_integrity()["ok"] is False

def test_health(tmp_path):
    assert SituationStore(tmp_path/"s.sqlite").health()["ok"] is True
