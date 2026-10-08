"""Local-first situation, telemetry, and event layer for AI-CYBER."""
from __future__ import annotations
import hashlib, json, sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION="situation_telemetry.v1"
EVENT_TYPES=("authentication","authorization","network","process","file","dns","http","endpoint","cloud","application","alert","custom")
SEVERITIES=("UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL")
SUBJECT_TYPES=("asset","user","process","ip","domain","account","service","session","other")
MAX_PAYLOAD_BYTES=64000
MAX_QUERY_LIMIT=5000

class SituationError(ValueError): pass

def _text(v:Any, field:str, required=False, max_len=4096):
    if v is None:
        if required: raise SituationError(f"{field} is required")
        return None
    if not isinstance(v,str): raise SituationError(f"{field} must be a string")
    v=v.strip()
    if "\x00" in v: raise SituationError(f"{field} contains NUL byte")
    if required and not v: raise SituationError(f"{field} is required")
    if len(v)>max_len: raise SituationError(f"{field} exceeds maximum length {max_len}")
    return v or None

def _list(v,field,limit):
    if v is None:return ()
    if not isinstance(v,(list,tuple)): raise SituationError(f"{field} must be a list")
    if len(v)>limit: raise SituationError(f"{field} exceeds maximum item count {limit}")
    out=tuple(_text(x,field,True,4096) for x in v)
    if len(set(out))!=len(out): raise SituationError(f"{field} contains duplicates")
    return out

def _json(v:Mapping[str,Any]):
    try: s=json.dumps(dict(v),ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False)
    except (TypeError,ValueError) as e: raise SituationError("payload must be finite JSON") from e
    if len(s.encode())>MAX_PAYLOAD_BYTES: raise SituationError("payload exceeds maximum size")
    return s

def _utc(v):
    if not isinstance(v,str): raise SituationError("observed_at must be an ISO-8601 string")
    try: dt=datetime.fromisoformat(v.strip().replace("Z","+00:00"))
    except ValueError as e: raise SituationError("observed_at must be valid ISO-8601") from e
    if dt.tzinfo is None: raise SituationError("observed_at must include timezone")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")

@dataclass(frozen=True)
class TelemetryEvent:
    event_type:str; observed_at:str; source:str; payload:Mapping[str,Any]
    event_id:str|None=None; external_id:str|None=None; severity:str="UNKNOWN"
    subject_type:str|None=None; subject_id:str|None=None; action:str|None=None; outcome:str|None=None
    evidence_refs:tuple[str,...]=(); related_record_ids:tuple[str,...]=()

    def __post_init__(self):
        et=_text(self.event_type,"event_type",True,64).lower()
        if et not in EVENT_TYPES: raise SituationError(f"unsupported event_type: {et}")
        src=_text(self.source,"source",True,256); obs=_utc(self.observed_at)
        sev=_text(self.severity,"severity",True,16).upper()
        if sev not in SEVERITIES: raise SituationError(f"unsupported severity: {sev}")
        st=_text(self.subject_type,"subject_type",max_len=32)
        if st is not None and st not in SUBJECT_TYPES: raise SituationError(f"unsupported subject_type: {st}")
        sid=_text(self.subject_id,"subject_id",max_len=512); ext=_text(self.external_id,"external_id",max_len=512)
        action=_text(self.action,"action",max_len=256); outcome=_text(self.outcome,"outcome",max_len=256)
        refs=_list(self.evidence_refs,"evidence_refs",64); rel=_list(self.related_record_ids,"related_record_ids",64)
        payload=dict(self.payload); pj=_json(payload)
        eid=_text(self.event_id,"event_id",True,128) if self.event_id is not None else self.deterministic_id(et,obs,src,ext,pj)
        for k,v in {"event_type":et,"observed_at":obs,"source":src,"severity":sev,"subject_type":st,"subject_id":sid,"external_id":ext,"action":action,"outcome":outcome,"evidence_refs":refs,"related_record_ids":rel,"payload":payload,"event_id":eid}.items(): object.__setattr__(self,k,v)

    @staticmethod
    def deterministic_id(event_type,observed_at,source,external_id,payload_json):
        return "evt-"+hashlib.sha256("\x00".join((event_type,observed_at,source,external_id or "",payload_json)).encode()).hexdigest()

    @property
    def payload_json(self): return _json(self.payload)
    @property
    def content_hash(self):
        c={"event_id":self.event_id,"event_type":self.event_type,"observed_at":self.observed_at,"source":self.source,"external_id":self.external_id,"severity":self.severity,"subject_type":self.subject_type,"subject_id":self.subject_id,"action":self.action,"outcome":self.outcome,"evidence_refs":list(self.evidence_refs),"related_record_ids":list(self.related_record_ids),"payload":self.payload}
        return hashlib.sha256(_json(c).encode()).hexdigest()
    def as_dict(self):
        return {k:getattr(self,k) for k in ("event_id","event_type","observed_at","source","external_id","severity","subject_type","subject_id","action","outcome","evidence_refs","related_record_ids","payload")}|{"content_hash":self.content_hash,"schema_version":SCHEMA_VERSION}

class SituationStore:
    SCHEMA_VERSION=SCHEMA_VERSION
    def __init__(self,db_path):
        self.db_path=Path(db_path); self.db_path.parent.mkdir(parents=True,exist_ok=True); self._init()
    def _connect(self):
        db=sqlite3.connect(self.db_path,timeout=10); db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA busy_timeout=5000"); return db
    def _init(self):
        with self._connect() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS situation_events(event_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,observed_at TEXT NOT NULL,source TEXT NOT NULL,external_id TEXT,severity TEXT NOT NULL,subject_type TEXT,subject_id TEXT,action TEXT,outcome TEXT,evidence_refs_json TEXT NOT NULL,related_record_ids_json TEXT NOT NULL,payload_json TEXT NOT NULL,content_hash TEXT NOT NULL,schema_version TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_situation_time ON situation_events(observed_at);
            CREATE INDEX IF NOT EXISTS idx_situation_subject ON situation_events(subject_type,subject_id,observed_at);
            CREATE INDEX IF NOT EXISTS idx_situation_type ON situation_events(event_type,observed_at);
            CREATE TABLE IF NOT EXISTS situation_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);""")
            db.execute("INSERT OR REPLACE INTO situation_meta(key,value) VALUES('schema_version',?)",(SCHEMA_VERSION,))
    def _write(self,db,e):
        cursor = db.execute(
            """INSERT INTO situation_events(
                event_id,event_type,observed_at,source,external_id,severity,
                subject_type,subject_id,action,outcome,evidence_refs_json,
                related_record_ids_json,payload_json,content_hash,schema_version
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(event_id) DO NOTHING""",
            (
                e.event_id,e.event_type,e.observed_at,e.source,e.external_id,e.severity,
                e.subject_type,e.subject_id,e.action,e.outcome,
                json.dumps(list(e.evidence_refs)),json.dumps(list(e.related_record_ids)),
                e.payload_json,e.content_hash,SCHEMA_VERSION,
            ),
        )
        if cursor.rowcount == 0:
            existing=db.execute(
                "SELECT content_hash FROM situation_events WHERE event_id=?",
                (e.event_id,),
            ).fetchone()
            if existing is None:
                raise SituationError(f"event write lost without an existing record: {e.event_id}")
            if existing[0] != e.content_hash:
                raise SituationError(
                    f"event_id collision with different content: {e.event_id}"
                )
            return False
        return True

    def ingest(self,event):
        if not isinstance(event,TelemetryEvent): raise SituationError("event must be TelemetryEvent")
        with self._connect() as db:self._write(db,event)
        return event.event_id
    def ingest_many(self,events):
        batch=list(events)
        if any(not isinstance(e,TelemetryEvent) for e in batch): raise SituationError("all events must be TelemetryEvent instances")
        with self._connect() as db:
            try:
                db.execute("BEGIN")
                ingested=0
                for e in batch:
                    ingested += int(self._write(db,e))
                db.commit()
            except Exception: db.rollback(); raise
        return {"ingested":ingested,"event_count":self.count()}
    def _row(self,row):
        e=TelemetryEvent(event_id=row[0],event_type=row[1],observed_at=row[2],source=row[3],external_id=row[4],severity=row[5],subject_type=row[6],subject_id=row[7],action=row[8],outcome=row[9],evidence_refs=tuple(json.loads(row[10])),related_record_ids=tuple(json.loads(row[11])),payload=json.loads(row[12]))
        if e.content_hash!=row[13]: raise SituationError(f"event content hash mismatch: {e.event_id}")
        return e.as_dict()
    def get(self,event_id):
        eid=_text(event_id,"event_id",True,128)
        with self._connect() as db: row=db.execute("SELECT event_id,event_type,observed_at,source,external_id,severity,subject_type,subject_id,action,outcome,evidence_refs_json,related_record_ids_json,payload_json,content_hash FROM situation_events WHERE event_id=?",(eid,)).fetchone()
        return None if row is None else self._row(row)
    def query(self,*,start=None,end=None,subject_type=None,subject_id=None,event_types=None,severities=None,source=None,limit=100):
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=5000: raise SituationError("limit must be between 1 and 5000")
        start=_utc(start) if start else None; end=_utc(end) if end else None
        if start and end and start>end: raise SituationError("start must be <= end")
        st=_text(subject_type,"subject_type",max_len=32); sid=_text(subject_id,"subject_id",max_len=512); src=_text(source,"source",max_len=256)
        if st and st not in SUBJECT_TYPES: raise SituationError(f"unsupported subject_type: {st}")
        types=tuple(_text(x,"event_type",True,64).lower() for x in (event_types or ())); levels=tuple(_text(x,"severity",True,16).upper() for x in (severities or ()))
        if any(x not in EVENT_TYPES for x in types) or any(x not in SEVERITIES for x in levels): raise SituationError("unsupported filter value")
        clauses=[]; params=[]
        if start:
            clauses.append("observed_at >= ?")
            params.append(start)
        if end:
            clauses.append("observed_at <= ?")
            params.append(end)
        for col,val in (("subject_type",st),("subject_id",sid),("source",src)):
            if val:
                clauses.append(col+" = ?")
                params.append(val)
        if types: clauses.append("event_type IN ("+",".join("?" for _ in types)+")"); params.extend(types)
        if levels: clauses.append("severity IN ("+",".join("?" for _ in levels)+")"); params.extend(levels)
        where=" WHERE "+" AND ".join(clauses) if clauses else ""
        params.append(limit)
        sql="SELECT event_id,event_type,observed_at,source,external_id,severity,subject_type,subject_id,action,outcome,evidence_refs_json,related_record_ids_json,payload_json,content_hash FROM situation_events"+where+" ORDER BY observed_at DESC,event_id ASC LIMIT ?"
        with self._connect() as db: rows=db.execute(sql,params).fetchall()
        return [self._row(r) for r in rows]
    def correlate(self,event_id,*,window_seconds=300,limit=100):
        if isinstance(window_seconds,bool) or not isinstance(window_seconds,int) or not 0<=window_seconds<=86400: raise SituationError("window_seconds must be between 0 and 86400")
        e=self.get(event_id)
        if e is None:return []
        if not e["subject_id"]:return [e]
        center=datetime.fromisoformat(e["observed_at"].replace("Z","+00:00"))
        a=(center-timedelta(seconds=window_seconds)).isoformat(timespec="microseconds").replace("+00:00","Z"); b=(center+timedelta(seconds=window_seconds)).isoformat(timespec="microseconds").replace("+00:00","Z")
        return self.query(start=a,end=b,subject_type=e["subject_type"],subject_id=e["subject_id"],limit=limit)
    def situation(self,*,subject_type,subject_id,start,end,limit=500):
        events=self.query(start=start,end=end,subject_type=subject_type,subject_id=subject_id,limit=limit)
        counts={s:0 for s in SEVERITIES}; types={}; sources={}
        for e in events:
            counts[e["severity"]]+=1; types[e["event_type"]]=types.get(e["event_type"],0)+1; sources[e["source"]]=sources.get(e["source"],0)+1
        return {"schema_version":SCHEMA_VERSION,"subject_type":subject_type,"subject_id":subject_id,"window":{"start":_utc(start),"end":_utc(end)},"event_count":len(events),"severity_counts":counts,"event_type_counts":dict(sorted(types.items())),"source_counts":dict(sorted(sources.items())),"latest_event_at":max((e["observed_at"] for e in events),default=None),"events":events,"evidence_only":True}
    def count(self):
        with self._connect() as db:return int(db.execute("SELECT count(*) FROM situation_events").fetchone()[0])
    def verify_integrity(self):
        errors=[]
        with self._connect() as db:
            rows=db.execute("SELECT event_id,event_type,observed_at,source,external_id,severity,subject_type,subject_id,action,outcome,evidence_refs_json,related_record_ids_json,payload_json,content_hash,schema_version FROM situation_events ORDER BY event_id").fetchall()
            meta=db.execute("SELECT value FROM situation_meta WHERE key='schema_version'").fetchone()
        if not meta or meta[0]!=SCHEMA_VERSION: errors.append("schema version mismatch")
        for row in rows:
            try:
                if row[14]!=SCHEMA_VERSION: raise SituationError("stored schema version mismatch")
                self._row(row[:14])
            except Exception as exc: errors.append(f"{row[0]}: {exc}")
        return {"ok":not errors,"schema_version":SCHEMA_VERSION,"event_count":len(rows),"errors":errors}
    def health(self):
        r=self.verify_integrity(); return {"ok":r["ok"],"schema_version":SCHEMA_VERSION,"event_count":r["event_count"],"errors":r["errors"]}

__all__=["EVENT_TYPES","SEVERITIES","SUBJECT_TYPES","SCHEMA_VERSION","SituationError","TelemetryEvent","SituationStore"]
