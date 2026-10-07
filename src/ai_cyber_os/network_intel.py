"""Safe normalization helpers for network-security telemetry.

Only structured telemetry/features are handled. This module does not capture
traffic, scan hosts, or perform live network operations.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .knowledge import _normalize


def parse_suricata_eve(path: str | Path, *, dataset: str = "suricata-eve",
                        source: str = "Suricata EVE", version: str = "",
                        source_uri: str = "", license: str = "",
                        validation_status: str = "unverified") -> list[dict[str, Any]]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        event_id = event.get("flow_id") or event.get("event_type") or f"event-{len(out)+1}"
        out.append(_normalize({"id": str(event_id), "event_type": event.get("event_type"),
                               "timestamp": event.get("timestamp"), "src_ip": event.get("src_ip"),
                               "dest_ip": event.get("dest_ip"), "src_port": event.get("src_port"),
                               "dest_port": event.get("dest_port"), "proto": event.get("proto"),
                               "alert": event.get("alert"), "app_proto": event.get("app_proto"),
                               "flow": event.get("flow")},
                              dataset=dataset, source=source, version=version,
                              source_uri=source_uri, license=license,
                              validation_status=validation_status))
    return out


def parse_zeek_json(path: str | Path, *, dataset: str = "zeek",
                    source: str = "Zeek", version: str = "",
                    source_uri: str = "", license: str = "",
                    validation_status: str = "unverified") -> list[dict[str, Any]]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        uid = event.get("uid") or f"event-{len(out)+1}"
        out.append(_normalize({**event, "id": str(uid)},
                              dataset=dataset, source=source, version=version,
                              source_uri=source_uri, license=license,
                              validation_status=validation_status))
    return out
