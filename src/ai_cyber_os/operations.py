"""Persistent local operational test/report state for AI-CYBER OS."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_DIR = Path(
    os.environ.get("AI_CYBER_REPORT_DIR", str(Path.home() / ".ai-cyber" / "reports"))
)
LATEST = REPORT_DIR / "latest.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_report(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "kind": kind,
        "timestamp": _now(),
        **payload,
    }
    fd, tmp = tempfile.mkstemp(prefix=".report-", suffix=".json", dir=REPORT_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
        os.replace(tmp, LATEST)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return report


def load_report() -> dict[str, Any] | None:
    try:
        return json.loads(LATEST.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def run_regression(project_root: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests"],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=600,
    )
    output = (completed.stdout + "\n" + completed.stderr).strip()
    return {
        "success": completed.returncode == 0,
        "returncode": completed.returncode,
        "output": output[-12000:],
    }
