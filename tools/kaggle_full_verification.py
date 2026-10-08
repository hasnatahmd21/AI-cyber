#!/usr/bin/env python3
"""Fresh-session AI-CYBER verification runner.

Designed for Kaggle/clean Linux sessions. It recreates the checkout, installs
the package, runs the full test suite, forensic inventory, canonical HYDRA
verification, and a real localhost UI/API smoke test. Large Git-LFS objects are
not downloaded because this verifier validates runtime/code wiring separately
from dataset acquisition.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path("/kaggle/working/AI-cyber")
REPO = os.environ.get("AI_CYBER_REPO", "hasnatahmd21/AI-cyber")
BRANCH = os.environ.get("AI_CYBER_BRANCH", "repair/forensic-reconstruction")
PORT = int(os.environ.get("AI_CYBER_UI_PORT", "8765"))


def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


def fetch(url: str, method: str = "GET", payload: bytes | None = None) -> dict:
    req = urllib.request.Request(
        url,
        method=method,
        data=payload,
        headers={"Content-Type": "application/json"} if payload else {},
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    print("=" * 88)
    print("AI-CYBER — FRESH SESSION FULL VERIFICATION")
    print("=" * 88)

    if ROOT.exists():
        shutil.rmtree(ROOT)

    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    run("git", "clone", "--branch", BRANCH, "--single-branch", f"https://github.com/{REPO}.git", str(ROOT), env=env)
    run(sys.executable, "-m", "pip", "install", "-q", "-e", ".", cwd=ROOT)
    run(sys.executable, "-m", "pip", "install", "-q", "pytest", cwd=ROOT)

    run(sys.executable, "-m", "compileall", "-q", "src", "tests", cwd=ROOT)
    run("pytest", "-q", "tests", cwd=ROOT)
    run(sys.executable, "tools/forensic_inventory.py", cwd=ROOT)

    # Phase 13 deterministic security evaluation: local-only fixtures plus
    # intentional evidence tamper detection. No external cyber target is used.
    run(sys.executable, "tools/phase13_security_evaluation_test.py", cwd=ROOT)
    run(sys.executable, "tools/end_to_end_dataset_test.py", cwd=ROOT)

    # Canonical runtime verification.
    code = (
        "from ai_cyber_os.hydra import run_hydra_phase; "
        "r=run_hydra_phase('all'); "
        "print(r); "
        "assert isinstance(r,dict) and r.get('summary',{}).get('success') is True"
    )
    run(sys.executable, "-c", code, cwd=ROOT)

    # Real localhost UI/API smoke test.
    server = subprocess.Popen(
        [sys.executable, "-m", "ai_cyber_os.ui", "--host", "127.0.0.1",
         "--port", str(PORT), "--no-browser"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        base = f"http://127.0.0.1:{PORT}"
        last_error = None
        for _ in range(40):
            try:
                status = fetch(base + "/api/status")
                last_error = None
                break
            except Exception as exc:
                last_error = exc
                time.sleep(0.5)
        if last_error is not None:
            raise RuntimeError(f"UI did not start: {last_error}")

        situation = fetch(base + "/api/situation")
        events = fetch(base + "/api/events")
        command = fetch(
            base + "/api/command",
            method="POST",
            payload=json.dumps({"command": "status"}).encode(),
        )
        assert status.get("success") is True
        assert "live" in status
        assert "run" in events
        assert situation.get("runtime") == "online"
        assert command.get("success") is True

        run_result = fetch(
            base + "/api/command",
            method="POST",
            payload=json.dumps({"command": "run phase 1"}).encode(),
        )
        assert "result" in run_result
        assert isinstance(run_result["result"], dict)
        assert "success" in run_result["result"]
        live_after = fetch(base + "/api/events")
        assert len(live_after.get("events", [])) >= len(events.get("events", []))
        print("UI/API + command execution smoke: PASS")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    print("=" * 88)
    print("AI-CYBER FULL VERIFICATION: PASS")
    print("=" * 88)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
