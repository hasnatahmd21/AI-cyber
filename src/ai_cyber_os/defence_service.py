"""Headless resident service for continuous AI-Cyber / IT-Tech defence monitoring."""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from .layered_defense.supervisor import DefenceSupervisor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the resident AI-Cyber / IT-Tech defensive monitor."
    )
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[2]),
        help="AI-Cyber repository/worktree root (must have reviewed signed baselines).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Integrity and engine health polling interval in seconds (0.25-60).",
    )
    args = parser.parse_args(argv)

    stop_event = threading.Event()
    previous_handlers: dict[int, object] = {}

    def request_stop(signum, frame) -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[sig] = signal.getsignal(sig)
        signal.signal(sig, request_stop)

    supervisor = DefenceSupervisor(args.root, interval_s=args.interval)
    try:
        supervisor.start()
    except Exception as exc:
        print(
            json.dumps({
                "service": "ai-cyber-defence-supervisor",
                "active": False,
                "ready": False,
                "status": "blocked",
                "error": f"{type(exc).__name__}: {exc}",
            }, sort_keys=True),
            file=sys.stderr,
        )
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
        return 2

    last_status = None
    try:
        print(json.dumps(supervisor.snapshot(), sort_keys=True), flush=True)
        while not stop_event.wait(1.0):
            current = supervisor.snapshot()
            summary = (
                current.get("status"),
                current.get("ready"),
                current.get("reason"),
                current.get("last_check_at"),
            )
            if summary[:3] != last_status:
                print(json.dumps(current, sort_keys=True), flush=True)
                last_status = summary[:3]
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        supervisor.stop()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)

    print(json.dumps(supervisor.snapshot(), sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
