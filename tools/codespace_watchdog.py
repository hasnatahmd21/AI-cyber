"""Keep the Codespaces UI and its resident defence alive while the container runs.

The watchdog never rebaselines or clears incidents. It restarts a crashed UI only
when no persisted incident latch is active; a latched incident suppresses restart
until the secured recovery path clears it after source review.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


def _restart_block_reason(root: Path) -> str | None:
    """Return a fail-closed reason when trust or incident state blocks a UI start."""
    try:
        from ai_cyber_os.layered_defense.supervisor import DefenceSupervisor

        service = DefenceSupervisor(str(root))
        latch_reason = service._persistent_latch_reason()
        if latch_reason:
            return latch_reason
        ok, reason, _checks = service._verify_source_assets()
        if not ok:
            return "signed source integrity is not healthy: " + reason
        return None
    except Exception as exc:
        return f"unable to verify source/incident state ({type(exc).__name__}); fail-closed"


def _terminate(child: subprocess.Popen) -> None:
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def run(root: Path, *, stop_event: threading.Event | None = None) -> int:
    root = root.resolve()
    stop = stop_event or threading.Event()
    previous_handlers: dict[int, object] = {}

    def request_stop(_signum, _frame) -> None:
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, request_stop)
        except ValueError:
            # Unit tests may call run from a worker thread; production starts as main.
            pass

    state_dir = root / ".ai_cyber"
    if state_dir.is_symlink():
        print("Codespaces watchdog refusing symlinked .ai_cyber state.", file=sys.stderr, flush=True)
        return 2

    delay = 1.0
    try:
        while not stop.is_set():
            incident = _restart_block_reason(root)
            if incident:
                print(
                    "Codespaces watchdog: persistent incident is active; UI restart suppressed: "
                    + incident,
                    flush=True,
                )
                if stop.wait(5.0):
                    break
                continue

            command = [sys.executable, "-m", "ai_cyber_os.ui", "--no-browser"]
            print("Codespaces watchdog: starting resident-defence UI.", flush=True)
            started_at = time.monotonic()
            try:
                child = subprocess.Popen(
                    command,
                    cwd=str(root),
                    stdin=subprocess.DEVNULL,
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                )
            except Exception as exc:
                print(
                    f"Codespaces watchdog: UI launch failed ({type(exc).__name__}: {exc}).",
                    file=sys.stderr,
                    flush=True,
                )
                child = None

            if child is not None:
                while not stop.wait(0.5):
                    if child.poll() is not None:
                        break
                if stop.is_set():
                    _terminate(child)
                    break
                exit_code = child.poll()
                uptime = time.monotonic() - started_at
                incident = _restart_block_reason(root)
                if incident:
                    print(
                        "Codespaces watchdog: UI exited with an incident latch present; "
                        "restart suppressed until reviewed recovery: " + incident,
                        flush=True,
                    )
                    continue
                print(
                    f"Codespaces watchdog: UI exited unexpectedly (code={exit_code}, "
                    f"uptime={uptime:.1f}s); retrying after {delay:.0f}s.",
                    flush=True,
                )
                if uptime >= 60.0:
                    delay = 1.0
            if stop.wait(delay):
                break
            delay = min(delay * 2.0, 60.0)
    finally:
        for sig, handler in previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except ValueError:
                pass
    print("Codespaces watchdog stopped.", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        required=True,
        help="AI-CYBER repository root",
    )
    args = parser.parse_args(argv)
    return run(Path(args.root))


if __name__ == "__main__":
    raise SystemExit(main())
