"""Start the localhost AI-CYBER UI with its resident defence in Codespaces.

This helper never creates or re-signs trust baselines. It starts the UI only when
both reviewed signed baseline files exist; the UI then cryptographically verifies
them and refuses service on an invalid baseline or a persistent incident latch.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

PORT = 8765
HEALTH_URL = f"http://127.0.0.1:{PORT}/api/defence"


def _process_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _is_codespace_watchdog_process(pid: int) -> bool:
    """Only adopt a PID when the Linux command line identifies our watchdog."""
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(
            "utf-8", errors="replace"
        )
    except (OSError, ValueError):
        return False
    return "tools/codespace_watchdog.py" in command and "--root" in command


def _read_health(timeout: float = 1.0) -> dict | None:
    try:
        with urlopen(HEALTH_URL, timeout=timeout) as response:
            if response.status != 200:
                return None
            value = json.loads(response.read().decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return None


def _port_is_open() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(0.25)
        return client.connect_ex(("127.0.0.1", PORT)) == 0


def _write_pid(pid_path: Path, pid: int) -> None:
    temporary = pid_path.with_name(pid_path.name + ".tmp")
    if pid_path.is_symlink() or temporary.is_symlink():
        raise RuntimeError("refusing symlinked Codespaces UI PID file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = os.open(temporary, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("refusing non-regular or hard-linked Codespaces PID temporary")
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            fd = None
            stream.write(f"{pid}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, pid_path)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_fd = os.open(pid_path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _remove_pid(pid_path: Path) -> None:
    if pid_path.is_symlink():
        raise RuntimeError("refusing symlinked Codespaces UI PID file")
    try:
        pid_path.unlink()
    except FileNotFoundError:
        pass


def _start_unlocked(root: Path, *, startup_timeout: float = 20.0) -> int:
    root = root.resolve()
    state_dir = root / ".ai_cyber"
    pid_path = state_dir / "codespace-ui.pid"
    log_path = state_dir / "codespace-ui.log"

    if state_dir.is_symlink():
        print("AI-CYBER Codespaces startup refused: .ai_cyber is a symlink.", file=sys.stderr)
        return 2
    for baseline in ("hydra_baseline.json", "it_tech_baseline.json"):
        path = state_dir / baseline
        if path.is_symlink() or not path.is_file():
            print(
                "AI-CYBER defence NOT started: reviewed signed source baselines are missing "
                "or unsafe. Review the checked-out commit, then run "
                "'python -m ai_cyber_os --defence-rebaseline --phase phase1 --json' "
                "once from a clean checkout. This script will not auto-trust/rebaseline source.",
                file=sys.stderr,
            )
            return 2

    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if pid_path.is_symlink():
        print("AI-CYBER Codespaces startup refused: PID file is a symlink.", file=sys.stderr)
        return 2

    if pid_path.exists():
        try:
            raw_pid = pid_path.read_text(encoding="ascii").strip()
            pid = int(raw_pid)
        except (OSError, ValueError):
            print(
                "AI-CYBER Codespaces startup refused: PID file is unreadable; inspect it "
                "and the service log before removing it.",
                file=sys.stderr,
            )
            return 2
        if _process_exists(pid):
            if not _is_codespace_watchdog_process(pid):
                print(
                    f"AI-CYBER Codespaces startup refused: PID file points to unrelated "
                    f"or unverifiable process {pid}; no process was stopped.",
                    file=sys.stderr,
                )
                return 2
            status = _read_health()
            if status and status.get("active") is True and status.get("ready") is True and status.get("status") == "healthy":
                print(json.dumps({"started": False, "already_running": True, "defence": status}, sort_keys=True))
                return 0
            print(
                "AI-CYBER watchdog is already running but the UI defence endpoint is not healthy. "
                "The watchdog will retry only when restart is permitted; inspect "
                ".ai_cyber/codespace-ui.log and the persistent incident latch.",
                file=sys.stderr,
            )
            return 3
        _remove_pid(pid_path)

    if _port_is_open():
        print(
            f"AI-CYBER Codespaces startup refused: localhost port {PORT} is occupied but "
            "there is no verified managed UI process. No process was stopped.",
            file=sys.stderr,
        )
        return 2

    command = [sys.executable, "tools/codespace_watchdog.py", "--root", str(root)]
    process: subprocess.Popen | None = None
    try:
        with log_path.open("a", encoding="utf-8") as log:
            process = subprocess.Popen(
                command,
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        _write_pid(pid_path, process.pid)
    except Exception as exc:
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        print(f"AI-CYBER Codespaces startup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    deadline = time.monotonic() + max(1.0, startup_timeout)
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            _remove_pid(pid_path)
            print(
                f"AI-CYBER UI exited during startup (code {exit_code}); inspect "
                f"{log_path}. No bypass/rebaseline was attempted.",
                file=sys.stderr,
            )
            return 3
        status = _read_health()
        if status is not None:
            if status.get("active") is True and status.get("ready") is True and status.get("status") == "healthy":
                print(json.dumps({
                    "started": True,
                    "pid": process.pid,
                    "url": "http://127.0.0.1:8765",
                    "defence": status,
                }, sort_keys=True))
                return 0
            if status.get("status") == "blocked" or status.get("ready") is False:
                print(
                    "AI-CYBER UI responded but defence is not healthy; execution remains fail-closed. "
                    f"Inspect {log_path} and the persistent incident latch.",
                    file=sys.stderr,
                )
                return 3
        time.sleep(0.25)

    # Keep the watchdog resident even when first readiness is delayed. It retries
    # with backoff when startup is transiently broken and suppresses restart while
    # a persistent incident latch remains active.
    if process.poll() is not None:
        _remove_pid(pid_path)
    print(
        f"AI-CYBER defence readiness was not confirmed within {startup_timeout:g}s; "
        f"the watchdog remains resident and will retry safely. Inspect {log_path}.",
        file=sys.stderr,
    )
    return 3



def start(root: Path, *, startup_timeout: float = 20.0) -> int:
    """Serialize lifecycle invocations so two starts cannot spawn competing watchdogs."""
    root = root.resolve()
    state_dir = root / ".ai_cyber"
    if state_dir.is_symlink():
        print("AI-CYBER Codespaces startup refused: .ai_cyber is a symlink.", file=sys.stderr)
        return 2
    for baseline in ("hydra_baseline.json", "it_tech_baseline.json"):
        path = state_dir / baseline
        if path.is_symlink() or not path.is_file():
            print(
                "AI-CYBER defence NOT started: reviewed signed source baselines are missing "
                "or unsafe. Review the checked-out commit, then run "
                "'python -m ai_cyber_os --defence-rebaseline --phase phase1 --json' "
                "once from a clean checkout. This script will not auto-trust/rebaseline source.",
                file=sys.stderr,
            )
            return 2

    lock_path = state_dir / "codespace-ui.start.lock"
    if lock_path.is_symlink():
        print("AI-CYBER Codespaces startup refused: startup lock is a symlink.", file=sys.stderr)
        return 2
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        print(
            f"AI-CYBER Codespaces startup refused: cannot safely open startup lock "
            f"({type(exc).__name__}).",
            file=sys.stderr,
        )
        return 2

    import fcntl

    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(
                "AI-CYBER Codespaces startup is already running in another process; "
                "no duplicate watchdog was launched.",
                file=sys.stderr,
            )
            return 3
        return _start_unlocked(root, startup_timeout=startup_timeout)
    finally:
        os.close(lock_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[1]),
        help="repository root (default: parent of tools/)",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="startup readiness deadline")
    args = parser.parse_args(argv)
    if not 1.0 <= args.timeout <= 120.0:
        parser.error("--timeout must be between 1 and 120 seconds")
    return start(Path(args.root), startup_timeout=args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
