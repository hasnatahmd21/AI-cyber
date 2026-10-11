"""Defence hook: always on, no switches. Layered defence lives in <repo>/layered_defense."""
import os
import sys
import threading

_LD = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "layered_defense")
)
if _LD not in sys.path:
    sys.path.insert(0, _LD)


def enforce(argv=None):
    from ai_cyber.secured import enforce as _enforce

    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--json" in arguments:
        # Keep the canonical CLI's machine-readable stdout clean.
        def diagnostic(*values, **kwargs):
            kwargs["file"] = sys.stderr
            print(*values, **kwargs)

        _enforce(arguments, out=diagnostic)
    else:
        _enforce(arguments)


def release():
    """Release the per-invocation guard after the corresponding CLI run ends."""
    try:
        from ai_cyber import secured
    except ImportError:
        return
    secured.ACTIVE = False

_EXECUTION_LOCK = threading.RLock()


class DefenceBlocked(RuntimeError):
    """Raised when the always-on defence refuses a UI execution request."""


def run_guarded(argv, action):
    """Serialize a UI execution, enforce defence once, then release the per-run guard."""
    with _EXECUTION_LOCK:
        try:
            try:
                enforce(argv)
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
                raise DefenceBlocked(f"layered defence blocked execution (exit {code})") from None
            return action()
        finally:
            release()
