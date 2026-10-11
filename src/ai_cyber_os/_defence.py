"""Defence hook: always on, no switches. Layered defence lives in <repo>/layered_defense."""
import os
import sys

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
