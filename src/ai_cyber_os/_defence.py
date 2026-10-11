"""Defence hook: always on, no switches. Layered defence lives in <repo>/layered_defense."""
import os
import sys

_LD = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "layered_defense"))
if _LD not in sys.path:
    sys.path.insert(0, _LD)


def enforce(argv=None):
    from ai_cyber.secured import enforce as _enforce
    _enforce(argv)


def release():
    """Release the per-invocation guard after the corresponding CLI run ends."""
    try:
        from ai_cyber import secured
    except ImportError:
        return
    secured.ACTIVE = False
