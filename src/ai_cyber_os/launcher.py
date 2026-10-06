"""Unified local launcher for the AI-Cyber operational UI."""
from __future__ import annotations

from .ui import main


def launch() -> int:
    """Start the localhost-only operational UI and open it in a browser."""
    return main()


if __name__ == "__main__":
    raise SystemExit(launch())
