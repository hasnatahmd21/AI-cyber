"""Canonical AI-Cyber runtime surface.

The implementation is preserved in one source-of-truth runtime module while
legacy monoliths remain evidence-only. This module intentionally contains no
second implementation.
"""
from .hydra import *  # noqa: F401,F403
