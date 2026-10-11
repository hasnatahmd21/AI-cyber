"""HYDRA integration: loads the split legacy phase modules WITHOUT modifying them, verifies
they are intact/lossless w.r.t. the original monolith, and runs their built-in test suites."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

from .contracts import SecurityError

LEGACY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "legacy")
PHASES_DIR = os.path.join(LEGACY_DIR, "hydra_phases")
FUTURE_LINE = "from __future__ import annotations"


class HydraError(SecurityError):
    pass


@dataclass(frozen=True)
class PhaseResult:
    phase: int
    file: str
    passed: int
    failed: int
    ok: bool
    detail: str = ""


class Hydra:
    def __init__(self, legacy_dir: str = LEGACY_DIR) -> None:
        self.legacy_dir = legacy_dir
        self.phases_dir = os.path.join(legacy_dir, "hydra_phases")
        with open(os.path.join(legacy_dir, "split_manifest.json"), encoding="utf-8") as f:
            self.manifest = json.load(f)

    # ---- inventory --------------------------------------------------------
    def phase_files(self) -> Dict[int, str]:
        out: Dict[int, str] = {}
        for seg in self.manifest["segments"]:
            out.setdefault(seg["phase"], seg["file"])
        return out

    def phase_numbers(self) -> List[int]:
        return sorted(self.phase_files())

    # ---- integrity --------------------------------------------------------
    def verify_files(self) -> List[str]:
        """Each phase file must match its recorded hash (detects tampering/corruption)."""
        bad = []
        for fn, digest in self.manifest["file_sha256"].items():
            p = os.path.join(self.phases_dir, fn)
            if not os.path.isfile(p):
                bad.append(f"missing:{fn}")
            elif hashlib.sha256(open(p, "rb").read()).hexdigest() != digest:
                bad.append(f"modified:{fn}")
        return bad

    def _original_segment(self, fn: str) -> bytes:
        data = open(os.path.join(self.phases_dir, fn), "rb").read().decode("utf-8")
        info = self.manifest["future_import_patch"]["files"][fn]
        ins = info["inserted_line"]
        if ins:
            lines = data.split("\n")
            if lines[ins - 1] != FUTURE_LINE:
                raise HydraError(f"patch line not where expected in {fn}")
            del lines[ins - 1]
            data = "\n".join(lines)
        return data.encode("utf-8")

    def verify_lossless(self) -> bool:
        """Reassemble all segments (in original order) and compare to the original monolith hash."""
        buf = b"".join(self._original_segment(s["file"]) for s in self.manifest["segments"])
        return hashlib.sha256(buf).hexdigest() == self.manifest["source_sha256"]

    # ---- execution --------------------------------------------------------
    def run_phase_subprocess(self, phase: int, timeout: float = 300.0) -> PhaseResult:
        fn = self.phase_files().get(phase)
        if fn is None:
            raise HydraError(f"unknown phase {phase}")
        try:
            cp = subprocess.run([sys.executable, os.path.join(self.phases_dir, fn)],
                                capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return PhaseResult(phase, fn, 0, 0, False, "timeout")
        last = (cp.stdout.strip().splitlines() or [""])[-1]
        import re
        m = re.search(r"(\d+) passed, (\d+) failed", last)
        if cp.returncode == 0 and m and int(m.group(2)) == 0:
            return PhaseResult(phase, fn, int(m.group(1)), 0, True)
        return PhaseResult(phase, fn, int(m.group(1)) if m else 0, int(m.group(2)) if m else -1, False,
                           (cp.stderr or last)[-300:])

    def load_phase(self, phase: int):
        """Import a phase module in-process (isolated module name)."""
        fn = self.phase_files()[phase]
        spec = importlib.util.spec_from_file_location(f"ai_cyber_hydra_phase_{phase:02d}",
                                                      os.path.join(self.phases_dir, fn))
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod       # dataclasses need this
        spec.loader.exec_module(mod)
        return mod

    def run_all(self, workers: int = 8) -> List[PhaseResult]:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(self.run_phase_subprocess, self.phase_numbers()))
