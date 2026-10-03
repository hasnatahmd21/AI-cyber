from pathlib import Path

from tools import reconstruct


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_reconstruction_output_isolated_from_canonical_package():
    assert reconstruct.OUT == REPO_ROOT / "reconstruction_artifacts" / "ai_cyber_os"
    assert reconstruct.OUT != REPO_ROOT / "src" / "ai_cyber_os"


def test_phase_header_parsing_uses_existing_regex_group():
    source = "# PHASE 12 — example\\nclass Demo: pass\\n"
    matches = list(reconstruct.PHASE_RE.finditer(source))
    assert len(matches) == 1
    assert int(matches[0].group(1)) == 12


def test_reconstruction_tool_does_not_target_canonical_compatibility_file():
    source = Path(REPO_ROOT / "tools" / "reconstruct.py").read_text(encoding="utf-8")
    assert 'ROOT / "src" / "ai_cyber_os.py"' not in source
    assert "ai_cyber_os.reconstructed" not in source
