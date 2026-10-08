# Kaggle + GitHub Verification Pipeline

Stage #11 provides one verification entry point for both a fresh Kaggle clone and GitHub Actions.

## Fresh Kaggle verification

After cloning this repository into a fresh Kaggle session:

```python
import subprocess, sys
from pathlib import Path

repo = Path("/kaggle/working/AI-cyber")
subprocess.run(
    ["git", "clone", "https://github.com/hasnatahmd21/AI-cyber.git", str(repo)],
    check=True,
)
subprocess.run(
    [sys.executable, str(repo / "tools" / "kaggle_github_verify.py"),
     "--repo-root", str(repo),
     "--report", "/kaggle/working/ai_cyber_verification_report.json"],
    check=True,
)
```

The verifier creates a machine-readable report and exits non-zero on any failed gate.

## What is verified

The pipeline checks the repository identity, tracked working-tree cleanliness, canonical module surface, source/test/tool compilation, editable installation, importability, dependency consistency, a forensic inventory of the canonical source surface, forensic baseline artifacts, installation of the verification test runner, the full pytest regression suite, the focused adversarial hardening suite, all 27 canonical HYDRA phases, and final hardening verification. Preserved root-level legacy monoliths remain forensic evidence and are not treated as canonical runtime source.

## Fail-closed rule

A single failed check makes the overall result `FAIL`. A partial pass is never promoted to GREEN.

## GitHub Actions

Workflow:

`.github/workflows/kaggle-github-verification.yml`

It runs the same verifier on every push to the stage branch and on pull requests targeting `main`, then uploads the JSON verification report as a workflow artifact.

