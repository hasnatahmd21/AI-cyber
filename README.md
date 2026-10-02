# AI Cyber OS

Canonical refactored runtime for the AI Cyber OS project.

## Runtime layout

- `src/ai_cyber_os/core/hydra_core.py` — canonical HYDRA cyber core
- `src/ai_cyber_os/security/os_security.py` — OS-security subsystem
- `src/ai_cyber_os/audit/forensic.py` — forensic/audit subsystem
- `src/ai_cyber_os/integration.py` — explicit cross-component health wiring
- `.github/workflows/ai-cyber-validation.yml` — compile/import/self-test validation

The former root-level monoliths were duplicate/superseded implementations. They
were removed from the active runtime surface so there is one canonical copy of
each subsystem.

## Validation

```bash
python -m pip install -r requirements.txt
PYTHONPATH=src python -c "from ai_cyber_os.integration import assert_healthy; assert_healthy()"
```

GitHub Actions additionally compiles the package and runs each canonical
component's built-in test entrypoint.
