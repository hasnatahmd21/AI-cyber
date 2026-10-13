"""Run every test: 19 phase modules + the wiring integration tests.

    python -m hydra_brain.tests.run_all        (from the repo root)
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
import unittest


def main() -> int:
    import hydra_brain.core as core
    import hydra_brain.optional as optional

    suite = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    for package in (core, optional):
        for info in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(f"{package.__name__}.{info.name}")
            suite.addTests(loader.loadTestsFromModule(module))
    suite.addTests(
        loader.loadTestsFromName("hydra_brain.tests.test_wiring")
    )
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
