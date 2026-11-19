"""Keep the ``models.audit`` imports working after the audit tree moved.

The audit harness now lives in the ``teeaudit`` submodule, while
``models/examples`` stays in this repository. Both directories contribute a
portion of the ``models`` namespace package, so putting teeaudit on sys.path
next to the repository root preserves the existing
``from models.audit.tools...`` imports without rewriting every test.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

for path in (ROOT / "teeaudit", ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
