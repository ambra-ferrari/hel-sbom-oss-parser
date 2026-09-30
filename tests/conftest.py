"""Test bootstrap: make the flat modules under ``src/`` importable.

The project uses a ``src/`` layout (see ``pyproject.toml``). Adding it to
``sys.path`` here lets every test — including ones that don't set it up
themselves — do ``import sbom_to_excel`` etc. without installing the package.
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
