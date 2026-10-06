"""Conformance checks for the machine-readable SBOM deliverable.

These wrap the standard open-source SBOM validation toolkit as pytest gates so
conformance is part of the pipeline (there is no official EU/CRA/MDR validation
portal — conformance is demonstrated with these tools):

  - SPDX 2.3 JSON Schema          (check-jsonschema)
  - SPDX 2.3 semantic validation  (spdx-tools)
  - NTIA minimum elements         (ntia-conformance-checker) — CRA/FDA baseline

Each check is skipped (not failed) when its validator or the generated
deliverable is not available, so the core unit-test run stays dependency-light.
Install the validators with:  pip install '.[conformance]'

Run just these:  pytest tests/test_sbom_conformance.py
"""
import json
import urllib.request
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SBOM_PATH = PROJECT_ROOT / "outputs" / "sbom_machine_readable" / "sbom_new.json"
SCHEMA_URL = (
    "https://raw.githubusercontent.com/spdx/spdx-spec/"
    "support/v2.3/schemas/spdx-schema.json"
)
_SCHEMA_CACHE = PROJECT_ROOT / ".venv-conformance" / "spdx-2.3.schema.json"


def _require_sbom():
    if not SBOM_PATH.is_file():
        pytest.skip(
            f"{SBOM_PATH} not generated — run src/normalize_sbom_aliases.py first"
        )


def _load_spdx_schema():
    """Return the SPDX 2.3 JSON schema dict, caching it locally once fetched."""
    if _SCHEMA_CACHE.is_file():
        return json.loads(_SCHEMA_CACHE.read_text(encoding="utf-8"))
    try:
        with urllib.request.urlopen(SCHEMA_URL, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
    except Exception as exc:  # offline / network blocked
        pytest.skip(f"SPDX schema unavailable ({exc})")
    _SCHEMA_CACHE.parent.mkdir(parents=True, exist_ok=True)
    _SCHEMA_CACHE.write_text(raw, encoding="utf-8")
    return json.loads(raw)


def test_sbom_valid_against_spdx_json_schema():
    _require_sbom()
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_spdx_schema()
    doc = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)


def test_sbom_passes_spdx_semantic_validation():
    _require_sbom()
    pytest.importorskip("spdx_tools")
    from spdx_tools.spdx.parser.parse_anything import parse_file
    from spdx_tools.spdx.validation.document_validator import (
        validate_full_spdx_document,
    )

    messages = validate_full_spdx_document(parse_file(str(SBOM_PATH)))
    rendered = "\n".join(m.validation_message for m in messages)
    assert messages == [], f"SPDX semantic validation issues:\n{rendered}"


def test_sbom_meets_ntia_minimum_elements():
    _require_sbom()
    pytest.importorskip("ntia_conformance_checker")
    from ntia_conformance_checker import SbomChecker

    checker = SbomChecker(str(SBOM_PATH))
    assert checker.compliant, "SBOM does not meet the NTIA minimum elements"
