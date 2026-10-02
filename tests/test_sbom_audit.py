"""Reproducible audit checklist for the machine-readable SBOM (SPDX JSON).

Codifies the manual review performed on outputs/sbom_normalized.json:
structural validity, SPDXID uniqueness, relationship integrity (no dangling
refs, no self-loops, no exact duplicates), DESCRIBES count vs. declared
project count, required package fields, purl validity, checksum presence,
name hygiene, and absence of explicitly-excluded components.

Unit tests below exercise `audit_spdx()` against small synthetic SPDX docs
(one issue at a time). The final test re-runs the SAME audit against the
real, regenerated `outputs/sbom_normalized.json` — rerun it any time after
regenerating the deliverable (`src/normalize_sbom_aliases.py`) to confirm it
is still clean; it's skipped when that file hasn't been generated yet.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sbom_lib import audit_spdx, load_excluded_components

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _spdx(packages=None, relationships=None, **top_level):
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test-doc",
        "documentNamespace": "https://example.com/spdx/test",
        "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": []},
        "packages": packages or [],
        "relationships": relationships or [],
    }
    doc.update(top_level)
    return doc


def _clean_package(spdxid="SPDXRef-a", name="hel-app", version="1.0.0"):
    return {"SPDXID": spdxid, "name": name, "versionInfo": version,
            "supplier": "Organization: Baxter"}


def test_clean_doc_has_no_issues():
    doc = _spdx([_clean_package()])
    assert audit_spdx(doc) == []


def test_detects_missing_top_level_field():
    doc = _spdx([_clean_package()])
    del doc["dataLicense"]
    issues = audit_spdx(doc)
    assert any("dataLicense" in i for i in issues)


def test_detects_duplicate_spdxid():
    doc = _spdx([_clean_package("SPDXRef-a"), _clean_package("SPDXRef-a", name="other")])
    issues = audit_spdx(doc)
    assert any("duplicate SPDXID" in i for i in issues)


def test_detects_missing_name():
    pkg = _clean_package()
    pkg["name"] = ""
    doc = _spdx([pkg])
    issues = audit_spdx(doc)
    assert any("missing name" in i for i in issues)


def test_detects_stray_whitespace_in_name():
    pkg = _clean_package(name=" hel-app ")
    doc = _spdx([pkg])
    issues = audit_spdx(doc)
    assert any("stray whitespace" in i for i in issues)


def test_detects_missing_version():
    pkg = _clean_package()
    pkg["versionInfo"] = ""
    doc = _spdx([pkg])
    issues = audit_spdx(doc)
    assert any("missing versionInfo" in i for i in issues)


def test_detects_malformed_purl():
    pkg = _clean_package()
    pkg["externalRefs"] = [{"referenceType": "purl", "referenceLocator": "not-a-purl"}]
    doc = _spdx([pkg])
    issues = audit_spdx(doc)
    assert any("malformed purl" in i for i in issues)


def test_accepts_well_formed_purl():
    pkg = _clean_package()
    pkg["externalRefs"] = [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.18.1"}]
    doc = _spdx([pkg])
    assert audit_spdx(doc) == []


def test_detects_missing_checksum_when_files_analyzed():
    pkg = _clean_package()
    pkg["filesAnalyzed"] = True
    doc = _spdx([pkg])
    issues = audit_spdx(doc)
    assert any("no checksums" in i for i in issues)


def test_accepts_checksum_when_files_analyzed():
    pkg = _clean_package()
    pkg["filesAnalyzed"] = True
    pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": "abc"}]
    doc = _spdx([pkg])
    assert audit_spdx(doc) == []


def test_detects_dangling_relationship_endpoint():
    doc = _spdx(
        [_clean_package("SPDXRef-a")],
        [{"spdxElementId": "SPDXRef-a", "relationshipType": "DEPENDS_ON",
          "relatedSpdxElement": "SPDXRef-ghost"}],
    )
    issues = audit_spdx(doc)
    assert any("dangling relationship endpoint" in i for i in issues)


def test_detects_relationship_self_loop():
    doc = _spdx(
        [_clean_package("SPDXRef-a")],
        [{"spdxElementId": "SPDXRef-a", "relationshipType": "DEPENDS_ON",
          "relatedSpdxElement": "SPDXRef-a"}],
    )
    issues = audit_spdx(doc)
    assert any("self-loop" in i for i in issues)


def test_detects_duplicate_relationship():
    rel = {"spdxElementId": "SPDXRef-a", "relationshipType": "DEPENDS_ON",
           "relatedSpdxElement": "SPDXRef-b"}
    doc = _spdx([_clean_package("SPDXRef-a"), _clean_package("SPDXRef-b", name="b")],
                [rel, dict(rel)])
    issues = audit_spdx(doc)
    assert any("duplicate relationship" in i for i in issues)


def test_detects_describes_count_mismatch():
    doc = _spdx(
        [_clean_package("SPDXRef-a")],
        [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
          "relatedSpdxElement": "SPDXRef-a"}],
        creationInfo={"created": "2026-01-01T00:00:00Z", "creators": [],
                      "comment": "Aggregated from 3 FOSSA project(s):\n- a\n- b\n- c"},
    )
    issues = audit_spdx(doc)
    assert any("DESCRIBES count" in i for i in issues)


def test_describes_count_match_is_clean():
    doc = _spdx(
        [_clean_package("SPDXRef-a")],
        [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
          "relatedSpdxElement": "SPDXRef-a"}],
        creationInfo={"created": "2026-01-01T00:00:00Z", "creators": [],
                      "comment": "Aggregated from 1 FOSSA project(s):\n- a"},
    )
    assert audit_spdx(doc) == []


def test_detects_excluded_component_still_present():
    pkg = _clean_package(name="biz.videomed:licensing")
    doc = _spdx([pkg])
    issues = audit_spdx(doc, excluded={"licensing": "test"})
    assert any("excluded component still present" in i for i in issues)


def test_excluded_map_empty_is_noop():
    pkg = _clean_package(name="biz.videomed:licensing")
    doc = _spdx([pkg])
    assert audit_spdx(doc, excluded={}) == []


# ── integration: audit the real regenerated deliverable ─────────────────────

def test_audit_real_normalized_sbom_is_clean():
    """Rerun this (after `python3 src/normalize_sbom_aliases.py ...`) any time
    to re-verify the actual machine-readable SBOM deliverable is clean."""
    path = PROJECT_ROOT / "outputs" / "sbom_normalized.json"
    if not path.is_file():
        import pytest
        pytest.skip(f"{path} not generated — run src/normalize_sbom_aliases.py first")

    with open(path, encoding="utf-8") as f:
        spdx = json.load(f)
    excluded = load_excluded_components(str(PROJECT_ROOT / "config" / "excluded_components.json"))

    issues = audit_spdx(spdx, excluded)
    assert issues == [], "SBOM audit found issues:\n" + "\n".join(issues)
