import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sbom_lib import (
    apply_component_aliases,
    canonical_component_name,
    load_component_aliases,
    normalize_purpose_text,
)

ALIASES = {
    "tl4-app-external": "hel-app",
    "tl4-app-print-helper": "hel-app-print-helper",
}


def test_canonical_maps_maven_coordinate_to_hel_name():
    assert canonical_component_name(
        "biz.videomed.tl4.installer:tl4-app-external", ALIASES
    ) == "hel-app"


def test_canonical_maps_bare_short_name():
    assert canonical_component_name("tl4-app-print-helper", ALIASES) == "hel-app-print-helper"


def test_canonical_is_case_insensitive():
    assert canonical_component_name("TL4-App-External", ALIASES) == "hel-app"


def test_canonical_passthrough_for_unmapped_name():
    assert canonical_component_name("hel-app", ALIASES) == "hel-app"
    assert canonical_component_name("org.apache:commons-lang3", ALIASES) == "org.apache:commons-lang3"


def test_canonical_empty_aliases_returns_name():
    assert canonical_component_name("tl4-app-external", {}) == "tl4-app-external"


def test_load_component_aliases_missing_path_returns_empty():
    assert load_component_aliases(None) == {}
    assert load_component_aliases("/no/such/file.json") == {}


def test_load_component_aliases_lowercases_keys(tmp_path):
    p = tmp_path / "aliases.json"
    p.write_text(json.dumps({"TL4-App-External": "hel-app", " tl4-x ": " hel-x "}))
    result = load_component_aliases(str(p))
    assert result == {"tl4-app-external": "hel-app", "tl4-x": "hel-x"}


# ── normalize_purpose_text ───────────────────────────────────────────────────

def test_normalize_purpose_strips_leading_and_trailing_whitespace():
    assert normalize_purpose_text("\n    Guava is a suite\n  ") == "Guava is a suite"


def test_normalize_purpose_strips_leading_emoji():
    assert normalize_purpose_text("👻 Primitive and flexible state management") == \
        "Primitive and flexible state management"


def test_normalize_purpose_strips_emoji_anywhere_in_text():
    assert normalize_purpose_text("Does things 🎉 well 🚀") == "Does things well"


def test_normalize_purpose_passthrough_for_clean_text():
    assert normalize_purpose_text("Does things") == "Does things"


def test_normalize_purpose_handles_empty_and_none():
    assert normalize_purpose_text("") == ""
    assert normalize_purpose_text(None) == ""


# ── apply_component_aliases ──────────────────────────────────────────────────

def test_apply_component_aliases_renames_first_party_package_name():
    spdx = {
        "packages": [
            {"name": "biz.videomed.tl4.installer:tl4-app-external",
             "supplier": "Organization: Baxter", "versionInfo": "1.0"},
        ]
    }
    out = apply_component_aliases(spdx, ALIASES)
    assert out["packages"][0]["name"] == "hel-app"


def test_apply_component_aliases_leaves_third_party_packages_untouched():
    spdx = {
        "packages": [
            {"name": "some-oss-lib", "supplier": "Organization: NPM", "versionInfo": "1.0"},
        ]
    }
    out = apply_component_aliases(spdx, ALIASES)
    assert out["packages"][0]["name"] == "some-oss-lib"


def test_apply_component_aliases_leaves_unmapped_first_party_names_untouched():
    spdx = {
        "packages": [
            {"name": "hel-app", "supplier": "Organization: Baxter", "versionInfo": "1.0"},
        ]
    }
    out = apply_component_aliases(spdx, ALIASES)
    assert out["packages"][0]["name"] == "hel-app"


def test_apply_component_aliases_does_not_mutate_input_doc():
    spdx = {
        "packages": [
            {"name": "biz.videomed.tl4.installer:tl4-app-external",
             "supplier": "Organization: Baxter", "versionInfo": "1.0"},
        ]
    }
    apply_component_aliases(spdx, ALIASES)
    assert spdx["packages"][0]["name"] == "biz.videomed.tl4.installer:tl4-app-external"


def test_apply_component_aliases_preserves_other_top_level_fields():
    spdx = {"spdxVersion": "SPDX-2.3", "packages": [], "relationships": [{"a": 1}]}
    out = apply_component_aliases(spdx, ALIASES)
    assert out["spdxVersion"] == "SPDX-2.3"
    assert out["relationships"] == [{"a": 1}]
