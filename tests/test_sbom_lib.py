import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sbom_lib import (
    apply_component_aliases,
    canonical_component_name,
    dedupe_first_party_packages,
    first_party_artifact_key,
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


# ── first_party_artifact_key ─────────────────────────────────────────────────

def test_first_party_artifact_key_strips_hel_prefix():
    assert first_party_artifact_key("hel-invalidated-tokens-api") == "invalidated-tokens-api"


def test_first_party_artifact_key_takes_maven_artifact_id():
    assert first_party_artifact_key("biz.videomed.tl4:invalidated-tokens-api") == \
        "invalidated-tokens-api"


def test_first_party_artifact_key_is_case_insensitive():
    assert first_party_artifact_key("HEL-Foo") == first_party_artifact_key("group:Foo")


def test_first_party_artifact_key_passthrough_for_plain_name():
    assert first_party_artifact_key("some-plain-name") == "some-plain-name"


# ── dedupe_first_party_packages ──────────────────────────────────────────────

def _spdx(packages, relationships=None):
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": packages,
        "relationships": relationships or [],
    }


def test_dedupe_removes_non_hel_twin_at_same_version():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-mvn", "name": "biz.videomed.tl4.installer:nms-gateway-helper",
         "versionInfo": "1.5.5", "supplier": "Organization: Maven"},
        {"SPDXID": "SPDXRef-hel", "name": "hel-nms-gateway-helper",
         "versionInfo": "1.5.5", "supplier": "Organization: Baxter"},
    ])
    out = dedupe_first_party_packages(spdx)
    names = [p["name"] for p in out["packages"]]
    assert names == ["hel-nms-gateway-helper"]


def test_dedupe_keeps_both_when_versions_differ():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-mvn", "name": "biz.videomed.nexxis:nms-broker-api",
         "versionInfo": "0.10.1", "supplier": "Organization: Maven"},
        {"SPDXID": "SPDXRef-hel", "name": "hel-nms-broker-api",
         "versionInfo": "0.10.5", "supplier": "Organization: Baxter"},
    ])
    out = dedupe_first_party_packages(spdx)
    names = {p["name"] for p in out["packages"]}
    assert names == {"biz.videomed.nexxis:nms-broker-api", "hel-nms-broker-api"}


def test_dedupe_does_not_rename_surviving_package():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-mvn", "name": "biz.videomed.tl4:invalidated-tokens-api",
         "versionInfo": "2.2.4", "supplier": "Organization: Maven"},
        {"SPDXID": "SPDXRef-hel", "name": "hel-invalidated-tokens-api",
         "versionInfo": "2.2.4", "supplier": "Organization: Baxter"},
    ])
    out = dedupe_first_party_packages(spdx)
    assert out["packages"][0]["name"] == "hel-invalidated-tokens-api"


def test_dedupe_redirects_relationships_to_the_surviving_package():
    spdx = _spdx(
        [
            {"SPDXID": "SPDXRef-mvn", "name": "biz.videomed.tl4.installer:nms-gateway-helper",
             "versionInfo": "1.5.5", "supplier": "Organization: Maven"},
            {"SPDXID": "SPDXRef-hel", "name": "hel-nms-gateway-helper",
             "versionInfo": "1.5.5", "supplier": "Organization: Baxter"},
        ],
        [
            {"spdxElementId": "SPDXRef-mvn", "relationshipType": "DEPENDENCY_OF",
             "relatedSpdxElement": "SPDXRef-tools"},
        ],
    )
    out = dedupe_first_party_packages(spdx)
    assert out["relationships"] == [
        {"spdxElementId": "SPDXRef-hel", "relationshipType": "DEPENDENCY_OF",
         "relatedSpdxElement": "SPDXRef-tools"},
    ]


def test_dedupe_drops_self_loop_relationships_created_by_redirect():
    spdx = _spdx(
        [
            {"SPDXID": "SPDXRef-mvn", "name": "biz.videomed.tl4.installer:nms-gateway-helper",
             "versionInfo": "1.5.5", "supplier": "Organization: Maven"},
            {"SPDXID": "SPDXRef-hel", "name": "hel-nms-gateway-helper",
             "versionInfo": "1.5.5", "supplier": "Organization: Baxter"},
        ],
        [
            {"spdxElementId": "SPDXRef-mvn", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-hel"},
        ],
    )
    out = dedupe_first_party_packages(spdx)
    assert out["relationships"] == []


def test_dedupe_does_not_mutate_input():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-mvn", "name": "biz.videomed.tl4.installer:nms-gateway-helper",
         "versionInfo": "1.5.5", "supplier": "Organization: Maven"},
        {"SPDXID": "SPDXRef-hel", "name": "hel-nms-gateway-helper",
         "versionInfo": "1.5.5", "supplier": "Organization: Baxter"},
    ])
    dedupe_first_party_packages(spdx)
    assert len(spdx["packages"]) == 2


def test_dedupe_ignores_oss_packages():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.18.1",
         "supplier": "Organization: NPM"},
        {"SPDXID": "SPDXRef-b", "name": "hel-lodash", "versionInfo": "4.18.1",
         "supplier": "Organization: NPM"},
    ])
    out = dedupe_first_party_packages(spdx)
    assert len(out["packages"]) == 2
