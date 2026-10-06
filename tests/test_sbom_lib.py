import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sbom_lib import (
    apply_component_aliases,
    canonical_component_name,
    declare_license_refs,
    dedupe_first_party_packages,
    drop_invalid_cpe_refs,
    ensure_person_creator,
    filter_direct_dependencies,
    first_party_artifact_key,
    is_excluded_component,
    load_component_aliases,
    load_excluded_components,
    normalize_purpose_text,
    populate_document_describes,
    populate_package_filenames,
    remove_excluded_packages,
    remove_incomplete_dependencies,
    set_document_name,
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


# ── excluded components ───────────────────────────────────────────────────────

EXCLUDED = {"licensing": "test exclusion", "license-parser": "test exclusion"}


def test_load_excluded_components_lowercases_keys(tmp_path):
    p = tmp_path / "excluded.json"
    p.write_text(json.dumps({"Licensing": "reason", "License-Parser": "reason"}))
    excluded = load_excluded_components(str(p))
    assert excluded == {"licensing": "reason", "license-parser": "reason"}


def test_load_excluded_components_missing_path_returns_empty():
    assert load_excluded_components(None) == {}
    assert load_excluded_components("/no/such/file.json") == {}


def test_is_excluded_component_matches_maven_coordinate():
    assert is_excluded_component("biz.videomed:licensing", EXCLUDED) is True


def test_is_excluded_component_matches_bare_name_case_insensitively():
    assert is_excluded_component("LICENSING", EXCLUDED) is True


def test_is_excluded_component_false_for_unlisted_name():
    assert is_excluded_component("hel-app", EXCLUDED) is False


def test_is_excluded_component_false_when_no_excluded_map():
    assert is_excluded_component("biz.videomed:licensing", {}) is False


def test_remove_excluded_packages_drops_matching_package():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-lic", "name": "biz.videomed:licensing",
         "versionInfo": "0.6.8", "supplier": "Organization: Maven"},
        {"SPDXID": "SPDXRef-hel", "name": "hel-app",
         "versionInfo": "1.0", "supplier": "Organization: Baxter"},
    ])
    out = remove_excluded_packages(spdx, EXCLUDED)
    names = [p["name"] for p in out["packages"]]
    assert names == ["hel-app"]


def test_remove_excluded_packages_drops_its_relationships():
    spdx = _spdx(
        [
            {"SPDXID": "SPDXRef-lic", "name": "biz.videomed:licensing",
             "versionInfo": "0.6.8", "supplier": "Organization: Maven"},
            {"SPDXID": "SPDXRef-backend", "name": "hel-backend",
             "versionInfo": "1.0", "supplier": "Organization: Baxter"},
        ],
        [
            {"spdxElementId": "SPDXRef-backend", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-lic"},
            {"spdxElementId": "SPDXRef-lic", "relationshipType": "DEPENDENCY_OF",
             "relatedSpdxElement": "SPDXRef-backend"},
        ],
    )
    out = remove_excluded_packages(spdx, EXCLUDED)
    assert out["relationships"] == []
    assert [p["name"] for p in out["packages"]] == ["hel-backend"]


def test_remove_excluded_packages_no_excluded_map_is_noop():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-lic", "name": "biz.videomed:licensing",
         "versionInfo": "0.6.8", "supplier": "Organization: Maven"},
    ])
    out = remove_excluded_packages(spdx, {})
    assert len(out["packages"]) == 1


def test_remove_excluded_packages_does_not_mutate_input():
    spdx = _spdx([
        {"SPDXID": "SPDXRef-lic", "name": "biz.videomed:licensing",
         "versionInfo": "0.6.8", "supplier": "Organization: Maven"},
    ])
    remove_excluded_packages(spdx, EXCLUDED)
    assert len(spdx["packages"]) == 1


def test_oss_deps_only_exclusions_do_not_remove_packages_from_sbom():
    excluded_path = Path(__file__).resolve().parent.parent / "config" / "excluded_components.json"
    excluded = load_excluded_components(str(excluded_path))
    spdx = _spdx([
        {"SPDXID": "SPDXRef-invalidated", "name": "hel-invalidated-tokens-api",
         "versionInfo": "1.0", "supplier": "Organization: Baxter"},
        {"SPDXID": "SPDXRef-broker", "name": "hel-nms-broker-api",
         "versionInfo": "1.0", "supplier": "Organization: Baxter"},
    ])

    out = remove_excluded_packages(spdx, excluded)

    assert [package["name"] for package in out["packages"]] == [
        "hel-invalidated-tokens-api",
        "hel-nms-broker-api",
    ]


def test_set_document_name_overrides_name():
    spdx = {"name": "561 / current (aggregated)", "packages": [], "relationships": []}
    out = set_document_name(spdx, "Truelink 4 (or Helion)/1.8.0")
    assert out["name"] == "Truelink 4 (or Helion)/1.8.0"


def test_set_document_name_does_not_mutate_input():
    spdx = {"name": "561 / current (aggregated)", "packages": [], "relationships": []}
    set_document_name(spdx, "Truelink 4 (or Helion)/1.8.0")
    assert spdx["name"] == "561 / current (aggregated)"


def test_set_document_name_noop_when_name_falsy():
    spdx = {"name": "561 / current (aggregated)", "packages": [], "relationships": []}
    assert set_document_name(spdx, None)["name"] == "561 / current (aggregated)"
    assert set_document_name(spdx, "")["name"] == "561 / current (aggregated)"


# ── drop_invalid_cpe_refs (SPDX 2.3 CPE conformance) ────────────────────────

def _pkg_with_refs(refs):
    return {"SPDXID": "SPDXRef-a", "name": "x", "versionInfo": "1",
            "externalRefs": refs}


def test_drop_invalid_cpe_refs_removes_maven_coordinate():
    spdx = {"packages": [_pkg_with_refs([
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
         "referenceLocator": "pkg:maven/cc.nssm/nssm@2.24"},
        {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
         "referenceLocator": "cc.nssm:nssm"},
    ])]}
    out = drop_invalid_cpe_refs(spdx)
    types = [r["referenceType"] for r in out["packages"][0]["externalRefs"]]
    assert types == ["purl"]


def test_drop_invalid_cpe_refs_keeps_valid_cpe23():
    cpe = "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"
    spdx = {"packages": [_pkg_with_refs([
        {"referenceType": "cpe23Type", "referenceLocator": cpe}])]}
    out = drop_invalid_cpe_refs(spdx)
    assert out["packages"][0]["externalRefs"][0]["referenceLocator"] == cpe


def test_drop_invalid_cpe_refs_drops_externalrefs_key_when_empty():
    spdx = {"packages": [_pkg_with_refs([
        {"referenceType": "cpe23Type", "referenceLocator": "a:b"}])]}
    out = drop_invalid_cpe_refs(spdx)
    assert "externalRefs" not in out["packages"][0]


def test_drop_invalid_cpe_refs_does_not_mutate_input():
    spdx = {"packages": [_pkg_with_refs([
        {"referenceType": "cpe23Type", "referenceLocator": "a:b"}])]}
    drop_invalid_cpe_refs(spdx)
    assert spdx["packages"][0]["externalRefs"]


# ── declare_license_refs (SPDX 2.3 LicenseRef declaration) ──────────────────

def test_declare_license_refs_declares_used_refs():
    spdx = {"packages": [
        {"licenseConcluded": "LicenseRef-MIT-123456", "licenseDeclared": "NONE"},
        {"licenseInfoFromFiles": ["LicenseRef-proprietary-license"]},
    ]}
    out = declare_license_refs(spdx)
    ids = {e["licenseId"] for e in out["hasExtractedLicensingInfos"]}
    assert ids == {"LicenseRef-MIT-123456", "LicenseRef-proprietary-license"}
    for e in out["hasExtractedLicensingInfos"]:
        assert e["extractedText"]  # required by SPDX


def test_declare_license_refs_preserves_existing_and_is_idempotent():
    spdx = {"packages": [{"licenseConcluded": "LicenseRef-MIT"}],
            "hasExtractedLicensingInfos": [
                {"licenseId": "LicenseRef-MIT", "extractedText": "custom"}]}
    out = declare_license_refs(spdx)
    assert len(out["hasExtractedLicensingInfos"]) == 1
    assert out["hasExtractedLicensingInfos"][0]["extractedText"] == "custom"


def test_declare_license_refs_noop_without_refs():
    spdx = {"packages": [{"licenseConcluded": "MIT", "licenseDeclared": "Apache-2.0"}]}
    out = declare_license_refs(spdx)
    assert "hasExtractedLicensingInfos" not in out


# ── populate_document_describes ─────────────────────────────────────────────

def test_populate_document_describes_from_relationships():
    spdx = {"SPDXID": "SPDXRef-DOCUMENT", "documentDescribes": [],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                 "relatedSpdxElement": "SPDXRef-a"},
                {"spdxElementId": "SPDXRef-a", "relationshipType": "DEPENDS_ON",
                 "relatedSpdxElement": "SPDXRef-b"},
            ]}
    out = populate_document_describes(spdx)
    assert out["documentDescribes"] == ["SPDXRef-a"]


def test_populate_document_describes_preserves_non_empty():
    spdx = {"SPDXID": "SPDXRef-DOCUMENT", "documentDescribes": ["SPDXRef-x"],
            "relationships": []}
    assert populate_document_describes(spdx)["documentDescribes"] == ["SPDXRef-x"]


# ── ensure_person_creator ───────────────────────────────────────────────────

def test_ensure_person_creator_adds_person():
    spdx = {"creationInfo": {"creators": ["Organization: Baxter", "Tool: fossa-cli"]}}
    out = ensure_person_creator(spdx, "Jane Doe")
    assert "Person: Jane Doe" in out["creationInfo"]["creators"]


def test_ensure_person_creator_skips_when_person_present():
    spdx = {"creationInfo": {"creators": ["Person: Existing"]}}
    out = ensure_person_creator(spdx, "Jane Doe")
    assert out["creationInfo"]["creators"] == ["Person: Existing"]


def test_ensure_person_creator_noop_when_author_falsy():
    spdx = {"creationInfo": {"creators": ["Organization: Baxter"]}}
    assert ensure_person_creator(spdx, None)["creationInfo"]["creators"] == ["Organization: Baxter"]


def _graph_doc():
    return {
        "documentDescribes": ["SPDXRef-root"],
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "root"},
            {"SPDXID": "SPDXRef-direct", "name": "direct-lib"},
            {"SPDXID": "SPDXRef-transitive", "name": "transitive-lib"},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-root"},
            {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-direct"},
            {"spdxElementId": "SPDXRef-direct", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-transitive"},
        ],
    }


def test_filter_direct_dependencies_drops_transitive_only_package():
    out = filter_direct_dependencies(_graph_doc())
    ids = {p["SPDXID"] for p in out["packages"]}
    assert ids == {"SPDXRef-root", "SPDXRef-direct"}
    rel_types = {(r["spdxElementId"], r["relatedSpdxElement"]) for r in out["relationships"]}
    assert ("SPDXRef-direct", "SPDXRef-transitive") not in rel_types


def test_filter_direct_dependencies_keeps_dependency_of_encoding():
    doc = {
        "documentDescribes": ["SPDXRef-root"],
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "root"},
            {"SPDXID": "SPDXRef-direct", "name": "direct-lib"},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-direct", "relationshipType": "DEPENDENCY_OF",
             "relatedSpdxElement": "SPDXRef-root"},
        ],
    }
    out = filter_direct_dependencies(doc)
    ids = {p["SPDXID"] for p in out["packages"]}
    assert ids == {"SPDXRef-root", "SPDXRef-direct"}


def test_filter_direct_dependencies_no_root_returns_unchanged():
    doc = {"documentDescribes": [], "packages": [{"SPDXID": "SPDXRef-x"}],
           "relationships": []}
    out = filter_direct_dependencies(doc)
    assert out["packages"] == doc["packages"]
    assert out is not doc


def test_remove_incomplete_dependencies_drops_placeholder_and_its_relationships():
    doc = {
        "packages": [
            {"SPDXID": "SPDXRef-real", "name": "real-pkg"},
            {"SPDXID": "SPDXRef-placeholder", "name": "https://example.com/file.zip",
             "comment": "Incomplete dependency"},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-placeholder"},
            {"spdxElementId": "SPDXRef-placeholder", "relationshipType": "DEPENDENCY_OF",
             "relatedSpdxElement": "SPDXRef-root"},
            {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-real"},
        ],
    }
    out = remove_incomplete_dependencies(doc)
    ids = {p["SPDXID"] for p in out["packages"]}
    assert ids == {"SPDXRef-real"}
    assert len(out["relationships"]) == 1
    assert out["relationships"][0]["relatedSpdxElement"] == "SPDXRef-real"


def test_remove_incomplete_dependencies_noop_when_none_present():
    doc = {"packages": [{"SPDXID": "SPDXRef-real", "name": "real-pkg"}],
           "relationships": []}
    out = remove_incomplete_dependencies(doc)
    assert out["packages"] == doc["packages"]
    assert out is not doc


def test_populate_package_filenames_derives_from_download_location():
    doc = {"packages": [
        {"SPDXID": "SPDXRef-1", "name": "commons-lang3",
         "downloadLocation": "https://repo1.maven.org/maven2/org/apache/commons/"
                              "commons-lang3/3.18.0/commons-lang3-3.18.0-sources.jar"},
    ]}
    out = populate_package_filenames(doc)
    assert out["packages"][0]["packageFileName"] == "commons-lang3-3.18.0-sources.jar"


def test_populate_package_filenames_skips_existing_filename():
    doc = {"packages": [
        {"SPDXID": "SPDXRef-1", "name": "root",
         "packageFileName": "custom+19518/helion/foo$1.0.0",
         "downloadLocation": "https://example.com/other.jar"},
    ]}
    out = populate_package_filenames(doc)
    assert out["packages"][0]["packageFileName"] == "custom+19518/helion/foo$1.0.0"


def test_populate_package_filenames_skips_unresolvable_download_location():
    doc = {"packages": [
        {"SPDXID": "SPDXRef-1", "name": "no-download", "downloadLocation": "NOASSERTION"},
    ]}
    out = populate_package_filenames(doc)
    assert "packageFileName" not in out["packages"][0]


def test_populate_package_filenames_derives_from_maven_purl_when_no_download_location():
    doc = {"packages": [
        {"SPDXID": "SPDXRef-1", "name": "cc.nssm:nssm", "downloadLocation": "NOASSERTION",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                            "referenceLocator": "pkg:maven/cc.nssm/nssm@2.24"}]},
    ]}
    out = populate_package_filenames(doc)
    assert out["packages"][0]["packageFileName"] == "nssm-2.24.jar"


def test_populate_package_filenames_derives_from_npm_purl_drops_scope():
    doc = {"packages": [
        {"SPDXID": "SPDXRef-1", "name": "@angular/core", "downloadLocation": "NOASSERTION",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                            "referenceLocator": "pkg:npm/%40angular/core@21.2.22"}]},
    ]}
    out = populate_package_filenames(doc)
    assert out["packages"][0]["packageFileName"] == "core-21.2.22.tgz"


def test_populate_package_filenames_skips_unresolvable_purl_type():
    doc = {"packages": [
        {"SPDXID": "SPDXRef-1", "name": "golang.org/x/text", "downloadLocation": "NOASSERTION",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                            "referenceLocator": "pkg:golang/golang.org/x/text@0.14.0"}]},
    ]}
    out = populate_package_filenames(doc)
    assert "packageFileName" not in out["packages"][0]
