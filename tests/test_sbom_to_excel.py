import sys
from pathlib import Path
import json as json_module
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
TEMPLATE = str(Path(__file__).resolve().parent.parent / "templates" / "template.xlsx")

from sbom_to_excel import (
    build_excel,
    extract_version_from_download_url,
    load_version_overrides,
    is_incomplete_dependency,
    strip_v_prefix,
    resolve_component_name,
    load_eol_map,
)


def _write_sbom(tmp_path, packages):
    doc = {
        "spdxVersion": "SPDX-2.3",
        "name": "Test",
        "creationInfo": {"created": "2026-09-25T00:00:00Z",
                          "creators": ["Organization: Baxter", "Tool: fossa-cli"]},
        "documentDescribes": [],
        "packages": packages,
        "relationships": [],
    }
    p = tmp_path / "sbom.json"
    p.write_text(json_module.dumps(doc))
    return str(p)


def _read_data_rows(xlsx_path):
    import openpyxl
    wb = openpyxl.load_workbook(xlsx_path)
    ws = wb.active
    rows = []
    for r in ws.iter_rows(min_row=8, values_only=True):
        if r[1] is None:  # column B = name
            continue
        rows.append(r)
    return rows


def test_build_excel_dedups_full_name_and_strips_v(tmp_path):
    packages = [
        {"SPDXID": "SPDXRef-1", "name": "github.com/golang-jwt/jwt/v5",
         "versionInfo": "v5.3.1", "supplier": "Organization: Maven", "externalRefs": []},
        {"SPDXID": "SPDXRef-2", "name": "github.com/golang-jwt/jwt/v5",
         "versionInfo": "5.3.1", "supplier": "Organization: Maven", "externalRefs": []},
        {"SPDXID": "SPDXRef-3", "name": "@angular/core",
         "versionInfo": "18.2.0", "supplier": "Organization: npm", "externalRefs": []},
    ]
    sbom = _write_sbom(tmp_path, packages)
    out = str(tmp_path / "out.xlsx")
    build_excel(sbom_path=sbom, template_path=TEMPLATE, output_path=out,
                product_name="P", product_version="1", version_overrides_path=None)

    rows = _read_data_rows(out)
    names = [r[1] for r in rows]
    versions = [str(r[2]) for r in rows]
    assert names.count("github.com/golang-jwt/jwt/v5") == 1
    assert "5.3.1" in versions and "v5.3.1" not in versions
    assert "@angular/core" in names
    assert len(rows) == 2


def test_flags_fossa_incomplete_dependency_placeholder():
    pkg = {
        "name": "https://download.bell-sw.com/java/17.0.19+11/bellsoft-jre17.0.19+11-windows-amd64.zip",
        "versionInfo": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "comment": "Incomplete dependency",
        "supplier": "Organization: Global URL",
    }
    assert is_incomplete_dependency(pkg) is True


def test_does_not_flag_a_real_package_as_incomplete():
    pkg = {
        "name": "bellsoft-jre17.0.19+11-windows-amd64.zip",
        "versionInfo": "7d23ca5a9128444155ccaf6756d71b4d",
        "downloadLocation": "https://download.bell-sw.com/java/17.0.19+11/bellsoft-jre17.0.19+11-windows-amd64.zip",
        "supplier": "Organization: FOSSA (Global URL)",
    }
    assert is_incomplete_dependency(pkg) is False


def test_extracts_version_with_plus_suffix_from_jre_url():
    pkg = {
        "name": "bellsoft-jre17.0.19+11-windows-amd64.zip",
        "versionInfo": "NOASSERTION",
        "externalRefs": [],
        "downloadLocation": "https://download.bell-sw.com/java/17.0.19+11/bellsoft-jre17.0.19+11-windows-amd64.zip",
    }
    assert extract_version_from_download_url(pkg) == "17.0.19+11"


def test_extracts_version_from_mongodb_url_ignoring_arch_string():
    pkg = {
        "name": "mongodb-windows-x86_64-8.0.17.zip",
        "versionInfo": "43706c28791673ac0fd7a2e0f5a3b95b",
        "externalRefs": [],
        "downloadLocation": "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-8.0.17.zip",
    }
    assert extract_version_from_download_url(pkg) == "8.0.17"


def test_returns_none_when_package_has_a_purl():
    pkg = {
        "name": "commons-io",
        "versionInfo": "2.16.1",
        "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:maven/commons-io/commons-io@2.16.1"}],
        "downloadLocation": "https://repo1.maven.org/maven2/commons-io/commons-io/2.16.1/commons-io-2.16.1.jar",
    }
    assert extract_version_from_download_url(pkg) is None


def test_returns_none_when_no_download_location():
    pkg = {"name": "tl4-ui-internal", "versionInfo": "09868c77055f4077a0405f5702597b8f8f0dd0e7", "externalRefs": []}
    assert extract_version_from_download_url(pkg) is None


def test_returns_none_when_url_has_no_version_pattern():
    pkg = {
        "name": "postgres",
        "versionInfo": "REL_18_3",
        "externalRefs": [],
        "downloadLocation": "https://github.com/postgres/postgres/archive/62d6c7d3df6287f1bd83199c1a746e50d31571a0.zip",
    }
    assert extract_version_from_download_url(pkg) is None


def test_load_version_overrides_returns_empty_dict_when_path_is_none():
    assert load_version_overrides(None) == {}


def test_load_version_overrides_reads_json_file(tmp_path):
    overrides_file = tmp_path / "overrides.json"
    overrides_file.write_text(json_module.dumps({"tl4-ui-internal": "2.5.0"}))
    assert load_version_overrides(str(overrides_file)) == {"tl4-ui-internal": "2.5.0"}


def test_load_version_overrides_raises_clear_error_on_missing_file():
    with pytest.raises(SystemExit, match="version-overrides file not found"):
        load_version_overrides("/no/such/file.json")


def test_load_version_overrides_raises_clear_error_on_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json")
    with pytest.raises(SystemExit, match="version-overrides file is not valid JSON"):
        load_version_overrides(str(bad_file))


def test_load_eol_map_missing_path_returns_empty(tmp_path):
    assert load_eol_map(None) == {}
    assert load_eol_map(str(tmp_path / "nope.json")) == {}


def test_load_eol_map_reads_eol_section(tmp_path):
    p = tmp_path / "eol_data.json"
    p.write_text(json_module.dumps({"eol": {"SPDXRef-react": "2026-04-30"}}))
    assert load_eol_map(str(p)) == {"SPDXRef-react": "2026-04-30"}


def test_strip_v_prefix_removes_leading_v_before_digit():
    assert strip_v_prefix("v5.3.1") == "5.3.1"


def test_strip_v_prefix_keeps_go_pseudo_version_body():
    assert strip_v_prefix("v0.0.0-20260824195058-abcdef") == "0.0.0-20260824195058-abcdef"


def test_strip_v_prefix_leaves_plain_version_unchanged():
    assert strip_v_prefix("1.2.3") == "1.2.3"


def test_strip_v_prefix_does_not_strip_v_before_non_digit():
    assert strip_v_prefix("version-2") == "version-2"


def test_strip_v_prefix_handles_empty_string():
    assert strip_v_prefix("") == ""


def test_resolve_component_name_keeps_full_path_like_name():
    assert resolve_component_name("github.com/golang-jwt/jwt/v5", "") == "github.com/golang-jwt/jwt/v5"


def test_resolve_component_name_keeps_scoped_npm_name():
    assert resolve_component_name("@angular/core", "") == "@angular/core"


def test_resolve_component_name_falls_back_to_coordinate_when_name_empty():
    assert resolve_component_name("", "com.fasterxml:jackson") == "com.fasterxml:jackson"


def test_resolve_component_name_prefers_name_over_coordinate():
    assert resolve_component_name("Apache Commons Lang", "commons:lang") == "Apache Commons Lang"


def test_build_excel_applies_version_override_by_short_name(tmp_path):
    # Override keyed by the short (last-path-segment) name still applies even
    # though the xlsx now shows the full package name.
    packages = [
        {"SPDXID": "SPDXRef-1", "name": "19518/helion/tl4-ui-internal",
         "versionInfo": "9d09a925aaaabbbbccccddddeeeeffff00001111",
         "supplier": "Organization: Baxter", "externalRefs": []},
    ]
    sbom = _write_sbom(tmp_path, packages)
    overrides = tmp_path / "ov.json"
    overrides.write_text(json_module.dumps({"tl4-ui-internal": "2.5.0"}))
    out = str(tmp_path / "out.xlsx")
    build_excel(sbom_path=sbom, template_path=TEMPLATE, output_path=out,
                product_name="P", product_version="1", version_overrides_path=str(overrides))

    rows = _read_data_rows(out)
    assert rows[0][1] == "19518/helion/tl4-ui-internal"
    assert str(rows[0][2]) == "2.5.0"


from sbom_to_excel import first_party_artifact_key, resolve_version


def test_first_party_artifact_key_strips_hel_prefix():
    assert first_party_artifact_key("hel-invalidated-tokens-api") == "invalidated-tokens-api"


def test_first_party_artifact_key_takes_maven_artifact_id():
    assert first_party_artifact_key("biz.videomed.tl4:invalidated-tokens-api") == "invalidated-tokens-api"


def test_resolve_version_strips_v_and_applies_override():
    pkg = {"SPDXID": "X", "name": "foo", "versionInfo": "v1.2.3", "externalRefs": []}
    assert resolve_version(pkg, {}) == "1.2.3"
    assert resolve_version(pkg, {"foo": "9.9.9"}) == "9.9.9"


def _fp_custom(name, ver):
    return {"SPDXID": "C-" + name, "name": name, "versionInfo": ver,
            "supplier": "Organization: Baxter", "externalRefs": []}


def _fp_maven(coord, ver):
    group, art = coord.split(":", 1)
    return {"SPDXID": "M-" + coord, "name": coord, "versionInfo": ver,
            "supplier": "Organization: Maven",
            "externalRefs": [{"referenceType": "purl",
                              "referenceLocator": f"pkg:maven/{group}/{art}@{ver}"}]}


def _build(tmp_path, packages):
    sbom = _write_sbom(tmp_path, packages)
    out = str(tmp_path / "out.xlsx")
    build_excel(sbom_path=sbom, template_path=TEMPLATE, output_path=out,
                product_name="P", product_version="1", version_overrides_path=None)
    return _read_data_rows(out)


def test_drops_maven_twin_keeps_principal_unchanged(tmp_path):
    rows = _build(tmp_path, [
        _fp_custom("hel-invalidated-tokens-api", "2.2.4"),
        _fp_maven("biz.videomed.tl4:invalidated-tokens-api", "2.2.4"),
    ])
    names = [r[1] for r in rows]
    assert names == ["hel-invalidated-tokens-api"]
    assert str(rows[0][3]) == "Not applicable***"  # principal row unchanged


def test_keeps_orphan_maven_coordinate_without_principal(tmp_path):
    rows = _build(tmp_path, [
        _fp_maven("biz.videomed:licensing", "0.6.8"),
    ])
    assert [r[1] for r in rows] == ["biz.videomed:licensing"]


def test_keeps_twins_with_different_versions(tmp_path):
    rows = _build(tmp_path, [
        _fp_custom("hel-nms-broker-api", "0.10.5"),
        _fp_maven("biz.videomed.nexxis:nms-broker-api", "0.10.1"),
    ])
    assert len(rows) == 2


def test_does_not_touch_oss_with_same_artifact(tmp_path):
    rows = _build(tmp_path, [
        {"SPDXID": "A", "name": "foo", "versionInfo": "1.0.0",
         "supplier": "Organization: npm", "externalRefs": []},
        {"SPDXID": "B", "name": "com.example:foo", "versionInfo": "1.0.0",
         "supplier": "Organization: Maven",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:maven/com.example/foo@1.0.0"}]},
    ])
    assert len(rows) == 2


def test_build_excel_applies_eol_date(tmp_path):
    packages = [
        {"SPDXID": "SPDXRef-react", "name": "react", "versionInfo": "18.2.0",
         "supplier": "Organization: npm",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:npm/react@18.2.0"}]},
        {"SPDXID": "SPDXRef-oss2", "name": "leftpad", "versionInfo": "1.0.0",
         "supplier": "Organization: npm", "externalRefs": []},
        {"SPDXID": "SPDXRef-fp", "name": "hel-thing", "versionInfo": "2.0.0",
         "supplier": "Organization: Baxter", "externalRefs": []},
    ]
    sbom = _write_sbom(tmp_path, packages)
    eol_path = tmp_path / "eol_data.json"
    eol_path.write_text(json_module.dumps({"eol": {"SPDXRef-react": "2026-04-30"}}))
    out = str(tmp_path / "out.xlsx")

    build_excel(sbom_path=sbom, template_path=TEMPLATE, output_path=out,
                product_name="P", product_version="1",
                eol_data_path=str(eol_path))

    rows = {r[1]: r[7] for r in _read_data_rows(out)}
    assert rows["react"] == "2026-04-30"                     # resolved OSS
    assert rows["leftpad"] == "N/A*"                         # unresolved OSS
    assert rows["hel-thing"] == "N/A - Internally Developed" # first-party


def test_build_excel_collapses_aliased_first_party_twins(tmp_path):
    packages = [
        {"SPDXID": "SPDXRef-hel", "name": "hel-app",
         "versionInfo": "1.15.6", "supplier": "Organization: Baxter",
         "externalRefs": []},
        {"SPDXID": "SPDXRef-mvn", "name": "biz.videomed.tl4.installer:tl4-app-external",
         "versionInfo": "1.15.6", "supplier": "Organization: Maven",
         "externalRefs": []},
    ]
    sbom = _write_sbom(tmp_path, packages)
    aliases_path = tmp_path / "aliases.json"
    aliases_path.write_text(json_module.dumps({"tl4-app-external": "hel-app"}))
    out = tmp_path / "out.xlsx"
    build_excel(sbom, TEMPLATE, str(out), component_aliases_path=str(aliases_path))

    rows = _read_data_rows(str(out))
    names = [r[1] for r in rows]  # column B = name
    assert names.count("hel-app") == 1
    assert not any(n and "tl4-app-external" in n for n in names)
