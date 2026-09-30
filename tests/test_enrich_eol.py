import json as _json

import enrich_eol


def _pkg(name, purl=None):
    pkg = {"name": name, "externalRefs": []}
    if purl:
        pkg["externalRefs"].append(
            {"referenceType": "purl", "referenceLocator": purl}
        )
    return pkg


def test_candidate_tokens_maven_coordinate():
    pkg = _pkg("com.fasterxml.jackson.core:jackson-annotations")
    tokens = enrich_eol.candidate_tokens(pkg)
    assert "jackson-annotations" in tokens


def test_candidate_tokens_scoped_npm():
    pkg = _pkg("@angular/core", "pkg:npm/%40angular/core@16.0.0")
    tokens = enrich_eol.candidate_tokens(pkg)
    assert "core" in tokens
    assert "@angular/core" in tokens


def test_candidate_tokens_golang_path():
    pkg = _pkg("github.com/gorilla/websocket", "pkg:golang/github.com/gorilla/websocket@v1.5.3")
    tokens = enrich_eol.candidate_tokens(pkg)
    assert "websocket" in tokens


def test_candidate_tokens_are_lowercased_and_unique():
    pkg = _pkg("React-DOM")
    tokens = enrich_eol.candidate_tokens(pkg)
    assert tokens == ["react-dom"]


def _products():
    return [
        {"name": "react", "aliases": ["reactjs"]},
        {"name": "postgresql", "aliases": ["postgres"]},
        {"name": "angular", "aliases": []},
    ]


def test_build_slug_index_includes_names_and_aliases():
    index = enrich_eol.build_slug_index(_products())
    assert index["react"] == "react"
    assert index["reactjs"] == "react"
    assert index["postgres"] == "postgresql"


def test_match_product_first_token_wins():
    index = enrich_eol.build_slug_index(_products())
    product, token = enrich_eol.match_product(["websocket", "react"], index)
    assert product == "react"
    assert token == "react"


def test_match_product_no_match():
    index = enrich_eol.build_slug_index(_products())
    product, token = enrich_eol.match_product(["nothing", "here"], index)
    assert product is None
    assert token is None


def test_match_product_dash_prefix_fallback():
    # 'spring-boot-starter-actuator' has no exact slug, but its 'spring-boot'
    # dash-prefix matches; the returned token is the full original token.
    index = enrich_eol.build_slug_index([{"name": "spring-boot", "aliases": []}])
    product, token = enrich_eol.match_product(["spring-boot-starter-actuator"], index)
    assert product == "spring-boot"
    assert token == "spring-boot-starter-actuator"


def test_match_product_dash_prefix_prefers_longest():
    # Both 'spring' and 'spring-boot' are slugs; the longer prefix wins.
    index = enrich_eol.build_slug_index([
        {"name": "spring-framework", "aliases": ["spring"]},
        {"name": "spring-boot", "aliases": []},
    ])
    product, token = enrich_eol.match_product(["spring-boot-starter-web"], index)
    assert product == "spring-boot"


def test_match_product_exact_beats_prefix():
    # An exact match on an earlier token takes precedence over a prefix match.
    index = enrich_eol.build_slug_index([
        {"name": "spring-boot", "aliases": []},
        {"name": "react", "aliases": []},
    ])
    product, token = enrich_eol.match_product(["react", "spring-boot-starter"], index)
    assert product == "react"
    assert token == "react"


def _releases():
    return [
        {"name": "1"},
        {"name": "1.20"},
        {"name": "18"},
    ]


def test_match_cycle_prefix_match():
    rel = enrich_eol.match_cycle("18.2.0", _releases())
    assert rel["name"] == "18"


def test_match_cycle_prefers_longest_cycle():
    rel = enrich_eol.match_cycle("1.20.4", _releases())
    assert rel["name"] == "1.20"


def test_match_cycle_segment_boundary():
    # cycle "1" must not match version "18.0.0" (segment-wise, not string-wise)
    rel = enrich_eol.match_cycle("18.0.0", [{"name": "1"}])
    assert rel is None


def test_match_cycle_no_match():
    assert enrich_eol.match_cycle("9.9.9", _releases()) is None


def test_release_date_prefers_eol():
    date, field = enrich_eol.release_date({"eolFrom": "2026-04-30", "eoasFrom": "2025-01-01"})
    assert date == "2026-04-30"
    assert field == "eol"


def test_release_date_falls_back_to_eoas():
    date, field = enrich_eol.release_date({"eolFrom": None, "eoasFrom": "2025-01-01"})
    assert date == "2025-01-01"
    assert field == "eoas"


def test_release_date_none_when_both_missing():
    date, field = enrich_eol.release_date({"eolFrom": None, "eoasFrom": None})
    assert date is None
    assert field is None


def _detail_fetcher(details):
    """Return a fetcher that yields details[name] or None, tracking calls."""
    calls = []

    def fetch(name):
        calls.append(name)
        return details.get(name)

    fetch.calls = calls
    return fetch


def test_resolve_library_full_path():
    index = enrich_eol.build_slug_index([{"name": "react", "aliases": []}])
    fetcher = _detail_fetcher({"react": {"releases": [{"name": "18", "eolFrom": "2026-04-30"}]}})
    pkg = _pkg("react", "pkg:npm/react@18.2.0")
    res = enrich_eol.resolve_library(pkg, "18.2.0", index, fetcher)
    assert res == {
        "product": "react",
        "token": "react",
        "cycle": "18",
        "date": "2026-04-30",
        "field": "eol",
        "kind": "exact",
    }


def test_resolve_library_unmatched_product_skips_fetch():
    index = enrich_eol.build_slug_index([{"name": "react", "aliases": []}])
    fetcher = _detail_fetcher({})
    res = enrich_eol.resolve_library(_pkg("leftpad"), "1.0.0", index, fetcher)
    assert res is None
    assert fetcher.calls == []


def test_resolve_library_no_cycle_returns_none():
    index = enrich_eol.build_slug_index([{"name": "react", "aliases": []}])
    fetcher = _detail_fetcher({"react": {"releases": [{"name": "18", "eolFrom": "2026-04-30"}]}})
    res = enrich_eol.resolve_library(_pkg("react"), "99.0.0", index, fetcher)
    assert res is None


def test_resolve_library_detail_none_returns_none():
    index = enrich_eol.build_slug_index([{"name": "react", "aliases": []}])
    fetcher = _detail_fetcher({"react": None})
    res = enrich_eol.resolve_library(_pkg("react"), "18.2.0", index, fetcher)
    assert res is None


def test_false_positive_scoped_npm():
    assert enrich_eol.is_false_positive(_pkg("@emotion/react"), "react") is True


def test_false_positive_driver_segment():
    assert enrich_eol.is_false_positive(_pkg("gorm.io/driver/postgres"), "postgres") is True


def test_false_positive_exact_name_not_flagged():
    assert enrich_eol.is_false_positive(_pkg("react"), "react") is False


def test_false_positive_plain_differs_not_flagged():
    # token differs but no scope / distinguishing segment -> not flagged
    assert enrich_eol.is_false_positive(_pkg("react-dom"), "react") is False


def test_false_negative_angular_core():
    index = enrich_eol.build_slug_index([{"name": "angular", "aliases": []}])
    assert enrich_eol.false_negative_slug(_pkg("@angular/core"), index) == "angular"


def test_false_negative_ignores_short_slugs():
    index = enrich_eol.build_slug_index([{"name": "go", "aliases": []}])
    # 'go' is < 4 chars -> not flagged even though it appears
    assert enrich_eol.false_negative_slug(_pkg("gorm.io/go/thing"), index) is None


def test_false_negative_none_when_no_slug_segment():
    index = enrich_eol.build_slug_index([{"name": "angular", "aliases": []}])
    assert enrich_eol.false_negative_slug(_pkg("leftpad"), index) is None

def test_enrich_end_to_end_in_memory():
    products = [
        {"name": "react", "aliases": []},
        {"name": "angular", "aliases": []},
    ]
    details = {"react": {"releases": [
        {"name": "18", "eolFrom": "2026-04-30"},
        {"name": "11", "eolFrom": "2023-06-01"},
    ]}}
    fetcher = _detail_fetcher(details)
    packages = [
        {"SPDXID": "SPDXRef-react", "name": "react", "versionInfo": "18.2.0",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/react@18.2.0"}]},
        {"SPDXID": "SPDXRef-emotion", "name": "@emotion/react", "versionInfo": "11.0.0",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/%40emotion/react@11.0.0"}]},
        {"SPDXID": "SPDXRef-ngcore", "name": "@angular/core", "versionInfo": "16.0.0",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/%40angular/core@16.0.0"}]},
        {"SPDXID": "SPDXRef-fp", "name": "hel-internal", "versionInfo": "1.0.0",
         "supplier": "Organization: Baxter", "externalRefs": []},
    ]
    result = enrich_eol.enrich(packages, products, fetcher, version_overrides={})
    # react resolves to its own cycle 18 and is applied. @emotion/react also
    # matches react (cycle 11) but via the weak scoped-npm token, so it is a
    # suspected false positive: reported but NOT applied to the deliverable.
    assert result["eol"] == {
        "SPDXRef-react": "2026-04-30",
    }
    # first-party package is skipped entirely
    assert "SPDXRef-fp" not in result["eol"]
    assert "SPDXRef-emotion" not in result["eol"]
    # @emotion/react is a suspected false positive (matched via scoped-npm token)
    assert any(row[0] == "@emotion/react" for row in result["false_positives"])
    # a false positive is not listed among the applied/resolved rows
    assert all(row[0] != "@emotion/react" for row in result["resolved"])
    # @angular/core is unresolved (angular has no detail here) and a suspected false negative
    assert any(row[0] == "@angular/core" for row in result["false_negatives"])
    # resolved rows carry name/version/product/cycle/date/field
    react_row = next(r for r in result["resolved"] if r[0] == "react")
    assert react_row == ("react", "18.2.0", "react", "18", "2026-04-30", "eol")


def test_enrich_npm_dash_prefix_is_false_positive_not_applied():
    # electron-log is an npm companion package that matches 'electron' only via
    # a dash-prefix; it must be flagged and NOT applied, even though Electron
    # historically had a cycle '5' with a date.
    products = [{"name": "electron", "aliases": []}]
    details = {"electron": {"releases": [{"name": "5", "eolFrom": "2020-02-03"}]}}
    fetcher = _detail_fetcher(details)
    packages = [
        {"SPDXID": "SPDXRef-elog", "name": "electron-log", "versionInfo": "5.4.4",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:npm/electron-log@5.4.4"}]},
    ]
    result = enrich_eol.enrich(packages, products, fetcher, version_overrides={})
    assert result["eol"] == {}
    assert any(row[0] == "electron-log" for row in result["false_positives"])


def test_enrich_maven_dash_prefix_is_applied():
    # spring-boot-starter-actuator (Maven) matches 'spring-boot' via dash-prefix
    # and IS applied: non-npm family artifacts carry a confirming namespace.
    products = [{"name": "spring-boot", "aliases": []}]
    details = {"spring-boot": {"releases": [{"name": "4.1", "eolFrom": "2027-07-31"}]}}
    fetcher = _detail_fetcher(details)
    packages = [
        {"SPDXID": "SPDXRef-sb", "name": "spring-boot-starter-actuator", "versionInfo": "4.1.1",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:maven/org.springframework.boot/spring-boot-starter-actuator@4.1.1"}]},
    ]
    result = enrich_eol.enrich(packages, products, fetcher, version_overrides={})
    assert result["eol"] == {"SPDXRef-sb": "2027-07-31"}
    assert result["false_positives"] == []


def test_write_eol_data(tmp_path):
    out = tmp_path / "eol_data.json"
    enrich_eol.write_eol_data(str(out), {"SPDXRef-react": "2026-04-30"})
    data = _json.loads(out.read_text())
    assert data["eol"] == {"SPDXRef-react": "2026-04-30"}
    assert data["source"] == "endoflife.date/api/v1"
    assert "generated_at" in data


def test_write_report_has_three_sections(tmp_path):
    out = tmp_path / "eol_report.md"
    result = {
        "eol": {"SPDXRef-react": "2026-04-30"},
        "resolved": [("react", "18.2.0", "react", "18", "2026-04-30", "eol")],
        "false_positives": [("@emotion/react", "11.0.0", "react", "react")],
        "false_negatives": [("@angular/core", "16.0.0", "angular")],
    }
    enrich_eol.write_report(str(out), result)
    text = out.read_text()
    assert "## Resolved matches" in text
    assert "## Suspected false positives" in text
    assert "## Suspected false negatives" in text
    assert "react" in text
    assert "@angular/core" in text


def test_fetch_json_retries_then_succeeds(monkeypatch):
    attempts = {"n": 0}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout=None):
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise enrich_eol.urllib.error.URLError("boom")
        return _Resp()

    monkeypatch.setattr(enrich_eol.urllib.request, "urlopen", fake_urlopen)
    # json.load reads from the response object; give it a .read that json can use
    monkeypatch.setattr(enrich_eol.json, "load", lambda fp: {"ok": True})
    result = enrich_eol.fetch_json("https://example.test/x", timeout=1, retries=2)
    assert result == {"ok": True}
    assert attempts["n"] == 2


def test_fetch_json_raises_after_exhausting_retries(monkeypatch):
    def always_fail(req, timeout=None):
        raise enrich_eol.urllib.error.URLError("down")

    monkeypatch.setattr(enrich_eol.urllib.request, "urlopen", always_fail)
    try:
        enrich_eol.fetch_json("https://example.test/x", timeout=1, retries=1)
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass

def test_load_overrides_missing_path_returns_empty():
    assert enrich_eol.load_overrides(None) == {}


def test_load_overrides_missing_file_returns_empty(tmp_path):
    assert enrich_eol.load_overrides(str(tmp_path / "nope.json")) == {}


def test_load_overrides_parses_entries(tmp_path):
    p = tmp_path / "ovr.json"
    p.write_text(_json.dumps({"overrides": [
        {"name": "Keycloak", "date": "2027-03-31", "reason": "major 26"},
        {"name": "Foo"},
    ]}), encoding="utf-8")
    ovr = enrich_eol.load_overrides(str(p))
    # keyed by normalized (lowercased, stripped) name
    assert ovr["keycloak"] == {"date": "2027-03-31", "reason": "major 26"}
    # entry without a date is ignored
    assert "foo" not in ovr


def test_load_overrides_reason_defaults_to_empty(tmp_path):
    p = tmp_path / "ovr.json"
    p.write_text(_json.dumps({"overrides": [
        {"name": "Keycloak", "date": "2027-03-31"},
    ]}), encoding="utf-8")
    assert enrich_eol.load_overrides(str(p))["keycloak"] == {
        "date": "2027-03-31", "reason": ""}


def test_load_overrides_ignores_non_dict_entries(tmp_path):
    p = tmp_path / "ovr.json"
    p.write_text(_json.dumps({"overrides": ["keycloak", 42,
        {"name": "Keycloak", "date": "2027-03-31"}]}), encoding="utf-8")
    ovr = enrich_eol.load_overrides(str(p))
    assert ovr == {"keycloak": {"date": "2027-03-31", "reason": ""}}


def test_load_overrides_non_list_overrides_returns_empty(tmp_path):
    p = tmp_path / "ovr.json"
    p.write_text(_json.dumps({"overrides": "keycloak"}), encoding="utf-8")
    assert enrich_eol.load_overrides(str(p)) == {}


def test_enrich_override_replaces_computed_date():
    # keycloak would resolve to cycle 26.6 -> 2026-07-09, but the override wins.
    products = [{"name": "keycloak", "aliases": []}]
    details = {"keycloak": {"releases": [
        {"name": "26.6", "eolFrom": "2026-07-09"},
        {"name": "26.5", "eolFrom": "2026-04-08"},
    ]}}
    fetcher = _detail_fetcher(details)
    packages = [
        {"SPDXID": "SPDXRef-kc", "name": "Keycloak", "versionInfo": "26.6.1",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:maven/org.keycloak/keycloak-parent@26.6.1"}]},
    ]
    overrides = {"keycloak": {"date": "2027-03-31", "reason": "major 26"}}
    result = enrich_eol.enrich(packages, products, fetcher,
                               version_overrides={}, overrides=overrides)
    assert result["eol"] == {"SPDXRef-kc": "2027-03-31"}
    assert result["overrides"] == [("Keycloak", "26.6.1", "2027-03-31", "major 26")]
    # not double-counted as a normal resolved row
    assert all(row[0] != "Keycloak" for row in result["resolved"])


def test_enrich_override_forces_date_when_unresolved():
    # No endoflife product at all, but the override still applies (force).
    products = []
    fetcher = _detail_fetcher({})
    packages = [
        {"SPDXID": "SPDXRef-kc", "name": "Keycloak", "versionInfo": "26.6.1",
         "externalRefs": []},
    ]
    overrides = {"keycloak": {"date": "2027-03-31", "reason": ""}}
    result = enrich_eol.enrich(packages, products, fetcher,
                               version_overrides={}, overrides=overrides)
    assert result["eol"] == {"SPDXRef-kc": "2027-03-31"}
    assert result["overrides"] == [("Keycloak", "26.6.1", "2027-03-31", "")]
    # an override is never reported as a false negative
    assert result["false_negatives"] == []


def test_enrich_override_is_case_insensitive():
    products = []
    fetcher = _detail_fetcher({})
    packages = [
        {"SPDXID": "SPDXRef-kc", "name": "KEYCLOAK", "versionInfo": "26.6.1",
         "externalRefs": []},
    ]
    overrides = {"keycloak": {"date": "2027-03-31", "reason": ""}}
    result = enrich_eol.enrich(packages, products, fetcher,
                               version_overrides={}, overrides=overrides)
    assert result["eol"] == {"SPDXRef-kc": "2027-03-31"}


def test_enrich_without_overrides_unchanged():
    products = [{"name": "keycloak", "aliases": []}]
    details = {"keycloak": {"releases": [{"name": "26.6", "eolFrom": "2026-07-09"}]}}
    fetcher = _detail_fetcher(details)
    packages = [
        {"SPDXID": "SPDXRef-kc", "name": "Keycloak", "versionInfo": "26.6.1",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:maven/org.keycloak/keycloak-parent@26.6.1"}]},
    ]
    result = enrich_eol.enrich(packages, products, fetcher, version_overrides={})
    assert result["eol"] == {"SPDXRef-kc": "2026-07-09"}
    assert result["overrides"] == []


def test_enrich_override_tolerates_null_name():
    # A package with an explicit null name must not crash the override lookup.
    products = []
    fetcher = _detail_fetcher({})
    packages = [
        {"SPDXID": "SPDXRef-x", "name": None, "versionInfo": "1.0.0",
         "externalRefs": []},
    ]
    overrides = {"keycloak": {"date": "2027-03-31", "reason": ""}}
    result = enrich_eol.enrich(packages, products, fetcher,
                               version_overrides={}, overrides=overrides)
    assert result["eol"] == {}
    assert result["overrides"] == []


def test_write_report_lists_overrides(tmp_path):
    result = {
        "resolved": [], "false_positives": [], "false_negatives": [],
        "overrides": [("Keycloak", "26.6.1", "2027-03-31", "major 26")],
    }
    out = tmp_path / "report.md"
    enrich_eol.write_report(str(out), result)
    text = out.read_text(encoding="utf-8")
    assert "## Applied overrides" in text
    assert "| Keycloak | 26.6.1 | 2027-03-31 | major 26 |" in text
