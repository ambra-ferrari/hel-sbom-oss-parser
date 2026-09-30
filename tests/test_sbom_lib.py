import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sbom_lib import (
    canonical_component_name,
    load_component_aliases,
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
