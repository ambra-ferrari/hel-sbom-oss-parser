import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from download_release_sbom import merge_spdx


def test_merge_spdx_adds_baxter_organization_creator():
    doc = {"spdxVersion": "SPDX-2.3", "packages": [], "files": [],
           "relationships": [], "documentDescribes": []}
    merged = merge_spdx([("proj", doc)], "Test Doc")
    assert "Organization: Baxter" in merged["creationInfo"]["creators"]


def test_merge_spdx_preserves_source_tool_version():
    doc = {"spdxVersion": "SPDX-2.3", "packages": [], "files": [],
           "relationships": [], "documentDescribes": [],
           "creationInfo": {"creators": ["Organization: FOSSA",
                                          "Tool: fossa-cli-3.9.44"]}}
    merged = merge_spdx([("proj", doc)], "Test Doc")
    assert "Tool: fossa-cli-3.9.44" in merged["creationInfo"]["creators"]
    assert "Tool: fossa-cli" not in merged["creationInfo"]["creators"]


def test_merge_spdx_falls_back_to_bare_tool_name_without_source_version():
    doc = {"spdxVersion": "SPDX-2.3", "packages": [], "files": [],
           "relationships": [], "documentDescribes": []}
    merged = merge_spdx([("proj", doc)], "Test Doc")
    assert "Tool: fossa-cli" in merged["creationInfo"]["creators"]


from download_release_sbom import purl_to_coordinate


def test_purl_coordinate_maven_uses_group_and_artifact():
    assert purl_to_coordinate(
        "pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.21"
    ) == "com.fasterxml.jackson.core:jackson-annotations"


def test_purl_coordinate_unscoped_npm_is_type_qualified():
    assert purl_to_coordinate("pkg:npm/react-dom@19.2.3") == "npm:react-dom"


def test_purl_coordinate_unscoped_pypi_is_type_qualified():
    assert purl_to_coordinate("pkg:pypi/requests@2.0") == "pypi:requests"


def test_purl_coordinate_scoped_npm_keeps_scope():
    assert purl_to_coordinate("pkg:npm/%40angular/core@1.2.3") == "@angular:core"


def test_purl_coordinate_golang_keeps_namespace():
    assert purl_to_coordinate(
        "pkg:golang/github.com/gorilla/websocket@v1.5.3"
    ) == "github.com/gorilla:websocket"


def test_purl_coordinate_returns_none_for_non_purl():
    assert purl_to_coordinate("not-a-purl") is None
