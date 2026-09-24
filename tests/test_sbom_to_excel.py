import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbom_to_excel import extract_version_from_download_url


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
