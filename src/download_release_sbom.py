#!/usr/bin/env python3
"""Download the *aggregated* SBOM of a FOSSA release group release as SPDX-JSON.

The FOSSA CLI (`fossa report attribution`) can only export a single project's
report. A release group release, however, aggregates several projects — and its
combined SBOM is not exposed by the CLI. This script talks to the FOSSA REST API
directly to:

    1. resolve the caller's organization id;
    2. resolve the release group + release (by title, or by numeric ids);
    3. list every project revision belonging to that release;
    4. download each project's SPDX-JSON attribution report; and
    5. merge them into a single, valid SPDX 2.3 JSON document.

The endpoints used are exactly those the open-source FOSSA CLI calls internally
(`/api/cli/organization`, `/api/cli/project_group/release_lookup`,
`/api/project_group/{id}/release`, `/api/revisions/{locator}/attribution/...`).

Only the Python standard library is used — no extra dependencies.

Configuration is read from ./fossa.config (same file used by download_sbom.sh);
the API key is read from $FOSSA_API_KEY or the git-ignored ./.fossa.secret file.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
DEFAULT_CONFIG = PROJECT_ROOT / "fossa.config"
SECRET_FILE = PROJECT_ROOT / ".fossa.secret"


# --------------------------------------------------------------------------- #
# Config / secret loading
# --------------------------------------------------------------------------- #
def load_config(path: Path) -> dict[str, str]:
    """Parse the shell-style KEY="value" fossa.config into a dict."""
    cfg: dict[str, str] = {}
    if not path.is_file():
        return cfg
    line_re = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        cfg[key] = val
    return cfg


def load_api_key() -> str:
    key = os.environ.get("FOSSA_API_KEY", "").strip()
    if key:
        return key
    if SECRET_FILE.is_file():
        for raw in SECRET_FILE.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("FOSSA_API_KEY="):
                line = line[len("FOSSA_API_KEY="):]
            return line.strip()
    die("FOSSA_API_KEY is not set. Export it or add it to " + str(SECRET_FILE))
    return ""  # unreachable


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def die(msg: str) -> None:
    print(f"❌  {msg}", file=sys.stderr)
    sys.exit(1)


def info(msg: str) -> None:
    print(msg, file=sys.stderr)


class FossaClient:
    def __init__(self, endpoint: str, api_key: str, timeout: int = 120) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _get(self, path: str, query: dict[str, str] | None = None) -> Any:
        url = self.endpoint + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            die(f"HTTP {e.code} for {url}\n{detail}")
        except urllib.error.URLError as e:
            die(f"Network error for {url}: {e.reason}")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            die(f"Non-JSON response from {url}:\n{body[:500]}")

    # -- API calls -------------------------------------------------------- #
    def organization_id(self) -> int:
        data = self._get("/api/cli/organization")
        org_id = data.get("organizationId")
        if org_id is None:
            die("Could not read organizationId from /api/cli/organization")
        return int(org_id)

    def resolve_release(self, rg_title: str, release_title: str) -> tuple[int, int]:
        data = self._get(
            "/api/cli/project_group/release_lookup",
            {"releaseGroupTitle": rg_title, "releaseTitle": release_title},
        )
        rg_id = data.get("releaseGroupId")
        rel_id = data.get("releaseId")
        if rg_id is None or rel_id is None:
            die(f"release_lookup did not return ids for "
                f"'{rg_title}' / '{release_title}': {data}")
        return int(rg_id), int(rel_id)

    def release_projects(self, rg_id: int, release_id: int) -> tuple[str, list[dict[str, str]]]:
        releases = self._get(f"/api/project_group/{rg_id}/release")
        if not isinstance(releases, list):
            die(f"Unexpected /release response for group {rg_id}: {releases}")
        match = next((r for r in releases if int(r.get("id", -1)) == release_id), None)
        if match is None:
            available = ", ".join(str(r.get("id")) for r in releases)
            die(f"Release id {release_id} not found in group {rg_id}. "
                f"Available release ids: {available}")
        projects = match.get("projects", [])
        if not projects:
            die(f"Release id {release_id} contains no projects.")
        return match.get("title", str(release_id)), projects

    def project_spdx(self, locator: str, revision_id: str) -> dict[str, Any]:
        # The release API returns projectId (the "fetcher+orgId/project" locator)
        # and revisionId. Depending on the FOSSA version, revisionId is either
        # the bare revision (e.g. "1.2.3") or the *full* revision locator
        # (e.g. "custom+19518/helion/jre$101.17.3"). Normalise to one full
        # "locator$revision" segment, then URL-encode it as a single path part.
        if "$" in revision_id:
            full_locator = revision_id
        elif "$" in locator:
            full_locator = locator
        else:
            full_locator = f"{locator}${revision_id}"
        seg = urllib.parse.quote(full_locator, safe="")
        return self._get(f"/api/revisions/{seg}/attribution/full/SPDX_JSON")


# --------------------------------------------------------------------------- #
# SPDX merge
# --------------------------------------------------------------------------- #
def _remap_id(spdx_id: str, prefix: str) -> str:
    if spdx_id == "SPDXRef-DOCUMENT":
        return spdx_id
    if spdx_id.startswith("SPDXRef-"):
        return f"SPDXRef-{prefix}-" + spdx_id[len("SPDXRef-"):]
    return spdx_id  # e.g. DocumentRef-x:SPDXRef-y — leave untouched


def _project_url(endpoint: str, locator: str, branch: str, revision: str) -> str:
    """Build the FOSSA deep-link URL for a project revision."""
    base = endpoint.rstrip("/")
    loc = urllib.parse.quote(locator, safe="")
    url = f"{base}/projects/{loc}"
    if branch:
        url += f"/refs/branch/{urllib.parse.quote(branch, safe='')}"
        if revision:
            url += f"/{urllib.parse.quote(revision, safe='')}"
    return url


DEFAULT_TEST_PATTERNS = [
    r"testify", r"testcontainers", r"junit", r"mockito", r"hamcrest",
    r"assertj", r"testng", r"mockk", r"\bjest\b", r"\bmocha\b", r"\bchai\b",
    r"\bsinon\b", r"enzyme", r"cypress", r"jasmine", r"\bkarma\b",
    r"pytest", r"jacoco", r"serialtest", r"systemtest",
]


def _package_purl(pkg: dict[str, Any]) -> str:
    for ref in pkg.get("externalRefs", []) or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator", "")
    return ""


def filter_test(
    spdx: dict[str, Any], patterns: list[str]
) -> tuple[dict[str, Any], list[str]]:
    """Drop test-only packages (matched by name/purl against `patterns`).

    FOSSA's SPDX export does not carry dependency scope, and it already omits
    Maven `test`-scope deps. This removes the remaining test artefacts (e.g. Go
    `testify`/`testcontainers`, first-party test modules) that leak in as direct
    dependencies. Returns the pruned doc and the list of removed package names.
    """
    if not patterns:
        return spdx, []
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    removed_ids: set[str] = set()
    removed_names: list[str] = []
    kept_pkgs = []
    for pkg in spdx.get("packages", []) or []:
        haystack = f"{pkg.get('name', '')} {_package_purl(pkg)}"
        if any(c.search(haystack) for c in compiled):
            removed_ids.add(pkg.get("SPDXID", ""))
            removed_names.append(str(pkg.get("name", "")))
        else:
            kept_pkgs.append(pkg)

    if not removed_ids:
        return spdx, []

    out = dict(spdx)
    out["packages"] = kept_pkgs
    out["relationships"] = [
        r for r in spdx.get("relationships", []) or []
        if r.get("spdxElementId") not in removed_ids
        and r.get("relatedSpdxElement") not in removed_ids
    ]
    if "documentDescribes" in out:
        out["documentDescribes"] = [
            d for d in out["documentDescribes"] if d not in removed_ids
        ]
    return out, removed_names


def filter_direct(spdx: dict[str, Any]) -> dict[str, Any]:
    """Reduce a project's SPDX to its root(s) + their *direct* dependencies.

    FOSSA encodes the graph as: SPDXRef-DOCUMENT --DESCRIBES--> <project root>,
    then <root> --DEPENDS_ON--> <dep> for every dependency (direct and, via
    dep->dep edges, transitive). A dependency is *direct* when the project root
    depends on it directly. Everything only reachable through another dependency
    is transitive and is dropped.
    """
    rels = spdx.get("relationships", []) or []
    pkgs = spdx.get("packages", []) or []

    roots: set[str] = {
        r.get("relatedSpdxElement", "")
        for r in rels
        if r.get("relationshipType") == "DESCRIBES"
    }
    roots.update(spdx.get("documentDescribes", []) or [])
    roots.discard("")

    if not roots:
        # No identifiable root — cannot tell direct from transitive; keep as-is.
        return spdx

    direct: set[str] = set()
    for r in rels:
        rtype = r.get("relationshipType")
        if rtype == "DEPENDS_ON" and r.get("spdxElementId") in roots:
            direct.add(r.get("relatedSpdxElement", ""))
        elif rtype == "DEPENDENCY_OF" and r.get("relatedSpdxElement") in roots:
            direct.add(r.get("spdxElementId", ""))
    direct.discard("")

    keep = roots | direct
    new_pkgs = []
    for pkg in pkgs:
        if pkg.get("SPDXID") in keep:
            p = dict(pkg)
            p.pop("hasFiles", None)  # file-level detail is not needed at dep level
            new_pkgs.append(p)

    new_rels = []
    for r in rels:
        rtype = r.get("relationshipType")
        a, b = r.get("spdxElementId"), r.get("relatedSpdxElement")
        if rtype == "DESCRIBES" and b in roots:
            new_rels.append(r)
        elif rtype == "DEPENDS_ON" and a in roots and b in direct:
            new_rels.append(r)
        elif rtype == "DEPENDENCY_OF" and b in roots and a in direct:
            new_rels.append(r)

    out = dict(spdx)
    out["packages"] = new_pkgs
    out["relationships"] = new_rels
    out.pop("files", None)
    if "documentDescribes" in out:
        out["documentDescribes"] = [d for d in out["documentDescribes"] if d in roots]
    return out


def purl_to_coordinate(purl: str) -> str | None:
    """Derive a Maven-style `groupId:artifactId` coordinate from a purl.

    Examples:
      pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.21
          -> com.fasterxml.jackson.core:jackson-annotations
      pkg:golang/github.com/gorilla/websocket@v1.5.3
          -> github.com/gorilla:websocket
      pkg:npm/%40angular/core@1.2.3      -> @angular:core
      pkg:pypi/requests@2.0              -> pypi:requests   (type-qualified)

    When a purl has no namespace (e.g. an unscoped npm/pypi package), the bare
    name alone just repeats the component name and adds no information, so the
    purl *type* (npm, pypi, ...) is used as the qualifier to keep the reference
    meaningful (e.g. `npm:react-dom` rather than `react-dom`).
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:"):]
    # Drop qualifiers (?...), subpath (#...) and version (@...).
    body = body.split("?", 1)[0].split("#", 1)[0]
    body = body.rsplit("@", 1)[0]
    parts = [urllib.parse.unquote(p) for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    # parts[0] is the purl type (maven/npm/golang/...); the rest is namespace* + name.
    purl_type = parts[0]
    namespace = parts[1:-1]
    name = parts[-1]
    if namespace:
        return "/".join(namespace) + ":" + name
    return purl_type + ":" + name


def add_cpe_refs(spdx: dict[str, Any]) -> dict[str, Any]:
    """Expose each package's `groupId:artifactId` coordinate as a CPE-type ref.

    FOSSA packages carry a `purl` but no CPE, so the deliverable's CPE column
    stays empty. This derives a Maven-style `groupId:artifactId` coordinate from
    the purl and records it as a `cpe23Type` external reference (when the package
    has a purl and no CPE yet), so downstream tools that read the CPE field
    surface that reference.
    """
    for pkg in spdx.get("packages", []) or []:
        refs = pkg.get("externalRefs", []) or []
        has_cpe = any(
            str(r.get("referenceType", "")).lower().startswith("cpe") for r in refs
        )
        if has_cpe:
            continue
        purl = next(
            (r.get("referenceLocator") for r in refs
             if r.get("referenceType") == "purl"),
            None,
        )
        coordinate = purl_to_coordinate(purl) if purl else None
        if coordinate:
            pkg["externalRefs"] = list(refs) + [{
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": coordinate,
            }]
    return spdx


def merge_spdx(
    docs: list[tuple[str, dict[str, Any]]],
    doc_name: str,
    projects: list[dict[str, str]] | None = None,
    endpoint: str = "https://app.fossa.com",
) -> dict[str, Any]:
    """Merge several SPDX 2.3 docs into one, namespacing SPDXIDs per source."""
    packages: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    describes: list[str] = []
    spdx_version = "SPDX-2.3"

    for idx, (label, doc) in enumerate(docs):
        prefix = f"P{idx}"
        spdx_version = doc.get("spdxVersion", spdx_version)

        def rm(_id: str) -> str:
            return _remap_id(_id, prefix)

        for pkg in doc.get("packages", []):
            p = dict(pkg)
            p["SPDXID"] = rm(p.get("SPDXID", ""))
            if "hasFiles" in p:
                p["hasFiles"] = [rm(f) for f in p["hasFiles"]]
            packages.append(p)

        for fl in doc.get("files", []):
            f = dict(fl)
            f["SPDXID"] = rm(f.get("SPDXID", ""))
            files.append(f)

        for rel in doc.get("relationships", []):
            r = dict(rel)
            r["spdxElementId"] = rm(r.get("spdxElementId", ""))
            r["relatedSpdxElement"] = rm(r.get("relatedSpdxElement", ""))
            relationships.append(r)

        for d in doc.get("documentDescribes", []):
            mapped = rm(d)
            if mapped not in describes:
                describes.append(mapped)

    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    creation_info: dict[str, Any] = {
        "created": now,
        "creators": [
            "Organization: Baxter",
            "Tool: fossa-cli",
            "Tool: sbom-parser-download_release_sbom",
        ],
    }

    # Record the source projects (and their FOSSA URLs) in the document comment.
    if projects:
        lines = [f"Aggregated from {len(projects)} FOSSA project(s):"]
        for proj in projects:
            locator = proj.get("projectId", "")
            revision = proj.get("revisionId", "")
            branch = proj.get("branch", "")
            url = _project_url(endpoint, locator, branch, revision)
            lines.append(f"- {locator} @ {revision} (branch: {branch or 'n/a'}) — {url}")
        creation_info["comment"] = "\n".join(lines)

    return {
        "spdxVersion": spdx_version,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": f"https://fossa.com/spdx/{uuid.uuid4()}",
        "creationInfo": creation_info,
        "documentDescribes": describes,
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Download & merge a FOSSA release group's aggregated SBOM "
                    "as SPDX-JSON.")
    p.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG,
                   help=f"Path to config file (default: {DEFAULT_CONFIG})")
    p.add_argument("-o", "--output", help="Output SBOM path (overrides config)")
    p.add_argument("--endpoint", help="FOSSA API base URL (overrides config)")
    p.add_argument("--release-group-title", help="Release group title")
    p.add_argument("--release-title", help="Release title")
    p.add_argument("--release-group-id", type=int, help="Numeric release group id")
    p.add_argument("--release-id", type=int, help="Numeric release id")
    dep_grp = p.add_mutually_exclusive_group()
    dep_grp.add_argument("--direct-only", dest="direct_only", action="store_true",
                         default=None,
                         help="Keep only each project's direct dependencies (default)")
    dep_grp.add_argument("--all-deps", dest="direct_only", action="store_false",
                         help="Keep the full graph (direct + transitive dependencies)")
    test_grp = p.add_mutually_exclusive_group()
    test_grp.add_argument("--exclude-test", dest="exclude_test", action="store_true",
                          default=None,
                          help="Drop test-only packages (default)")
    test_grp.add_argument("--include-test", dest="exclude_test", action="store_false",
                          help="Keep test-only packages")
    return p.parse_args()


def pick(*vals: Any) -> Any:
    for v in vals:
        if v is not None and str(v).strip() != "":
            return v
    return None


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    if not args.config.is_file():
        die(f"Config file not found: {args.config}")

    endpoint = pick(args.endpoint, cfg.get("FOSSA_ENDPOINT"), "https://app.fossa.com")
    output = pick(args.output, cfg.get("RELEASE_SBOM_OUTPUT"), "sbom_new.json")
    rg_title = pick(args.release_group_title, cfg.get("FOSSA_RELEASE_GROUP_TITLE"))
    rel_title = pick(args.release_title, cfg.get("FOSSA_RELEASE_TITLE"))
    rg_id = pick(args.release_group_id, cfg.get("FOSSA_RELEASE_GROUP_ID"))
    rel_id = pick(args.release_id, cfg.get("FOSSA_RELEASE_ID"))

    # Direct-only is the default; config DIRECT_ONLY / --all-deps can turn it off.
    if args.direct_only is not None:
        direct_only = args.direct_only
    else:
        direct_only = str(cfg.get("DIRECT_ONLY", "true")).strip().lower() \
            not in ("false", "0", "no", "off")

    if args.exclude_test is not None:
        exclude_test = args.exclude_test
    else:
        exclude_test = str(cfg.get("EXCLUDE_TEST", "true")).strip().lower() \
            not in ("false", "0", "no", "off")
    test_patterns = list(DEFAULT_TEST_PATTERNS)
    extra = cfg.get("TEST_PATTERNS", "").strip()
    if extra:
        test_patterns += [p.strip() for p in extra.split(",") if p.strip()]

    api_key = load_api_key()
    client = FossaClient(endpoint, api_key)

    # Resolve the release group + release ids.
    if rg_id and rel_id:
        rg_id, rel_id = int(rg_id), int(rel_id)
        info(f"⬇️   Using release group id {rg_id}, release id {rel_id}")
    elif rg_title and rel_title:
        info(f"⬇️   Resolving release '{rel_title}' in group '{rg_title}' ...")
        rg_id, rel_id = client.resolve_release(rg_title, rel_title)
        info(f"     → release group id {rg_id}, release id {rel_id}")
    else:
        die("Specify the release either by title "
            "(FOSSA_RELEASE_GROUP_TITLE + FOSSA_RELEASE_TITLE) or by numeric ids "
            "(FOSSA_RELEASE_GROUP_ID + FOSSA_RELEASE_ID), via config or flags.")

    resolved_release_title, projects = client.release_projects(rg_id, rel_id)
    if not rel_title:
        rel_title = resolved_release_title
    info(f"     release '{resolved_release_title}' contains {len(projects)} project(s)")

    mode = "direct dependencies only" if direct_only else "all dependencies (direct + transitive)"
    info(f"     mode: {mode}")
    if exclude_test:
        info("     excluding test-only packages")

    docs: list[tuple[str, dict[str, Any]]] = []
    removed_test: list[str] = []
    for proj in projects:
        locator = proj.get("projectId", "")
        revision = proj.get("revisionId", "")
        if not locator or not revision:
            info(f"     ⚠️  skipping project with missing locator/revision: {proj}")
            continue
        info(f"     • {locator} @ {revision}")
        spdx = client.project_spdx(locator, revision)
        if direct_only:
            spdx = filter_direct(spdx)
        if exclude_test:
            spdx, removed = filter_test(spdx, test_patterns)
            removed_test.extend(removed)
        add_cpe_refs(spdx)
        docs.append((locator, spdx))

    if not docs:
        die("No project SBOMs could be downloaded.")

    total_pkgs = sum(len(d.get("packages", [])) for _, d in docs)
    doc_name = " / ".join(filter(None, [str(rg_title or rg_id), str(rel_title or rel_id)]))
    merged = merge_spdx(docs, f"{doc_name} (aggregated)", projects=projects, endpoint=endpoint)

    out_path = Path(output)
    out_path.write_text(json.dumps(merged, indent=2))
    if removed_test:
        uniq = sorted(set(removed_test))
        info(f"     excluded {len(removed_test)} test package(s) "
             f"({len(uniq)} unique): {', '.join(uniq)}")
    info(f"✅  Aggregated {len(docs)} project SBOM(s), "
         f"{total_pkgs} packages → {out_path}")


if __name__ == "__main__":
    main()
