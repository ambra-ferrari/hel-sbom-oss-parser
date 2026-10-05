"""
sbom_lib.py — SBOM-parsing helpers shared by sbom_to_excel.py and
sbom_to_oss_dependencies.py.

These are pure functions with no knowledge of any particular xlsx template;
they only understand SPDX 2.3 JSON package dicts.
"""

import collections
import json
import os
import re
import sys
from copy import copy


# Canonical SPDX casing for the license families FOSSA emits as LicenseRef-*.
_LICENSE_CANONICAL = {
    "mit": "MIT",
    "isc": "ISC",
    "zlib": "Zlib",
    "0bsd": "0BSD",
    "apache-2.0": "Apache-2.0",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "cc0-1.0": "CC0-1.0",
    "cc-by-4.0": "CC-BY-4.0",
    "ofl-1.1": "OFL-1.1",
    "mpl-1.1": "MPL-1.1",
    "ms-pl": "MS-PL",
    "ms-net": "MS-NET",
    "epl-1.0": "EPL-1.0",
    "epl-2.0": "EPL-2.0",
    "cddl-1.0": "CDDL-1.0",
    "cddl-1.1": "CDDL-1.1",
    "lgpl-3.0-only": "LGPL-3.0-only",
    "gpl-1.0-only": "GPL-1.0-only",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "postgresql": "PostgreSQL",
    "bouncycastle": "BouncyCastle",
    "apache-2.0-with-llvm-exception": "Apache-2.0 WITH LLVM-exception",
}

_LICENSEREF_HASH = re.compile(r"-\d{6,}$")


def _canonical_license_body(body: str) -> str:
    """Map a stripped LicenseRef body to canonical SPDX casing, else return as-is."""
    key = body.lower()
    if key in _LICENSE_CANONICAL:
        return _LICENSE_CANONICAL[key]
    if "-WITH-" in body:
        left, right = body.split("-WITH-", 1)
        return f"{_canonical_license_body(left)} WITH {right}"
    return body


def normalize_license(expr):
    """Normalize a FOSSA license expression to clean SPDX identifiers.

    Strips the opaque `LicenseRef-` prefix and any trailing `-<hash>` that FOSSA
    appends, canonicalizes casing for known SPDX families, and preserves the
    `OR` / `AND` / `WITH` operators and plain SPDX tokens untouched. Returns the
    input unchanged for falsy values.
    """
    if not expr:
        return expr
    out = []
    for token in expr.split():
        if token.startswith("LicenseRef-"):
            body = _LICENSEREF_HASH.sub("", token[len("LicenseRef-"):])
            out.append(_canonical_license_body(body))
        else:
            out.append(token)
    return " ".join(out)


_EMOJI_PATTERN = re.compile(
    "["
    "\U0001F300-\U0001FAFF"  # pictographs, emoticons, transport/map, supplemental, extended-A
    "\U00002600-\U000026FF"  # misc symbols
    "\U00002700-\U000027BF"  # dingbats
    "\U0001F1E6-\U0001F1FF"  # regional indicator (flag) letters
    "\uFE0F"                  # variation selector-16 (emoji presentation)
    "\u200d"                  # zero-width joiner (emoji sequences)
    "]+",
    flags=re.UNICODE,
)


def normalize_purpose_text(text: str | None) -> str:
    """Clean up a package's "Purpose" text for the OSS deps deliverable.

    Removes emoji/pictograph characters (some upstream package summaries lead
    with a decorative emoji) and strips useless leading/trailing whitespace
    (including the newlines + indentation some SBOM summaries carry from
    multi-line source doc-comments). Returns "" for falsy input.
    """
    if not text:
        return ""
    cleaned = _EMOJI_PATTERN.sub(" ", text)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    return cleaned.strip()


def load_package_overrides(path: str | None) -> dict[str, dict]:
    """Load curated per-package overrides, keyed by normalized name.

    Reads {"overrides": [{"name", "license"?, "purpose"?, "reference"?, ...}, ...]}
    and returns {name.lower().strip(): entry_dict}. Entries without a usable name
    are ignored. Missing path or absent file returns {} — overrides are optional.
    This is the single source consumed to derive the license/purpose/reference
    override maps.
    """
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            sys.exit(f"package-overrides file is not valid JSON: {path} ({exc})")
    out: dict[str, dict] = {}
    raw = data.get("overrides") if isinstance(data, dict) else None
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        if name:
            out[name.lower()] = entry
    return out


def _override_field_map(path: str | None, field: str) -> dict[str, str]:
    """Map of {name: <field>} for override entries that define a non-empty field."""
    out: dict[str, str] = {}
    for name, entry in load_package_overrides(path).items():
        value = str(entry.get(field, "")).strip()
        if value:
            out[name] = value
    return out


def load_license_overrides(path: str | None) -> dict[str, str]:
    """Curated per-package license overrides: {name.lower().strip(): license}.
    Derived from load_package_overrides(); entries without a license are skipped.
    """
    return _override_field_map(path, "license")


def load_purpose_overrides(path: str | None) -> dict[str, str]:
    """Curated per-package purpose overrides: {name.lower().strip(): purpose}."""
    return _override_field_map(path, "purpose")


def load_reference_overrides(path: str | None) -> dict[str, str]:
    """Curated per-package reference overrides: {name.lower().strip(): reference}."""
    return _override_field_map(path, "reference")


def load_vendor_overrides(path: str | None) -> dict[str, str]:
    """Curated per-package vendor overrides: {name.lower().strip(): vendor}."""
    return _override_field_map(path, "vendor")


def _short_artifact_name(name: str) -> str:
    """Last path segment of a package name: the part after the final ':' or '/'.

    'biz.videomed.tl4.installer:tl4-app-external' -> 'tl4-app-external'
    'github.com/golang-jwt/jwt/v5'               -> 'v5'
    'hel-app'                                     -> 'hel-app'
    """
    seg = (name or "").strip()
    for sep in (":", "/"):
        if sep in seg:
            seg = seg.rsplit(sep, 1)[-1]
    return seg


def load_component_aliases(path: str | None) -> dict[str, str]:
    """Load a curated {alias short-name: canonical name} map.

    JSON shape: {"<alias>": "<canonical>", ...}. Keys are lowercased/stripped
    for case-insensitive matching against a package's short artifact name.
    Returns {} when no path is given or the file is absent — the alias map is
    optional and the parser stays fully offline. Exits with a clear error if a
    given path is not valid JSON, so a typo can't be silently ignored.
    """
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            sys.exit(f"component-aliases file is not valid JSON: {path} ({exc})")
    if not isinstance(data, dict):
        return {}
    return {
        str(k).strip().lower(): str(v).strip()
        for k, v in data.items()
        if str(k).strip() and str(v).strip()
    }


def canonical_component_name(name: str, aliases: dict[str, str]) -> str:
    """Canonical internal-component name for `name`.

    Looks up the package's short artifact name (case-insensitive) in the curated
    alias map and returns the mapped canonical name; unmapped names are returned
    unchanged. Collapses the two representations of the same first-party
    component (e.g. 'biz.videomed…:tl4-app-external' and 'hel-app').
    """
    if not aliases:
        return name
    key = _short_artifact_name(name).lower()
    return aliases.get(key, name)


def first_party_artifact_key(name: str) -> str:
    """Case-insensitive grouping key for a first-party component name.

    Strips the Maven group id (everything up to and including the last `:`)
    or the `hel-` prefix, leaving the bare artifact id. Two spellings of the
    same internal component that share this key and version (e.g.
    'biz.videomed.tl4:invalidated-tokens-api' and 'hel-invalidated-tokens-api')
    are the same artifact and should be treated as duplicates, independent of
    any curated alias entry.
    """
    if ":" in name:
        art = name.rsplit(":", 1)[-1]
    elif name.lower().startswith("hel-"):
        art = name[len("hel-"):]
    else:
        art = name
    return art.strip().lower()


def is_incomplete_dependency(pkg: dict) -> bool:
    """
    FOSSA emits placeholder packages (comment == "Incomplete dependency",
    downloadLocation/versionInfo both "NOASSERTION") for URLs it couldn't
    fully resolve. These duplicate a real package entry that already
    carries the actual version info (e.g. the JRE/MongoDB zip is described
    both by a proper package and by one of these placeholders sharing the
    same file name) and must be excluded from the SBOM output.
    """
    return pkg.get("comment") == "Incomplete dependency"


def is_first_party(pkg: dict) -> bool:
    """Internally-developed (Baxter) components.

    Markers, depending on the SBOM source:
    - supplier `Custom (provided build)` — single-project FOSSA exports;
    - supplier `Organization: Baxter`    — release-group aggregate exports;
    - a `biz.videomed` group id in the name/purl — first-party libraries
      published under Baxter's Videomed group.
    """
    supplier = (pkg.get("supplier") or "").lower()
    if "custom (provided build)" in supplier or "baxter" in supplier:
        return True
    haystack = (pkg.get("name") or "")
    for ref in pkg.get("externalRefs", []) or []:
        haystack += " " + str(ref.get("referenceLocator", ""))
    return "biz.videomed" in haystack.lower()


def apply_component_aliases(spdx: dict, aliases: dict[str, str]) -> dict:
    """Return a copy of an SPDX doc with first-party package names canonicalized.

    Renames each first-party package's `name` via `canonical_component_name`
    so the raw SPDX JSON stays consistent with the generated Excel
    deliverables (which already display the canonical `hel-*` name). OSS
    (third-party) packages and all other top-level SPDX fields are left
    untouched. The input doc is not mutated.
    """
    out = dict(spdx)
    new_packages = []
    for pkg in spdx.get("packages", []) or []:
        pkg = dict(pkg)
        if is_first_party(pkg):
            pkg["name"] = canonical_component_name(pkg.get("name", ""), aliases)
        new_packages.append(pkg)
    out["packages"] = new_packages
    return out


def dedupe_first_party_packages(spdx: dict) -> dict:
    """Return a copy of an SPDX doc with generic first-party name-twins removed.

    Groups first-party packages by (first_party_artifact_key, version); for any
    group containing a 'hel-*' named package alongside one or more non-'hel-*'
    twins at the SAME version, drops the non-'hel-*' duplicates (no renaming —
    the surviving package keeps its original name). Relationships referencing a
    removed package are repointed to the surviving package's SPDXID; any
    relationship that becomes a self-loop as a result (or an exact duplicate of
    another relationship) is dropped. OSS packages, groups without a 'hel-*'
    member, and groups whose versions differ are left untouched. The input doc
    is not mutated.
    """
    packages = spdx.get("packages", []) or []
    groups: dict[tuple[str, str], list[dict]] = {}
    for pkg in packages:
        if not is_first_party(pkg):
            continue
        key = (first_party_artifact_key(pkg.get("name", "")), pkg.get("versionInfo", ""))
        groups.setdefault(key, []).append(pkg)

    redirect: dict[str, str] = {}
    remove_ids: set[str] = set()
    for members in groups.values():
        if len(members) < 2:
            continue
        hel_members = [p for p in members if (p.get("name") or "").lower().startswith("hel-")]
        if not hel_members:
            continue
        survivor_id = hel_members[0].get("SPDXID")
        for p in members:
            if p is hel_members[0]:
                continue
            pid = p.get("SPDXID")
            if pid:
                remove_ids.add(pid)
                redirect[pid] = survivor_id

    out = dict(spdx)
    out["packages"] = [p for p in packages if p.get("SPDXID") not in remove_ids]

    new_relationships = []
    seen_relationships = set()
    for rel in spdx.get("relationships", []) or []:
        rel = dict(rel)
        rel["spdxElementId"] = redirect.get(rel.get("spdxElementId"), rel.get("spdxElementId"))
        rel["relatedSpdxElement"] = redirect.get(
            rel.get("relatedSpdxElement"), rel.get("relatedSpdxElement")
        )
        if rel["spdxElementId"] == rel["relatedSpdxElement"]:
            continue
        dedupe_key = tuple(sorted(rel.items()))
        if dedupe_key in seen_relationships:
            continue
        seen_relationships.add(dedupe_key)
        new_relationships.append(rel)
    out["relationships"] = new_relationships
    return out


def load_excluded_components(path: str | None) -> dict[str, str]:
    """Load the curated {short artifact name: reason} map of explicitly-excluded
    components (config/excluded_components.json).

    Keys are the package's short artifact name (last segment after ':' or
    '/'), lowercased/stripped for case-insensitive matching — mirroring
    `load_component_aliases`. Returns {} when no path is given or the file is
    absent. Exits with a clear error if a given path is not valid JSON.
    """
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            sys.exit(f"excluded-components file is not valid JSON: {path} ({exc})")
    if not isinstance(data, dict):
        return {}
    return {
        str(k).strip().lower(): str(v).strip()
        for k, v in data.items()
        if str(k).strip()
    }


def is_excluded_component(name: str, excluded: dict[str, str]) -> bool:
    """True if `name`'s short artifact id matches a curated exclusion entry."""
    if not excluded:
        return False
    return _short_artifact_name(name).lower() in excluded


def remove_excluded_packages(spdx: dict, excluded: dict[str, str]) -> dict:
    """Return a copy of an SPDX doc with explicitly-excluded packages dropped.

    Packages matching a curated entry in `excluded` (see
    `load_excluded_components`) are removed entirely, along with every
    relationship that references them (either side) — there is no survivor to
    redirect to, unlike `dedupe_first_party_packages`. Used to scrub
    components that must not appear in the machine-readable SBOM at all (e.g.
    internal tooling never meant to be reported). The input doc is not
    mutated; a no-op when `excluded` is empty.
    """
    packages = spdx.get("packages", []) or []
    if not excluded:
        return dict(spdx)

    remove_ids = {
        pkg.get("SPDXID") for pkg in packages
        if is_excluded_component(pkg.get("name", ""), excluded)
    }

    out = dict(spdx)
    out["packages"] = [p for p in packages if p.get("SPDXID") not in remove_ids]
    out["relationships"] = [
        dict(rel) for rel in (spdx.get("relationships", []) or [])
        if rel.get("spdxElementId") not in remove_ids
        and rel.get("relatedSpdxElement") not in remove_ids
    ]
    return out


def set_document_name(spdx: dict, name: str | None) -> dict:
    """Return a copy of an SPDX doc with its top-level `name` field overridden.

    FOSSA/download_release_sbom.py derives the document `name` from the
    release-group/release ids or titles (e.g. "561 / current (aggregated)"),
    which isn't a meaningful product identifier for consumers of the
    machine-readable SBOM. This lets callers pin a static, human-readable
    name (e.g. "Truelink 4 (or Helion)/1.8.0") via config/CLI instead.

    A no-op (returns a shallow copy unchanged) when `name` is falsy/None, so
    omitting the override leaves the FOSSA-derived name untouched.
    """
    if not name:
        return dict(spdx)
    out = dict(spdx)
    out["name"] = name
    return out


def audit_spdx(spdx: dict, excluded: dict[str, str] | None = None) -> list[str]:
    """Structural/consistency audit of an SPDX 2.3 JSON doc.

    Returns a list of human-readable issue descriptions (empty = clean).
    Codifies the machine-readable SBOM review checklist:
      - required top-level fields present;
      - every package has a non-empty name, SPDXID and versionInfo;
      - SPDXIDs are unique;
      - every relationship endpoint resolves to a known package or the
        document itself (no dangling references);
      - no relationship self-loops or exact-duplicate relationships;
      - the number of DESCRIBES relationships matches the project count
        parsed from the creationInfo comment, when present (aggregated
        release exports only — best-effort, skipped if unparseable);
      - purls (externalRefs of type 'purl') all start with 'pkg:';
      - packages with filesAnalyzed=true declare at least one checksum;
      - package names have no stray leading/trailing whitespace;
      - none of `excluded`'s curated entries (see
        `load_excluded_components`) are present in the package list.
    """
    issues: list[str] = []
    excluded = excluded or {}

    for field in ("spdxVersion", "dataLicense", "SPDXID", "name",
                  "documentNamespace", "creationInfo", "packages", "relationships"):
        if field not in spdx:
            issues.append(f"missing top-level field: {field}")

    packages = spdx.get("packages", []) or []
    relationships = spdx.get("relationships", []) or []

    ids = [p.get("SPDXID") for p in packages]
    id_counts = collections.Counter(ids)
    for spdxid, count in id_counts.items():
        if count > 1:
            issues.append(f"duplicate SPDXID: {spdxid} ({count}x)")

    for p in packages:
        name = p.get("name")
        if not name:
            issues.append(f"package missing name: SPDXID={p.get('SPDXID')}")
        elif name != name.strip():
            issues.append(f"package name has stray whitespace: {name!r}")
        if not p.get("SPDXID"):
            issues.append(f"package missing SPDXID: name={name!r}")
        if not p.get("versionInfo"):
            issues.append(f"package missing versionInfo: {name!r} ({p.get('SPDXID')})")
        for ref in p.get("externalRefs", []) or []:
            if ref.get("referenceType") == "purl":
                locator = ref.get("referenceLocator", "")
                if not locator.startswith("pkg:"):
                    issues.append(f"malformed purl on {name!r}: {locator!r}")
        if p.get("filesAnalyzed") and not p.get("checksums"):
            issues.append(f"filesAnalyzed=true but no checksums: {name!r}")
        if is_excluded_component(name or "", excluded):
            issues.append(f"excluded component still present: {name!r} ({p.get('SPDXID')})")

    doc_id = spdx.get("SPDXID")
    known_ids = set(ids) | ({doc_id} if doc_id else set())
    for rel in relationships:
        a, b = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        if a not in known_ids:
            issues.append(f"dangling relationship endpoint: spdxElementId={a!r}")
        if b not in known_ids and b != "NOASSERTION":
            issues.append(f"dangling relationship endpoint: relatedSpdxElement={b!r}")
        if a == b:
            issues.append(f"relationship self-loop: {a!r}")

    rel_keys = [tuple(sorted(r.items())) for r in relationships]
    for key, count in collections.Counter(rel_keys).items():
        if count > 1:
            issues.append(f"duplicate relationship ({count}x): {dict(key)}")

    describes_count = sum(1 for r in relationships if r.get("relationshipType") == "DESCRIBES")
    comment = (spdx.get("creationInfo", {}) or {}).get("comment", "")
    m = re.search(r"Aggregated from (\d+) FOSSA project", comment)
    if m:
        expected = int(m.group(1))
        if describes_count != expected:
            issues.append(
                f"DESCRIBES count ({describes_count}) != project count in "
                f"creationInfo comment ({expected})"
            )

    return issues


def strip_v_prefix(version: str) -> str:
    """Drop a leading 'v' when immediately followed by a digit (e.g. 'v5.3.1' -> '5.3.1').

    Go pseudo-versions keep their body ('v0.0.0-...' -> '0.0.0-...'); anything
    not matching the pattern (empty, 'version-2', '1.2.3') is returned unchanged.
    """
    if re.match(r"^v\d", version):
        return version[1:]
    return version


def extract_version_from_download_url(pkg: dict) -> str | None:
    """
    For packages with no purl (direct binary/URL downloads, e.g. a JRE or
    MongoDB zip), the SPDX `versionInfo` is often a checksum or
    `NOASSERTION` because there's no package-manager version. The real
    version is usually embedded in the download URL/filename — extract it
    from there. Returns None if the package has a purl (has a real
    package-manager version already) or if no version-like pattern is found.
    """
    if pkg.get("externalRefs"):
        return None
    download_location = pkg.get("downloadLocation")
    if not download_location or download_location == "NOASSERTION":
        return None
    matches = re.findall(r"\d+\.\d+\.\d+(?:\+\d+)?", download_location)
    return matches[-1] if matches else None


def resolve_version(pkg: dict, version_overrides: dict) -> str:
    """Resolve a package's final displayed version.

    Applies (in order) the download-URL–extracted version, any override keyed by
    SPDXID / full name / short (last-path-segment) name, then strips a leading
    'v' prefix. Kept as a standalone helper so the same resolution can be reused
    outside the main write loop.
    """
    spdx_id = pkg.get("SPDXID", "")
    raw_name = pkg.get("name") or ""
    version = pkg.get("versionInfo", "")
    extracted_version = extract_version_from_download_url(pkg)
    if extracted_version:
        version = extracted_version
    short_name = raw_name.rsplit("/", 1)[-1]
    version = version_overrides.get(
        spdx_id,
        version_overrides.get(
            raw_name,
            version_overrides.get(short_name, version),
        ),
    )
    return strip_v_prefix(version)


def load_version_overrides(path: str | None) -> dict[str, str]:
    """
    Load a manual version-override map from a JSON file of
    {"<package name or SPDXID>": "<real version>"}. Returns {} if no path is
    given. Exits with a clear error if the path doesn't exist or isn't valid
    JSON — silent fallback would hide a typo in the file path.
    """
    if not path:
        return {}
    if not os.path.isfile(path):
        sys.exit(f"version-overrides file not found: {path}")
    with open(path, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as exc:
            sys.exit(f"version-overrides file is not valid JSON: {path} ({exc})")


def copy_row_style(ws, src_row: int, dst_row: int, num_cols: int):
    """Copy cell styles (fill, font, border, alignment, number_format) from one row to another."""
    for col in range(1, num_cols + 1):
        src = ws.cell(src_row, col)
        dst = ws.cell(dst_row, col)
        if src.has_style:
            dst.font = copy(src.font)
            dst.fill = copy(src.fill)
            dst.border = copy(src.border)
            dst.alignment = copy(src.alignment)
            dst.number_format = src.number_format
