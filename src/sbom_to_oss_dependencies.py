#!/usr/bin/env python3
"""
sbom_to_oss_dependencies.py — Populate the OTS-SOUP OSS dependencies Excel
template (`oss-template.xlsx`, Helion product line) from an SPDX 2.3 JSON
SBOM file.

Two sheets are produced:
  - "Dependencies (OTS SOUP)": one row per external OSS package, with the
    internal Helion components that depend on it listed in a single
    comma-joined cell.
  - "SW-SYS Components (Ref-only)": the internal (first-party) Helion
    components themselves, for reference.

See docs/superpowers/specs/2026-09-29-oss-dependencies-agent-design.md for
the full design rationale.
"""

import argparse
import json
import re
import sys

try:
    import openpyxl
    from openpyxl.cell.cell import MergedCell
except ImportError:
    sys.exit("Missing dependency: pip install openpyxl")

from sbom_lib import (
    is_incomplete_dependency,
    is_first_party,
    resolve_version,
    load_version_overrides,
    canonical_component_name,
    load_component_aliases,
    load_license_overrides,
    load_purpose_overrides,
    load_reference_overrides,
    normalize_license,
    copy_row_style,
)


# ── component graph ───────────────────────────────────────────────────────────

def build_component_graph(packages: list[dict], relationships: list[dict]) -> dict[str, set[str]]:
    """Map every real package's SPDXID to the set of internal-component
    SPDXIDs that depend on it.

    Two sources of edges:
      1. Direct: a `DEPENDENCY_OF` relationship whose `relatedSpdxElement`
         is a first-party component.
      2. Placeholder chain: FOSSA sometimes routes a component's dependency
         through an "Incomplete dependency" placeholder package instead of
         the real one (component -> placeholder -> real). When that
         happens, the placeholder's own resolved components (from step 1)
         are attributed directly to the real package it `DEPENDS_ON`.
    """
    component_ids = {pkg["SPDXID"] for pkg in packages if is_first_party(pkg)}
    placeholder_ids = {pkg["SPDXID"] for pkg in packages if is_incomplete_dependency(pkg)}

    pkg_to_components: dict[str, set[str]] = {}
    for rel in relationships:
        if rel.get("relationshipType") != "DEPENDENCY_OF":
            continue
        related = rel.get("relatedSpdxElement")
        if related in component_ids:
            pkg_to_components.setdefault(rel["spdxElementId"], set()).add(related)

    for rel in relationships:
        if rel.get("relationshipType") != "DEPENDS_ON":
            continue
        source = rel.get("spdxElementId")
        if source in placeholder_ids:
            comps = pkg_to_components.get(source)
            if comps:
                real_id = rel.get("relatedSpdxElement")
                pkg_to_components.setdefault(real_id, set()).update(comps)

    return pkg_to_components


# ── field resolution ──────────────────────────────────────────────────────────

def resolve_license(pkg: dict, license_overrides: dict | None = None) -> str:
    """Curated override (by package name) wins; else declared license; else the
    first file-scanned license with a note; else an explicit review flag. All
    non-override results are normalized from FOSSA LicenseRef-* to clean SPDX."""
    license_overrides = license_overrides or {}
    name = (pkg.get("name") or "").strip().lower()
    if name in license_overrides:
        return license_overrides[name]
    declared = pkg.get("licenseDeclared")
    if declared and declared != "NONE":
        return normalize_license(declared)
    files = pkg.get("licenseInfoFromFiles") or []
    if files:
        return f"{normalize_license(files[0])} (derived from file scan; no declared license)"
    return "UNKNOWN - Review Required"


def resolve_reference(pkg: dict, reference_overrides: dict | None = None) -> str:
    """Curated override (by package name) wins; else `website=<url>` using
    homepage, falling back to the download location."""
    reference_overrides = reference_overrides or {}
    name = (pkg.get("name") or "").strip().lower()
    if name in reference_overrides:
        return reference_overrides[name]
    homepage = pkg.get("homepage")
    if homepage and homepage != "NOASSERTION":
        return f"website={homepage}"
    download = pkg.get("downloadLocation")
    if download and download != "NOASSERTION":
        return f"website={download}"
    return ""


def resolve_purl(pkg: dict) -> str:
    """Package URL from externalRefs, falling back to the download location."""
    for ref in pkg.get("externalRefs") or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator", "")
    download = pkg.get("downloadLocation")
    if download and download != "NOASSERTION":
        return download
    return ""


def resolve_purpose(pkg: dict, purpose_overrides: dict | None = None) -> str:
    """Curated override (by package name) wins; else the package summary,
    blanked when SPDX has no real value for it."""
    purpose_overrides = purpose_overrides or {}
    name = (pkg.get("name") or "").strip().lower()
    if name in purpose_overrides:
        return purpose_overrides[name]
    summary = pkg.get("summary")
    if not summary or summary == "NOASSERTION":
        return ""
    return summary


# ── row assembly ──────────────────────────────────────────────────────────────

def build_rows(packages: list[dict], relationships: list[dict], version_overrides: dict,
               license_overrides: dict | None = None,
               purpose_overrides: dict | None = None,
               reference_overrides: dict | None = None,
               aliases: dict[str, str] | None = None):
    """Build one output row per unique OSS package (name + version).

    Returns (rows, placeholders_dropped, duplicates_merged):
      - rows: list of dicts with keys name/version/purpose/license/reference/
        components (comma-joined str)/ref, sorted by (name.lower(), version).
      - placeholders_dropped: count of FOSSA "Incomplete dependency" entries excluded.
      - duplicates_merged: count of packages that shared a (name, version) key
        with an already-written row and had their components merged into it
        instead of creating a duplicate row (happens with aggregated
        multi-project SBOMs).
    """
    pkg_to_components = build_component_graph(packages, relationships)
    pkgs_by_id = {pkg["SPDXID"]: pkg for pkg in packages}
    aliases = aliases or {}

    placeholders_dropped = sum(1 for pkg in packages if is_incomplete_dependency(pkg))

    oss_packages = [
        pkg for pkg in packages
        if not is_first_party(pkg) and not is_incomplete_dependency(pkg)
    ]

    rows_by_key: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    duplicates_merged = 0

    for pkg in oss_packages:
        name = (pkg.get("name") or "").strip() or resolve_purl(pkg) or pkg.get("downloadLocation", "")
        version = resolve_version(pkg, version_overrides)
        key = (name.lower(), version)

        component_ids = pkg_to_components.get(pkg["SPDXID"], set())
        component_names = {
            canonical_component_name(pkgs_by_id[c]["name"], aliases)
            for c in component_ids if c in pkgs_by_id
        }

        if key in rows_by_key:
            rows_by_key[key]["components"].update(component_names)
            duplicates_merged += 1
            continue

        rows_by_key[key] = {
            "name": name,
            "version": version,
            "purpose": resolve_purpose(pkg, purpose_overrides),
            "license": resolve_license(pkg, license_overrides),
            "reference": resolve_reference(pkg, reference_overrides),
            "components": set(component_names),
            "ref": resolve_purl(pkg),
        }
        order.append(key)

    rows = [rows_by_key[key] for key in order]
    rows.sort(key=lambda r: (r["name"].lower(), r["version"]))
    for row in rows:
        row["components"] = ", ".join(sorted(row["components"], key=str.lower))

    return rows, placeholders_dropped, duplicates_merged


_COPYLEFT_RE = re.compile(
    r"\b(GPL|LGPL|AGPL|MPL|CDDL|EPL|SSPL|OSL|CC-BY|CC0|OFL|MS-PL|MS-NET|Zlib)\b",
    re.IGNORECASE,
)


def flag_review_rows(rows: list[dict]) -> list[dict]:
    """Rows whose license needs human/legal review: copyleft or notable family,
    an explicit UNKNOWN flag, or a low-confidence file-scan derivation."""
    flagged = []
    for row in rows:
        lic = row["license"]
        if (lic == "UNKNOWN - Review Required"
                or "(derived from file scan" in lic
                or _COPYLEFT_RE.search(lic)):
            flagged.append(row)
    return flagged


def build_components(packages: list[dict], version_overrides: dict,
                     aliases: dict[str, str] | None = None) -> list[dict]:
    """Internal Helion components for the 'SW-SYS Components (Ref-only)' sheet.

    Names are resolved to their canonical form via the curated alias map so the
    two representations of the same first-party component collapse to one row.
    Deduplicated by (canonical name, version), sorted by name.
    """
    aliases = aliases or {}
    seen: set[tuple[str, str]] = set()
    components: list[dict] = []
    for pkg in packages:
        if not is_first_party(pkg):
            continue
        name = canonical_component_name(pkg.get("name", ""), aliases)
        version = resolve_version(pkg, version_overrides)
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        components.append({"name": name, "version": version})
    components.sort(key=lambda c: c["name"].lower())
    return components


# ── sheet writing ─────────────────────────────────────────────────────────────

def _unmerge_all(ws):
    for rng in list(ws.merged_cells.ranges):
        ws.unmerge_cells(str(rng))


def _clear_row_values(ws, start_row: int, end_row: int, num_cols: int):
    for r in range(start_row, end_row + 1):
        for c in range(1, num_cols + 1):
            cell = ws.cell(row=r, column=c)
            if isinstance(cell, MergedCell):
                continue
            cell.value = None


def write_oss_dependencies_sheet(wb, rows: list[dict]):
    """Write the 'Dependencies (OTS SOUP)' sheet, trimmed to exactly
    1 header row + len(rows) data rows and 10 columns (A-J)."""
    ws = wb["Dependencies (OTS SOUP)"]
    num_cols = 10  # A..J
    _unmerge_all(ws)
    _clear_row_values(ws, 2, ws.max_row, num_cols)

    for i, row in enumerate(rows):
        r = i + 2
        if r > 2:
            copy_row_style(ws, 2, r, num_cols)
        ws.cell(r, 1).value = row["name"]
        ws.cell(r, 2).value = "See Website"
        ws.cell(r, 3).value = row["version"]
        ws.cell(r, 4).value = "Open Source"
        ws.cell(r, 5).value = row["purpose"]
        ws.cell(r, 6).value = "Same as Purpose"
        ws.cell(r, 7).value = row["license"]
        ws.cell(r, 8).value = row["reference"]
        ws.cell(r, 9).value = row["components"]
        ws.cell(r, 10).value = row["ref"]

    last_row = len(rows) + 1
    if ws.max_row > last_row:
        ws.delete_rows(last_row + 1, ws.max_row - last_row)
    if ws.max_column > num_cols:
        ws.delete_cols(num_cols + 1, ws.max_column - num_cols)

    ws.auto_filter.ref = f"A1:J{last_row}"
    ws.freeze_panes = "A2"


def write_components_sheet(wb, components: list[dict], product_name: str):
    """Write the 'SW-SYS Components (Ref-only)' sheet, trimmed to exactly
    2 header rows + len(components) data rows and 3 columns (A-C)."""
    ws = wb["SW-SYS Components (Ref-only)"]
    num_cols = 3  # A..C
    _unmerge_all(ws)
    _clear_row_values(ws, 3, ws.max_row, num_cols)

    ws.cell(1, 1).value = (
        f"List of components of {product_name} developed internally "
        "(not SOUP/OTS) - for reference only"
    )

    for i, comp in enumerate(components):
        r = i + 3
        if r > 3:
            copy_row_style(ws, 3, r, num_cols)
        ws.cell(r, 1).value = comp["name"]
        ws.cell(r, 2).value = comp["version"]
        ws.cell(r, 3).value = ""

    last_row = len(components) + 2
    if ws.max_row > last_row:
        ws.delete_rows(last_row + 1, ws.max_row - last_row)
    if ws.max_column > num_cols:
        ws.delete_cols(num_cols + 1, ws.max_column - num_cols)


# ── main ──────────────────────────────────────────────────────────────────────

def build_excel(sbom_path: str, template_path: str, output_path: str,
                 product_name: str | None = None,
                 version_overrides_path: str | None = None,
                 license_overrides_path: str | None = None,
                 component_aliases_path: str | None = None):
    version_overrides = load_version_overrides(version_overrides_path)
    license_overrides = load_license_overrides(license_overrides_path)
    purpose_overrides = load_purpose_overrides(license_overrides_path)
    reference_overrides = load_reference_overrides(license_overrides_path)
    aliases = load_component_aliases(component_aliases_path)

    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)

    packages = sbom.get("packages", [])
    relationships = sbom.get("relationships", [])
    resolved_name = product_name or sbom.get("name", "Unknown Product")

    rows, placeholders_dropped, duplicates_merged = build_rows(
        packages, relationships, version_overrides,
        license_overrides, purpose_overrides, reference_overrides,
        aliases=aliases,
    )
    components = build_components(packages, version_overrides, aliases)

    unknown_licenses = sum(1 for row in rows if row["license"] == "UNKNOWN - Review Required")
    fallback_licenses = sum(1 for row in rows if "(derived from file scan" in row["license"])
    review_rows = flag_review_rows(rows)

    wb = openpyxl.load_workbook(template_path)
    write_oss_dependencies_sheet(wb, rows)
    write_components_sheet(wb, components, resolved_name)
    wb.save(output_path)

    print(
        f"✅  Written {len(rows)} OSS rows + {len(components)} components → {output_path}\n"
        f"    placeholders dropped: {placeholders_dropped}, "
        f"duplicate rows merged: {duplicates_merged}, "
        f"licenses from file-scan fallback: {fallback_licenses}, "
        f"licenses UNKNOWN: {unknown_licenses}"
    )
    if review_rows:
        print(f"\n⚠️  {len(review_rows)} rows need license review (copyleft / UNKNOWN / file-scan):")
        for r in review_rows:
            print(f"    - {r['name']} {r['version']}: {r['license']}")


def main():
    parser = argparse.ArgumentParser(
        description="Populate the OTS-SOUP OSS dependencies xlsx from an SPDX 2.3 JSON SBOM."
    )
    parser.add_argument("--sbom", required=True, help="Path to SPDX 2.3 JSON SBOM file")
    parser.add_argument("--template", required=True, help="Path to the OTS-SOUP Excel template (.xlsx)")
    parser.add_argument("--output", required=True, help="Path for the output Excel file (.xlsx)")
    parser.add_argument(
        "--product-name", default=None,
        help="Product name shown in the SW-SYS Components sheet title "
             "(defaults to the SBOM document's own 'name' field)"
    )
    parser.add_argument(
        "--version-overrides", default=None,
        help="Path to a JSON file of {package name or SPDXID: real version} "
             "to use instead of the SPDX versionInfo."
    )
    parser.add_argument(
        "--license-overrides", default=None,
        help="Path to a JSON file of curated {package name: SPDX license} overrides "
             "(e.g. license_overrides.json) for external binaries FOSSA can't resolve."
    )
    parser.add_argument(
        "--component-aliases", default=None,
        help="Path to a JSON file of {alternate first-party name: canonical "
             "hel-* name} (e.g. component_aliases.json) to collapse the two "
             "representations of the same internal component into one row."
    )
    args = parser.parse_args()

    build_excel(
        sbom_path=args.sbom,
        template_path=args.template,
        output_path=args.output,
        product_name=args.product_name,
        version_overrides_path=args.version_overrides,
        license_overrides_path=args.license_overrides,
        component_aliases_path=args.component_aliases,
    )


if __name__ == "__main__":
    main()
