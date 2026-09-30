#!/usr/bin/env python3
"""
sbom_to_excel.py — Populate the official SBOM Excel template from an SPDX 2.3
JSON SBOM file (e.g. `sbom_new.json`).

Classification rules inferred from the SBOM's own SPDX relationships/metadata:
  - Dependency relationship: every real component is verified (via the SPDX
    DEPENDS_ON graph) to be a direct dependant of one of the product roots —
    there is no recorded intermediate/transitive chain in this SBOM — so all
    rows are classified "Direct".
  - OSS vs First-Party: components whose `supplier` is the distinctive
    "Organization: FOSSA (Custom (provided build))" marker are internally
    developed (Baxter) components; everything else (has a real npm/Maven/
    NuGet/Go/GitHub package-manager origin) is classified as OSS.

Usage:
    python3 sbom_to_excel.py \
        --sbom sbom_new.json \
        --template template.xlsx \
        --output output-dependencies.xlsx \
        [--product-name "My Product"] \
        [--product-version "1.2.3"]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Border, Alignment
except ImportError:
    sys.exit("Missing dependency: pip install openpyxl")

from sbom_lib import (
    is_incomplete_dependency,
    is_first_party,
    resolve_version,
    extract_version_from_download_url,
    strip_v_prefix,
    load_version_overrides,
    canonical_component_name,
    load_component_aliases,
    copy_row_style,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def extract_creator_org(creators: list[str]) -> str:
    """Return 'OrgName' from 'Organization: OrgName' entry."""
    for c in creators:
        if c.startswith("Organization:"):
            return c.split(":", 1)[1].strip()
    return "Unknown"


def extract_tool(creators: list[str]) -> str:
    """Return tool name from 'Tool: <name>' entry."""
    for c in creators:
        if c.startswith("Tool:"):
            return c.split(":", 1)[1].strip()
    return ""


def extract_supplier_name(supplier: str, originator: str) -> str:
    """
    Derive a short supplier name from SPDX supplier/originator fields.
    Falls back to 'OSS Community' when the supplier is NOASSERTION.
    """
    for raw in (supplier, originator):
        if not raw or raw == "NOASSERTION":
            continue
        if ":" in raw:
            tag, value = raw.split(":", 1)
            tag = tag.strip()
            value = value.strip()
            if tag == "Organization":
                return value
            # For "Person: email1,email2,..." just return the first email or a shortened form
            if tag == "Person":
                first = value.split(",")[0].strip()
                return first
        return raw.strip()
    return "OSS Community"


def get_cpe(external_refs: list[dict]) -> str:
    """Return first CPE from externalRefs, or 'Not applicable***'."""
    for ref in external_refs:
        if ref.get("referenceType", "").lower().startswith("cpe"):
            return ref.get("referenceLocator", "Not applicable***")
    return "Not applicable***"


def resolve_component_name(name: str, coordinate: str) -> str:
    """Return the full SPDX package name (no truncation).

    The FOSSA name is already full and descriptive (e.g. 'Apache Commons Lang',
    'github.com/golang-jwt/jwt/v5', '@angular/core'). Fall back to the CPE
    coordinate only when the name is empty.
    """
    name = (name or "").strip()
    if name:
        return name
    return (coordinate or "").strip()


def first_party_artifact_key(name: str) -> str:
    """Normalized artifact identity for a Baxter/first-party component name.

    Links the two representations of the same internal library:
      - project-root name 'hel-<artifact>'    -> '<artifact>'
      - Maven coordinate '<group>:<artifact>' -> '<artifact>'
    Comparison is case-insensitive.
    """
    if ":" in name:
        art = name.rsplit(":", 1)[-1]
    elif name.lower().startswith("hel-"):
        art = name[len("hel-"):]
    else:
        art = name
    return art.strip().lower()


def load_eol_map(path: str | None) -> dict[str, str]:
    """Load the {SPDXID: "YYYY-MM-DD"} end-of-support cache from enrich_eol.

    Returns {} when no path is given or the file is absent — the enrichment
    step is optional and the parser stays fully offline. The cache's top-level
    'eol' object holds the map.
    """
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    eol = data.get("eol", {}) if isinstance(data, dict) else {}
    return eol if isinstance(eol, dict) else {}


def parse_iso_date(date_str: str) -> datetime:
    """Parse ISO 8601 datetime string to a naive datetime (UTC)."""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None)
    except ValueError:
        return datetime.now()


# ── main ──────────────────────────────────────────────────────────────────────

def build_excel(sbom_path: str, template_path: str, output_path: str,
                product_name: str | None = None,
                product_version: str | None = None,
                version_overrides_path: str | None = None,
                component_aliases_path: str | None = None,
                eol_data_path: str | None = None):

    version_overrides = load_version_overrides(version_overrides_path)
    aliases = load_component_aliases(component_aliases_path)
    eol_map = load_eol_map(eol_data_path)

    # ── load SBOM ──
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)

    creation = sbom.get("creationInfo", {})
    creators = creation.get("creators", [])
    created_str = creation.get("created", "")
    assembly_dt = parse_iso_date(created_str)

    org = extract_creator_org(creators)
    tool = extract_tool(creators)
    author_of_sbom = f"{org} / {tool}" if tool else org

    packages = sbom.get("packages", [])
    packages = [pkg for pkg in packages if not is_incomplete_dependency(pkg)]

    # Derive product info from SBOM if not overridden
    resolved_name = product_name or sbom.get("name", "Unknown Product")
    resolved_version = product_version or ""

    # ── load template ──
    wb = openpyxl.load_workbook(template_path)
    ws = wb["SBOM"]

    num_cols = 11  # A–K

    # ── update metadata header rows ──
    ws.cell(2, 4).value = resolved_name
    ws.cell(3, 4).value = resolved_version
    ws.cell(4, 4).value = f"{org} – {next((c.split(':', 1)[1].strip() for c in creators if c.startswith('Person:')), '')} via {tool}" if tool else org
    ws.cell(5, 4).value = created_str

    # ── find/clear existing data rows (row 8 onward) ──
    data_start_row = 8
    last_data_row = ws.max_row
    if last_data_row >= data_start_row:
        for row in ws.iter_rows(min_row=data_start_row, max_row=last_data_row):
            for cell in row:
                cell.value = None

    # Keep a reference row for style copying (row 8 — first data row in template)
    style_ref_row = data_start_row  # We'll copy styles from the original row 8

    # Internally-developed (First-Party) components listed first, then OSS —
    # stable sort preserves original relative ordering within each group.
    packages = sorted(packages, key=lambda pkg: not is_first_party(pkg))

    # ── write package rows ──
    # A Baxter library appears twice under different names: as a friendly
    # 'hel-*' project root (the "principal" row) and as its 'group:artifact'
    # Maven twin. Pre-compute the (artifact, version) of every principal row
    # (first-party, non-coordinate name) so the coordinate twin can be dropped
    # while leaving the principal row untouched. Orphan coordinates (no
    # principal twin) are never removed.
    principal_fp_artifacts: set[tuple[str, str]] = set()
    for pkg in packages:
        if not is_first_party(pkg):
            continue
        nm = canonical_component_name(
            resolve_component_name(
                pkg.get("name", ""), get_cpe(pkg.get("externalRefs", []) or [])
            ),
            aliases,
        )
        if ":" in nm:
            continue
        principal_fp_artifacts.add(
            (first_party_artifact_key(nm), resolve_version(pkg, version_overrides))
        )

    seen_rows: set[tuple[str, str]] = set()
    row_idx = data_start_row
    for pkg in packages:
        raw_name = pkg.get("name", "")
        version = resolve_version(pkg, version_overrides)
        supplier_raw = pkg.get("supplier", "NOASSERTION")
        originator_raw = pkg.get("originator", "NOASSERTION")
        external_refs = pkg.get("externalRefs", [])

        supplier_name = extract_supplier_name(supplier_raw, originator_raw)
        cpe = get_cpe(external_refs)
        name = resolve_component_name(raw_name, cpe)
        # All components in this SBOM are declared directly by one of the
        # product manifests (verified via the SPDX DEPENDS_ON relationships:
        # every real component is a direct dependant of a product root, with
        # no intermediate transitive chain recorded) — so every row is Direct.
        dep_rel = "Direct"

        first_party = is_first_party(pkg)
        if first_party:
            name = canonical_component_name(name, aliases)
            end_of_support = "N/A - Internally Developed"
            level_of_support = "Maintained"
            category = "First-Party"
            comment = "Own development"
            supplier_name = "Baxter"
            # First-party (Baxter) components are not tracked by CPE.
            cpe = "Not applicable***"
        else:
            end_of_support = eol_map.get(pkg.get("SPDXID", ""), "N/A*")
            level_of_support = "Supported"
            category = "OSS"
            comment = "OSS Community Development"
            supplier_name = "OSS Community"

        dedup_key = (name.lower(), version)
        if dedup_key in seen_rows:
            continue
        seen_rows.add(dedup_key)

        # Drop a first-party Maven-coordinate row when its principal twin
        # (same artifact + version, friendly non-coordinate name) is present.
        if first_party and ":" in name and (
            (first_party_artifact_key(name), version) in principal_fp_artifacts
        ):
            continue

        # Copy styles from the template reference row
        if row_idx > data_start_row:
            copy_row_style(ws, data_start_row, row_idx, num_cols)

        ws.cell(row_idx, 1).value = supplier_name
        ws.cell(row_idx, 2).value = name
        ws.cell(row_idx, 3).value = version
        ws.cell(row_idx, 4).value = cpe
        ws.cell(row_idx, 5).value = dep_rel
        ws.cell(row_idx, 6).value = author_of_sbom
        ws.cell(row_idx, 7).value = assembly_dt
        ws.cell(row_idx, 7).number_format = "YYYY-MM-DD"
        ws.cell(row_idx, 8).value = end_of_support
        ws.cell(row_idx, 9).value = level_of_support
        ws.cell(row_idx, 10).value = category
        ws.cell(row_idx, 11).value = comment

        row_idx += 1

    wb.save(output_path)
    print(f"✅  Written {row_idx - data_start_row} packages → {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Populate a Baxter SBOM Excel template from an SPDX 2.3 JSON SBOM."
    )
    parser.add_argument("--sbom", required=True, help="Path to SPDX 2.3 JSON SBOM file")
    parser.add_argument("--template", required=True, help="Path to the Excel template (.xlsx)")
    parser.add_argument("--output", required=True, help="Path for the output Excel file (.xlsx)")
    parser.add_argument("--product-name", default=None, help="Override product name in the header")
    parser.add_argument("--product-version", default=None, help="Override product version in the header")
    parser.add_argument(
        "--version-overrides", default=None,
        help="Path to a JSON file of {package name or SPDXID: real version} "
             "to use instead of the SPDX versionInfo (e.g. for packages "
             "whose version is a commit SHA)."
    )
    parser.add_argument(
        "--component-aliases", default=None,
        help="Path to a JSON file of {alternate first-party name: canonical "
             "hel-* name} to collapse the two representations of the same "
             "internal component into one row."
    )
    parser.add_argument(
        "--eol-data", default=None,
        help="Path to eol_data.json (from enrich_eol.py) mapping package "
             "SPDXID to an end-of-support date; missing entries fall back to N/A*."
    )

    args = parser.parse_args()

    build_excel(
        sbom_path=args.sbom,
        template_path=args.template,
        output_path=args.output,
        product_name=args.product_name,
        product_version=args.product_version,
        version_overrides_path=args.version_overrides,
        component_aliases_path=args.component_aliases,
        eol_data_path=args.eol_data,
    )


if __name__ == "__main__":
    main()
