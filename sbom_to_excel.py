#!/usr/bin/env python3
"""
sbom_to_excel.py — Populate a Baxter SBOM Excel template from an SPDX 2.3 JSON file.

Usage:
    python3 sbom_to_excel.py \
        --sbom SBOM.json \
        --template template.xlsx \
        --output output.xlsx \
        [--product-name "My Product"] \
        [--product-version "1.2.3"]
"""

import argparse
import json
import sys
from copy import copy
from datetime import datetime, timezone

try:
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Border, Alignment
except ImportError:
    sys.exit("Missing dependency: pip install openpyxl")


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


def is_baxter(supplier: str) -> bool:
    name = extract_supplier_name(supplier, "NOASSERTION")
    return name.lower() == "baxter"


def parse_iso_date(date_str: str) -> datetime:
    """Parse ISO 8601 datetime string to a naive datetime (UTC)."""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None)
    except ValueError:
        return datetime.now()


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


# ── main ──────────────────────────────────────────────────────────────────────

def build_excel(sbom_path: str, template_path: str, output_path: str,
                product_name: str | None, product_version: str | None):

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

    # Direct packages = those listed in documentDescribes
    direct_ids = set(creation.get("documentDescribes", []))

    packages = sbom.get("packages", [])

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

    # ── write package rows ──
    row_idx = data_start_row
    for pkg in packages:
        spdx_id = pkg.get("SPDXID", "")
        name = pkg.get("name", "")
        # Keep only the last segment if the name is a path (e.g. "19518/gitlab.../nms-broker")
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        version = pkg.get("versionInfo", "")
        supplier_raw = pkg.get("supplier", "NOASSERTION")
        originator_raw = pkg.get("originator", "NOASSERTION")
        external_refs = pkg.get("externalRefs", [])

        supplier_name = extract_supplier_name(supplier_raw, originator_raw)
        cpe = get_cpe(external_refs)
        dep_rel = "Direct" if spdx_id in direct_ids else "Indirect"

        baxter = is_baxter(supplier_raw)
        if baxter:
            end_of_support = "N/A - Internally Developed"
            level_of_support = "Maintained"
            category = "First-Party"
            comment = "Own development"
        else:
            end_of_support = "N/A*"
            level_of_support = "Supported"
            category = "OSS"
            comment = "OSS Community Development"
            supplier_name = "OSS Community"

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

    args = parser.parse_args()

    build_excel(
        sbom_path=args.sbom,
        template_path=args.template,
        output_path=args.output,
        product_name=args.product_name,
        product_version=args.product_version,
    )


if __name__ == "__main__":
    main()
