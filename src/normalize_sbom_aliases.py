#!/usr/bin/env python3
"""Produce a copy of an SPDX SBOM with first-party package names canonicalized.

Reads the raw aggregated SPDX JSON (as downloaded by download_release_sbom.py)
and the curated component-alias map (config/component_aliases.json), and
writes a new SPDX JSON where each first-party package's `name` is replaced by
its canonical `hel-*` name — the same canonicalization already applied by
sbom_to_excel.py and sbom_to_oss_dependencies.py when rendering the Excel
deliverables.

The raw input file is left untouched; this writes a separate output file
(e.g. for inclusion in the machine-readable SBOM deliverable) so the FOSSA
export stays available as pristine source data.

Stdlib + sbom_lib only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sbom_lib import apply_component_aliases, load_component_aliases

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
DEFAULT_CONFIG = PROJECT_ROOT / "fossa.config"


def main() -> None:
    from download_release_sbom import load_config
    cfg = load_config(DEFAULT_CONFIG)

    ap = argparse.ArgumentParser(
        description="Canonicalize first-party component names in an SPDX JSON SBOM."
    )
    ap.add_argument("--sbom", default=cfg.get("RELEASE_SBOM_OUTPUT", "inputs/sbom_new.json"),
                    help="Path to the raw SPDX 2.3 JSON SBOM (left untouched)")
    ap.add_argument("--component-aliases", default=cfg.get("OSS_COMPONENT_ALIASES"),
                    help="Path to the curated component-alias JSON map")
    ap.add_argument("--output", required=True,
                    help="Path to write the canonicalized SPDX JSON to")
    args = ap.parse_args()

    with open(args.sbom, encoding="utf-8") as f:
        spdx = json.load(f)

    aliases = load_component_aliases(args.component_aliases)
    out = apply_component_aliases(spdx, aliases)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    renamed = sum(
        1 for old, new in zip(
            (p.get("name") for p in spdx.get("packages", []) or []),
            (p.get("name") for p in out.get("packages", []) or []),
        ) if old != new
    )
    print(f"✅  Canonicalized {renamed} first-party package name(s) → {args.output}")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as exc:
        sys.exit(f"File not found: {exc}")
