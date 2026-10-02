#!/usr/bin/env python3
"""Produce a copy of an SPDX SBOM with first-party package names canonicalized.

Reads the raw aggregated SPDX JSON (as downloaded by download_release_sbom.py)
and the curated component-alias map (config/component_aliases.json), and
writes a new SPDX JSON where:
  - each first-party package's `name` is replaced by its canonical `hel-*`
    name for pairs curated in the alias map (same canonicalization already
    applied by sbom_to_excel.py and sbom_to_oss_dependencies.py);
  - first-party package twins sharing an artifact id and version with a
    'hel-*' counterpart (no alias entry needed) are DROPPED — not renamed —
    keeping only the 'hel-*' package, consistent with the Components sheet
    dedup in sbom_to_oss_dependencies.py. Relationships pointing at a dropped
    package are repointed to the surviving 'hel-*' package;
  - components matching a curated entry in the excluded-components map
    (config/excluded_components.json) are removed entirely, along with every
    relationship that references them — used to scrub components that must
    never appear in the machine-readable SBOM (e.g. internal tooling never
    meant to be reported);
  - the document's top-level `name` is overridden with a static, configurable
    value (OSS_SBOM_DOCUMENT_NAME in fossa.config, or --document-name), since
    FOSSA derives it from the release-group/release ids/titles (e.g.
    "561 / current (aggregated)"), which isn't a meaningful product name for
    consumers of the machine-readable SBOM.

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

from sbom_lib import (
    apply_component_aliases,
    dedupe_first_party_packages,
    load_component_aliases,
    load_excluded_components,
    remove_excluded_packages,
    set_document_name,
)

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
    ap.add_argument("--excluded-components", default=cfg.get("OSS_EXCLUDED_COMPONENTS"),
                    help="Path to the curated excluded-components JSON map")
    ap.add_argument("--document-name", default=cfg.get("OSS_SBOM_DOCUMENT_NAME"),
                    help="Static name to set as the SPDX document's top-level "
                         "'name' field, overriding the FOSSA-derived release "
                         "name (e.g. 'Truelink 4 (or Helion)/1.8.0')")
    ap.add_argument("--output", required=True,
                    help="Path to write the canonicalized SPDX JSON to")
    args = ap.parse_args()

    with open(args.sbom, encoding="utf-8") as f:
        spdx = json.load(f)

    aliases = load_component_aliases(args.component_aliases)
    excluded = load_excluded_components(args.excluded_components)

    aliased = apply_component_aliases(spdx, aliases)
    deduped = dedupe_first_party_packages(aliased)
    excluded_out = remove_excluded_packages(deduped, excluded)
    out = set_document_name(excluded_out, args.document_name)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    renamed = sum(
        1 for old, new in zip(
            (p.get("name") for p in spdx.get("packages", []) or []),
            (p.get("name") for p in aliased.get("packages", []) or []),
        ) if old != new
    )
    removed = len(spdx.get("packages", []) or []) - len(out.get("packages", []) or [])
    print(f"✅  Canonicalized {renamed} first-party package name(s), "
          f"removed {removed} duplicate/excluded package(s) → {args.output}")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as exc:
        sys.exit(f"File not found: {exc}")
