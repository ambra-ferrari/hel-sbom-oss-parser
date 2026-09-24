#!/usr/bin/env python3
"""
lockfile_sbom_agent.py — Reviewer agent that confirms npm dependency versions
declared in a `package-lock.json` (source of truth for what actually gets
installed) against the versions recorded in an SPDX SBOM JSON file
(e.g. `sbom_new.json`).

Scope: only components present in BOTH files are compared. It reports:
  - version_mismatch: same package name in both files, different version
  - version_match    : same package name in both files, consistent version

Presence/absence differences (declared-but-missing or extra packages) are out
of scope for this check — use a separate coverage/diff tool for that.

Usage:
    python3 tools/lockfile_sbom_agent.py \
        --lockfile package-lock.json \
        --sbom sbom_new.json \
        --report lockfile-vs-sbom-report.md \
        --csv lockfile-vs-sbom-diff.csv
"""
import argparse
import csv
import json
import re
from collections import defaultdict
from urllib.parse import unquote


def norm_name(n: str) -> str:
    return n.strip().lower()


def load_lockfile(path):
    """Return (direct_deps, all_resolved) for an npm package-lock.json (v2/v3 'packages' format)."""
    with open(path, encoding="utf-8") as f:
        d = json.load(f)

    packages = d.get("packages", {})
    root = packages.get("", {})
    direct = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, range_spec in root.get(section, {}).items():
            direct[name] = range_spec

    resolved = defaultdict(set)  # name -> set of resolved versions found anywhere in the tree
    for key, meta in packages.items():
        if key == "":
            continue
        # key looks like "node_modules/@scope/pkg" or "node_modules/a/node_modules/@scope/pkg"
        name = key.rsplit("node_modules/", 1)[-1]
        version = meta.get("version")
        if name and version:
            resolved[name].add(version)

    return direct, resolved


def load_sbom_npm(path):
    """Return name -> set of resolved versions for npm packages in an SPDX SBOM JSON."""
    with open(path, encoding="utf-8") as f:
        d = json.load(f)

    sbom_versions = defaultdict(set)
    for pkg in d.get("packages", []):
        name = pkg.get("name")
        if not name or name.startswith("19518/"):
            continue
        is_npm = False
        for ref in pkg.get("externalRefs", []):
            loc = ref.get("referenceLocator", "")
            if loc.startswith("pkg:npm/"):
                is_npm = True
                break
        if not is_npm:
            continue
        version = pkg.get("versionInfo")
        if version:
            sbom_versions[unquote(name)].add(version)

    return sbom_versions


def parse_semver(v):
    if not v:
        return None
    v = v.lstrip("v")
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else None


def satisfies_range(declared, resolved_versions):
    """True if any resolved version satisfies a simple exact / ^ / ~ declared range."""
    if declared in resolved_versions:
        return True
    op, base = (declared[0], declared[1:]) if declared[:1] in ("^", "~") else (None, declared)
    b = parse_semver(base)
    if b is None:
        return False
    for rv in resolved_versions:
        r = parse_semver(rv)
        if r is None:
            continue
        if op == "^":
            if b[0] > 0 and r[0] == b[0] and (r[1], r[2]) >= (b[1], b[2]):
                return True
            if b[0] == 0 and b[1] > 0 and r[0] == 0 and r[1] == b[1] and r[2] >= b[2]:
                return True
            if b[0] == 0 and b[1] == 0 and r == b:
                return True
        elif op == "~":
            if r[0] == b[0] and r[1] == b[1] and r[2] >= b[2]:
                return True
        elif b == r:
            return True
    return False


def run(lockfile_path, sbom_path):
    """Compare direct-dependency versions for packages present in BOTH files.
    Packages missing from either side are out of scope (not reported)."""
    direct, resolved = load_lockfile(lockfile_path)
    sbom_versions = load_sbom_npm(sbom_path)

    mismatches = []  # direct dep whose declared range isn't satisfied by any SBOM version
    matched = []     # direct dep confirmed consistent with the SBOM
    skipped = 0      # direct dep not present in SBOM -> excluded from this comparison

    for name, declared in sorted(direct.items()):
        sbom_vers = sbom_versions.get(name)
        if not sbom_vers:
            skipped += 1
            continue
        sbom_v_str = ";".join(sorted(sbom_vers))
        if satisfies_range(declared, sbom_vers):
            matched.append((name, declared, sbom_v_str))
        else:
            mismatches.append((name, declared, sbom_v_str))

    return {
        "direct_total": len(direct),
        "compared_total": len(matched) + len(mismatches),
        "skipped_not_in_sbom": skipped,
        "mismatches": mismatches,
        "matched": matched,
    }


def write_csv(results, csv_path):
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["change_type", "component", "lockfile_version", "sbom_version"])
        for name, declared, sbom_v in results["mismatches"]:
            w.writerow(["version_mismatch", name, declared, sbom_v])
        for name, declared, sbom_v in results["matched"]:
            w.writerow(["version_match", name, declared, sbom_v])


def write_report(results, md_path, lockfile_path, sbom_path):
    lines = []
    lines.append("# Lockfile vs SBOM — Version Confirmation Report\n")
    lines.append(f"Source of truth: `{lockfile_path}` (npm package-lock — direct dependencies).")
    lines.append(f"Checked against: `{sbom_path}` (npm packages only).")
    lines.append(
        "Scope: only components present in **both** files are compared — this "
        "report confirms version consistency, it does not track presence/absence.\n"
    )

    lines.append("## Executive summary\n")
    lines.append("| Metric | Count |")
    lines.append("|---|---|")
    lines.append(f"| Direct dependencies declared in lockfile | {results['direct_total']} |")
    lines.append(f"| Compared (present in both lockfile and SBOM) | {results['compared_total']} |")
    lines.append(f"| **Version mismatches** | **{len(results['mismatches'])}** |")
    lines.append(f"| Versions confirmed consistent | {len(results['matched'])} |")
    lines.append(f"| Not comparable (declared dep not present in SBOM, out of scope) | {results['skipped_not_in_sbom']} |\n")

    lines.append("## 1. Version mismatches\n")
    if results["mismatches"]:
        lines.append("| Component | Lockfile version | SBOM version |")
        lines.append("|---|---|---|")
        for name, declared, sbom_v in results["mismatches"]:
            lines.append(f"| {name} | {declared} | {sbom_v} |")
    else:
        lines.append("None — all comparable direct dependencies match.")
    lines.append("")

    lines.append("## 2. Versions confirmed consistent\n")
    if results["matched"]:
        lines.append("| Component | Lockfile version | SBOM version |")
        lines.append("|---|---|---|")
        for name, declared, sbom_v in results["matched"]:
            lines.append(f"| {name} | {declared} | {sbom_v} |")
    else:
        lines.append("None.")
    lines.append("")

    with open(md_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Cross-check package-lock.json vs SBOM npm versions")
    ap.add_argument("--lockfile", required=True)
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--csv", required=True)
    args = ap.parse_args()

    results = run(args.lockfile, args.sbom)
    write_csv(results, args.csv)
    write_report(results, args.report, args.lockfile, args.sbom)

    print(f"Direct deps: {results['direct_total']}")
    print(f"Compared (present in both): {results['compared_total']}")
    print(f"Mismatches: {len(results['mismatches'])}")
    print(f"Confirmed consistent: {len(results['matched'])}")
    print(f"Not comparable (not in SBOM): {results['skipped_not_in_sbom']}")
    print(f"Report written to {args.report}")
    print(f"CSV written to {args.csv}")


if __name__ == "__main__":
    main()
