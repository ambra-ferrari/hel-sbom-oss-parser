#!/usr/bin/env python3
"""Enrich an SPDX SBOM with end-of-support dates from endoflife.date.

Reads sbom_new.json, resolves an end-of-support date for each third-party
(OSS) library via the endoflife.date v1 REST API, and writes:
  - eol_data.json : {SPDXID: "YYYY-MM-DD"} cache read by sbom_to_excel.py
  - eol_report.md : advisory report (resolved / suspected FP / suspected FN)

Stdlib only. Shared logic (is_first_party, resolve_version, config parsing) is
imported from sbom_to_excel and download_release_sbom so the stages agree.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from sbom_to_excel import is_first_party, resolve_version, load_version_overrides
from download_release_sbom import load_config

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
DEFAULT_CONFIG = PROJECT_ROOT / "fossa.config"
API_BASE = "https://endoflife.date/api/v1"
DISTINGUISHING_SEGMENTS = {"driver", "types", "client", "binding"}


def is_false_positive(pkg: dict, matched_token: str) -> bool:
    """Flag a match reached through a weak/ambiguous token.

    Flags when the matched token differs from the full package name AND the
    name carries an extra distinguishing signal: an npm scope ('@...') or a
    segment in DISTINGUISHING_SEGMENTS (driver/types/client/binding).
    """
    name = (pkg.get("name") or "").strip().lower()
    if not matched_token or matched_token == name:
        return False
    has_scope = name.startswith("@")
    segments = set(re.split(r"[/:]", name))
    has_distinguishing = bool(segments & DISTINGUISHING_SEGMENTS)
    return has_scope or has_distinguishing


def get_purl(pkg: dict) -> str:
    """Return the package's purl external reference locator, or ''."""
    for ref in pkg.get("externalRefs", []) or []:
        if str(ref.get("referenceType", "")).lower() == "purl":
            return str(ref.get("referenceLocator", ""))
    return ""


def candidate_tokens(pkg: dict) -> list[str]:
    """Build lowercased, de-duplicated match tokens for a package.

    Sources (in priority order): artifactId (after last ':'), last path segment
    (after last '/'), scope-stripped npm name, the full name, and the purl's
    final name segment.
    """
    name = (pkg.get("name") or "").strip()
    tokens: list[str] = []
    if ":" in name:
        tokens.append(name.rsplit(":", 1)[-1])
    if "/" in name:
        tokens.append(name.rsplit("/", 1)[-1])
    if name.startswith("@") and "/" in name:
        tokens.append(name.split("/", 1)[1])
    tokens.append(name)
    purl = get_purl(pkg)
    if purl.startswith("pkg:"):
        body = purl[len("pkg:"):].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[0]
        parts = [urllib.parse.unquote(p) for p in body.split("/") if p]
        if len(parts) >= 2:
            tokens.append(parts[-1])
    out: list[str] = []
    for tok in tokens:
        tok = tok.strip().lower()
        if tok and tok not in out:
            out.append(tok)
    return out


def build_slug_index(products: list[dict]) -> dict[str, str]:
    """Map every product name and alias (lowercased) to its canonical name."""
    index: dict[str, str] = {}
    for prod in products:
        pname = prod.get("name", "")
        for slug in [pname] + list(prod.get("aliases", []) or []):
            slug = (slug or "").strip().lower()
            if slug:
                index.setdefault(slug, pname)
    return index


def match_product(tokens: list[str], slug_index: dict[str, str]) -> tuple[str | None, str | None]:
    """Return (product_name, matching_token) for the first token found, else (None, None).

    Each token is tried as an exact slug first, then via progressively shorter
    dash-delimited prefixes (longest first). The prefix fallback lets a family
    artifact such as 'spring-boot-starter-actuator' match the 'spring-boot'
    product, or 'spring-security-web' match 'spring-security'. Wrong prefix
    matches are still filtered downstream by the version->cycle step (a
    companion package like 'react-router' whose version has no matching product
    cycle stays unresolved) and by the false-positive heuristic.
    """
    for tok in tokens:
        if tok in slug_index:
            return slug_index[tok], tok
        parts = tok.split("-")
        for i in range(len(parts) - 1, 0, -1):
            prefix = "-".join(parts[:i])
            if prefix in slug_index:
                return slug_index[prefix], tok
    return None, None


def match_cycle(version: str, releases: list[dict]) -> dict | None:
    """Return the release whose cycle name is a dot-segment prefix of version.

    Longest matching cycle wins ('1.20' beats '1'). Comparison is on
    dot-delimited segments, so cycle '1' matches '1.2.3' but not '18.0.0'.
    """
    ver_segs = version.split(".")
    best: dict | None = None
    best_len = -1
    for rel in releases:
        cyc_segs = str(rel.get("name", "")).split(".")
        if len(cyc_segs) > len(ver_segs):
            continue
        if ver_segs[:len(cyc_segs)] == cyc_segs and len(cyc_segs) > best_len:
            best = rel
            best_len = len(cyc_segs)
    return best


def release_date(release: dict) -> tuple[str | None, str | None]:
    """Return (date, field) using eolFrom, else eoasFrom, else (None, None)."""
    eol = release.get("eolFrom")
    if isinstance(eol, str) and eol:
        return eol, "eol"
    eoas = release.get("eoasFrom")
    if isinstance(eoas, str) and eoas:
        return eoas, "eoas"
    return None, None


def resolve_library(pkg: dict, version: str, slug_index: dict[str, str],
                    detail_fetcher) -> dict | None:
    """Resolve one package to {product, token, cycle, date, field}, or None.

    detail_fetcher(product_name) returns the product detail dict (with a
    'releases' list) or None. It is only called for a matched product.
    """
    tokens = candidate_tokens(pkg)
    product, token = match_product(tokens, slug_index)
    if not product:
        return None
    detail = detail_fetcher(product)
    if not detail:
        return None
    rel = match_cycle(version, detail.get("releases", []) or [])
    if rel is None:
        return None
    date, field = release_date(rel)
    if date is None:
        return None
    return {
        "product": product,
        "token": token,
        "cycle": str(rel.get("name", "")),
        "date": date,
        "field": field,
        # 'exact' when the token is itself a product slug; 'prefix' when the
        # match came from a shorter dash-delimited prefix of the token.
        "kind": "exact" if token in slug_index else "prefix",
    }


def false_negative_slug(pkg: dict, slug_index: dict[str, str]) -> str | None:
    """Suggest a product for an unresolved library whose name contains a slug.

    Splits the name on @ / : . and returns the canonical product for the first
    segment (length >= 4) that is a known slug. Short slugs are skipped to
    avoid noise. Call only for libraries that did not resolve.
    """
    name = (pkg.get("name") or "").lower()
    for seg in re.split(r"[@/:.]", name):
        seg = seg.strip()
        if len(seg) >= 4 and seg in slug_index:
            return slug_index[seg]
    return None


def load_overrides(path: str | None) -> dict[str, dict]:
    """Load curated per-library EOS overrides, keyed by normalized name.

    Reads a JSON file shaped as {"overrides": [{"name","date","reason"?}, ...]}
    and returns {name.lower().strip(): {"date": str, "reason": str}}. Entries
    without a usable 'name' or 'date' are ignored. Missing path or absent file
    returns {} — overrides are optional.
    """
    if not path or not Path(path).is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out: dict[str, dict] = {}
    raw = data.get("overrides") if isinstance(data, dict) else None
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        date = str(entry.get("date", "")).strip()
        if not name or not date:
            continue
        out[name.lower()] = {"date": date, "reason": str(entry.get("reason", ""))}
    return out


def enrich(packages: list[dict], product_index: list[dict], detail_fetcher,
           version_overrides: dict, overrides: dict[str, dict] | None = None) -> dict:
    """Resolve every OSS package to a date, returning cache + report rows.

    Returns a dict with:
      eol             : {SPDXID: "YYYY-MM-DD"} for resolved libraries
      overrides       : [(name, version, date, reason), ...] curated overrides
      resolved        : [(name, version, product, cycle, date, field), ...]
      false_positives : [(name, version, product, token), ...]
      false_negatives : [(name, version, suggested_product), ...]
    """
    slug_index = build_slug_index(product_index)
    eol: dict[str, str] = {}
    resolved: list[tuple] = []
    false_positives: list[tuple] = []
    false_negatives: list[tuple] = []
    overrides = overrides or {}
    override_rows: list[tuple] = []

    for pkg in packages:
        if is_first_party(pkg):
            continue
        spdx_id = pkg.get("SPDXID", "")
        name = pkg.get("name", "")
        version = resolve_version(pkg, version_overrides)
        ovr = overrides.get((name or "").strip().lower())
        if ovr:
            eol[spdx_id] = ovr["date"]
            override_rows.append((name, version, ovr["date"], ovr["reason"]))
            continue
        res = resolve_library(pkg, version, slug_index, detail_fetcher)
        if res is None:
            slug = false_negative_slug(pkg, slug_index)
            if slug:
                false_negatives.append((name, version, slug))
            continue
        # A dash-prefix match on an npm package is treated as a suspected false
        # positive: npm 'base-suffix' names (electron-log, react-router) are
        # usually independent companion packages, not the base product. Family
        # artifacts in ecosystems that carry a confirming namespace (e.g. Maven
        # spring-boot-* under org.springframework.boot) are unaffected.
        npm_prefix_match = (
            res["kind"] == "prefix" and get_purl(pkg).startswith("pkg:npm")
        )
        if is_false_positive(pkg, res["token"]) or npm_prefix_match:
            # Suspected false positive: report it for human review but do NOT
            # apply the date to the deliverable.
            false_positives.append((name, version, res["product"], res["token"]))
            continue
        eol[spdx_id] = res["date"]
        resolved.append((name, version, res["product"], res["cycle"], res["date"], res["field"]))

    return {
        "eol": eol,
        "overrides": override_rows,
        "resolved": resolved,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def write_eol_data(path: str, eol: dict[str, str]) -> None:
    """Write the SPDXID -> date cache read by sbom_to_excel.py."""
    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "endoflife.date/api/v1",
        "eol": eol,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")


def write_report(path: str, result: dict) -> None:
    """Write the advisory Markdown report (overrides / resolved / FP / FN sections)."""
    lines: list[str] = ["# End-of-Support Enrichment Report", ""]

    lines.append("## Applied overrides")
    lines.append("")
    lines.append("| Library | Version | Date | Reason |")
    lines.append("|---|---|---|---|")
    for name, version, date, reason in result.get("overrides", []):
        lines.append(f"| {name} | {version} | {date} | {reason} |")
    lines.append("")

    lines.append("## Resolved matches")
    lines.append("")
    lines.append("| Library | Version | Product | Cycle | Date | Field |")
    lines.append("|---|---|---|---|---|---|")
    for name, version, product, cycle, date, field in result["resolved"]:
        lines.append(f"| {name} | {version} | {product} | {cycle} | {date} | {field} |")
    lines.append("")

    lines.append("## Suspected false positives")
    lines.append("")
    lines.append("| Library | Version | Matched product | Via token |")
    lines.append("|---|---|---|---|")
    for name, version, product, token in result["false_positives"]:
        lines.append(f"| {name} | {version} | {product} | {token} |")
    lines.append("")

    lines.append("## Suspected false negatives")
    lines.append("")
    lines.append("| Library | Version | Suggested product |")
    lines.append("|---|---|---|")
    for name, version, product in result["false_negatives"]:
        lines.append(f"| {name} | {version} | {product} |")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def fetch_json(url: str, timeout: float = 10.0, retries: int = 2) -> dict:
    """GET a JSON document with a timeout and a small bounded retry."""
    last_exc: Exception | None = None
    for _ in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sbom-eol/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_exc = exc
    raise RuntimeError(f"failed to fetch {url}: {last_exc}")


def fetch_product_index() -> list[dict]:
    """Fetch the endoflife.date product catalogue."""
    return fetch_json(f"{API_BASE}/products/").get("result", [])


def make_detail_fetcher():
    """Return a cached fetcher: product name -> detail dict (or None on error)."""
    cache: dict[str, dict | None] = {}

    def fetch(name: str) -> dict | None:
        if name in cache:
            return cache[name]
        try:
            detail = fetch_json(f"{API_BASE}/products/{name}").get("result")
        except RuntimeError:
            detail = None
        cache[name] = detail
        return detail

    return fetch


def main() -> None:
    cfg = load_config(DEFAULT_CONFIG)
    ap = argparse.ArgumentParser(description="Enrich an SBOM with end-of-support dates.")
    ap.add_argument("--sbom", default=cfg.get("RELEASE_SBOM_OUTPUT", "sbom_new.json"),
                    help="Path to the SPDX 2.3 JSON SBOM")
    ap.add_argument("--eol-data", default=cfg.get("EOL_DATA_OUTPUT", "eol_data.json"),
                    help="Output path for the SPDXID->date cache")
    ap.add_argument("--eol-report", default=cfg.get("EOL_REPORT_OUTPUT", "eol_report.md"),
                    help="Output path for the advisory report")
    ap.add_argument("--overrides", default=cfg.get("EOL_OVERRIDES", "eol_overrides.json"),
                    help="Optional JSON file of curated per-library EOS overrides.")
    ap.add_argument("--version-overrides", default=None,
                    help="Optional JSON version-override map (same file as sbom_to_excel).")
    args = ap.parse_args()

    with open(args.sbom, encoding="utf-8") as f:
        sbom = json.load(f)
    packages = sbom.get("packages", []) or []
    version_overrides = load_version_overrides(args.version_overrides)
    overrides = load_overrides(args.overrides)

    try:
        product_index = fetch_product_index()
    except RuntimeError as exc:
        sys.exit(f"endoflife.date unavailable, keeping existing cache: {exc}")

    result = enrich(packages, product_index, make_detail_fetcher(), version_overrides,
                    overrides=overrides)
    write_eol_data(args.eol_data, result["eol"])
    write_report(args.eol_report, result)
    print(f"✅  Resolved {len(result['eol'])} of {len(packages)} packages "
          f"({len(result['overrides'])} via override) → {args.eol_data}")
    print(f"    Report: {args.eol_report} "
          f"(FP: {len(result['false_positives'])}, FN: {len(result['false_negatives'])})")


if __name__ == "__main__":
    main()
