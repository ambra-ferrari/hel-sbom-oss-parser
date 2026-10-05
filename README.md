# hel-sbom-oss-parser

Tools to generate the official SBOM Excel deliverables from an SPDX 2.3 JSON
SBOM (e.g. produced by FOSSA), and to cross-check dependency versions and
end-of-support dates against other sources of truth (npm lockfile, a previous
baseline xlsx, endoflife.date).

## Repository layout

```
hel-sbom-oss-parser/
├── src/                  # Python modules & shell wrappers (the actual tools)
│   ├── sbom_lib.py                  # shared SBOM-parsing helpers
│   ├── sbom_to_excel.py             # → official SBOM dependencies xlsx
│   ├── sbom_to_oss_dependencies.py  # → Helion OTS-SOUP OSS dependencies xlsx
│   ├── enrich_eol.py                # → end-of-support date cache + report
│   ├── download_release_sbom.py     # aggregate a FOSSA release-group SBOM
│   └── download_sbom.sh             # single-project FOSSA SBOM download
├── tools/                # auxiliary reviewer agents
│   └── lockfile_sbom_agent.py       # npm lockfile vs SBOM version check
├── templates/            # blank official xlsx templates
│   ├── template.xlsx
│   └── oss-template.xlsx
├── config/               # curated, hand-maintained override files
│   ├── eol_overrides.json
│   ├── license_overrides.json
│   └── version-overrides.example.json
├── inputs/               # SBOMs / lockfiles fed into the tools (git-ignored)
├── outputs/              # generated xlsx / csv / md deliverables (git-ignored)
├── tests/                # pytest suite
├── fossa.config          # FOSSA connection settings (no secrets — safe to commit)
├── pyproject.toml        # packaging / dependencies / pytest config
└── README.md
```

`inputs/` and `outputs/` are git-ignored working directories: put your SBOM
(`sbom_new.json`), `package-lock.json`, baseline xlsx, etc. into `inputs/`, and
the tools write their deliverables to `outputs/`.

## Requirements

- Python 3.9+
- `openpyxl`

Install as an editable package (recommended — makes the `src/` modules
importable from anywhere and pins the dependency):

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"   # [dev] adds pytest for the test suite
```

Or install just the runtime dependency:

```bash
.venv/bin/pip install openpyxl
```

For downloading SBOMs from FOSSA you also need the
[FOSSA CLI](https://github.com/fossas/fossa-cli) on your `PATH`.

> The examples below run the tools as scripts (`python3 src/<tool>.py …`); run
> them from the repository root so the default `inputs/`, `outputs/`,
> `config/` and `templates/` paths resolve.

---

## Downloading the SBOM from FOSSA

Connection settings live in [`fossa.config`](fossa.config) (safe to commit — it
holds **no** secrets). The API key is read from the environment
(`export FOSSA_API_KEY=...`) or from a git-ignored `.fossa.secret` file in the
repository root.

### `src/download_sbom.sh` — single project (SPDX-JSON)

Thin wrapper around `fossa report attribution --format spdx-json` that writes a
validated SPDX-JSON SBOM (atomically — a failed download never clobbers a good
file). Reads `fossa.config`/`.fossa.secret` from the repository root.

```bash
export FOSSA_API_KEY=xxxx
./src/download_sbom.sh                       # uses ./fossa.config, writes inputs/sbom_new.json
./src/download_sbom.sh -p my-project -o inputs/out.json
```

Set `FOSSA_PROJECT` / `FOSSA_ENDPOINT` in `fossa.config`, or leave `FOSSA_PROJECT`
empty to let the CLI infer it from the current git `origin` remote.

### `src/download_release_sbom.py` — aggregated release group (SPDX-JSON)

The FOSSA CLI can only export a **single project**. To get the **aggregated**
SBOM of a *release group release* (several projects combined) this script calls
the FOSSA REST API directly: it resolves the org and release, lists every
project revision in the release, downloads each project's SPDX-JSON attribution,
and merges them into one valid SPDX 2.3 document (SPDXIDs are namespaced per
project so nothing collides). Standard library only — no extra dependencies.

By default only each project's **direct** dependencies are kept (the packages
the project root `DEPENDS_ON` directly); transitive dependencies are dropped.
Use `--all-deps` (or `DIRECT_ONLY="false"` in `fossa.config`) to keep the full
graph. Test-only packages (e.g. `testify`, `testcontainers`, `junit`, `jest`,
first-party test modules) are dropped by default — use `--include-test` (or
`EXCLUDE_TEST="false"`) to keep them, and `TEST_PATTERNS` to extend the match
list. The URLs of every source project are recorded in the SPDX
`creationInfo.comment`.

Identify the release by title or by numeric ids (in `fossa.config` or via flags):

```bash
export FOSSA_API_KEY=xxxx

# by title (direct dependencies only, the default)
./src/download_release_sbom.py \
    --release-group-title "My Product" \
    --release-title "2024.1" \
    -o inputs/sbom_new.json

# or by numeric ids, keeping transitive deps too
./src/download_release_sbom.py --release-group-id 123 --release-id 456 --all-deps
```

The merged output plugs straight into `sbom_to_excel.py` and the agents below.

---

## `src/sbom_to_excel.py` — generate the official SBOM xlsx

Populates the official SBOM Excel template from an SPDX JSON SBOM file.

### Classification rules

- **Dependency relationship**: every real component is a direct dependant of
  one of the product roots (verified via the SPDX `DEPENDS_ON` graph — there
  is no recorded transitive chain in this SBOM), so all rows are classified
  `Direct`.
- **OSS vs First-Party**: components whose `supplier` contains
  `"Custom (provided build)"` are internally developed (Baxter) components;
  everything else is classified `OSS`. First-Party rows are listed first in
  the output, then OSS.
- **Incomplete/placeholder packages**: FOSSA sometimes emits a duplicate
  placeholder package for a URL it couldn't fully resolve
  (`comment == "Incomplete dependency"`, version/download location both
  `NOASSERTION`). These are automatically excluded — the real package entry
  for the same component already carries the correct version.
- **Non-semver versions**:
  - Binary/URL downloads with no purl (e.g. a JRE or MongoDB zip) often have
    a checksum or `NOASSERTION` as `versionInfo` — the real version is
    extracted automatically from the download URL/filename.
  - A handful of components have no resolvable version at all (e.g. a
    package whose version is a commit SHA). Use `--version-overrides` (see
    below) to supply the real version manually.
  - Some versions are intentionally left as-is because they're already
    correct for their ecosystem (e.g. 2-segment Maven versions like `1.8`,
    or a git tag such as `REL_18_3` for a source build).

### Usage

```bash
python3 src/sbom_to_excel.py \
    --sbom inputs/sbom_new.json \
    --template templates/template.xlsx \
    --output outputs/output-dependencies.xlsx \
    [--product-name "My Product"] \
    [--product-version "1.2.3"] \
    [--version-overrides config/version-overrides.json] \
    [--component-aliases config/component_aliases.json] \
    [--excluded-components config/excluded_components.json] \
    [--eol-data outputs/eol_data.json]
```

| Flag | Required | Description |
|---|---|---|
| `--sbom` | yes | Path to the SPDX JSON SBOM to read |
| `--template` | yes | Path to the blank official xlsx template |
| `--output` | yes | Path to write the populated xlsx to |
| `--product-name` | no | Override the product name shown in the header |
| `--product-version` | no | Override the product version shown in the header |
| `--version-overrides` | no | Path to a JSON file of manual version overrides (see below) |
| `--component-aliases` | no | Path to a JSON file of curated first-party component aliases (see `config/component_aliases.json`) that collapse the same internal component's two names into one canonical row |
| `--excluded-components` | no | Path to a JSON file of curated component exclusions (see `config/excluded_components.json`) for components that must never appear in the output |
| `--eol-data` | no | Path to `eol_data.json` (from `enrich_eol.py`) to fill the end-of-support column |

### Manual version overrides

For components whose version can't be determined automatically (e.g. a
commit SHA with no accessible tag/release), create a JSON file mapping the
package's short name (as shown in the xlsx) or its SPDXID to the real
version. See `config/version-overrides.example.json` for the format:

```json
{
  "tl4-ui-internal": "2.5.0"
}
```

Pass it with `--version-overrides path/to/overrides.json`. The tool exits
with a clear error (instead of silently ignoring it) if the file is missing
or not valid JSON.

### Curated component aliases (`config/component_aliases.json`)

Some internal (first-party) components appear in the SBOM twice under two
different names for the SAME component — e.g. a Maven coordinate
(`biz.videomed.tl4.installer:tl4-app-external`) and a friendly project-root
name (`hel-app`) — with no derivable relationship between the two names. This
curated file maps the alternate name (matched on its short artifact name,
case-insensitive) to the canonical `hel-*` name so both representations
collapse into one row:

```json
{
  "tl4-app-external": "hel-app",
  "tl4-app-print-helper": "hel-app-print-helper"
}
```

Pass it with `--component-aliases config/component_aliases.json`. Optional —
omitting it leaves both names as separate rows. Used identically by
`sbom_to_excel.py` and `sbom_to_oss_dependencies.py`.

### Curated component exclusions (`config/excluded_components.json`)

Some components must never appear in the output at all (e.g. internal
tooling that isn't meant to be reported as a tracked component). This
curated file maps the component's short artifact name (case-insensitive) to
a free-text reason; matching packages are dropped entirely — not just
deduped — from every generated deliverable:

```json
{
  "licensing": "Explicitly excluded per request — internal licensing helper not meant to be reported as a tracked component.",
  "license-parser": "Explicitly excluded per request — internal licensing helper not meant to be reported as a tracked component. Kept as a safety-net alias in case a future SBOM pull uses this exact (singular) spelling.",
  "licenses-parser": "Explicitly excluded per request — internal licensing helper not meant to be reported as a tracked component. Actual artifact name found in the SBOM as 'biz.videomed.util:licenses-parser' (plural)."
}
```

Pass it with `--excluded-components config/excluded_components.json`.
Optional — omitting it changes nothing. Used identically by
`sbom_to_excel.py`, `sbom_to_oss_dependencies.py`, and
`normalize_sbom_aliases.py` (which also drops any relationship referencing
the excluded package from the normalized SPDX JSON).

### OSS-dependencies-only exclusions

`config/oss_deps_excluded_components.json` lists components omitted only from
the OTS-SOUP OSS dependencies workbook. These packages remain in the SBOM and
other deliverables:

```json
{
  "hel-invalidated-tokens-api": "Excluded from the OSS dependencies deliverable only; retain in the SBOM.",
  "invalidated-tokens-api": "Maven artifact alias of hel-invalidated-tokens-api; exclude from OSS dependencies only and retain in the SBOM.",
  "hel-nms-broker-api": "Excluded from the OSS dependencies deliverable only; retain in the SBOM.",
  "nms-broker-api": "Maven artifact alias of hel-nms-broker-api; exclude from OSS dependencies only and retain in the SBOM."
}
```

`sbom_to_oss_dependencies.py` applies this file by default. Override its
location with `--oss-deps-excluded-components`. Maven artifact aliases are
included because OSS-deps canonicalizes those package names to the matching
`hel-*` component after exclusions are applied.

### Static document name override (`normalize_sbom_aliases.py --document-name`)

`normalize_sbom_aliases.py` (the script that writes the normalized SPDX JSON
used in the machine-readable SBOM deliverable) also overrides the document's
top-level `name` field with a static, configurable value, since FOSSA derives
it from the release-group/release ids or titles (e.g.
`"561 / current (aggregated)"`), which isn't a meaningful product name for
consumers of the file. Configure it via `OSS_SBOM_DOCUMENT_NAME` in
`fossa.config` (e.g. `"Truelink 4 (or Helion)/1.8.0"`) or override per-run
with `--document-name`. Leave empty to keep the FOSSA-derived name as-is.

---

## `src/enrich_eol.py` — resolve end-of-support dates

Enriches an SPDX SBOM with end-of-support dates from
[endoflife.date](https://endoflife.date). For each third-party (OSS) library it
resolves an end-of-support date via the endoflife.date v1 REST API and writes:

- `outputs/eol_data.json` — a `{SPDXID: "YYYY-MM-DD"}` cache consumed by
  `sbom_to_excel.py` via `--eol-data`.
- `outputs/eol_report.md` — an advisory report listing resolved matches plus
  suspected false positives / false negatives for manual review.

Standard library only. Shared logic (`is_first_party`, `resolve_version`,
config parsing) is imported from `sbom_to_excel` and `download_release_sbom` so
all stages agree on classification and versions. All defaults are read from
`fossa.config`, so from the repo root a bare invocation just works.

### Curated end-of-support overrides (`config/eol_overrides.json`)

Pins a fixed end-of-support date for a library by name (case-insensitive, any
version), winning over the value computed from endoflife.date — for libraries
the API misidentifies or doesn't cover.

### Usage

```bash
python3 src/enrich_eol.py \
    [--sbom inputs/sbom_new.json] \
    [--eol-data outputs/eol_data.json] \
    [--eol-report outputs/eol_report.md] \
    [--overrides config/eol_overrides.json] \
    [--version-overrides config/version-overrides.json]
```

| Flag | Required | Description |
|---|---|---|
| `--sbom` | no | Path to the SPDX JSON SBOM (default from `fossa.config`) |
| `--eol-data` | no | Output path for the `SPDXID → date` cache |
| `--eol-report` | no | Output path for the advisory report |
| `--overrides` | no | Curated per-library end-of-support overrides |
| `--version-overrides` | no | Same version-override map used by `sbom_to_excel.py` |

Typical pipeline: `enrich_eol.py` → `sbom_to_excel.py --eol-data outputs/eol_data.json`.

---

## `src/sbom_to_oss_dependencies.py` — generate the Helion OTS-SOUP OSS dependencies xlsx

Populates the two-sheet OTS-SOUP Excel template (`templates/oss-template.xlsx`)
from an SPDX JSON SBOM: one row per external OSS package in
"Dependencies (OTS SOUP)", and the internal Helion components in
"SW-SYS Components (Ref-only)".

### Classification rules

- **OSS vs internal component**: same `is_first_party()` marker as
  `sbom_to_excel.py` (`supplier` contains `Custom (provided build)`) — those
  packages go to the components sheet, never to the OSS sheet.
- **Configured first-party dependencies**: artifact IDs listed in
  `config/oss_deps_first_party_dependencies.json` override the first-party
  classification for this workbook only. They appear in `Dependencies (OTS
  SOUP)` with their dependent first-party components and are omitted from
  `SW-SYS Components (Ref-only)`. Matching is an exact, case-insensitive
  comparison against the final name segment after `:` (the Maven artifact
  ID), independent of group and version. The default list includes
  `lang-manifest`, `LDBootloader`, `SerialTest`, and `SystemTest`; these
  packages remain unchanged in both the input and normalized SBOM.
- **Incomplete/placeholder packages**: FOSSA's "Incomplete dependency"
  placeholders are dropped; if an internal component depended on the
  placeholder instead of the real package, that dependency is re-attributed
  to the real, resolved package.
- **Shared packages**: when the same OSS package is depended on by more than
  one internal component, it gets a single row with all component names
  comma-joined in "SW-SYS Components" — never duplicate rows.
- **Genuine duplicates**: if an aggregated (release-group) SBOM contains the
  same package name+version twice under different SPDXIDs, the two entries
  are merged into one row (components unioned) rather than producing a
  duplicate row.
- **License normalization**: FOSSA emits opaque `LicenseRef-<family>-<hash>`
  values (e.g. `LicenseRef-MIT-89469734`); these are normalized to clean SPDX
  identifiers (`MIT`, `Apache-2.0`, `EPL-2.0`, …) while preserving `OR`/`AND`/
  `WITH` operators. Plain SPDX values pass through untouched.
- **License fallback**: a curated override (see `--license-overrides`) wins
  first; otherwise `licenseDeclared` is used (normalized); when it's `NONE`,
  the first entry of `licenseInfoFromFiles` is used with a
  `(derived from file scan; no declared license)` note; when neither is
  available the cell reads `UNKNOWN - Review Required` so the gap is never
  silently missed.
- **Review flagging**: after writing the xlsx the tool prints the rows whose
  license is copyleft/notable (GPL, LGPL, MPL, CDDL, EPL, SSPL, OFL, …),
  `UNKNOWN`, or file-scan-derived, so legal review has a ready checklist.

### Curated package overrides (`config/license_overrides.json`)

External binaries FOSSA can't resolve (nginx, PostgreSQL, MongoDB, FFmpeg,
the BellSoft JRE, NSSM, …) would otherwise land as `UNKNOWN` licenses and
with empty **Purpose** / **Reference** cells. The committed
`config/license_overrides.json` pins source-verified metadata per package,
keyed by package **name** (case-insensitive). Each entry may carry any of:

- `license` — an SPDX license (wins over FOSSA, used verbatim; may be a custom
  `LicenseRef-*` id, e.g. `LicenseRef-FTDI-FTD2XX`, to correct a scanner false
  positive).
- `purpose` — a short description used when SPDX has no usable summary.
- `reference` — the Reference cell value (typically `website=<url>`).
- `ref` — fallback value for the Ref column in the OSS-dependencies workbook,
  used only when SPDX has neither a usable PURL nor a download location.
  A usable PURL or download location takes precedence. This differs from
  `reference`, which populates the separate Reference column.
- `vendor` — the Vendor cell value in the OSS-dependencies workbook; packages
  without this override keep the default `Open Source`.

Any field may be omitted; a `purpose`/`reference`/`ref`/`vendor`-only entry leaves
the license untouched. These overrides change generated workbook cells only;
both `ref` and `reference` are workbook-only metadata and do not modify the
source SBOM. Format:

```json
{
  "overrides": [
    {"name": "org.nginx:nginx-windows", "license": "BSD-2-Clause",
     "purpose": "HTTP server and reverse proxy (nginx)",
     "reference": "website=https://nginx.org/",
     "source": "https://nginx.org/LICENSE"}
  ]
}
```

Pass it with `--license-overrides config/license_overrides.json`.

### Usage

```bash
python3 src/sbom_to_oss_dependencies.py \
    --sbom inputs/sbom_new.json \
    --template templates/oss-template.xlsx \
    --output outputs/output-oss-dependencies.xlsx \
    [--product-name "Helion System"] \
    [--version-overrides config/version-overrides.json] \
    [--license-overrides config/license_overrides.json] \
    [--component-aliases config/component_aliases.json] \
    [--excluded-components config/excluded_components.json] \
    [--oss-deps-excluded-components config/oss_deps_excluded_components.json] \
    [--oss-deps-first-party-dependencies config/oss_deps_first_party_dependencies.json]
```

| Flag | Required | Description |
|---|---|---|
| `--sbom` | yes | Path to the SPDX JSON SBOM to read |
| `--template` | yes | Path to the blank OTS-SOUP xlsx template |
| `--output` | yes | Path to write the populated xlsx to |
| `--product-name` | no | Product name shown in the components sheet title (defaults to the SBOM's own `name` field) |
| `--version-overrides` | no | Path to a JSON file of manual version overrides (same format as `sbom_to_excel.py` — see above) |
| `--license-overrides` | no | Path to a JSON file of curated SPDX license overrides (see `config/license_overrides.json`) |
| `--component-aliases` | no | Path to a JSON file of curated first-party component aliases (see `config/component_aliases.json`) that collapse the same internal component's two names into one canonical row |
| `--excluded-components` | no | Path to a JSON file of curated component exclusions (see `config/excluded_components.json`) for components that must never appear in the output |
| `--oss-deps-excluded-components` | no | Path to the OSS-dependencies-only exclusions (defaults to `config/oss_deps_excluded_components.json`); these components remain in the SBOM |
| `--oss-deps-first-party-dependencies` | no | Path to the JSON map of first-party artifact IDs emitted as dependencies in this workbook only (defaults to `config/oss_deps_first_party_dependencies.json`) |

---

## `tools/lockfile_sbom_agent.py` — confirm npm versions against the SBOM

Reviewer agent that checks npm dependency versions declared in a
`package-lock.json` (source of truth for what actually gets installed)
against the versions recorded in the SBOM JSON.

Scope: only components present in **both** files are compared — it reports
`version_match` / `version_mismatch`. Presence/absence differences are out of
scope (use a diff tool for that instead).

### Usage

```bash
python3 tools/lockfile_sbom_agent.py \
    --lockfile inputs/package-lock.json \
    --sbom inputs/sbom_new.json \
    --report outputs/lockfile-vs-sbom-report.md \
    --csv outputs/lockfile-vs-sbom-diff.csv
```

| Flag | Required | Description |
|---|---|---|
| `--lockfile` | yes | Path to `package-lock.json` |
| `--sbom` | yes | Path to the SPDX JSON SBOM |
| `--report` | yes | Path to write the Markdown report to |
| `--csv` | yes | Path to write the CSV diff data to |

---

## Tests

Run the full suite from the repository root:

```bash
.venv/bin/python -m pytest        # or just: pytest
```

Or a single module:

```bash
.venv/bin/python -m pytest tests/test_sbom_to_excel.py -v
.venv/bin/python -m pytest tests/test_sbom_to_oss_dependencies.py -v
```
