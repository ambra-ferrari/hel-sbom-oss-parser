# sbom-parser

Tools to generate the official SBOM Excel deliverable from an SPDX 2.3 JSON
SBOM (e.g. produced by FOSSA), and to cross-check dependency versions against
other sources of truth (npm lockfile, a previous baseline xlsx).

## Requirements

- Python 3.9+
- `openpyxl`

```bash
python3 -m venv .venv
.venv/bin/pip install openpyxl pytest
```

(`pytest` is only needed to run the test suite in `tests/`.)

---

## `sbom_to_excel.py` — generate the official SBOM xlsx

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
python3 sbom_to_excel.py \
    --sbom sbom_new.json \
    --template template.xlsx \
    --output output-dependencies.xlsx \
    [--product-name "My Product"] \
    [--product-version "1.2.3"] \
    [--version-overrides version-overrides.json]
```

| Flag | Required | Description |
|---|---|---|
| `--sbom` | yes | Path to the SPDX JSON SBOM to read |
| `--template` | yes | Path to the blank official xlsx template |
| `--output` | yes | Path to write the populated xlsx to |
| `--product-name` | no | Override the product name shown in the header |
| `--product-version` | no | Override the product version shown in the header |
| `--version-overrides` | no | Path to a JSON file of manual version overrides (see below) |

### Manual version overrides

For components whose version can't be determined automatically (e.g. a
commit SHA with no accessible tag/release), create a JSON file mapping the
package's short name (as shown in the xlsx) or its SPDXID to the real
version. See `version-overrides.example.json` for the format:

```json
{
  "tl4-ui-internal": "2.5.0"
}
```

Pass it with `--version-overrides path/to/overrides.json`. The tool exits
with a clear error (instead of silently ignoring it) if the file is missing
or not valid JSON.

### Tests

```bash
.venv/bin/python -m pytest tests/test_sbom_to_excel.py -v
```

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
    --lockfile package-lock.json \
    --sbom sbom_new.json \
    --report lockfile-vs-sbom-report.md \
    --csv lockfile-vs-sbom-diff.csv
```

| Flag | Required | Description |
|---|---|---|
| `--lockfile` | yes | Path to `package-lock.json` |
| `--sbom` | yes | Path to the SPDX JSON SBOM |
| `--report` | yes | Path to write the Markdown report to |
| `--csv` | yes | Path to write the CSV diff data to |
