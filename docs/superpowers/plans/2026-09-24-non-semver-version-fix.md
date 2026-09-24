# Non-Semver Component Version Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `sbom_to_excel.py` show real versions for the 6 rows that currently
display a checksum/`NOASSERTION` (binary URL downloads), and allow manual
correction of the 4 rows backed by a commit SHA, without touching the rows
whose non-semver version (Maven 2-segment, git tag) is already correct.

**Architecture:** Two small, independently-testable pure functions —
`extract_version_from_download_url()` and `load_version_overrides()` — plumbed
into the existing `build_excel()` row-writing loop, plus one new optional CLI
flag. No changes to the xlsx template, column layout, or existing
classification logic (First-Party/OSS, Direct).

**Tech Stack:** Python 3, `openpyxl`, `pytest` (new dev dependency for this repo).

Spec: `docs/superpowers/specs/2026-09-24-non-semver-version-fix-design.md`

---

## Before You Start

This repo has no existing test suite. This plan introduces `pytest`. Confirm
it's installed:

```bash
python3 -c "import pytest" || pip install pytest
```

All file paths below are relative to the repo root
`/Users/ambra/workspace/Helion/sbom-parser`.

---

### Task 1: `extract_version_from_download_url()` — pure function + tests

**Files:**
- Modify: `sbom_to_excel.py` (add function after `get_cpe`, i.e. after line 83)
- Create: `tests/test_sbom_to_excel.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_sbom_to_excel.py`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbom_to_excel import extract_version_from_download_url


def test_extracts_version_with_plus_suffix_from_jre_url():
    pkg = {
        "name": "bellsoft-jre17.0.19+11-windows-amd64.zip",
        "versionInfo": "NOASSERTION",
        "externalRefs": [],
        "downloadLocation": "https://download.bell-sw.com/java/17.0.19+11/bellsoft-jre17.0.19+11-windows-amd64.zip",
    }
    assert extract_version_from_download_url(pkg) == "17.0.19+11"


def test_extracts_version_from_mongodb_url_ignoring_arch_string():
    pkg = {
        "name": "mongodb-windows-x86_64-8.0.17.zip",
        "versionInfo": "43706c28791673ac0fd7a2e0f5a3b95b",
        "externalRefs": [],
        "downloadLocation": "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-8.0.17.zip",
    }
    assert extract_version_from_download_url(pkg) == "8.0.17"


def test_returns_none_when_package_has_a_purl():
    pkg = {
        "name": "commons-io",
        "versionInfo": "2.16.1",
        "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:maven/commons-io/commons-io@2.16.1"}],
        "downloadLocation": "https://repo1.maven.org/maven2/commons-io/commons-io/2.16.1/commons-io-2.16.1.jar",
    }
    assert extract_version_from_download_url(pkg) is None


def test_returns_none_when_no_download_location():
    pkg = {"name": "tl4-ui-internal", "versionInfo": "09868c77055f4077a0405f5702597b8f8f0dd0e7", "externalRefs": []}
    assert extract_version_from_download_url(pkg) is None


def test_returns_none_when_url_has_no_version_pattern():
    pkg = {
        "name": "postgres",
        "versionInfo": "REL_18_3",
        "externalRefs": [],
        "downloadLocation": "https://github.com/postgres/postgres/archive/62d6c7d3df6287f1bd83199c1a746e50d31571a0.zip",
    }
    assert extract_version_from_download_url(pkg) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ambra/workspace/Helion/sbom-parser && python3 -m pytest tests/test_sbom_to_excel.py -v`
Expected: `ImportError: cannot import name 'extract_version_from_download_url'` (or collection error) — the function doesn't exist yet.

- [ ] **Step 3: Implement the function**

In `sbom_to_excel.py`, add this right after the `get_cpe()` function (after line 83, before `def is_first_party`):

```python
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
```

Add `import re` to the imports at the top of `sbom_to_excel.py` (after `import json`, before `import sys`):

```python
import json
import re
import sys
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ambra/workspace/Helion/sbom-parser && python3 -m pytest tests/test_sbom_to_excel.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
cd /Users/ambra/workspace/Helion/sbom-parser
git add sbom_to_excel.py tests/test_sbom_to_excel.py
git commit --no-gpg-sign -m "feat: extract real version from download URL for binary packages

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: `load_version_overrides()` — pure function + tests

**Files:**
- Modify: `sbom_to_excel.py` (add function after `extract_version_from_download_url`)
- Modify: `tests/test_sbom_to_excel.py` (append tests)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_sbom_to_excel.py`:

```python
import json as json_module

import pytest

from sbom_to_excel import load_version_overrides


def test_load_version_overrides_returns_empty_dict_when_path_is_none():
    assert load_version_overrides(None) == {}


def test_load_version_overrides_reads_json_file(tmp_path):
    overrides_file = tmp_path / "overrides.json"
    overrides_file.write_text(json_module.dumps({"tl4-ui-internal": "2.5.0"}))
    assert load_version_overrides(str(overrides_file)) == {"tl4-ui-internal": "2.5.0"}


def test_load_version_overrides_raises_clear_error_on_missing_file():
    with pytest.raises(SystemExit, match="version-overrides file not found"):
        load_version_overrides("/no/such/file.json")


def test_load_version_overrides_raises_clear_error_on_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json")
    with pytest.raises(SystemExit, match="version-overrides file is not valid JSON"):
        load_version_overrides(str(bad_file))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ambra/workspace/Helion/sbom-parser && python3 -m pytest tests/test_sbom_to_excel.py -v`
Expected: 4 new failures — `ImportError`/`AttributeError` for `load_version_overrides` (function doesn't exist yet).

- [ ] **Step 3: Implement the function**

In `sbom_to_excel.py`, add this right after `extract_version_from_download_url()`:

```python
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
```

Add `import os` to the imports at the top of `sbom_to_excel.py` (alphabetically, after `import json`... imports are: `argparse, json, re, sys` — insert `os` after `json`):

```python
import argparse
import json
import os
import re
import sys
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ambra/workspace/Helion/sbom-parser && python3 -m pytest tests/test_sbom_to_excel.py -v`
Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
cd /Users/ambra/workspace/Helion/sbom-parser
git add sbom_to_excel.py tests/test_sbom_to_excel.py
git commit --no-gpg-sign -m "feat: add version-overrides loader with clear error handling

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Wire both functions into `build_excel()` and add the CLI flag

**Files:**
- Modify: `sbom_to_excel.py:116-117` (function signature)
- Modify: `sbom_to_excel.py` (row-writing loop, version assignment)
- Modify: `sbom_to_excel.py:225-243` (`main()`)

- [ ] **Step 1: Update `build_excel()` signature and load overrides**

Find:
```python
def build_excel(sbom_path: str, template_path: str, output_path: str,
                product_name: str | None, product_version: str | None):

    # ── load SBOM ──
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)
```

Replace with:
```python
def build_excel(sbom_path: str, template_path: str, output_path: str,
                product_name: str | None, product_version: str | None,
                version_overrides_path: str | None = None):

    version_overrides = load_version_overrides(version_overrides_path)

    # ── load SBOM ──
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)
```

- [ ] **Step 2: Apply the extracted/overridden version in the row-writing loop**

Find:
```python
        version = pkg.get("versionInfo", "")
        supplier_raw = pkg.get("supplier", "NOASSERTION")
```

Replace with:
```python
        version = pkg.get("versionInfo", "")
        extracted_version = extract_version_from_download_url(pkg)
        if extracted_version:
            version = extracted_version
        version = version_overrides.get(spdx_id, version_overrides.get(name, version))
        supplier_raw = pkg.get("supplier", "NOASSERTION")
```

Note: `name` at this point has already been truncated to its last `/`-segment
a few lines above (e.g. `tl4-ui-internal`, not `19518/helion/tl4-ui-internal`)
— this is intentional, since that's the human-friendly key someone would put
in the overrides file. `spdx_id` (e.g.
`SPDXRef-custom-19518-helion-tl4-ui-internal-09868c77...`) is checked first in
case two different packages happen to share the same short name.

- [ ] **Step 3: Add the `--version-overrides` CLI flag**

Find:
```python
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
```

Replace with:
```python
    parser.add_argument("--product-name", default=None, help="Override product name in the header")
    parser.add_argument("--product-version", default=None, help="Override product version in the header")
    parser.add_argument(
        "--version-overrides", default=None,
        help="Path to a JSON file of {package name or SPDXID: real version} "
             "to use instead of the SPDX versionInfo (e.g. for packages "
             "whose version is a commit SHA)."
    )

    args = parser.parse_args()

    build_excel(
        sbom_path=args.sbom,
        template_path=args.template,
        output_path=args.output,
        product_name=args.product_name,
        product_version=args.product_version,
        version_overrides_path=args.version_overrides,
    )
```

- [ ] **Step 4: Run the existing unit tests to confirm nothing broke**

Run: `cd /Users/ambra/workspace/Helion/sbom-parser && python3 -m pytest tests/test_sbom_to_excel.py -v`
Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
cd /Users/ambra/workspace/Helion/sbom-parser
git add sbom_to_excel.py
git commit --no-gpg-sign -m "feat: wire URL-extracted and manually-overridden versions into xlsx output

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Example overrides file + manual end-to-end verification

**Files:**
- Create: `version-overrides.example.json`

- [ ] **Step 1: Create the example overrides file**

```json
{
  "_comment": "Copy to version-overrides.json and fill in real versions for packages whose SPDX versionInfo is a commit SHA or otherwise not human-readable. Keys are the package's short name (as shown in the xlsx) or its SPDXID.",
  "tl4-ui-internal": ""
}
```

- [ ] **Step 2: Regenerate the xlsx without overrides and verify the URL-extraction fix**

Run:
```bash
cd /Users/ambra/workspace/Helion/sbom-parser
python3 sbom_to_excel.py --sbom sbom_new.json --template template.xlsx --output output-dependencies.xlsx
python3 -c "
import openpyxl
wb = openpyxl.load_workbook('output-dependencies.xlsx', data_only=True)
ws = wb['SBOM']
rows = [r for r in ws.iter_rows(min_row=8, values_only=True) if r[1] is not None]
targets = ['bellsoft-jre17.0.19+11-windows-amd64.zip', 'mongodb-windows-x86_64-8.0.17.zip', 'tl4-ui-internal', 'postgres', 'Apache Commons CSV']
for r in rows:
    if r[1] in targets:
        print(r[1], '|', r[2])
"
```
Expected output (order may vary):
```
tl4-ui-internal | 09868c77055f4077a0405f5702597b8f8f0dd0e7
Apache Commons CSV | 1.8
postgres | REL_18_3
bellsoft-jre17.0.19+11-windows-amd64.zip | 17.0.19+11
mongodb-windows-x86_64-8.0.17.zip | 8.0.17
```
Confirm: JRE and MongoDB now show real versions; `tl4-ui-internal` still
shows the SHA (no override supplied); `Apache Commons CSV` and `postgres`
are unchanged.

- [ ] **Step 3: Regenerate the xlsx WITH an override and verify it takes effect**

```bash
cd /Users/ambra/workspace/Helion/sbom-parser
echo '{"tl4-ui-internal": "2.5.0-test"}' > /tmp/test-overrides.json
python3 sbom_to_excel.py --sbom sbom_new.json --template template.xlsx --output /tmp/test-output.xlsx --version-overrides /tmp/test-overrides.json
python3 -c "
import openpyxl
wb = openpyxl.load_workbook('/tmp/test-output.xlsx', data_only=True)
ws = wb['SBOM']
for r in ws.iter_rows(min_row=8, values_only=True):
    if r[1] == 'tl4-ui-internal':
        print(r[1], '|', r[2])
"
rm /tmp/test-overrides.json /tmp/test-output.xlsx
```
Expected output: `tl4-ui-internal | 2.5.0-test`

- [ ] **Step 4: Verify the clear-error behavior for a bad overrides path**

```bash
cd /Users/ambra/workspace/Helion/sbom-parser
python3 sbom_to_excel.py --sbom sbom_new.json --template template.xlsx --output /tmp/test-output.xlsx --version-overrides /no/such/file.json; echo "exit code: $?"
```
Expected: prints `version-overrides file not found: /no/such/file.json` and `exit code: 1` (no `/tmp/test-output.xlsx` created).

- [ ] **Step 5: Commit**

```bash
cd /Users/ambra/workspace/Helion/sbom-parser
git add version-overrides.example.json output-dependencies.xlsx
git commit --no-gpg-sign -m "feat: add version-overrides example file, regenerate official SBOM xlsx

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Summary of spec coverage

- Pattern 1 (Maven 2-segment) — verified unchanged in Task 4 Step 2. ✅
- Pattern 2 (binary/URL downloads) — Task 1 + wired in Task 3, verified in Task 4 Step 2. ✅
- Pattern 3 (git tag) — verified unchanged in Task 4 Step 2. ✅
- Pattern 4 (commit SHA) — Task 2 + wired in Task 3, verified with and without override in Task 4 Steps 2–3. ✅
- Clear error on bad overrides file — Task 2 tests + Task 4 Step 4. ✅
