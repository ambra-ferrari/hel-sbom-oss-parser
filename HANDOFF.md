# Hand-off — OSS dependency first-party classification

**Date**: 2026-10-05
**Authors**: Ambra Ferrari, Copilot

---

## What Was Done

The user asked to classify four Maven artifacts shown in a screenshot as
first-party dependencies in the OTS-SOUP OSS-dependencies workbook rather than
as internal components. The artifacts are `lang-manifest`, `LDBootloader`,
`SerialTest`, and `SystemTest`. This is a workbook-only rule: it must not
remove or rewrite these packages in the input or normalized SBOM.

A design was approved and committed as `6dd4128`. An implementation plan was
written in `docs/superpowers/plans/2026-10-05-oss-first-party-dependency-rules.md`.
The plan file is ignored by the repository's `docs/*` ignore rule and is not
committed.

Implementation changes are present but uncommitted. The OSS-dependencies
generator now loads a dedicated list of first-party dependency artifact IDs,
matches the final Maven coordinate segment case-insensitively, classifies
matching packages into the dependency sheet, attributes their dependent
components for either direct SPDX relationship orientation, and excludes them
from the Components sheet. Existing placeholder dependency-chain behavior is
retained. Config path resolution supports the source checkout and installed
package data, with explicit errors for missing/invalid config files. The
configuration is included in setuptools `data-files`.

`README.md` was updated to explain the rule and the
`--oss-deps-first-party-dependencies` option. Independent specification and
code-quality reviews found no remaining blocking issues. The case-normalized
explicit-set test, installed wheel content, full test suite, and actual
workbook generated from the current SBOM were all verified.

## File Changes

| File | Action | What changed |
|---|---|---|
| `config/oss_deps_first_party_dependencies.json` | Created | Maps `lang-manifest`, `ldbootloader`, `serialtest`, and `systemtest` to reasons. |
| `src/sbom_to_oss_dependencies.py` | Modified | Adds config lookup/loading, exact case-insensitive artifact matching, both direct relationship orientations, optional API inputs, workbook classification, and CLI override `--oss-deps-first-party-dependencies`. |
| `pyproject.toml` | Modified | Includes the new JSON configuration under `share/hel-sbom-oss-parser` data-files for wheel installs. |
| `tests/test_sbom_to_oss_dependencies.py` | Modified | Adds config lookup/error tests, mixed-case matching test, explicit config override test, and workbook regression for all four artifacts including input SBOM immutability. |
| `README.md` | Modified | Has pre-existing/earlier-session OSS-only exclusion documentation plus the first-party dependency classification and CLI flag documentation. |
| `tests/test_sbom_lib.py` | Modified | Has pre-existing/earlier-session coverage for general SBOM exclusions; not part of the new first-party classification feature. |
| `config/oss_deps_excluded_components.json` | Untracked | Earlier user request: exclude `hel-invalidated-tokens-api` and `hel-nms-broker-api` and their Maven aliases from the OSS workbook only. |
| `docs/superpowers/specs/2026-10-05-oss-dependency-first-party-classification-design.md` | Created, committed | Approved design for the workbook-only classification override. |
| `docs/superpowers/plans/2026-10-05-oss-first-party-dependency-rules.md` | Created, ignored | Implementation plan; includes direct `DEPENDENCY_OF` and `DEPENDS_ON` relation coverage. |

Several edits in the already-dirty `README.md`,
`src/sbom_to_oss_dependencies.py`, and
`tests/test_sbom_to_oss_dependencies.py` predate this implementation: those
include the user's previous OSS-dependencies-only exclusion changes. Preserve
them and do not stage unrelated changes together with any future commit.

## Commit History

Commits relevant to this session, newest first:

- `b0b6c0d docs: add OSS classification handoff`
- `6dd4128 docs: specify first-party dependency classification`
- `e994ff5 feat: static configurable document name for normalized SPDX JSON`
- `89f8bf3 docs: sync README excluded-components example with licenses-parser key`
- `d175f1c feat: curated component exclusions + reproducible SBOM audit test`
- `295a8b1 fix: drop generic first-party name twins in normalized SPDX JSON`
- `a52d128 fix: dedupe first-party component twins by artifact key in Components sheet`

The design and handoff documents are committed. All implementation changes
remain unstaged/uncommitted on branch `main`.

## Current Configuration

`config/oss_deps_first_party_dependencies.json` currently contains:

```json
{
  "lang-manifest": "Internal library treated as a dependency only in the OSS-dependencies workbook.",
  "ldbootloader": "Internal library treated as a dependency only in the OSS-dependencies workbook.",
  "serialtest": "Internal library treated as a dependency only in the OSS-dependencies workbook.",
  "systemtest": "Internal library treated as a dependency only in the OSS-dependencies workbook."
}
```

Use `--oss-deps-first-party-dependencies <path>` to override this JSON file.
`build_excel` also accepts `first_party_dependency_config_path` or the
normalized `first_party_dependency_ids` set; passing both is rejected.

## Prerequisites / Environment

- Branch: `main`
- Runtime: Python 3.12.4
- Validation environment: `/tmp/hel-sbom-validation-venv`
- Installed in that environment: pytest 9.1.1 and openpyxl 3.1.5
- The system `python3.12` environment does not have pytest/openpyxl; use the
  validation venv for tests.
- The working directory was not moved to a worktree; the user chose to keep
  working on the current branch.

## How to Use

Generate the OTS-SOUP workbook with the repository default configuration:

```bash
/tmp/hel-sbom-validation-venv/bin/python src/sbom_to_oss_dependencies.py \
  --sbom inputs/sbom_new.json \
  --template templates/oss-template.xlsx \
  --output /tmp/output-oss-dependencies.xlsx \
  --component-aliases config/component_aliases.json \
  --excluded-components config/excluded_components.json
```

An explicit first-party dependency config can be supplied with:

```bash
--oss-deps-first-party-dependencies config/oss_deps_first_party_dependencies.json
```

## Test Results

Fresh verification immediately before handoff:

```text
/tmp/hel-sbom-validation-venv/bin/python -m pytest tests/ -q
202 passed in 1.87s
git diff --check
passed
```

Real workbook generation from `inputs/sbom_new.json` verified that all four
configured artifacts appear on `Dependencies (OTS SOUP)`, are attributed to
`hel-tools`, and do not appear on `SW-SYS Components (Ref-only)`. The same four
artifact IDs remain in `outputs/sbom_normalized.json`.

The wheel was built with `pip wheel --no-deps --no-build-isolation`; archive
inspection confirmed
`hel_sbom_oss_parser-1.0.0.data/data/share/hel-sbom-oss-parser/oss_deps_first_party_dependencies.json`
is packaged. A final independent code review found no Critical, Important, or
Minor issues. Both config JSON files parsed successfully and
`git diff --check` passed.

## Known Limitations

- The rule matches exact artifact IDs by taking the portion after the last
  colon, case-folding it, and checking set membership. It does not perform
  substring matching.
- Both direct SPDX representations are supported. The existing FOSSA
  incomplete-dependency placeholder chain behavior is retained in its
  established `DEPENDS_ON` orientation; inverse placeholder-chain traversal
  was not added.

## Next Steps

1. If committing the implementation, stage only feature-specific hunks/files;
   do not accidentally include older user changes in `README.md`,
   `src/sbom_to_oss_dependencies.py`, `tests/test_sbom_to_oss_dependencies.py`,
   `tests/test_sbom_lib.py`, or
   `config/oss_deps_excluded_components.json`.
