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

The last implementation subagent was interrupted by the session handoff
request; its final quality review was therefore not completed. A spec review
approved the implementation. A quality review before the final test
normalization adjustment found no functional blocker after prior packaging and
config-validation changes; it suggested confirming installed-wheel config
lookup and retained a low-severity observation that the default-config
integration test does not by itself prove behavior for caller-provided custom
configuration. Earlier review comments about preserving an artifact set's
case-insensitive behavior and validating config shape were addressed.

The README has not yet been updated for this new classification rule or the
new CLI flag. Finish this as the next step, then request a final quality review
and run the real-output checks below.

## File Changes

| File | Action | What changed |
|---|---|---|
| `config/oss_deps_first_party_dependencies.json` | Created | Maps `lang-manifest`, `ldbootloader`, `serialtest`, and `systemtest` to reasons. |
| `src/sbom_to_oss_dependencies.py` | Modified | Adds config lookup/loading, exact case-insensitive artifact matching, both direct relationship orientations, optional API inputs, workbook classification, and CLI override `--oss-deps-first-party-dependencies`. |
| `pyproject.toml` | Modified | Includes the new JSON configuration under `share/hel-sbom-oss-parser` data-files for wheel installs. |
| `tests/test_sbom_to_oss_dependencies.py` | Modified | Adds config lookup/error tests, mixed-case matching test, explicit config override test, and workbook regression for all four artifacts including input SBOM immutability. |
| `README.md` | Modified | Has pre-existing/earlier-session OSS-only exclusion documentation; still needs the first-party dependency classification docs and CLI flag. |
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

- `6dd4128 docs: specify first-party dependency classification`
- `e994ff5 feat: static configurable document name for normalized SPDX JSON`
- `89f8bf3 docs: sync README excluded-components example with licenses-parser key`
- `d175f1c feat: curated component exclusions + reproducible SBOM audit test`
- `295a8b1 fix: drop generic first-party name twins in normalized SPDX JSON`
- `a52d128 fix: dedupe first-party component twins by artifact key in Components sheet`

Only `6dd4128` was created during this classification request. All implementation
changes remain unstaged/uncommitted on branch `main`.

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
202 passed in 1.85s
git diff --check
passed
```

The implementation subagent also reported a successful wheel build and
confirmed the config JSON was present in the wheel's `.data/data/share/`
directory. This was not independently rerun in the final handoff check.

The integration tests use small fixture SBOMs. A real-output verification
against `inputs/sbom_new.json` and a final post-documentation quality review
are still outstanding.

## Known Limitations

- The rule matches exact artifact IDs by taking the portion after the last
  colon, case-folding it, and checking set membership. It does not perform
  substring matching.
- Both direct SPDX representations are supported. The existing FOSSA
  incomplete-dependency placeholder chain behavior is retained in its
  established `DEPENDS_ON` orientation; inverse placeholder-chain traversal
  was not added.
- A complete final quality review has not been performed after the latest
  implementation/test changes.

## Next Steps

1. Update `README.md` under the OSS-dependencies section with the new
   classification rule, four artifact IDs, exact matching behavior, and the
   `--oss-deps-first-party-dependencies` option.
2. Review the complete implementation diff while separating it from older
   OSS-exclusion changes already present in the worktree.
3. Run the OSS-dependencies test module and full suite with the validation
   environment.
4. Generate the workbook from `inputs/sbom_new.json` to a temporary output,
   verify the four rows are on `Dependencies (OTS SOUP)` with their real
   dependent first-party components and absent from
   `SW-SYS Components (Ref-only)`, and verify those packages remain in
   `outputs/sbom_normalized.json`.
5. Rebuild/inspect the wheel to verify the config file is packaged, then run a
   final code-quality review.
6. If committing the implementation, stage only feature-specific hunks/files;
   do not accidentally include older user changes in `README.md`,
   `src/sbom_to_oss_dependencies.py`, `tests/test_sbom_to_oss_dependencies.py`,
   `tests/test_sbom_lib.py`, or
   `config/oss_deps_excluded_components.json`.
