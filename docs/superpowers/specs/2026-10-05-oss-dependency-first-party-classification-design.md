# Configurable first-party dependency classification

## Context

The OTS-SOUP OSS-dependencies workbook currently classifies packages using
`is_first_party()`. Packages under the `biz.videomed` group are consequently
listed as internal components in the `SW-SYS Components (Ref-only)` sheet.
Four such packages shown in the user's screenshot are dependencies of other
first-party components and belong in the `Dependencies (OTS SOUP)` sheet:
`lang-manifest`, `LDBootloader`, `SerialTest`, and `SystemTest`.

This is a workbook-only classification override. It must not modify the source
or normalized SPDX SBOM.

## Design

Add a dedicated configuration file for first-party artifact IDs that should be
treated as dependencies by `sbom_to_oss_dependencies.py`. Store the four
artifact IDs from the screenshot in this file. Match artifact IDs
case-insensitively, independent of version and Maven group ID.

During OSS workbook generation, configured packages are classified as
dependencies even if the existing `is_first_party()` heuristic would classify
them as components. Include them in the first sheet's dependency rows and use
their SPDX relationships to list dependent internal components in the
Components column. Exclude them from the second sheet's component list.
Existing classification remains unchanged for every package not selected by
the configuration.

The configuration is specific to the OSS-dependencies generator, not the
general SBOM exclusions or normalized SBOM pipeline. Keep its location and
the configured artifact list clear in the README.

## Validation

- Unit tests verify matching of configured Maven coordinates by
  case-insensitive artifact ID, regardless of group/version.
- End-to-end workbook test verifies each configured package appears in the
  first sheet with its dependent first-party component, and none appears in
  the second sheet.
- A regression check verifies the input SBOM package list is not modified.
- Existing OSS-dependencies and full test suites continue to pass.
