# OSS dependencies empty-cell repair

## Context

The current `Dependencies (OTS SOUP)` workbook has seven empty data cells:

- `Reference` for `com.github.lukepet:yalv` version `1.4.0.0`.
- `SW-SYS Components` for `annotations-api`, `Jackson-annotations`, and
  `Jackson-core`.
- `Ref` for `dcm4che`, `dcmtk`, and `ffmpeg`.

The input SBOM contains no homepage or download URL for YALV, and no PURL or
download URL for the three FOSSA Archive packages. It does contain direct SPDX
relationships from the three dependencies to `hel-invalidated-tokens-api` or
`hel-nms-broker-api`. Those first-party components are excluded from the
Components sheet by policy, but should still be visible as dependency
attribution in the Dependencies sheet.

## Design

Persist workbook metadata in the existing `config/license_overrides.json` and
extend its per-package override handling with an optional `ref` value. The
`Reference` column for YALV will use its official project page:
`https://github.com/LukePet/YALV`.

For the `Ref` column, preserve existing behavior when the SBOM has a PURL or a
real download location. If both are absent or `NOASSERTION`, use a configured
`ref` override. Add these official project URLs for the Archive packages:

- `dcm4che`: `https://github.com/dcm4che/dcm4che`
- `dcmtk`: `https://github.com/DCMTK/dcmtk`
- `ffmpeg`: `https://ffmpeg.org/`

Build dependency-to-component attribution from the complete package set before
applying curated component exclusions. Continue generating dependency rows
and the Components sheet from the excluded package set so excluded components
remain absent as dependency entries and from the Components sheet. Keep their
names available in the `SW-SYS Components` field when an included OSS
dependency has a direct SPDX relationship to them. This changes workbook
attribution only; it does not alter the SBOM or the exclusion policy.

The official sources support the selected values: YALV's GitHub README
identifies it as a Log4Net/Serilog log viewer; the dcm4che and DCMTK project
repositories describe their DICOM toolkit/library purpose; FFmpeg's official
about page describes the multimedia framework.

## Validation

- Tests verify the `ref` fallback is only used when PURL and download URL are
  unavailable, and that existing PURL/download resolution takes precedence.
- A regression test verifies excluded internal components remain absent from
  the Components sheet but appear in attribution for dependent included
  packages.
- End-to-end workbook verification confirms the seven previously empty cells
  have the approved values.
- The source SBOM remains byte-for-byte unchanged and the relevant test suite
  passes.
