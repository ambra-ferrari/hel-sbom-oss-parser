# OSS first-party library metadata overrides

## Context

The `Dependencies (OTS SOUP)` sheet includes four internally developed Maven
packages: `biz.videomed.tl4.tools:lang-manifest`,
`biz.videomed.tl4.tools:LDBootloader`,
`biz.videomed.tl4.tools:SystemTest`, and
`biz.videomed.tl4.tools:SerialTest`. Their current SPDX records have no
homepage, download location, description, or declared license, so the
generated workbook has incomplete metadata.

## Design

Keep the existing workbook-only classification and SBOM data unchanged. Extend
the existing per-package OSS overrides to support a `vendor` value in addition
to license, purpose, and reference. Apply these field overrides to the four
Maven package names and regenerate the OSS workbook from the current input SBOM.

Set `Vendor` to `Baxter` and `License` to `internally developed` for all four
packages. Set `Reference` to each package's Maven Central artifact directory:

- `https://repo1.maven.org/maven2/biz/videomed/tl4/tools/lang-manifest/`
- `https://repo1.maven.org/maven2/biz/videomed/tl4/tools/LDBootloader/`
- `https://repo1.maven.org/maven2/biz/videomed/tl4/tools/SystemTest/`
- `https://repo1.maven.org/maven2/biz/videomed/tl4/tools/SerialTest/`

Set the package purposes to:

- `lang-manifest`: `proper listing of supported languages for selection from configuration tool`
- `LDBootloader`: `VMboards firmware update tool`
- `SystemTest`: `low level interaction with VMBoards for service or test`
- `SerialTest`: `low level interaction with control ports for service or test`

No new override file is needed. All other packages and existing generated
workbook behavior remain unchanged.

## Validation

- Add regression coverage proving the per-package vendor override is emitted
  while packages without that override retain their existing vendor behavior.
- Verify all four generated workbook rows contain the exact requested vendor,
  license, reference, and purpose values.
- Verify the source SBOM remains unchanged and run the relevant test suite.
