#!/usr/bin/env bash
#
# validate_sbom.sh — conformance-check the machine-readable SBOM deliverable.
#
# Runs the standard, open-source SBOM validation toolkit against an SPDX 2.3
# JSON SBOM and reports a single pass/fail. There is no official EU/CRA/MDR
# validation portal; conformance is demonstrated with these tools:
#
#   1. SPDX 2.3 JSON Schema        (check-jsonschema)
#   2. SPDX 2.3 semantic rules     (spdx-tools)
#   3. NTIA minimum elements       (ntia-conformance-checker)  — CRA/FDA baseline
#   4. Quality score / BSI TR-03183 (sbomqs, optional — Go binary)
#
# Checks 1-3 are hard gates (exit non-zero on failure). Check 4 is advisory
# (reported, never fails the run) and is skipped when `sbomqs` is not on PATH.
#
# Usage:
#   ./src/validate_sbom.sh [SBOM_PATH]
#
#   SBOM_PATH   Path to the SPDX 2.3 JSON SBOM to validate
#               (default: outputs/sbom_machine_readable/sbom_new.json)
#
# The Python validators are installed into a cached, git-ignored virtualenv
# (.venv-conformance) on first run, so the script is self-contained.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SBOM_PATH="${1:-${PROJECT_ROOT}/outputs/sbom_machine_readable/sbom_new.json}"

VENV="${PROJECT_ROOT}/.venv-conformance"
SCHEMA="${VENV}/spdx-2.3.schema.json"
SCHEMA_URL="https://raw.githubusercontent.com/spdx/spdx-spec/support/v2.3/schemas/spdx-schema.json"

pass() { echo "✅  $*"; }
fail() { echo "❌  $*" >&2; FAILED=1; }
info() { echo "➡️   $*"; }

FAILED=0

[ -f "${SBOM_PATH}" ] || { echo "❌  SBOM not found: ${SBOM_PATH}" >&2; exit 2; }
info "Validating: ${SBOM_PATH}"

# ── set up the validator venv (cached) ──────────────────────────────────────
if [ ! -x "${VENV}/bin/python" ]; then
  info "Creating conformance virtualenv (${VENV}) ..."
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install -q --upgrade pip
  "${VENV}/bin/pip" install -q spdx-tools check-jsonschema ntia-conformance-checker
fi
PY="${VENV}/bin/python"

# ── fetch the official SPDX 2.3 schema (cached) ─────────────────────────────
if [ ! -s "${SCHEMA}" ]; then
  info "Downloading SPDX 2.3 JSON schema ..."
  curl -fsSL -o "${SCHEMA}" "${SCHEMA_URL}"
fi

echo
echo "── 1/4  SPDX 2.3 JSON Schema ──────────────────────────────────────────"
if "${VENV}/bin/check-jsonschema" --schemafile "${SCHEMA}" "${SBOM_PATH}"; then
  pass "JSON schema valid"
else
  fail "JSON schema validation failed"
fi

echo
echo "── 2/4  SPDX 2.3 semantic validation (spdx-tools) ─────────────────────"
if "${PY}" - "${SBOM_PATH}" <<'PYEOF'; then
import sys
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
msgs = validate_full_spdx_document(parse_file(sys.argv[1]))
if msgs:
    for m in msgs[:20]:
        print("  -", m.validation_message[:200])
    print(f"  ... {len(msgs)} total message(s)")
    sys.exit(1)
print("  0 semantic validation messages")
PYEOF
  pass "SPDX semantic rules satisfied"
else
  fail "SPDX semantic validation reported issues"
fi

echo
echo "── 3/4  NTIA minimum elements (CRA/FDA baseline) ──────────────────────"
if "${VENV}/bin/ntia-checker" --file "${SBOM_PATH}" | tee /tmp/ntia_out.txt | sed 's/^/  /' \
   && grep -q "Conformant: True" /tmp/ntia_out.txt; then
  pass "NTIA minimum elements conformant"
else
  fail "NTIA minimum elements NOT conformant"
fi

echo
echo "── 4/4  Quality score / BSI TR-03183 (sbomqs, advisory) ───────────────"
if command -v sbomqs >/dev/null 2>&1; then
  sbomqs score "${SBOM_PATH}" | sed 's/^/  /' || true
else
  echo "  (skipped — install interlynk-io/sbomqs to enable: go install github.com/interlynk-io/sbomqs@latest)"
fi

echo
if [ "${FAILED}" -eq 0 ]; then
  echo "✅  SBOM conformance: PASS (checks 1-3 green)"
  exit 0
else
  echo "❌  SBOM conformance: FAIL — see messages above"
  exit 1
fi
