#!/usr/bin/env bash
#
# download_sbom.sh — download the project SBOM from FOSSA as SPDX (JSON).
#
# Thin, robust wrapper around the FOSSA CLI (`fossa report attribution`).
# Reads connection settings from a config file (default: ./fossa.config) and
# the API key from the environment / a git-ignored secret file, then writes a
# validated SPDX-JSON SBOM ready for sbom_to_excel.py.
#
# Usage:
#   ./download_sbom.sh [-c CONFIG] [-o OUTPUT] [-p PROJECT] [-r REVISION]
#
#   -c CONFIG    Path to the config file       (default: ./fossa.config)
#   -o OUTPUT    Override SBOM_OUTPUT           (where to write the SBOM)
#   -p PROJECT   Override FOSSA_PROJECT
#   -r REVISION  Override FOSSA_REVISION
#   -h           Show this help and exit
#
# The API key is NEVER read from the config file. Provide it via:
#   export FOSSA_API_KEY="xxxx"
# or a git-ignored file ".fossa.secret" next to this script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${PROJECT_ROOT}/fossa.config"
OUT_OVERRIDE=""
PROJECT_OVERRIDE=""
REVISION_OVERRIDE=""

die() { echo "❌  $*" >&2; exit 1; }

usage() { sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts ":c:o:p:r:h" opt; do
  case "$opt" in
    c) CONFIG_FILE="$OPTARG" ;;
    o) OUT_OVERRIDE="$OPTARG" ;;
    p) PROJECT_OVERRIDE="$OPTARG" ;;
    r) REVISION_OVERRIDE="$OPTARG" ;;
    h) usage 0 ;;
    \?) die "Unknown option: -$OPTARG (use -h for help)" ;;
    :)  die "Option -$OPTARG requires an argument" ;;
  esac
done

# --- preconditions --------------------------------------------------------
command -v fossa >/dev/null 2>&1 || \
  die "FOSSA CLI not found. Install it: https://github.com/fossas/fossa-cli"

[[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"

# --- load config ----------------------------------------------------------
# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Load the API key from a git-ignored secret file if not already in the env.
SECRET_FILE="${PROJECT_ROOT}/.fossa.secret"
if [[ -z "${FOSSA_API_KEY:-}" && -f "$SECRET_FILE" ]]; then
  secret="$(grep -v '^[[:space:]]*#' "$SECRET_FILE" | grep -m1 . || true)"
  secret="${secret#FOSSA_API_KEY=}"
  FOSSA_API_KEY="$(echo "$secret" | tr -d '[:space:]')"
fi

[[ -n "${FOSSA_API_KEY:-}" ]] || die \
  "FOSSA_API_KEY is not set. Export it or add it to ${SECRET_FILE}"

# Apply CLI overrides.
[[ -n "$OUT_OVERRIDE" ]]      && SBOM_OUTPUT="$OUT_OVERRIDE"
[[ -n "$PROJECT_OVERRIDE" ]]  && FOSSA_PROJECT="$PROJECT_OVERRIDE"
[[ -n "$REVISION_OVERRIDE" ]] && FOSSA_REVISION="$REVISION_OVERRIDE"

: "${FOSSA_ENDPOINT:=https://app.fossa.com}"
: "${SBOM_OUTPUT:=sbom_new.json}"
: "${SBOM_FORMAT:=spdx-json}"
: "${FOSSA_TIMEOUT:=600}"

# --- build the fossa command ---------------------------------------------
cmd=(fossa report attribution
     --format "$SBOM_FORMAT"
     --endpoint "$FOSSA_ENDPOINT"
     --fossa-api-key "$FOSSA_API_KEY"
     --timeout "$FOSSA_TIMEOUT")

[[ -n "${FOSSA_PROJECT:-}" ]]  && cmd+=(--project "$FOSSA_PROJECT")
[[ -n "${FOSSA_REVISION:-}" ]] && cmd+=(--revision "$FOSSA_REVISION")

echo "⬇️   Downloading SBOM from ${FOSSA_ENDPOINT}"
echo "     project : ${FOSSA_PROJECT:-<git origin>}"
echo "     revision: ${FOSSA_REVISION:-<git HEAD>}"
echo "     format  : ${SBOM_FORMAT}"
echo "     output  : ${SBOM_OUTPUT}"

# Write to a temp file first so a failed/partial download never clobbers a
# previously-good SBOM.
tmp_out="$(mktemp "${SBOM_OUTPUT}.XXXXXX")"
trap 'rm -f "$tmp_out"' EXIT

if ! "${cmd[@]}" > "$tmp_out"; then
  die "FOSSA report command failed (see output above)."
fi

# --- validate -------------------------------------------------------------
[[ -s "$tmp_out" ]] || die "FOSSA returned an empty SBOM."

if command -v python3 >/dev/null 2>&1; then
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$tmp_out" \
    || die "Downloaded SBOM is not valid JSON."
fi

mv "$tmp_out" "$SBOM_OUTPUT"
trap - EXIT

bytes=$(wc -c < "$SBOM_OUTPUT" | tr -d ' ')
echo "✅  SBOM saved to ${SBOM_OUTPUT} (${bytes} bytes)"
