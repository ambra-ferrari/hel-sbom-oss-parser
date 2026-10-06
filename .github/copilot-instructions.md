# Copilot instructions — hel-sbom-oss-parser

Tools that generate the official SBOM/OSS-dependencies Excel deliverables
and the machine-readable SPDX 2.3 JSON SBOM from FOSSA exports. Full
per-tool documentation lives in `README.md` — read the relevant section
before changing a tool's behavior; do not duplicate it here.

## Authoritative references
- `README.md` — exhaustive usage/flags/classification-rules per tool; treat as the source of truth over any code comment.
- `docs/superpowers/specs/*-design.md` — approved design docs (closest thing to ADRs) for notable past changes; the only `docs/*` files actually committed (see below).
- `fossa.config` — all default CLI flag values; safe to read/commit (no secrets).

## Project layout
- `src/` — the tools (flat modules + 2 shell wrappers), src-layout package (`pyproject.toml`, `package-dir = {"" = "src"}`).
- `tools/` — auxiliary one-off reviewer agents (e.g. lockfile-vs-SBOM check), not part of the main pipeline.
- `config/*.json` — curated, hand-maintained override files consumed by multiple tools (aliases, exclusions, license/EOL/version overrides). Each is documented in `README.md`; follow the existing shape when adding entries.
- `templates/*.xlsx` — blank Excel templates populated by the generators; don't hand-edit generated output into these.
- `inputs/`, `outputs/`, `build/`, `.venv*` — git-ignored working/generated directories. Never commit files here.

## Build / install
```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"        # adds pytest
.venv/bin/pip install -e ".[conformance]" # adds SPDX/NTIA validators, optional
```

## Test
```bash
pytest                                    # full suite (testpaths = tests/)
pytest tests/test_sbom_to_excel.py -v     # single module
pytest tests/test_sbom_conformance.py     # SBOM validator gates (needs [conformance] + a generated deliverable; auto-skips otherwise)
./src/validate_sbom.sh [SBOM_PATH]        # one-shot schema/semantic/NTIA validation, self-contained
```
No lint/type-check tool is configured in this repo (no flake8/ruff/mypy/black config found) — don't invent one.
No CI/CD pipeline exists (no `.github/workflows` or other CI config) — don't assume one runs these checks automatically.

## Coding conventions (verified in `src/sbom_lib.py` and callers)
- SBOM-transforming functions take an SPDX dict and **return a new dict; never mutate the input** (explicitly documented and asserted in tests, e.g. `assert out is spdx` when a no-op). Follow this when adding new transforms.
- CLI scripts report status via `print()` with `✅`/`❌`/`⬇️` markers; fatal errors use `sys.exit("message")` (argparse-style scripts) or `print(..., file=sys.stderr); sys.exit(1)`. No `logging` module is used anywhere in `src/`.
- Shell scripts start with `#!/usr/bin/env bash`, `set -euo pipefail`, and a header comment block documenting usage/flags (`src/validate_sbom.sh`, `src/download_sbom.sh`).
- Secrets (`FOSSA_API_KEY`) are never read from `fossa.config`; only from the environment or the git-ignored `.fossa.secret` file.

## Definition of Done
1. `pytest` passes (full suite; add/update tests for any behavior change, including a non-mutation assertion for new SPDX-transform functions).
2. If a tool's CLI flags, config file shape, or classification rules changed, update the matching `README.md` section.
3. If the SBOM-generation pipeline (`normalize_sbom_aliases.py`, `sbom_lib.py`) changed, regenerate the machine-readable deliverable and confirm `./src/validate_sbom.sh` still passes checks 1–3 (hard gates).
4. Don't commit anything under `inputs/`, `outputs/`, `build/`, or `.venv*`.
