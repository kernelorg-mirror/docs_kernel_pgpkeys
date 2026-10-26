#!/usr/bin/env sh

set -eu

# The dev tooling lives in scripts/pyproject.toml, so run from here no
# matter where ci.sh was invoked from.
cd "$(dirname "$0")"

# Run each gate in order, stopping at the first failure.  Every step has
# its own exit code so a failure is discernible both from the printed
# banner and from ci.sh's own exit status (e.g. exit 13 == ty check).

run() {
    # run <exit-code-on-failure> <description> <command...>
    _code="$1"
    _step="$2"
    shift 2
    printf '\n=== %s ===\n' "$_step"
    if ! "$@"; then
        printf '\n>>> CI FAILED at: %s (ci.sh exit %d)\n' "$_step" "$_code" >&2
        exit "$_code"
    fi
}

run 10 'uv sync'      uv sync --all-groups
run 11 'ruff format'  uv run ruff format --check
run 12 'ruff check'   uv run ruff check
run 13 'ty check'     uv run ty check
run 14 'mypy'         uv run mypy .
run 15 'pyright'      uv run pyright
run 16 'pytest'       uv run pytest --durations=20

printf '\n=== CI PASSED ===\n'
