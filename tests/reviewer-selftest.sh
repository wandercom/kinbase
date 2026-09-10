#!/usr/bin/env bash
# Reviewer-safe, product-independent instrument validation.
#
# Detector Reviewer finding 2: the ordinary bootstrap read `evidence/**` through
# the manifest's review-evidence and receipt paths, and could create `tests/.venv`
# and install from the network. Neither is inside an implementation-blind
# Reviewer's surface.
#
# This entrypoint:
#   * reads only ratified `spec/**` and `tests/**` (KINBASE_REVIEWER_MODE=1
#     verifies the six authority-artifact digests and stops there);
#   * installs nothing and touches no network;
#   * creates no file inside the repository -- pytest's cache is disabled and its
#     temporary root is redirected outside the tree;
#   * runs pyflakes over tests/** before pytest (Tester dispatch 006), then
#     only `selftest`-marked work, which never invokes the product.
#
# The interpreter must already have tests/requirements.txt available (pytest,
# pytest-timeout, pyflakes). tests/.venv is used automatically when it exists;
# otherwise pass ACCEPT_PYTHON. Nothing is installed here.
#
# Usage:  tests/reviewer-selftest.sh [extra pytest args]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ -n "${ACCEPT_PYTHON:-}" ]; then
  PYTHON="$ACCEPT_PYTHON"
elif [ -x ".venv/bin/python" ]; then
  PYTHON="./.venv/bin/python"
else
  PYTHON="python3"
fi
TMPROOT="$(mktemp -d "${TMPDIR:-/tmp}/kinbase-reviewer-XXXXXX")"
trap 'rm -rf "$TMPROOT"' EXIT

export KINBASE_REVIEWER_MODE=1
export KINBASE_TESTER_VAULT="$TMPROOT/vault"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export TMPDIR="$TMPROOT"

echo "kinbase reviewer self-test"
echo "  interpreter: $("$PYTHON" -V 2>&1)"
echo "  reads:       spec/** and tests/** only"
echo "  installs:    nothing; no network access"
echo "  writes:      $TMPROOT (outside the repository)"
echo

# Static analysis first: an undefined name inside a gate module raises only
# when its node runs, which in the Validator's run means after real product
# state has been built. pyflakes finds it with no product present. Tester
# dispatch 006 made this a handover condition. pyflakes is a dependency of
# tests/requirements.txt; an interpreter without it cannot attest cleanliness
# and the entrypoint says so rather than skipping.
if ! "$PYTHON" -c "import pyflakes" 2>/dev/null; then
  echo "kinbase reviewer self-test: pyflakes is not importable by $PYTHON;" >&2
  echo "  install tests/requirements.txt into tests/.venv (tests/run-acceptance.sh does) or pass ACCEPT_PYTHON" >&2
  exit 70
fi
echo "static analysis: pyflakes over tests/**"
"$PYTHON" -m pyflakes conftest.py acceptance tools
echo "  clean"
echo

# pytest's cache provider is disabled, so its `cache_dir` option no longer
# exists and --strict-config (pytest.ini) would refuse `-o cache_dir=...`.
exec "$PYTHON" -m pytest -c pytest.ini \
    -p no:cacheprovider \
    --basetemp="$TMPROOT/pytest-tmp" \
    -m selftest \
    "$@"
