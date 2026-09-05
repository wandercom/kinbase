#!/usr/bin/env bash
# Reviewer-safe, product-independent instrument validation.
#
# Detector Reviewer finding 2: the ordinary bootstrap read `evidence/**` through
# the manifest's review-evidence and receipt paths, and could create `tests/.venv`
# and install from the network. Neither is inside an implementation-blind
# Reviewer's surface.
#
# This entrypoint:
#   * reads only ratified `spec/**` and `tests/**` (GUILDHALL_REVIEWER_MODE=1
#     verifies the six authority-artifact digests and stops there);
#   * installs nothing and touches no network;
#   * creates no file inside the repository -- pytest's cache is disabled and its
#     temporary root is redirected outside the tree;
#   * runs only `selftest`-marked work, which never invokes the product.
#
# Usage:  tests/reviewer-selftest.sh [extra pytest args]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PYTHON="${ACCEPT_PYTHON:-python3}"
TMPROOT="$(mktemp -d "${TMPDIR:-/tmp}/guildhall-reviewer-XXXXXX")"
trap 'rm -rf "$TMPROOT"' EXIT

export GUILDHALL_REVIEWER_MODE=1
export GUILDHALL_TESTER_VAULT="$TMPROOT/vault"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export TMPDIR="$TMPROOT"

echo "guildhall reviewer self-test"
echo "  interpreter: $("$PYTHON" -V 2>&1)"
echo "  reads:       spec/** and tests/** only"
echo "  installs:    nothing; no network access"
echo "  writes:      $TMPROOT (outside the repository)"
echo

exec "$PYTHON" -m pytest -c pytest.ini \
    -p no:cacheprovider \
    -o cache_dir="$TMPROOT/pytest-cache" \
    --basetemp="$TMPROOT/pytest-tmp" \
    -m selftest \
    "$@"
