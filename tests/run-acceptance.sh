#!/usr/bin/env bash
# Exact Validator invocation for the Kinbase black-box acceptance suite.
#
# Lane rule (Tester dispatch): every dependency and this invocation live beneath
# tests/, so no shared packaging file at the repository root is read or edited.
#
# Usage
#   tests/run-acceptance.sh                       # full suite
#   tests/run-acceptance.sh -m "selftest"         # instrument validity only
#   tests/run-acceptance.sh -m "v3 and not slow"  # one gate, fast subset
#   KINBASE_ACCEPT_MUTATION=v5.newest_wins tests/run-acceptance.sh -m v5
#
# Environment
#   KINBASE_BIN                 argv prefix for the ratified CLI (default: PATH, then `python -m kinbase`)
#   KINBASE_SPEC_ROOT           repository containing spec/ (default: discovered from this file)
#   KINBASE_TESTER_VAULT        mode-0700 canary vault root (default: $TMPDIR/kinbase-acceptance-vault-$UID)
#   KINBASE_HOST_CODEX          absolute path to the pinned Codex executable
#   KINBASE_HOST_CLAUDE         absolute path to the pinned Claude executable
#   KINBASE_ACCEPT_GATE_VECTOR  path to write the JSON gate vector
#   KINBASE_ACCEPT_MUTATION     one frozen mutation id; named nodes must then FAIL
#   KINBASE_ACCEPT_DETECTOR_MUTATION  one detector mutation id
#   ACCEPT_PYTHON                 interpreter (default: python3)
#   ACCEPT_NO_VENV=1              use the ambient interpreter instead of tests/.venv
#
# Exit status is pytest's. The suite reports a gate vector, never a verdict:
# spec/verification.md "Role separation" reserves the verdict to the Validator.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PYTHON="${ACCEPT_PYTHON:-python3}"

if [ "${ACCEPT_NO_VENV:-0}" != "1" ]; then
  if [ ! -x ".venv/bin/python" ]; then
    echo "kinbase acceptance: creating tests/.venv" >&2
    "$PYTHON" -m venv .venv
    ./.venv/bin/python -m pip install --disable-pip-version-check --quiet \
      --upgrade pip
    ./.venv/bin/python -m pip install --disable-pip-version-check --quiet \
      -r requirements.txt
  fi
  PYTHON="./.venv/bin/python"
fi

export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"

exec "$PYTHON" -m pytest -c pytest.ini "$@"
