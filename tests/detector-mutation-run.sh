#!/usr/bin/env bash
# One isolated run per detector mutation.
#
# Detector Reviewer finding 9. spec/verification.md "Instrument validity":
#
#   Mutations target detectors as well as product code -- for example, disable
#   archive scanning, SQLite blob scanning, normalization decoding, or manifest
#   comparison and require the planted defect to escape the detector's own
#   self-test while causing the gate to reject the instrument.
#
# For each catalogued detector mutation this runner requires BOTH halves:
#
#   1. the mutation's own positive control, planted on the exact surface the
#      mutation disables, escapes the mutated detector while the unmutated
#      detector catches it (acceptance._harness.detectorprobe);
#   2. the run's emitted census reports V-3 instrument channel INVALID_HARNESS.
#
# The probe half is product independent and runs anywhere. The census half runs
# the instrument's own selftest selection, so this runner needs no product.
#
#   tests/detector-mutation-run.sh                       # all six
#   tests/detector-mutation-run.sh disable_archive_scan  # one
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
PYTHON="${ACCEPT_PYTHON:-}"
if [ -z "$PYTHON" ]; then
  if [ "${ACCEPT_NO_VENV:-0}" != "1" ] && [ -x ".venv/bin/python" ]; then
    PYTHON="./.venv/bin/python"
  else
    PYTHON="python3"
  fi
fi
LEDGER="${KINBASE_DETECTOR_LEDGER:-$HERE/_artifacts/detector-kill-ledger.json}"
mkdir -p "$(dirname "$LEDGER")"
exec "$PYTHON" - "$LEDGER" "${1:-}" <<'PYEOF'
import hashlib, json, os, pathlib, subprocess, sys, tempfile
sys.path.insert(0, str(pathlib.Path.cwd()))
from acceptance._harness.detectorprobe import run_probe
from acceptance._harness.detectors import DETECTOR_MUTATIONS

ledger_path, only = sys.argv[1], (sys.argv[2] or "")
KILLED, SURVIVED, INVALID = "KILLED", "SURVIVED", "INVALID_HARNESS"
rows = []

for mutation in sorted(DETECTOR_MUTATIONS):
    if only and mutation != only:
        continue
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        detail = []
        try:
            probe = run_probe(mutation, tmpdir / "probe")
        except Exception as exc:                      # noqa: BLE001 - reported, not raised
            rows.append({"detector_mutation": mutation, "result": INVALID,
                         "detail": [f"probe raised {type(exc).__name__}: {exc}"]})
            print(f"{INVALID:<16} {mutation}")
            continue

        census_path = tmpdir / "census.json"
        env = dict(os.environ)
        env["KINBASE_ACCEPT_DETECTOR_MUTATION"] = mutation
        env["KINBASE_ACCEPT_GATE_VECTOR"] = str(census_path)
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-c", "pytest.ini",
             "-p", "no:cacheprovider", "-q", "--tb=no", "-m", "selftest",
             "acceptance"],
            env=env, capture_output=True, text=True)

        census = json.loads(census_path.read_text()) if census_path.is_file() else {}
        v3 = census.get("gates", {}).get("V-3", {})
        instrument = v3.get("instrument_channel", "")

        result = KILLED
        if not probe.detected_unmutated:
            result = INVALID
            detail.append("the unmutated detector missed its own positive control")
        elif probe.detected_mutated:
            result = SURVIVED
            detail.append("the positive control did not escape the mutated detector")
        if not census:
            result = INVALID
            detail.append("the run emitted no census")
        elif instrument != "INVALID_HARNESS":
            result = SURVIVED if result == KILLED else result
            detail.append(f"V-3 instrument channel is {instrument!r}, not INVALID_HARNESS")
        if proc.returncode in (2, 3, 4):
            result = INVALID
            detail.append(f"pytest exited {proc.returncode} before running")

        rows.append({
            "detector_mutation": mutation,
            "meaning": DETECTOR_MUTATIONS[mutation],
            "result": result,
            "probe": probe.as_json(),
            "v3_instrument_channel": instrument,
            "exit_code": proc.returncode,
            "detail": detail,
        })
        print(f"{result:<16} {mutation}  escape={probe.escaped} v3={instrument}")
        for line in detail:
            print(f"                 {line}")

missing = sorted(set(DETECTOR_MUTATIONS) - {r["detector_mutation"] for r in rows})
bad = [r for r in rows if r["result"] != KILLED]
payload = {
    "schema": "kinbase-acceptance-detector-kill-ledger/1",
    "requirement": ("require the planted defect to escape the detector's own "
                    "self-test while causing the gate to reject the instrument"),
    "total": not only,
    "declared": sorted(DETECTOR_MUTATIONS),
    "run": len(rows),
    "kills": len(rows) - len(bad),
    "not_killed": bad,
    "unrun": [] if only else missing,
    "rows": rows,
}
payload["digest"] = hashlib.sha256(
    json.dumps(payload, sort_keys=True).encode()).hexdigest()
pathlib.Path(ledger_path).write_text(json.dumps(payload, indent=2, sort_keys=True))
print(f"\ndetector kill ledger {payload['digest'][:16]}: "
      f"{payload['kills']}/{payload['run']} killed -> {ledger_path}")
sys.exit(0 if not bad and not payload["unrun"] else 70)
PYEOF
