#!/usr/bin/env bash
# Validator-applied mutation run with a total kill ledger.
#
# Detector Reviewer finding 6. Selecting a mutation previously applied nothing.
# This script installs one executable planter ahead of the product entry point,
# runs the nodes the frozen catalog says must fail under it, and requires every
# one of them to fail. A surviving mutant is INVALID_HARNESS, never a pass.
#
#   tests/mutation-run.sh                 # every catalogued planter
#   tests/mutation-run.sh v5.newest_wins  # one planter
#
# Requires GUILDHALL_BIN (or `guildhall` on PATH) to resolve the real product.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PYTHON="${ACCEPT_PYTHON:-python3}"
REAL="${GUILDHALL_BIN:-$(command -v guildhall || true)}"
if [ -z "$REAL" ]; then
  echo "mutation-run: no product entry point; set GUILDHALL_BIN" >&2
  exit 70
fi

LEDGER="${GUILDHALL_KILL_LEDGER:-$HERE/_artifacts/product-kill-ledger.json}"
mkdir -p "$(dirname "$LEDGER")"
exec "$PYTHON" - "$REAL" "$LEDGER" "${1:-}" <<'PYEOF'
import json, os, subprocess, sys, tempfile, pathlib
sys.path.insert(0, str(pathlib.Path.cwd()))
from acceptance._harness.planters import PLANTERS, install, coverage_gaps

real, ledger_path, only = sys.argv[1], sys.argv[2], (sys.argv[3] or "")
rows = []
for planter in PLANTERS:
    if only and planter.mutation_id != only:
        continue
    with tempfile.TemporaryDirectory() as tmp:
        bin_dir = pathlib.Path(tmp) / "bin"
        install(planter, bin_dir, [real])
        env = dict(os.environ)
        env["GUILDHALL_BIN"] = str(bin_dir / "guildhall")
        env["GUILDHALL_PLANTER_SPEC"] = json.dumps({
            "transform": planter.transform, "target": planter.target,
            "value": planter.value, "commands": list(planter.commands)})
        env["GUILDHALL_PLANTER_REAL"] = json.dumps([real])
        env["GUILDHALL_ACCEPT_MUTATION"] = planter.mutation_id
        nodes = [f"acceptance/{n}" for n in planter.must_fail_nodes]
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-c", "pytest.ini", "-p", "no:cacheprovider",
             "-q", "--tb=no", *nodes],
            env=env, capture_output=True, text=True)
        killed = proc.returncode != 0
        rows.append({
            "mutation_id": planter.mutation_id, "gate": planter.mutation.gate,
            "transform": planter.transform, "nodes": planter.must_fail_nodes,
            "result": "KILLED" if killed else "SURVIVED",
            "exit_code": proc.returncode,
        })
        print(f"{'KILLED  ' if killed else 'SURVIVED'} {planter.mutation_id}")

survived = [r for r in rows if r["result"] != "KILLED"]
payload = {
    "schema": "guildhall-acceptance-product-kill-ledger/1",
    "total": not only, "planters_run": len(rows),
    "kills": len(rows) - len(survived), "survived": survived,
    "coverage_gaps": coverage_gaps(), "rows": rows,
}
import hashlib
payload["digest"] = hashlib.sha256(
    json.dumps(payload, sort_keys=True).encode()).hexdigest()
pathlib.Path(ledger_path).write_text(json.dumps(payload, indent=2, sort_keys=True))
print(f"\nkill ledger {payload['digest'][:16]}: "
      f"{payload['kills']}/{payload['planters_run']} killed -> {ledger_path}")
sys.exit(0 if not survived and not payload["coverage_gaps"] else 70)
PYEOF
