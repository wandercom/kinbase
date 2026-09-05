#!/usr/bin/env bash
# Validator-applied mutation run with per-node kill accounting.
#
# Detector Reviewer finding 8: any nonzero pytest status previously marked a
# mutation KILLED, even when only one of two named nodes failed, or when
# collection, setup or the environment failed. Kill accounting now parses the
# per-node call-phase report and requires every named node to fail in its
# expected channel; collection, setup and environment failures are
# INVALID_HARNESS, never a kill.
#
#   tests/mutation-run.sh                 # every catalogued planter
#   tests/mutation-run.sh v5.newest_wins  # one planter
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
import hashlib, json, os, pathlib, subprocess, sys, tempfile
sys.path.insert(0, str(pathlib.Path.cwd()))
from acceptance._harness.planters import PLANTERS, coverage_gaps, install

real, ledger_path, only = sys.argv[1], sys.argv[2], (sys.argv[3] or "")

KILLED, SURVIVED, INVALID = "KILLED", "SURVIVED", "INVALID_HARNESS"


def per_node_outcomes(report_path: pathlib.Path) -> dict:
    """Read the census the run emitted and return per-node call outcomes."""
    if not report_path.is_file():
        return {}
    payload = json.loads(report_path.read_text())
    out = {}
    for record in payload.get("nodes", []):
        out[record["node"].split("/")[-1]] = {
            "outcome": record["outcome"],
            "phases": record.get("phases", {}),
            "channel": record.get("channel", ""),
            "reason": record.get("reason", ""),
        }
    return out


rows = []
for planter in PLANTERS:
    if only and planter.mutation_id != only:
        continue
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        bin_dir = tmpdir / "bin"
        install(planter, bin_dir, [real])
        census_path = tmpdir / "census.json"
        env = dict(os.environ)
        env["GUILDHALL_BIN"] = str(bin_dir / "guildhall")
        env["GUILDHALL_PLANTER_SPEC"] = json.dumps({
            "transform": planter.transform, "target": planter.target,
            "value": planter.value, "commands": list(planter.commands)})
        env["GUILDHALL_PLANTER_REAL"] = json.dumps([real])
        env["GUILDHALL_ACCEPT_MUTATION"] = planter.mutation_id
        env["GUILDHALL_ACCEPT_GATE_VECTOR"] = str(census_path)
        nodes = [f"acceptance/{n}" for n in planter.must_fail_nodes]
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-c", "pytest.ini",
             "-p", "no:cacheprovider", "-q", "--tb=no", *nodes],
            env=env, capture_output=True, text=True)

        observed = per_node_outcomes(census_path)
        expected = {n.split("::")[0] + "::" + n.split("::")[1]
                    for n in planter.must_fail_nodes}
        detail, result = [], KILLED
        if proc.returncode in (2, 3, 4):          # usage / collection / internal
            result, detail = INVALID, [f"pytest exited {proc.returncode} before running"]
        elif not observed:
            result, detail = INVALID, ["the run emitted no census; nodes never executed"]
        else:
            for node in expected:
                seen = observed.get(node)
                if seen is None:
                    result = INVALID
                    detail.append(f"{node}: never executed under the mutation")
                    continue
                if seen["phases"].get("setup") == "failed":
                    result = INVALID
                    detail.append(f"{node}: failed in setup, not by observing the defect")
                    continue
                if seen["outcome"] == "PASS":
                    result = SURVIVED if result != INVALID else result
                    detail.append(f"{node}: passed under the mutation")
                elif seen["outcome"] == "INVALID_HARNESS":
                    result = INVALID
                    detail.append(f"{node}: instrument condition, not a product kill")
                else:
                    detail.append(f"{node}: {seen['outcome']} ({seen['reason']})")

        rows.append({
            "mutation_id": planter.mutation_id, "gate": planter.mutation.gate,
            "transform": planter.transform, "nodes": list(planter.must_fail_nodes),
            "result": result, "exit_code": proc.returncode, "detail": detail,
            "per_node": observed,
        })
        print(f"{result:<16} {planter.mutation_id}")
        for line in detail:
            print(f"                 {line}")

not_killed = [r for r in rows if r["result"] != KILLED]
payload = {
    "schema": "guildhall-acceptance-product-kill-ledger/2",
    "accounting": "per-node call-phase outcomes; a batch exit code is never a kill",
    "total": not only, "planters_run": len(rows),
    "kills": len(rows) - len(not_killed),
    "survived": [r for r in rows if r["result"] == SURVIVED],
    "invalid": [r for r in rows if r["result"] == INVALID],
    "coverage_gaps": coverage_gaps(), "rows": rows,
}
payload["digest"] = hashlib.sha256(
    json.dumps(payload, sort_keys=True).encode()).hexdigest()
pathlib.Path(ledger_path).write_text(json.dumps(payload, indent=2, sort_keys=True))
print(f"\nkill ledger {payload['digest'][:16]}: "
      f"{payload['kills']}/{payload['planters_run']} killed -> {ledger_path}")
sys.exit(0 if not not_killed and not payload["coverage_gaps"] else 70)
PYEOF
