#!/usr/bin/env bash
# Pre-execution mutation run with per-node kill accounting.
#
# Detector Reviewer finding 7: the previous runner installed an interposer that
# ran the real product and then rewrote its stdout and exit status, so a
# "mutation" changed the observation rather than the behaviour. Planters are now
# pre-execution: acceptance._harness.planters mutates the raw state the product
# will read -- event bytes, certificate, registry, config, corpus record, native
# source, fault schedule -- at a declared seam, before the product starts, and
# records an independent read-back witness.
#
# Detector Reviewer finding 8: kill accounting reads the emitted census and
# requires every named node to fail in the planter's declared channel.
# Collection, setup and environment failures are INVALID_HARNESS, never a kill,
# and a run whose planter never reached its seam is INVALID_HARNESS because it
# exercised no defect at all.
#
#   tests/mutation-run.sh                 # every catalogued planter
#   tests/mutation-run.sh v5.newest_wins  # one planter
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
REAL="${KINBASE_BIN:-$(command -v kinbase || true)}"
if [ -z "$REAL" ]; then
  echo "mutation-run: no product entry point; set KINBASE_BIN" >&2
  echo "mutation-run: INVALID_HARNESS -- a mutation run without a product" >&2
  echo "              tests nothing; it is not a kill and not a pass." >&2
  exit 70
fi
LEDGER="${KINBASE_KILL_LEDGER:-$HERE/_artifacts/product-kill-ledger.json}"
mkdir -p "$(dirname "$LEDGER")"
exec "$PYTHON" - "$REAL" "$LEDGER" "${1:-}" <<'PYEOF'
import hashlib, json, os, pathlib, subprocess, sys, tempfile
sys.path.insert(0, str(pathlib.Path.cwd()))
from acceptance._harness.planters import PLANTERS, coverage

real, ledger_path, only = sys.argv[1], sys.argv[2], (sys.argv[3] or "")

KILLED, SURVIVED, INVALID = "KILLED", "SURVIVED", "INVALID_HARNESS"


def per_node_outcomes(payload: dict) -> dict:
    out = {}
    for record in payload.get("nodes", []):
        out[record["node"].split("/")[-1].split("[", 1)[0]] = {
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
        census_path = tmpdir / "census.json"
        env = dict(os.environ)
        env["KINBASE_BIN"] = real
        env["KINBASE_ACCEPT_MUTATION"] = planter.mutation_id
        env["KINBASE_ACCEPT_GATE_VECTOR"] = str(census_path)
        nodes = [f"acceptance/{n}" for n in planter.must_fail_nodes]
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-c", "pytest.ini",
             "-p", "no:cacheprovider", "-q", "--tb=no", *nodes],
            env=env, capture_output=True, text=True)

        census = json.loads(census_path.read_text()) if census_path.is_file() else {}
        observed = per_node_outcomes(census)
        applications = [
            a for a in census.get("planter_applications", [])
            if a.get("mutation_id") == planter.mutation_id
        ]
        witnessed = [a for a in applications if a.get("effective")]
        readback = [a for a in witnessed if a.get("independently_readback")]
        expected = {n.split("[", 1)[0] for n in planter.must_fail_nodes}

        detail, result = [], KILLED
        if proc.returncode in (2, 3, 4):
            result, detail = INVALID, [f"pytest exited {proc.returncode} before running"]
        elif not census:
            result, detail = INVALID, ["the run emitted no census; nodes never executed"]
        elif not applications:
            result = INVALID
            detail.append(
                f"the planter never reached its seam {planter.point!r}: the run "
                "exercised no defect, so no node failure under it is a kill")
        elif not witnessed:
            result = INVALID
            detail.append("the planter changed no byte; an inert planter kills nothing")
        else:
            if not readback:
                detail.append(
                    "no independent read-back witness was recorded for this seam")
            for node in sorted(expected):
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
                elif seen["outcome"] != planter.expected_channel:
                    result = INVALID
                    detail.append(
                        f"{node}: failed as {seen['outcome']}, not the declared "
                        f"{planter.expected_channel}; {seen['reason'][:160]}")
                else:
                    detail.append(f"{node}: {seen['outcome']} ({seen['reason'][:120]})")

        rows.append({
            "mutation_id": planter.mutation_id, "gate": planter.mutation.gate,
            "point": planter.point, "kind": planter.kind,
            "expected_channel": planter.expected_channel,
            "nodes": list(planter.must_fail_nodes),
            "result": result, "exit_code": proc.returncode, "detail": detail,
            "applications": applications, "per_node": observed,
        })
        print(f"{result:<16} {planter.mutation_id}  ({planter.point})")
        for line in detail:
            print(f"                 {line}")

not_killed = [r for r in rows if r["result"] != KILLED]
payload = {
    "schema": "kinbase-acceptance-product-kill-ledger/3",
    "accounting": ("pre-execution planters; per-node call-phase outcomes in the "
                   "planter's declared channel; a batch exit code is never a kill"),
    "total": not only, "planters_run": len(rows),
    "kills": len(rows) - len(not_killed),
    "survived": [r for r in rows if r["result"] == SURVIVED],
    "invalid": [r for r in rows if r["result"] == INVALID],
    "catalogued_mutations_without_a_planter": list(coverage()),
    "rows": rows,
}
payload["digest"] = hashlib.sha256(
    json.dumps(payload, sort_keys=True).encode()).hexdigest()
pathlib.Path(ledger_path).write_text(json.dumps(payload, indent=2, sort_keys=True))
print(f"\nkill ledger {payload['digest'][:16]}: "
      f"{payload['kills']}/{payload['planters_run']} killed -> {ledger_path}")
sys.exit(0 if not not_killed and not payload["catalogued_mutations_without_a_planter"] else 70)
PYEOF
