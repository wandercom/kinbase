#!/usr/bin/env python3
"""Freeze the raw positive and negative control fixtures, once.

Detector Reviewer finding 4: ``conforming()``, ``violating()``, ``benign()``, the
blinded checker and the judge all derived from one clause object at run time, so
the kill ledger could only ever restate the clause to itself. Weakening a clause
weakened its own controls in the same step, and the 400-row ledger could not
establish sensitivity to anything.

This tool derives the controls **once**, from the catalog as it stands at freeze
time, and writes them to ``tests/fixtures/controls/controls.json`` together with
the exact tag each negative must trip. At run time the ledger reads those frozen
bytes and never calls the generators: a clause that is later loosened no longer
rejects its own frozen negative, and the ledger reports a survivor.

The frozen file also records, per row, the ratified fail-closed channel and the
executable pre-execution planter bound to the obligation's nodes, so a row is
sound only when a real product mutation exists for it as well.

    tests/tools/freeze-controls.py --check    # verify the committed bytes
    tests/tools/freeze-controls.py --write    # regenerate
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from acceptance._harness.catalog import OBLIGATIONS  # noqa: E402
from acceptance._harness.planters import PLANTERS  # noqa: E402

CONTROLS = HERE / "fixtures" / "controls" / "controls.json"
DIGEST = HERE / "fixtures" / "controls" / "CONTROLS-DIGEST"


def _planters_for(obligation) -> list[str]:
    nodes = {n.split("[", 1)[0] for n in obligation.nodes}
    out = []
    for planter in PLANTERS:
        if nodes & {n.split("[", 1)[0] for n in planter.must_fail_nodes}:
            out.append(planter.mutation_id)
    return sorted(out)


def build() -> dict:
    rows = []
    for obligation in OBLIGATIONS:
        clause_set = obligation.clause_set
        entry = {
            "oid": obligation.oid,
            "gate": obligation.gate,
            "fail_closed": obligation.fail_closed,
            "nodes": list(obligation.nodes),
            "product_mutations": _planters_for(obligation),
            "positive": clause_set.conforming(),
            "negatives": [],
        }
        for clause in clause_set.clauses:
            entry["negatives"].append({
                "tag": clause.tag,
                "kind": clause.kind,
                "expected_failing_tag": clause.tag,
                "payload": clause_set.violating(clause.tag),
                "benign": clause_set.benign(clause.tag),
            })
        rows.append(entry)
    return {
        "schema": "kinbase-frozen-controls/1",
        "provenance": (
            "Derived once from the preregistered obligation catalog by "
            "tests/tools/freeze-controls.py and committed. The suite reads these "
            "bytes and never regenerates them, so a later clause change cannot "
            "move its own controls."
        ),
        "obligation_count": len(rows),
        "control_rows": sum(len(r["negatives"]) for r in rows),
        "obligations": rows,
    }


def canonical(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    payload = build()
    raw = canonical(payload)
    digest = hashlib.sha256(raw).hexdigest()
    if "--write" in sys.argv:
        CONTROLS.parent.mkdir(parents=True, exist_ok=True)
        CONTROLS.write_bytes(raw)
        DIGEST.write_text(digest + "\n", encoding="utf-8")
        print("wrote " + str(CONTROLS) + " (" + digest[:16] + ")")
        return 0
    if not CONTROLS.is_file():
        print("controls are not frozen")
        return 1
    committed = hashlib.sha256(CONTROLS.read_bytes()).hexdigest()
    print("frozen digest " + committed[:16]
          + ("; catalog would now derive " + digest[:16]
             if committed != digest else "; unchanged"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
