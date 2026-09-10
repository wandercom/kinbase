"""The frozen raw control fixtures the kill ledger reads.

Detector Reviewer finding 4. The ledger used to build its positive control, its
negative control and its mutation from the same clause object it was testing, so
loosening a clause loosened its own controls in the same edit and the ledger
could not detect the change. It also had no link to any executable product
mutation, so a "sensitive" row proved only that a synthesised payload tripped a
predicate.

These controls are frozen bytes: ``tests/fixtures/controls/controls.json``,
generated once by ``tests/tools/freeze-controls.py`` and committed with its
digest. At run time nothing regenerates them. If a clause is later weakened, its
frozen negative no longer trips it and the ledger reports a survivor --- which is
exactly the sensitivity the Reviewer found missing.

Each row also carries the executable pre-execution planter bound to the
obligation's own nodes, so a product-fail-closed row is sound only when a real
raw-state mutation exists for it too.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import prereq

CONTROLS_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "controls" / "controls.json"
DIGEST_PATH = CONTROLS_PATH.parent / "CONTROLS-DIGEST"

_CACHE: dict | None = None


def load() -> dict:
    """Read the frozen controls and verify the committed digest."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    raw = prereq.fixture_file(
        CONTROLS_PATH,
        why="the kill ledger reads frozen control bytes rather than regenerating "
            "them from the clause it is testing",
        minimum_bytes=1024,
    )
    expected = prereq.fixture_file(
        DIGEST_PATH, why="the committed digest of the frozen controls",
        minimum_bytes=64,
    ).decode("utf-8").strip()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected:
        raise prereq.missing(
            "fixture", str(CONTROLS_PATH),
            "frozen control digest " + observed + " does not match the committed "
            + expected + "; the controls moved without being re-frozen",
        )
    _CACHE = json.loads(raw.decode("utf-8"))
    return _CACHE


def _row(oid: str) -> dict:
    for entry in load()["obligations"]:
        if entry["oid"] == oid:
            return entry
    raise prereq.missing(
        "fixture", oid,
        "no frozen control row exists for this obligation; run "
        "tests/tools/freeze-controls.py --write after adding it",
    )


def positive(oid: str) -> dict:
    return _row(oid)["positive"]


def negative(oid: str, tag: str) -> dict:
    for entry in _row(oid)["negatives"]:
        if entry["tag"] == tag:
            return entry["payload"]
    raise prereq.missing("fixture", oid + "#" + tag, "no frozen negative control")


def benign(oid: str, tag: str) -> dict:
    for entry in _row(oid)["negatives"]:
        if entry["tag"] == tag:
            return entry["benign"]
    raise prereq.missing("fixture", oid + "#" + tag, "no frozen benign control")


def expected_failing_tag(oid: str, tag: str) -> str:
    for entry in _row(oid)["negatives"]:
        if entry["tag"] == tag:
            return str(entry["expected_failing_tag"])
    raise prereq.missing("fixture", oid + "#" + tag, "no frozen expectation")


def product_mutations(oid: str) -> tuple[str, ...]:
    return tuple(_row(oid)["product_mutations"])


def digest() -> str:
    return hashlib.sha256(CONTROLS_PATH.read_bytes()).hexdigest()


def coverage_gaps(obligations) -> tuple[str, ...]:
    """Catalog rows with no frozen control, or frozen tags the catalog dropped."""
    frozen = {e["oid"]: {n["tag"] for n in e["negatives"]}
              for e in load()["obligations"]}
    gaps: list[str] = []
    for obligation in obligations:
        tags = set(obligation.clause_set.tags())
        if obligation.oid not in frozen:
            gaps.append(obligation.oid + ": no frozen control row")
            continue
        missing = tags - frozen[obligation.oid]
        extra = frozen[obligation.oid] - tags
        for tag in sorted(missing):
            gaps.append(obligation.oid + "#" + tag + ": no frozen control")
        for tag in sorted(extra):
            gaps.append(obligation.oid + "#" + tag + ": frozen control has no clause")
    return tuple(gaps)
