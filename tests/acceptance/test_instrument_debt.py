"""The instrument reports its own outstanding validity debt.

Detector Reviewer dispatch 003 raised 22 blocking defects. Some are closed;
several require deep causal rework that is not done. An instrument in that state
must say so rather than pass.

These tests fail while blocking debt is open. That is the intended behaviour:
``spec/verification.md`` "Instrument validity" makes an instrument that cannot
substantiate its own controls ``INVALID_HARNESS``, never PASS, and the failure
carries the exact remaining work rather than a bare red.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import debt
from ._harness.requirements import THREAT, VERIFY, HarnessInvalid, spec_ref

pytestmark = pytest.mark.selftest


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_instrument_declares_no_open_validity_debt() -> None:
    """Fails while any blocking finding remains open, naming the exact work."""
    outstanding = debt.open_entries()
    if outstanding:
        lines = [
            f"  finding {e.finding}: {e.title}",
            ]
        rendered = "\n".join(
            f"  finding {e.finding} [{', '.join(e.gates)}]: {e.title}\n"
            f"      why: {e.why_blocking}\n"
            f"      needs: {e.required_work}"
            for e in outstanding
        )
        raise HarnessInvalid(
            f"{len(outstanding)} of {len(debt.LEDGER)} instrument-validity findings "
            "remain open, so the instrument is INVALID_HARNESS and must not be "
            f"exposed to a product snapshot:\n{rendered}"
        )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "machine-readable",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog",
    )
)
def test_debt_ledger_mirror_is_current() -> None:
    mirror = Path(__file__).resolve().parents[1] / "fixtures" / "catalog" / "debt.json"
    assert mirror.is_file(), "the instrument debt ledger must be committed"
    committed = json.loads(mirror.read_text(encoding="utf-8"))
    assert committed == debt.as_json(), (
        "the committed debt ledger is stale; regenerate it"
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_every_finding_is_accounted_for() -> None:
    numbers = sorted(e.finding for e in debt.LEDGER)
    assert numbers == list(range(1, 23)), (
        f"the ledger must account for all 22 findings; observed {numbers}"
    )
    for entry in debt.LEDGER:
        assert entry.why_blocking and entry.required_work, (
            f"finding {entry.finding} records no reason or required work"
        )
        assert entry.status in (debt.OPEN, debt.CLOSED)
