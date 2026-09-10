"""Bind a gate test to its catalogued obligation.

A gate test builds real state, drives the product, assembles *typed evidence*,
and hands it here. The assertion logic lives in the catalog, so the same clauses
that the executable kill ledger proved sensitive are the ones the gate applies.

That coupling is the point. The Detector Reviewer's central complaint was that
gate assertions and catalog entries were unrelated artefacts: an assertion could
be vacuous while its catalog row claimed a control. With this indirection a gate
cannot assert less than its obligation declares, and the ledger cannot certify a
sensitivity the gate does not use.
"""

from __future__ import annotations

from typing import Any, Mapping

from . import consumption
from .catalog import BY_ID, Obligation
from .evidence_model import Evidence, Origin
from .requirements import HarnessInvalid

#: Origins matching each declared fail-closed channel.
_ORIGIN = {
    "PRODUCT_FAILURE": Origin.PRODUCT,
    "INVALID_HARNESS": Origin.HARNESS,
}


def obligation(oid: str) -> Obligation:
    try:
        return BY_ID[oid]
    except KeyError as exc:
        raise HarnessInvalid(
            f"no catalogued obligation {oid!r}; a gate test may not assert an "
            "obligation the frozen catalog does not declare"
        ) from exc


def check(oid: str, payload: Mapping[str, Any], *, label: str = "") -> Evidence:
    """Evaluate the full catalogued conjunction over assembled evidence.

    Raises ``ProductFailure`` or ``HarnessInvalid`` per the obligation's declared
    fail-closed channel. Returns the content-addressed evidence record so a gate
    test can bind it into the run census.
    """
    ob = obligation(oid)
    ev = Evidence(
        obligation=oid,
        origin=_ORIGIN[ob.fail_closed],
        label=label or oid,
        payload=dict(payload),
    )
    # Detector Reviewer finding 5: record the content-addressed evaluation
    # *before* the clauses run, so a row is credited only to the node that
    # actually consumed it and a failing evaluation still leaves a trace.
    consumption.record(oid, ev.label, ev.origin.value, ev.payload)
    ob.clause_set.check(ev)
    return ev


def thresholds(oid: str) -> tuple[str, ...]:
    return obligation(oid).thresholds
