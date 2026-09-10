"""Executable, content-addressed total mutation kill ledger.

Detector Reviewer finding 6: the previous catalog was declarative. Selecting
``KINBASE_ACCEPT_MUTATION=v5.newest_wins`` applied nothing, checked nothing,
and left every gate ``PASS``; five detector entries pointed at a self-test that
*passed when the mutant was blind*.

This module makes the whole catalog executable and, critically, executable
**without the product**. Because every obligation's checker is a conjunction of
declared clauses over typed evidence, each of the four ratified elements can be
run as a real experiment against synthesised evidence:

===================  ==========================================================
element              executed assertion
===================  ==========================================================
positive control     conforming evidence -> checker must accept
product mutation     evidence violating one clause -> checker must reject, in
                     the obligation's declared fail-closed channel
detector mutation    the same violating evidence with that clause deleted from
                     the checker -> the blinded checker must **miss** it
negative control     a perturbation the obligation does not forbid -> checker
                     must stay clean, proving it is not trivially positive
===================  ==========================================================

A mutation that does not change the verdict is not a mutation, and this ledger
fails on exactly that condition. The result is content addressed so a Validator
can bind it, and it is *total*: every obligation, every threshold, no sampling.

Validator-applied product planters (the source-level defects that must be
introduced into a combined snapshot) are declared alongside in
:mod:`acceptance._harness.planters`; this ledger proves the *instrument's*
sensitivity, which is the precondition for believing any planter result.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Sequence

from . import rawcontrols
from .catalog import OBLIGATIONS, Obligation
from .evidence_model import Evidence, Origin
from .requirements import HarnessInvalid, ProductFailure

#: Outcome of one experiment.
KILLED = "KILLED"
SURVIVED = "SURVIVED"
FALSE_POSITIVE = "FALSE_POSITIVE"
BLIND = "BLIND"
SIGHTED = "SIGHTED"
ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"


@dataclass(frozen=True)
class KillRow:
    """One (obligation, threshold) row with all four experiments run."""

    oid: str
    gate: str
    tag: str
    clause_kind: str
    fail_closed: str
    positive_control: str
    negative_control: str
    product_mutation: str
    detector_mutation: str
    positive_result: str
    product_result: str
    detector_result: str
    negative_result: str
    channel: str
    detail: str
    #: Executable pre-execution planters bound to this obligation's own nodes.
    bound_product_mutations: tuple[str, ...] = ()

    @property
    def sound(self) -> bool:
        """Every element behaved as the ratified catalog requires."""
        return (
            self.positive_result == ACCEPTED
            and self.product_result == KILLED
            and self.detector_result == BLIND
            and self.negative_result == ACCEPTED
            and self.channel == self.fail_closed
        )

    def as_json(self) -> dict:
        return {
            "oid": self.oid,
            "gate": self.gate,
            "threshold": self.tag,
            "clause_kind": self.clause_kind,
            "fail_closed": self.fail_closed,
            "bound_product_mutations": list(self.bound_product_mutations),
            "positive_control": self.positive_control,
            "negative_control": self.negative_control,
            "product_mutation": self.product_mutation,
            "detector_mutation": self.detector_mutation,
            "positive_result": self.positive_result,
            "product_result": self.product_result,
            "detector_result": self.detector_result,
            "negative_result": self.negative_result,
            "observed_channel": self.channel,
            "sound": self.sound,
            "detail": self.detail,
        }


def _origin_for(obligation: Obligation) -> Origin:
    """Evidence origin matching the obligation's fail-closed channel."""
    return (
        Origin.PRODUCT if obligation.fail_closed == "PRODUCT_FAILURE" else Origin.HARNESS
    )


def _evidence(obligation: Obligation, label: str, payload: dict) -> Evidence:
    return Evidence(
        obligation=obligation.oid,
        origin=_origin_for(obligation),
        label=label,
        payload=payload,
    )


def run_row(obligation: Obligation, tag: str) -> KillRow:
    """Execute all four frozen elements for one threshold."""
    clause_set = obligation.clause_set
    clause = clause_set.clause(tag)
    channel = ""
    detail = ""

    # Detector Reviewer finding 4: every control below is *frozen bytes* read
    # from tests/fixtures/controls/controls.json, not a payload derived from the
    # clause under test. A clause that is later loosened no longer rejects its
    # own frozen negative, which is what makes the row sensitive at all.
    frozen_positive = rawcontrols.positive(obligation.oid)
    frozen_negative = rawcontrols.negative(obligation.oid, tag)
    frozen_benign = rawcontrols.benign(obligation.oid, tag)

    # 1. Positive control: conforming evidence must be accepted.
    try:
        clause_set.check(_evidence(obligation, f"pc:{tag}", frozen_positive))
        positive = ACCEPTED
    except (ProductFailure, HarnessInvalid) as exc:
        positive = REJECTED
        detail = f"positive control rejected: {exc}"

    # 2. Product mutation: a violating clause must be caught, in the declared
    #    fail-closed channel.
    violating = frozen_negative
    try:
        clause_set.check(_evidence(obligation, f"pm:{tag}", violating))
        product = SURVIVED
        detail = detail or "product mutation survived: the checker did not notice"
    except ProductFailure as exc:
        product = KILLED
        channel = "PRODUCT_FAILURE"
        detail = detail or str(exc)[:160]
    except HarnessInvalid as exc:
        product = KILLED
        channel = "INVALID_HARNESS"
        detail = detail or str(exc)[:160]

    # 3. Detector mutation: blinding that clause must make the checker miss it.
    try:
        clause_set.check(
            _evidence(obligation, f"dm:{tag}", violating), blind=tag
        )
        detector = BLIND
    except (ProductFailure, HarnessInvalid) as exc:
        detector = SIGHTED
        detail = (
            f"detector mutation did not blind the checker; still caught: {exc}"[:200]
        )

    # 4. Negative control: a permitted perturbation must stay clean.
    try:
        clause_set.check(_evidence(obligation, f"nc:{tag}", frozen_benign))
        negative = ACCEPTED
    except (ProductFailure, HarnessInvalid) as exc:
        negative = FALSE_POSITIVE
        detail = f"negative control tripped the checker: {exc}"[:200]

    return KillRow(
        oid=obligation.oid,
        gate=obligation.gate,
        tag=tag,
        clause_kind=clause.kind,
        fail_closed=obligation.fail_closed,
        positive_control=obligation.positive_control(tag),
        negative_control=obligation.negative_control(tag),
        product_mutation=obligation.product_mutation(tag),
        detector_mutation=obligation.detector_mutation(tag),
        positive_result=positive,
        product_result=product,
        detector_result=detector,
        negative_result=negative,
        channel=channel,
        detail=detail,
        bound_product_mutations=rawcontrols.product_mutations(obligation.oid),
    )


@dataclass(frozen=True)
class KillLedger:
    """The total ledger over every obligation and threshold."""

    rows: tuple[KillRow, ...]

    @property
    def unsound(self) -> tuple[KillRow, ...]:
        return tuple(r for r in self.rows if not r.sound)

    @property
    def survived(self) -> tuple[KillRow, ...]:
        return tuple(r for r in self.rows if r.product_result != KILLED)

    @property
    def sighted(self) -> tuple[KillRow, ...]:
        return tuple(r for r in self.rows if r.detector_result != BLIND)

    @property
    def false_positives(self) -> tuple[KillRow, ...]:
        return tuple(r for r in self.rows if r.negative_result != ACCEPTED)

    @property
    def rejected_controls(self) -> tuple[KillRow, ...]:
        return tuple(r for r in self.rows if r.positive_result != ACCEPTED)

    def as_json(self) -> dict:
        gates = sorted({r.gate for r in self.rows})
        return {
            "schema": "kinbase-acceptance-kill-ledger/1",
            "total": True,
            "obligation_count": len({r.oid for r in self.rows}),
            "threshold_count": len(self.rows),
            "gates": gates,
            "per_gate": {
                g: sum(1 for r in self.rows if r.gate == g) for g in gates
            },
            "kills": sum(1 for r in self.rows if r.product_result == KILLED),
            "blinded_detectors": sum(
                1 for r in self.rows if r.detector_result == BLIND
            ),
            "clean_negative_controls": sum(
                1 for r in self.rows if r.negative_result == ACCEPTED
            ),
            "accepted_positive_controls": sum(
                1 for r in self.rows if r.positive_result == ACCEPTED
            ),
            "unsound": [r.as_json() for r in self.unsound],
            "rows": [r.as_json() for r in self.rows],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.as_json(), sort_keys=True).encode("utf-8")
        ).hexdigest()

    def summary(self) -> str:
        payload = self.as_json()
        return (
            f"kill ledger {self.digest[:16]}: "
            f"{payload['threshold_count']} thresholds over "
            f"{payload['obligation_count']} obligations; "
            f"kills={payload['kills']} blinded={payload['blinded_detectors']} "
            f"clean_nc={payload['clean_negative_controls']} "
            f"unsound={len(self.unsound)}"
        )


def run_ledger(obligations: Sequence[Obligation] = OBLIGATIONS) -> KillLedger:
    """Execute the total ledger. No sampling, no early exit."""
    rows: list[KillRow] = []
    for obligation in obligations:
        for tag in obligation.thresholds:
            rows.append(run_row(obligation, tag))
    return KillLedger(tuple(rows))
