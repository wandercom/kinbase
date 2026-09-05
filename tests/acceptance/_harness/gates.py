"""Verdict composition, exactly as ``spec/verification.md`` "Verdict semantics".

The composition table is transcribed verbatim and the extra ordering rules in
the surrounding prose are implemented as explicit predicates rather than left
to prose. The acceptance suite asserts the *product's* verdict computation
against this independent implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

GATE_RESULTS: tuple[str, ...] = ("PASS", "PRODUCT_FAILURE", "INVALID_HARNESS")

MEASUREMENT_RESULTS: tuple[str, ...] = (
    "PROVEN",
    "NOT_PROVEN",
    "INCONCLUSIVE_NO_HEADROOM",
    "INCONCLUSIVE_CEILING",
    "NOT_RUN",
)

TERMINAL_VERDICTS: tuple[str, ...] = (
    "PROVEN",
    "NOT_PROVEN",
    "INCONCLUSIVE_NO_HEADROOM",
    "INCONCLUSIVE_CEILING",
    "INVALID_RUN",
)

#: Verbatim transcription of the ``spec/verification.md`` composition table.
COMPOSITION: dict[tuple[str, str], str] = {
    ("PASS", "PROVEN"): "PROVEN",
    ("PASS", "NOT_PROVEN"): "NOT_PROVEN",
    ("PASS", "INCONCLUSIVE_NO_HEADROOM"): "INCONCLUSIVE_NO_HEADROOM",
    ("PASS", "INCONCLUSIVE_CEILING"): "INCONCLUSIVE_CEILING",
    ("PASS", "NOT_RUN"): "NOT_PROVEN",
    ("PRODUCT_FAILURE", "PROVEN"): "NOT_PROVEN",
    ("PRODUCT_FAILURE", "NOT_PROVEN"): "NOT_PROVEN",
    ("PRODUCT_FAILURE", "INCONCLUSIVE_NO_HEADROOM"): "NOT_PROVEN",
    ("PRODUCT_FAILURE", "INCONCLUSIVE_CEILING"): "NOT_PROVEN",
    ("PRODUCT_FAILURE", "NOT_RUN"): "NOT_PROVEN",
    ("INVALID_HARNESS", "PROVEN"): "INVALID_RUN",
    ("INVALID_HARNESS", "NOT_PROVEN"): "INVALID_RUN",
    ("INVALID_HARNESS", "INCONCLUSIVE_NO_HEADROOM"): "INVALID_RUN",
    ("INVALID_HARNESS", "INCONCLUSIVE_CEILING"): "INVALID_RUN",
    ("INVALID_HARNESS", "NOT_RUN"): "INVALID_RUN",
}

#: Gate identifiers V-1 .. V-9 whose vector composes ``gate_result``.
GATE_IDS: tuple[str, ...] = tuple(f"V-{i}" for i in range(1, 10))


@dataclass(frozen=True)
class Composition:
    gate_result: str
    measurement_result: str
    terminal: str
    headroom_flag_visible: bool
    diagnostics: tuple[str, ...] = field(default_factory=tuple)


def compose(
    gate_result: str,
    measurement_result: str,
    *,
    independent_product_failure: bool = False,
    headroom_condition: bool = False,
    ceiling_condition: bool = False,
) -> Composition:
    """Total, ordered composition.

    Implements, in order, the prose rules that surround the table:

    * "A separately verified product/privacy failure yields terminal
      ``NOT_PROVEN`` regardless of measurement state."
    * "Otherwise an integrity failure that makes gate observations untrustworthy
      yields ``INVALID_RUN``."
    * "If a separately content-addressed product-failure observation exists
      alongside an invalid detector, the product failure is retained and
      terminal ``NOT_PROVEN`` dominates."
    * "If both headroom and ceiling conditions hold, ceiling is reported as the
      instrument failure and the headroom flag remains visible, but neither can
      mask a product gate failure."
    * "``NOT_RUN`` is terminal ``NOT_PROVEN`` because the proof was not
      performed, with a diagnostic that must not imply a product mechanism
      falsifier."
    """
    if gate_result not in GATE_RESULTS:
        raise ValueError(f"unknown gate_result {gate_result!r}")
    if measurement_result not in MEASUREMENT_RESULTS:
        raise ValueError(f"unknown measurement_result {measurement_result!r}")

    diagnostics: list[str] = []
    effective_measurement = measurement_result

    if headroom_condition and ceiling_condition:
        # Ceiling is reported as the instrument failure; the headroom flag stays
        # visible rather than being overwritten.
        effective_measurement = "INCONCLUSIVE_CEILING"
        diagnostics.append("HEADROOM_FLAG_VISIBLE")
        diagnostics.append("CEILING_REPORTED_AS_INSTRUMENT_FAILURE")

    if gate_result == "PRODUCT_FAILURE" or independent_product_failure:
        terminal = "NOT_PROVEN"
        diagnostics.append("PRODUCT_FAILURE_DOMINATES")
        return Composition(
            gate_result=gate_result,
            measurement_result=effective_measurement,
            terminal=terminal,
            headroom_flag_visible=headroom_condition,
            diagnostics=tuple(diagnostics),
        )

    terminal = COMPOSITION[(gate_result, effective_measurement)]
    if effective_measurement == "NOT_RUN" and gate_result == "PASS":
        diagnostics.append("MEASUREMENT_NOT_PERFORMED_NOT_A_MECHANISM_FALSIFIER")
    return Composition(
        gate_result=gate_result,
        measurement_result=effective_measurement,
        terminal=terminal,
        headroom_flag_visible=headroom_condition,
        diagnostics=tuple(diagnostics),
    )


def gate_result_from_vector(vector: Mapping[str, str]) -> str:
    """Fold the V-1..V-9 gate vector into ``gate_result``.

    ``PRODUCT_FAILURE`` dominates ``INVALID_HARNESS`` because
    ``spec/verification.md`` retains an independently valid product failure even
    when a detector is invalid.
    """
    missing = [g for g in GATE_IDS if g not in vector]
    if missing:
        raise ValueError(f"gate vector is missing {missing}")
    values = [vector[g] for g in GATE_IDS]
    unknown = [v for v in values if v not in {"PASS", "PRODUCT_FAILURE", "INVALID_HARNESS"}]
    if unknown:
        raise ValueError(f"unknown gate states {unknown}")
    if "PRODUCT_FAILURE" in values:
        return "PRODUCT_FAILURE"
    if "INVALID_HARNESS" in values:
        return "INVALID_HARNESS"
    return "PASS"


#: Statuses that are explicitly *not* run verdicts.
NON_VERDICT_STATUSES: tuple[str, ...] = ("candidate", "ratified", "proven")

#: Claims that ``spec/verification.md`` names as never being product verdicts.
NON_VERDICT_EVENTS: tuple[str, ...] = (
    "implementation complete",
    "service starts",
    "unit green",
    "architecture present",
    "Factory milestone reached",
)

#: ``spec/verification.md``: Factory method evidence for this run is labelled
#: ``METHOD_POC``, never ``CLEAN_QUALIFIED``.
REQUIRED_METHOD_LABEL = "METHOD_POC"
FORBIDDEN_METHOD_LABEL = "CLEAN_QUALIFIED"

#: ``spec/product.md`` P-10 exact licensed claim template.
LICENSED_CLAIM_FRAGMENT = (
    "On the digest-identified task population, repositories, model/provider "
    "fingerprint, budgets, authority service, and finite threat model in this "
    "run, Guildhall met P-1 through P-9 and raised blinded brownfield quality "
    "to the preregistered P-10 equivalence band."
)

#: Statements ``spec/product.md`` P-10 explicitly refuses to license.
FORBIDDEN_CLAIMS: tuple[str, ...] = (
    "Kindex works",
    "privacy is proved",
    "all brownfield coding reaches greenfield quality",
)

#: ``spec/threat-model.md`` "Claim boundary" permitted V-3 claim.
V3_CLAIM_FRAGMENT = (
    "Zero observed unauthorized durable disclosure outside the authorized "
    "processor boundary under Acceptance Threat Model"
)

#: Terminal diagnostic required when the design cannot be powered or funded.
UNFUNDED_DIAGNOSTIC = "UNFUNDED_OR_UNDERPOWERED"
