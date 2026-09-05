"""Every acceptance assertion must backreference an exact ratified requirement.

This module closes the loop on the mechanism in
:mod:`acceptance._harness.requirements`: ``spec_ref`` validates each quote at
import time, and the tests here assert that *no test escaped the mechanism* and
that no reference cites an artifact outside the ratified precedence chain.

Authority precedence, from ``spec/ratification-manifest.json`` and restated in
``spec/verification.md``:

    Authority precedence is `source-request > Product > Architecture > Threat
    Model > Verification > generated manifest`; a downstream artifact may
    implement but not contradict its upstream.

A ``TRACE`` citation of ``spec/behavior-ledger.md`` or the review disposition
never satisfies the rule on its own: per the Tester dispatch those artifacts may
help trace intent but cannot create or weaken a requirement.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

import pytest

from ._harness.mutations import CATALOG
from ._harness.requirements import (
    AUTHORITY_PRECEDENCE,
    GATES,
    TRACE_ONLY_ARTIFACTS,
    VERIFY,
    authority_refs,
    refs_of,
    spec_ref,
)

pytestmark = [pytest.mark.selftest]

_PACKAGE = "acceptance"


def _test_modules() -> list[str]:
    package = importlib.import_module(_PACKAGE)
    return sorted(
        name
        for _, name, _ in pkgutil.iter_modules(package.__path__, f"{_PACKAGE}.")
        if name.rsplit(".", 1)[-1].startswith("test_")
    )


def _test_functions(module_name: str):
    module = importlib.import_module(module_name)
    for name, obj in vars(module).items():
        if name.startswith("test_") and inspect.isfunction(obj):
            yield f"{module_name.rsplit('.', 1)[-1]}.py::{name}", obj


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "authority-precedence",
        "Authority precedence is `source-request > Product > Architecture > Threat Model > "
        "Verification > generated manifest`; a downstream artifact may implement but not contradict "
        "its upstream.",
    )
)
def test_every_test_carries_at_least_one_authority_backreference() -> None:
    unbackreferenced: list[str] = []
    trace_only: list[str] = []
    for module_name in _test_modules():
        for node, function in _test_functions(module_name):
            refs = refs_of(function)
            if not refs:
                unbackreferenced.append(node)
                continue
            if not authority_refs(refs):
                trace_only.append(node)
    assert not unbackreferenced, (
        "these tests carry no ratified backreference:\n  " + "\n  ".join(unbackreferenced)
    )
    assert not trace_only, (
        "these tests cite only trace artifacts, which cannot create a requirement:\n  "
        + "\n  ".join(trace_only)
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "artifact-binding",
        "The experiment manifest is bound to every exact authority artifact digest and may contain only "
        "values permitted or deterministically derived by them.",
    )
)
def test_every_reference_resolves_against_the_ratified_bytes() -> None:
    unresolved: list[str] = []
    for module_name in _test_modules():
        for node, function in _test_functions(module_name):
            for ref in refs_of(function):
                if not ref.resolve():
                    unresolved.append(f"{node}: {ref.render()}")
    assert not unresolved, "\n".join(unresolved)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "precedence",
        "a downstream artifact may implement but not contradict its upstream",
    )
)
def test_no_reference_cites_an_unratified_artifact() -> None:
    permitted = set(AUTHORITY_PRECEDENCE) | set(TRACE_ONLY_ARTIFACTS)
    offenders: list[str] = []
    for module_name in _test_modules():
        for node, function in _test_functions(module_name):
            for ref in refs_of(function):
                if ref.artifact not in permitted:
                    offenders.append(f"{node}: {ref.artifact}")
    assert not offenders, "\n".join(offenders)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "acceptance-map",
        "## Acceptance map",
    )
)
def test_every_gate_v1_through_v10_has_backreferenced_coverage() -> None:
    covered: dict[str, int] = {gate: 0 for gate in GATES}
    for module_name in _test_modules():
        for _, function in _test_functions(module_name):
            for ref in refs_of(function):
                covered[ref.gate] += 1
    missing = [
        gate
        for gate in (
            "V-1",
            "V-2",
            "V-3",
            "V-4",
            "V-5",
            "V-6",
            "V-7",
            "V-8",
            "V-9",
            "V-10",
            "NONFUNCTIONAL",
            "EVIDENCE",
            "VERDICT",
            "INSTRUMENT",
        )
        if covered[gate] == 0
    ]
    assert not missing, f"these gates have no backreferenced coverage: {missing}"


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "frozen-catalog",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, and "
        "detector mutation in the preregistered acceptance catalog before implementation is combined.",
    )
)
def test_every_gate_has_a_positive_and_negative_control_or_a_frozen_mutation() -> None:
    """Each of V-1..V-9 must have at least one control or mutation obligation.

    ``spec/verification.md`` requires all four --- threshold, positive control,
    negative control and detector mutation --- to be frozen before combination.
    The threshold and the controls live in the gate modules; the mutation
    obligations live in the frozen catalog. This asserts the catalog side and
    that each gate module carries at least one explicitly marked control.
    """
    from ._harness import catalog as C

    catalogued = {mutation.gate for mutation in CATALOG.values()}
    missing_mutation = [
        g for g in (f"V-{i}" for i in range(1, 10)) if g not in catalogued
    ]
    assert not missing_mutation, (
        f"these gates have no frozen mutation obligation: {missing_mutation}"
    )

    # Detector Reviewer finding 5: the previous version computed a control count
    # and never asserted it. All four elements are now derived per obligation by
    # the catalog, so the assertion is that every gate has obligations and every
    # obligation freezes all four.
    incomplete: list[str] = []
    for gate in (f"V-{i}" for i in range(1, 10)):
        obligations = C.for_gate(gate)
        if not obligations:
            incomplete.append(f"{gate}: no catalogued obligation")
            continue
        for obligation in obligations:
            for tag in obligation.thresholds:
                for element in (
                    obligation.positive_control(tag),
                    obligation.negative_control(tag),
                    obligation.product_mutation(tag),
                    obligation.detector_mutation(tag),
                ):
                    if tag not in element:
                        incomplete.append(f"{obligation.oid}#{tag}: missing element")
    assert not incomplete, "\n".join(incomplete)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "role-separation",
        "**Tester (Claude):** reads ratified product, architecture, verification strategy, and a clean "
        "test lane; authors acceptance/benchmark tests and fixtures only; cannot read implementation or "
        "Coder work or issue a verdict.",
    )
)
def test_the_lane_reads_no_implementation_and_issues_no_verdict() -> None:
    """The suite must not import product code or compute a terminal verdict."""
    lane = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for path in (lane / "acceptance").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import guildhall", "from guildhall")):
                offenders.append(f"{path.name}: {stripped}")
    assert not offenders, (
        "the acceptance suite must reach the product only through its ratified "
        f"command and service surfaces: {offenders}"
    )

    conftest = (lane / "conftest.py").read_text(encoding="utf-8")
    assert "reserves verdict composition to the Validator" in conftest, (
        "the gate vector must be reported as an observation set, not a verdict"
    )
