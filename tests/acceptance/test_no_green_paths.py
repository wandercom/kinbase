"""No assertion may pass without evidence, analysed per test.

Detector Reviewer finding 6. The previous version of this module checked three
literal defaults and then accepted an entire gate module if any one
total-quantifier name appeared anywhere in it. That is a module-level heuristic,
not an audit: the Reviewer subsequently found 24 collection defaults, 17 optional
loops and 41 guarded assertion blocks inside modules this file had passed.

The analysis now lives in :mod:`acceptance._harness.greenpath` and runs over
every test function individually. This module is the assertion surface for it,
one test per rule so a failure names the exact defect class, plus the static half
of the obligation-coupling rule from finding 5.

Nothing here is exemptable and nothing is sampled. Every gate module is analysed
on every run.
"""

from __future__ import annotations

import collections
from pathlib import Path

import pytest

from ._harness import greenpath
from ._harness.catalog import OBLIGATIONS
from ._harness.requirements import VERIFY, spec_ref

pytestmark = pytest.mark.selftest

_SUITE = Path(__file__).resolve().parent

#: Every module that asserts against the product. Selftest modules are the
#: instrument's own unit tests and are governed by the catalog rules instead.
_GATE_MODULES: tuple[str, ...] = (
    "test_v1_ingestion.py",
    "test_v2_classification.py",
    "test_v3_privacy.py",
    "test_v3_attacks.py",
    "test_v3_qualification.py",
    "test_v4_maintenance.py",
    "test_v5_temporal.py",
    "test_v6_authority.py",
    "test_v7_projection.py",
    "test_v8_company_refs.py",
    "test_v9_fatigue.py",
    "test_v9_host_lifecycle.py",
    "test_v10_protocol.py",
    "test_nonfunctional.py",
    "test_evidence_packet.py",
)

_FAIL_CLOSED = VERIFY(
    "INSTRUMENT",
    "fail-closed",
    "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
)


def _findings() -> list[greenpath.Finding]:
    out: list[greenpath.Finding] = []
    for name in _GATE_MODULES:
        path = _SUITE / name
        if not path.is_file():
            out.append(
                greenpath.Finding(name, 0, "<module>", "missing-module",
                                  "a declared gate module is absent from the lane")
            )
            continue
        out.extend(greenpath.analyse_module(path))
    return out


def _by_rule(rule: str) -> list[greenpath.Finding]:
    return [f for f in _findings() if f.rule == rule]


def _report(rule: str, explanation: str) -> None:
    hits = _by_rule(rule)
    assert not hits, (
        f"{len(hits)} occurrence(s) of [{rule}]. {explanation}\n  "
        + "\n  ".join(f.render() for f in hits[:60])
        + ("\n  ..." if len(hits) > 60 else "")
    )


@spec_ref(_FAIL_CLOSED)
def test_no_bare_return_ends_a_gate_test_green() -> None:
    _report("bare-return",
            "A bare return ends the test green with no claim evaluated.")


@spec_ref(_FAIL_CLOSED)
def test_no_untyped_assertion_in_a_gate_module() -> None:
    """A gate claim must declare whose failure it is.

    Detector Reviewer finding 10: a bare ``AssertionError`` was classified as a
    ``PRODUCT_FAILURE`` even when it asserted a Tester fixture count or an
    absent prerequisite. Removing bare ``assert`` from the gate modules is what
    makes the classifier's fail-closed rule sound.
    """
    _report("bare-assert",
            "Route the claim through O.check, require_*, forbid, or a typed "
            "prerequisite from acceptance._harness.prereq.")


@spec_ref(_FAIL_CLOSED)
def test_no_permissive_default_satisfies_an_assertion() -> None:
    _report("permissive-default",
            "`.get(key, default)` turns absent product evidence into satisfied "
            "evidence.")


@spec_ref(_FAIL_CLOSED)
def test_no_collection_fallback_substitutes_an_empty_domain() -> None:
    _report("collection-fallback",
            "`payload.get(k) or []` makes a missing list a satisfied loop.")


@spec_ref(_FAIL_CLOSED)
def test_no_tautological_assertion() -> None:
    _report("tautology", "The assertion is true regardless of the product.")


@spec_ref(_FAIL_CLOSED)
def test_no_except_handler_swallows_a_typed_failure() -> None:
    _report("swallowed-failure",
            "An except handler that does not re-raise converts a typed failure "
            "into a green path.")


@spec_ref(_FAIL_CLOSED)
def test_every_loop_carrying_a_claim_proves_its_domain() -> None:
    _report("unproved-loop",
            "`for x in xs: check(...)` is vacuously satisfied when xs is empty; "
            "prove the domain with require_nonempty/require_all first.")


@spec_ref(_FAIL_CLOSED)
def test_every_gate_test_has_an_unconditional_claim() -> None:
    _report("optional-guard",
            "Every claim in the test is nested inside a guard on product output, "
            "so a product that produces nothing takes a path with no claim.")


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "catalog-coupling",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog before implementation is "
        "combined.",
    )
)
def test_every_gate_test_evaluates_a_catalogued_obligation() -> None:
    _report("no-catalog-consumption",
            "The test asserts something the frozen catalog does not declare, so "
            "the census would credit a row this node never checked.")


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "catalog-coupling",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog before implementation is "
        "combined.",
    )
)
def test_every_catalog_row_is_consumed_by_the_node_that_declares_it() -> None:
    """Static half of Detector Reviewer finding 5.

    An obligation names the nodes that must check it. Unless the body of that
    exact function contains ``O.check("<oid>", ...)`` for that exact OID, the
    row is uncoupled: the node can pass while asserting something else entirely.
    The runtime half lives in :mod:`acceptance._harness.consumption`.
    """
    consumed: dict[str, set[str]] = {}
    for name in _GATE_MODULES:
        path = _SUITE / name
        if not path.is_file():
            continue
        for func, oids in greenpath.consumed_oids(path).items():
            consumed.setdefault(f"{name}::{func}", set()).update(oids)

    uncoupled: list[str] = []
    for obligation in OBLIGATIONS:
        for node in obligation.nodes:
            key = node.split("[", 1)[0]
            if obligation.oid not in consumed.get(key, set()):
                uncoupled.append(f"{obligation.oid} declares {key}")

    assert not uncoupled, (
        f"{len(uncoupled)} catalog row(s) name a node that never calls their "
        "checker; the census would count the row as covered while the node "
        "asserted something unrelated:\n  "
        + "\n  ".join(sorted(uncoupled)[:60])
        + ("\n  ..." if len(uncoupled) > 60 else "")
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "catalog-coupling",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog before implementation is "
        "combined.",
    )
)
def test_no_node_evaluates_an_obligation_the_catalog_gives_to_another_node() -> None:
    declared: dict[str, set[str]] = collections.defaultdict(set)
    for obligation in OBLIGATIONS:
        for node in obligation.nodes:
            declared[node.split("[", 1)[0]].add(obligation.oid)

    trespass: list[str] = []
    for name in _GATE_MODULES:
        path = _SUITE / name
        if not path.is_file():
            continue
        for func, oids in greenpath.consumed_oids(path).items():
            key = f"{name}::{func}"
            for oid in sorted(oids - declared.get(key, set())):
                trespass.append(f"{key} evaluates {oid}")

    assert not trespass, (
        "these nodes evaluate an obligation the catalog assigns elsewhere, so "
        "one node's work would green another node's row:\n  "
        + "\n  ".join(sorted(trespass)[:40])
    )
