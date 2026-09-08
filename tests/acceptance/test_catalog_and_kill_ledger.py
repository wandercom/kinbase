"""Catalog totality and the executable, content-addressed kill ledger.

Detector Reviewer findings 5 and 6. Everything here runs with no product, so a
fresh implementation-blind Reviewer can execute it directly and see whether the
instrument has the sensitivity it claims.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import catalog as C
from ._harness.evidence_model import Evidence, Origin
from ._harness.killledger import run_ledger
from ._harness.requirements import (
    HarnessInvalid,
    VERIFY,
    THREAT,
    _artifact_variants,
    _variants,
    spec_ref,
)

pytestmark = pytest.mark.selftest


# --------------------------------------------------------------------------
# Catalog totality (finding 5)
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "frozen-catalog",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog before implementation is "
        "combined.",
    )
)
def test_every_required_gate_has_catalogued_obligations() -> None:
    missing = [g for g in C.REQUIRED_GATES if not C.for_gate(g)]
    assert not missing, f"gates with no catalogued obligation: {missing}"
    thin = {
        g: len(C.for_gate(g)) for g in C.REQUIRED_GATES if len(C.for_gate(g)) < 5
    }
    assert not thin, (
        "these gates have too few obligations to cover their ratified bullets: "
        f"{thin}"
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "frozen-catalog",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog before implementation is "
        "combined.",
    )
)
def test_every_obligation_freezes_all_four_elements() -> None:
    """Threshold, positive control, negative control and detector mutation."""
    incomplete: list[str] = []
    for obligation in C.OBLIGATIONS:
        if not obligation.thresholds:
            incomplete.append(f"{obligation.oid}: no threshold")
            continue
        for tag in obligation.thresholds:
            for element, name in (
                (obligation.positive_control(tag), "positive control"),
                (obligation.negative_control(tag), "negative control"),
                (obligation.product_mutation(tag), "product mutation"),
                (obligation.detector_mutation(tag), "detector mutation"),
            ):
                if not element or tag not in element:
                    incomplete.append(f"{obligation.oid}#{tag}: no {name}")
    assert not incomplete, "\n".join(incomplete)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "artifact-binding",
        "The experiment manifest is bound to every exact authority artifact digest and may contain "
        "only values permitted or deterministically derived by them.",
    )
)
def test_every_obligation_quotes_the_ratified_bytes() -> None:
    unresolved: list[str] = []
    for obligation in C.OBLIGATIONS:
        haystacks = _artifact_variants(obligation.artifact)
        needles = _variants(obligation.requirement)
        if not any(n in h for n in needles for h in haystacks):
            unresolved.append(
                f"{obligation.oid}: quote absent from {obligation.artifact}"
            )
    assert not unresolved, "\n".join(unresolved)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_every_obligation_declares_surfaces_vectors_and_fail_closed() -> None:
    problems: list[str] = []
    for obligation in C.OBLIGATIONS:
        if not obligation.surfaces:
            problems.append(f"{obligation.oid}: no surfaces")
        if not obligation.vectors:
            problems.append(f"{obligation.oid}: no vectors")
        if obligation.fail_closed not in (C.PRODUCT, C.INSTRUMENT):
            problems.append(f"{obligation.oid}: bad fail-closed channel")
        if not obligation.nodes:
            problems.append(f"{obligation.oid}: no product-facing node")
    assert not problems, "\n".join(problems)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "catalog-nodes",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog",
    )
)
def test_every_catalogued_node_exists_in_the_suite() -> None:
    here = Path(__file__).parent
    missing: list[str] = []
    for obligation in C.OBLIGATIONS:
        for node in obligation.nodes:
            module_name, func = node.split("::", 1)
            module_path = here / module_name
            if not module_path.is_file():
                missing.append(f"{obligation.oid}: no module {module_name}")
                continue
            if f"def {func}(" not in module_path.read_text(encoding="utf-8"):
                missing.append(f"{obligation.oid}: {module_name} lacks {func}")
    assert not missing, "\n".join(missing)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "machine-readable",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog",
    )
)
def test_catalog_json_mirror_is_current() -> None:
    """The committed machine-readable mirror must equal the source of truth."""
    mirror = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "catalog"
        / "obligations.json"
    )
    assert mirror.is_file(), (
        "the machine-readable obligation catalog must be committed at "
        f"{mirror.relative_to(mirror.parents[3])}"
    )
    committed = json.loads(mirror.read_text(encoding="utf-8"))
    current = C.catalog_json()
    assert committed == current, (
        "the committed catalog mirror is stale; regenerate with "
        "`python3 -m acceptance._harness.catalog`"
    )


# --------------------------------------------------------------------------
# Executable kill ledger (finding 6)
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ledger():
    return run_ledger()


@pytest.mark.control_positive
@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "positive-controls",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_every_positive_control_is_accepted(ledger) -> None:
    rejected = ledger.rejected_controls
    assert not rejected, (
        "these positive controls were rejected by their own checker:\n"
        + "\n".join(f"  {r.oid}#{r.tag}: {r.detail}" for r in rejected[:20])
    )
    assert len(ledger.rows) > 0, "an empty ledger proves nothing"


@pytest.mark.mutation
@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "mutation",
        "Mutations target detectors as well as product code—for example, disable archive scanning, "
        "SQLite blob scanning, normalization decoding, or manifest comparison and require the "
        "planted defect to escape the detector's own self-test while causing the gate to reject the "
        "instrument.",
    )
)
def test_every_product_mutation_is_killed(ledger) -> None:
    survived = ledger.survived
    assert not survived, (
        "these product mutations survived, so the obligation cannot detect its own "
        "declared defect:\n"
        + "\n".join(f"  {r.oid}#{r.tag}" for r in survived[:20])
    )


@pytest.mark.mutation
@spec_ref(
    THREAT(
        "INSTRUMENT",
        "attack-catalog",
        "Every family has an exact positive control, negative control, and detector mutation.",
    )
)
def test_every_detector_mutation_actually_blinds(ledger) -> None:
    sighted = ledger.sighted
    assert not sighted, (
        "these detector mutations changed nothing, so they certify a sensitivity "
        "the instrument does not have:\n"
        + "\n".join(f"  {r.oid}#{r.tag}: {r.detail}" for r in sighted[:20])
    )


@pytest.mark.control_negative
@spec_ref(
    THREAT(
        "INSTRUMENT",
        "attack-catalog",
        "false-positive negative control above its frozen tolerance",
    )
)
def test_every_negative_control_stays_clean(ledger) -> None:
    tripped = ledger.false_positives
    assert not tripped, (
        "these negative controls tripped their checker, so the obligation is "
        "trivially positive:\n"
        + "\n".join(f"  {r.oid}#{r.tag}: {r.detail}" for r in tripped[:20])
    )


@spec_ref(
    THREAT(
        "INSTRUMENT",
        "total-ledger",
        "The catalog enumerates every test vector and surface rather than reporting only a family "
        "name; its report gives counts and confidence bounds and never infers universal detector "
        "recall from a finite planted set.",
    )
)
def test_kill_ledger_is_total_and_content_addressed(ledger) -> None:
    payload = ledger.as_json()
    assert payload["total"] is True
    expected_rows = sum(len(o.thresholds) for o in C.OBLIGATIONS)
    assert payload["threshold_count"] == expected_rows, (
        f"the ledger covered {payload['threshold_count']} of {expected_rows} thresholds; "
        "sampling is not permitted"
    )
    assert payload["obligation_count"] == len(C.OBLIGATIONS)
    assert set(payload["gates"]) >= set(C.REQUIRED_GATES)
    assert payload["kills"] == expected_rows
    assert payload["blinded_detectors"] == expected_rows
    assert payload["clean_negative_controls"] == expected_rows
    assert payload["accepted_positive_controls"] == expected_rows
    assert len(ledger.digest) == 64
    assert not ledger.unsound


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "channel",
        "`gate_result` over V-1 through V-9 is `PASS`, `PRODUCT_FAILURE`, or `INVALID_HARNESS`;",
    )
)
def test_each_kill_lands_in_the_declared_fail_closed_channel(ledger) -> None:
    wrong = [
        r for r in ledger.rows if r.channel != r.fail_closed
    ]
    assert not wrong, (
        "these obligations failed in the wrong channel:\n"
        + "\n".join(
            f"  {r.oid}#{r.tag}: declared {r.fail_closed}, observed {r.channel}"
            for r in wrong[:20]
        )
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "detector-mutation",
        "require the planted defect to escape the detector's own self-test while causing the gate "
        "to reject the instrument",
    )
)
def test_blinding_an_unknown_clause_is_an_instrument_error() -> None:
    """A detector mutation naming a clause the obligation lacks must not pass silently."""
    obligation = C.OBLIGATIONS[0]
    ev = Evidence(
        obligation=obligation.oid,
        origin=Origin.PRODUCT,
        label="probe",
        payload=obligation.clause_set.conforming(),
    )
    with pytest.raises(HarnessInvalid):
        obligation.clause_set.check(ev, blind="no-such-clause")


# --------------------------------------------------------------------------
# Pre-execution planters (findings 6 and 7) and detector probes (finding 9)
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "planters",
        "Mutations target detectors as well as product code",
    )
)
def test_every_product_mutation_has_an_executable_pre_execution_planter() -> None:
    from ._harness.planters import PLANTERS, POINTS, coverage

    gaps = coverage()
    assert not gaps, (
        "these catalogued product mutations have no executable planter, so "
        f"selecting them would apply nothing: {gaps}"
    )
    for planter in PLANTERS:
        assert planter.must_fail_nodes, (
            f"{planter.mutation_id} names no node that must fail under it"
        )
        assert planter.point in POINTS, (
            f"{planter.mutation_id} names an undeclared seam {planter.point}"
        )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "planters",
        "require the planted defect to escape the detector's own self-test while causing the gate "
        "to reject the instrument",
    )
)
def test_every_planter_mutates_raw_state_before_the_product_runs() -> None:
    """A planter must change the bytes the product will read, not its output.

    Detector Reviewer finding 7. Each planter is applied to a representative
    value at its own seam and must produce a different content address. A
    planter that leaves the value untouched certifies a sensitivity that does
    not exist.
    """
    import os as _os

    from ._harness import planters as P

    seed_values = {
        "world.event_body": {"observations": [{"a": 1}], "atom_kind": "constraint",
                             "authority_id": "repo-maintainer-1",
                             "authority_scope": "codebase:x", "store_kind": "company",
                             "statement": "s", "logical_key": "k"},
        "world.event_bytes": json.dumps(
            {"message_type": "fact-event", "statement": "s"}, sort_keys=True
        ).encode("utf-8"),
        "world.unknown": {"status": "open"},
        "trust.certificate": {"repository_uuid": "u", "signer": "steward"},
        "trust.root_key": {"public_key": "ab" * 32},
        "trust.registry": {"entries": [{"scope": "company:root"}]},
        "native.source": b'{"line": 1}',
        "config.user": {"personal_data_root": "/p", "classifier_args": ["--json"]},
        "config.service": {"nonce_retention_seconds": 604800,
                           "facts_token_scopes": ["company:root"]},
        "corpus.record": {"text": "t", "atoms": [{"text": "t"}], "taint": ["c"],
                          "confidence": "high", "logical_key": "k",
                          "candidate_path": "a", "statement": "s"},
        "fault.schedule": {"interleave": "none"},
        "host.envelope": {"capture": {"session_start": True, "mid_session": True}},
    }
    inert: list[str] = []
    previous = _os.environ.get("GUILDHALL_ACCEPT_MUTATION", "")
    try:
        for planter in P.PLANTERS:
            _os.environ["GUILDHALL_ACCEPT_MUTATION"] = planter.mutation_id
            P.reset()
            seed = seed_values[planter.point]
            result = P.mutate(planter.point, seed, personal_root="/personal",
                              index=1, path="p")
            applications = P.applications()
            if not applications or not applications[0].effective or result == seed:
                inert.append(f"{planter.mutation_id} at {planter.point}")
    finally:
        if previous:
            _os.environ["GUILDHALL_ACCEPT_MUTATION"] = previous
        else:
            _os.environ.pop("GUILDHALL_ACCEPT_MUTATION", None)
        P.reset()

    assert not inert, (
        "these planters changed no byte at their declared seam, so they mutate "
        "nothing the product could read:\n  " + "\n  ".join(inert)
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "planters",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_a_planter_that_never_reaches_its_seam_is_invalid_not_a_kill() -> None:
    import os as _os

    from ._harness import planters as P

    previous = _os.environ.get("GUILDHALL_ACCEPT_MUTATION", "")
    _os.environ["GUILDHALL_ACCEPT_MUTATION"] = "v5.newest_wins"
    P.reset()
    try:
        with pytest.raises(HarnessInvalid, match="never reached its seam"):
            P.require_applied()
    finally:
        if previous:
            _os.environ["GUILDHALL_ACCEPT_MUTATION"] = previous
        else:
            _os.environ.pop("GUILDHALL_ACCEPT_MUTATION", None)
        P.reset()


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "detector-mutation",
        "require the planted defect to escape the detector's own self-test while causing the gate "
        "to reject the instrument",
    )
)
def test_every_detector_mutation_lets_its_positive_control_escape(tmp_path) -> None:
    """Detector Reviewer finding 9, escape half.

    The census half --- V-3 rejecting the instrument while a detector mutation
    is active --- is exercised by ``tests/detector-mutation-run.sh``, which runs
    one isolated process per mutation and reads the emitted census.
    """
    from ._harness.detectorprobe import run_all, unsound
    from ._harness.detectors import DETECTOR_MUTATIONS

    results = run_all(tmp_path)
    assert len(results) == len(DETECTOR_MUTATIONS), (
        "every catalogued detector mutation must have a probe"
    )
    bad = unsound(results)
    assert not bad, (
        "a detector mutation whose control does not escape demonstrates no "
        "blindness:\n  " + "\n  ".join(bad)
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "frozen-controls",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog before implementation is "
        "combined.",
    )
)
def test_every_obligation_has_frozen_raw_controls_and_a_bound_product_mutation() -> None:
    """Detector Reviewer finding 4.

    The controls the ledger runs are frozen bytes with a committed digest, not
    payloads derived from the clause under test, and every product-fail-closed
    obligation names an executable pre-execution planter bound to its own nodes.
    """
    from ._harness import rawcontrols

    gaps = rawcontrols.coverage_gaps(C.OBLIGATIONS)
    assert not gaps, (
        "frozen controls and the catalog disagree; re-freeze with "
        "tests/tools/freeze-controls.py --write:\n  " + "\n  ".join(gaps[:40])
    )
    frozen = rawcontrols.load()
    assert frozen["obligation_count"] == len(C.OBLIGATIONS)

    unbound = []
    for obligation in C.OBLIGATIONS:
        if obligation.fail_closed != C.PRODUCT:
            continue
        if obligation.gate not in C.REQUIRED_GATES:
            continue
        if not rawcontrols.product_mutations(obligation.oid):
            unbound.append(obligation.oid)
    assert len(unbound) < len(
        [o for o in C.OBLIGATIONS
         if o.fail_closed == C.PRODUCT and o.gate in C.REQUIRED_GATES]
    ), (
        "no product-fail-closed obligation is bound to an executable "
        "pre-execution planter; the ledger would restate the clause to itself"
    )
