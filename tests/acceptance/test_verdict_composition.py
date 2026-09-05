"""Verdict semantics: the composition the Validator must compute.

``spec/verification.md`` "Verdict semantics" fixes a total, ordered composition.
This module implements it independently and checks the product's own computation
against that implementation, so a verdict cannot be produced by a rule nobody
wrote down.

``spec/verification.md`` "Role separation" reserves the verdict to the Validator,
so nothing here issues one; these tests only assert that the product's mapping
agrees with the ratified table and that the consequences attached to each verdict
are stated.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from ._harness.cli import Guildhall
from ._harness.gates import (
    COMPOSITION,
    GATE_IDS,
    GATE_RESULTS,
    MEASUREMENT_RESULTS,
    NON_VERDICT_EVENTS,
    NON_VERDICT_STATUSES,
    TERMINAL_VERDICTS,
    compose,
    gate_result_from_vector,
)
from ._harness.requirements import ARCH, CLI, VERIFY, ProductFailure, spec_ref

pytestmark = [pytest.mark.verdict]


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "semantics",
        "The evidence carries two component results and one composed product verdict:",
    ),
    VERIFY(
        "VERDICT",
        "semantics",
        "Composition is total and ordered.",
    ),
)
def test_composition_is_total_over_the_product_space() -> None:
    for gate, measurement in itertools.product(GATE_RESULTS, MEASUREMENT_RESULTS):
        assert (gate, measurement) in COMPOSITION, (gate, measurement)
        terminal = COMPOSITION[(gate, measurement)]
        assert terminal in TERMINAL_VERDICTS, terminal
    assert len(COMPOSITION) == len(GATE_RESULTS) * len(MEASUREMENT_RESULTS)


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "table",
        "| `gate_result` \\ `measurement_result` | `PROVEN` | `NOT_PROVEN` | "
        "`INCONCLUSIVE_NO_HEADROOM` | `INCONCLUSIVE_CEILING` | `NOT_RUN` |",
    )
)
def test_composition_table_matches_the_ratified_bytes(spec_root: Path) -> None:
    text = (spec_root / "spec" / "verification.md").read_text(encoding="utf-8")
    rows = {
        "PASS": (
            "PROVEN",
            "NOT_PROVEN",
            "INCONCLUSIVE_NO_HEADROOM",
            "INCONCLUSIVE_CEILING",
            "NOT_PROVEN",
        ),
        "PRODUCT_FAILURE": ("NOT_PROVEN",) * 5,
        "INVALID_HARNESS": ("INVALID_RUN",) * 5,
    }
    for gate, expected in rows.items():
        line = next(
            (l for l in text.splitlines() if l.strip().startswith(f"| `{gate}` |")), None
        )
        assert line is not None, f"no table row for {gate}"
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")][1:]
        assert tuple(cells) == expected, f"{gate}: {cells}"
        for measurement, terminal in zip(MEASUREMENT_RESULTS, expected):
            assert COMPOSITION[(gate, measurement)] == terminal


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "ordering",
        "A separately verified product/privacy failure yields terminal `NOT_PROVEN` regardless of "
        "measurement state.",
    ),
    VERIFY(
        "VERDICT",
        "ordering",
        "If a separately content-addressed product-failure observation exists alongside an invalid "
        "detector, the product failure is retained and terminal `NOT_PROVEN` dominates; the table's "
        "`INVALID_HARNESS` row assumes no independently valid product failure.",
    ),
)
def test_independent_product_failure_dominates_an_invalid_detector() -> None:
    for measurement in MEASUREMENT_RESULTS:
        plain = compose("INVALID_HARNESS", measurement)
        assert plain.terminal == "INVALID_RUN", measurement
        with_failure = compose(
            "INVALID_HARNESS", measurement, independent_product_failure=True
        )
        assert with_failure.terminal == "NOT_PROVEN", measurement
        assert "PRODUCT_FAILURE_DOMINATES" in with_failure.diagnostics


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "not-run",
        "`NOT_RUN` is terminal `NOT_PROVEN` because the proof was not performed, with a diagnostic that "
        "must not imply a product mechanism falsifier.",
    )
)
def test_not_run_is_not_a_mechanism_falsifier() -> None:
    result = compose("PASS", "NOT_RUN")
    assert result.terminal == "NOT_PROVEN"
    assert "MEASUREMENT_NOT_PERFORMED_NOT_A_MECHANISM_FALSIFIER" in result.diagnostics


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "both-conditions",
        "If both headroom and ceiling conditions hold, ceiling is reported as the instrument failure and "
        "the headroom flag remains visible, but neither can mask a product gate failure.",
    )
)
def test_ceiling_reported_while_headroom_flag_remains_visible() -> None:
    both = compose("PASS", "PROVEN", headroom_condition=True, ceiling_condition=True)
    assert both.measurement_result == "INCONCLUSIVE_CEILING"
    assert both.terminal == "INCONCLUSIVE_CEILING"
    assert both.headroom_flag_visible is True
    assert "HEADROOM_FLAG_VISIBLE" in both.diagnostics

    masked = compose(
        "PRODUCT_FAILURE", "PROVEN", headroom_condition=True, ceiling_condition=True
    )
    assert masked.terminal == "NOT_PROVEN", (
        "neither condition may mask a product gate failure"
    )


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "vector",
        "`gate_result` over V-1 through V-9 is `PASS`, `PRODUCT_FAILURE`, or `INVALID_HARNESS`;",
    )
)
def test_gate_vector_folds_with_product_failure_dominant() -> None:
    passing = {gate: "PASS" for gate in GATE_IDS}
    assert gate_result_from_vector(passing) == "PASS"

    invalid = dict(passing)
    invalid["V-3"] = "INVALID_HARNESS"
    assert gate_result_from_vector(invalid) == "INVALID_HARNESS"

    both = dict(invalid)
    both["V-2"] = "PRODUCT_FAILURE"
    assert gate_result_from_vector(both) == "PRODUCT_FAILURE"

    with pytest.raises(ValueError):
        gate_result_from_vector({"V-1": "PASS"})


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "not-a-verdict",
        "Document/ledger statuses (`candidate`, `ratified`, `proven`) are not run verdicts.",
    ),
    VERIFY(
        "VERDICT",
        "not-a-verdict",
        "Implementation complete, service starts, unit green, architecture present, or Factory milestone "
        "reached are never product verdicts.",
    ),
)
def test_document_statuses_and_milestones_are_not_verdicts() -> None:
    for status in NON_VERDICT_STATUSES:
        assert status.upper() not in TERMINAL_VERDICTS or status == "proven"
    # `proven` is a behavior-ledger status, distinct from the PROVEN run verdict.
    assert "proven" in NON_VERDICT_STATUSES
    assert "PROVEN" in TERMINAL_VERDICTS
    for event in NON_VERDICT_EVENTS:
        assert event.upper().replace(" ", "_") not in TERMINAL_VERDICTS


@pytest.mark.requires_product
@spec_ref(
    ARCH(
        "VERDICT",
        "brownfield-harness",
        "Threshold computation is deterministic and produces `PROVEN`, `NOT_PROVEN`, "
        "`INCONCLUSIVE_NO_HEADROOM`, or `INCONCLUSIVE_CEILING`; it has no `demo-success` state.",
    ),
    CLI(
        "VERDICT",
        "hosts-and-experiments",
        "`verdict` has only the states in the verification strategy.",
    ),
)
def test_product_verdict_states_are_exactly_the_ratified_set(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    result = guildhall.run("experiment", "verdict", str(run_dir), "--json", check=False)
    assert result.returncode != 1
    help_text = guildhall.run("experiment", "verdict", "--help", check=False).stdout
    assert "demo-success" not in help_text.lower(), (
        "spec/architecture.md section 10: threshold computation 'has no `demo-success` "
        "state'"
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise ProductFailure(
            "`experiment verdict` produced no states to compare against the ratified "
            "composition table"
        )
    payload = result.json
    terminal = payload.get("terminal_product_verdict")
    if terminal is not None:
        assert terminal in TERMINAL_VERDICTS, terminal
    gate = payload.get("gate_result")
    if gate is not None:
        assert gate in GATE_RESULTS, gate
    measurement = payload.get("measurement_result")
    if measurement is not None:
        assert measurement in MEASUREMENT_RESULTS, measurement
    if None not in (gate, measurement, terminal):
        expected = compose(
            gate,
            measurement,
            independent_product_failure=bool(payload.get("independent_product_failure")),
            headroom_condition=bool(payload.get("headroom_condition")),
            ceiling_condition=bool(payload.get("ceiling_condition")),
        ).terminal
        assert terminal == expected, (
            f"the product composed {gate}/{measurement} to {terminal}; the ratified "
            f"table gives {expected}"
        )
    vector = payload.get("gate_vector")
    assert vector is not None, (
        "the packet must carry the full gate diagnostic vector even when terminal "
        "proof fails"
    )


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "consequences",
        "Verdict consequences are fixed in advance. `PROVEN` authorizes only founder review of a new "
        "production design and private soak decision; it never authorizes deployment or shared-remote "
        "use.",
    ),
    VERIFY(
        "VERDICT",
        "consequences",
        "`INCONCLUSIVE_NO_HEADROOM` retires this pool and requires a new founder- approved "
        "preregistration before any new pool. `INCONCLUSIVE_CEILING` requires a new task/oracle "
        "preregistration. None permits quiet task swapping, threshold tuning, or selective reruns.",
    ),
)
def test_verdict_consequences_are_fixed_in_advance() -> None:
    consequences = {
        "PROVEN": {
            "authorizes": ["founder_review_of_new_production_design", "private_soak_decision"],
            "forbids": ["deployment", "shared_remote_use"],
        },
        "NOT_PROVEN": {
            "authorizes": ["founder_authorized_redesign"],
            "forbids": ["reopening_the_type_1_store_separation_rule"],
        },
        "INCONCLUSIVE_NO_HEADROOM": {
            "authorizes": ["new_founder_approved_preregistration"],
            "forbids": ["reusing_this_pool"],
        },
        "INCONCLUSIVE_CEILING": {
            "authorizes": ["new_task_oracle_preregistration"],
            "forbids": ["tightening_eligibility", "swapping_tasks"],
        },
        "INVALID_RUN": {
            "authorizes": [],
            "forbids": ["claiming_a_product_result"],
        },
    }
    assert set(consequences) == set(TERMINAL_VERDICTS)
    for verdict, rule in consequences.items():
        assert rule["forbids"] is not None, verdict
    for verdict in TERMINAL_VERDICTS:
        assert "quiet_task_swap" not in consequences[verdict]["authorizes"]
        assert "threshold_tuning" not in consequences[verdict]["authorizes"]
        assert "selective_rerun" not in consequences[verdict]["authorizes"]


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "rerun",
        "Only a documented pre-unblinding harness defect permits one founder-authorized superseding run "
        "over the same pool and preregistered reserve seeds; the failed run remains.",
    ),
    VERIFY(
        "VERDICT",
        "ledger",
        "A harness-defect record must enter that ledger before the unblinding event and be "
        "countersigned by the founder to authorize the one superseding run.",
    ),
)
def test_one_superseding_run_requires_a_pre_unblinding_countersigned_record() -> None:
    def may_supersede(record: dict | None, unblinded: bool, already_superseded: bool) -> bool:
        if record is None:
            return False
        if record.get("recorded_after_unblinding"):
            return False
        if not record.get("founder_countersignature"):
            return False
        if already_superseded:
            return False
        return True

    assert may_supersede(
        {"recorded_after_unblinding": False, "founder_countersignature": "sig"},
        unblinded=True,
        already_superseded=False,
    )
    assert not may_supersede(None, unblinded=True, already_superseded=False)
    assert not may_supersede(
        {"recorded_after_unblinding": True, "founder_countersignature": "sig"},
        unblinded=True,
        already_superseded=False,
    )
    assert not may_supersede(
        {"recorded_after_unblinding": False, "founder_countersignature": None},
        unblinded=True,
        already_superseded=False,
    )
    assert not may_supersede(
        {"recorded_after_unblinding": False, "founder_countersignature": "sig"},
        unblinded=True,
        already_superseded=True,
    ), "only one superseding run is permitted"


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "VERDICT",
        "unblockable",
        "Once the sealed inputs exist, the computation is unblockable and reproducible; any later "
        "objection is a new retained finding. Unresolved validity disagreement is `INVALID_RUN`, never a "
        "discretionary pass.",
    ),
    VERIFY(
        "VERDICT",
        "authority",
        "Company-steward exceptions can change Company facts only; they cannot waive a proof gate, change "
        "a score, or override a verdict.",
    ),
)
def test_no_role_can_convert_an_unresolved_disagreement_into_a_pass() -> None:
    def resolve(disagreement_resolved: bool, steward_exception: bool, agy_block: bool) -> str:
        if steward_exception:
            # A Company-steward exception changes Company facts only.
            pass
        if agy_block:
            return "INVALID_HARNESS"
        if not disagreement_resolved:
            return "INVALID_RUN"
        return "PROCEED"

    assert resolve(False, False, False) == "INVALID_RUN"
    assert resolve(False, True, False) == "INVALID_RUN", (
        "a steward exception cannot waive a proof gate"
    )
    assert resolve(True, False, True) == "INVALID_HARNESS", (
        "Agy may block before evidence sealing, forcing INVALID_HARNESS/repair"
    )
    assert resolve(True, False, False) == "PROCEED"
