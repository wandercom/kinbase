"""Dispatch 016 instrument controls; all recordings here are synthetic."""
import copy
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from itertools import combinations

import pytest

from . import test_v9_fatigue as fatigue
from ._harness import consumption, corpora, operator_exercise as instrument
from ._harness.requirements import HarnessInvalid, ProductFailure, VERIFY, spec_ref
from ._harness.roots import ProofRoots

pytestmark = pytest.mark.selftest
REFERENCE = VERIFY("INSTRUMENT", "fail-closed", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.")


@pytest.fixture
def exercise():
    return corpora.load_gold("operator_exercise.json")


@spec_ref(REFERENCE)
def test_predictability_and_destination_balance(exercise):
    metrics = instrument.validate(exercise)
    # Independent brute-force optimal lookup: try every binary assignment to
    # the distinct field values, rather than repeating the majority algorithm.
    fields = [key for key, _ in instrument.DISPLAYED_FIELDS]
    for size in (1, 2):
        for selected in combinations(fields, size):
            values = [tuple(i[k] for k in selected) for i in exercise["items"]]
            unique = list(dict.fromkeys(values))
            best = max(sum(
                ("approve" if mask & (1 << unique.index(value)) else "reject") == item["gold_decision"]
                for value, item in zip(values, exercise["items"])
            ) for mask in range(1 << len(unique))) / 20
            assert metrics["scores"][selected] == best <= 0.70
    assert metrics["best_single"] == 0.60
    assert metrics["best_pair"] == 0.60
    assert Counter(i["gold_decision"] for i in exercise["items"]) == {"approve": 10, "reject": 10}
    for dest in ("personal", "company", "codebase", "none"):
        assert {i["gold_decision"] for i in exercise["items"] if i["proposed_destination"] == dest} == {"approve", "reject"}


@spec_ref(REFERENCE)
@pytest.mark.parametrize("shortcut", ["destination", "kind", "pair"])
def test_acceptance_node_refuses_predictable_fixture_before_responses(exercise, tmp_path, monkeypatch, shortcut):
    for item in exercise["items"]:
        shared = item["proposed_destination"] in {"company", "codebase"}
        constraint = item["atom_kind"] == "constraint"
        approve = shared if shortcut == "destination" else constraint
        if shortcut == "pair":
            approve = shared == constraint
        item["gold_decision"] = "approve" if approve else "reject"
    exercise["approval_count"] = sum(i["gold_decision"] == "approve" for i in exercise["items"])
    if shortcut == "pair":
        assert instrument.predictability(exercise)["best_single"] <= 0.70
        assert instrument.predictability(exercise)["best_pair"] == 1.0
    monkeypatch.setattr(fatigue.corpora, "load_gold", lambda _: exercise)

    def forbidden():
        pytest.fail("defective fixture reached response loading")

    monkeypatch.setattr(fatigue, "_operator_responses", forbidden)
    roots = ProofRoots.create(tmp_path / "proof", company_port=0)
    with pytest.raises(HarnessInvalid, match="predictability.*exceeds 70%"):
        fatigue.test_blinded_operator_exercise_accuracy_and_median_time(roots)


@spec_ref(REFERENCE)
def test_predictability_boundary_is_inclusive(exercise):
    # Two minority-label splits raise the pair lookup from 12/20 to 14/20.
    for item in exercise["items"]:
        item["atom_kind"] = "question" if item["item_id"] in {"op01", "op06"} else "observation"
    assert instrument.validate(exercise)["best_pair"] == 0.70
    next(i for i in exercise["items"] if i["item_id"] == "op10")["atom_kind"] = "question"
    assert instrument.predictability(exercise)["best_pair"] == 0.75
    with pytest.raises(HarnessInvalid, match="75% exceeds 70%"):
        instrument.validate(exercise)


@spec_ref(REFERENCE)
@pytest.mark.parametrize("ident,category,destination", [
    ("op11", "organization_to_personal", "personal"),
    ("op03", "private_to_shared", "company"),
    ("op01", "repository_to_company", "company"),
    ("op08", "transient_to_store", "codebase"),
])
def test_required_misroute_coverage(exercise, ident, category, destination):
    item = next(i for i in exercise["items"] if i["item_id"] == ident)
    assert item["gold_misroute"] == category
    assert item["proposed_destination"] == destination
    assert item["gold_decision"] == "reject"
    del item["gold_misroute"]
    with pytest.raises(HarnessInvalid, match="missing misroute coverage: " + category):
        instrument.validate(exercise)


@spec_ref(REFERENCE)
def test_fixture_semantics_render_verbatim_and_gold_stays_hidden(exercise, tmp_path):
    bound = corpora.bind_operator_exercise(exercise, tmp_path / "presentation.jsonl")
    records = [json.loads(line) for line in bound.path.read_text().splitlines()]
    assert len(records) == 20
    for item, record in zip(exercise["items"], records):
        assert record["text"].splitlines()[0] == exercise["decision_semantics"]
        assert exercise["routing_context"] in record["text"]
        assert item["rendered_statement"] in record["text"]
        for key, label in instrument.DISPLAYED_FIELDS:
            assert label + ": " + item[key] in record["text"]
        assert item["gold_reason"] not in record["text"]
        assert "gold_misroute" not in record["text"]
    by_id = {i["item_id"]: i for i in exercise["items"]}
    assert by_id["op05"]["gold_decision"] == "approve"
    assert "credential" in by_id["op05"]["rendered_statement"]
    assert by_id["op15"]["proposed_destination"] == "none"
    assert by_id["op15"]["gold_decision"] == "approve"
    assert by_id["op16"]["proposed_destination"] == "none"
    assert by_id["op16"]["gold_decision"] == "reject"
    changed = copy.deepcopy(exercise)
    changed["decision_semantics"] += " Only this action is scored."
    rebound = corpora.bind_operator_exercise(changed, tmp_path / "rebound.jsonl")
    assert not set(bound.gold).intersection(rebound.gold)
    del changed["decision_semantics"]
    with pytest.raises(HarnessInvalid, match="missing decision_semantics"):
        corpora.bind_operator_exercise(changed, tmp_path / "invalid.jsonl")


@spec_ref(REFERENCE)
@pytest.mark.parametrize("strategy", ["rubber_stamp", "destination_only"])
def test_synthetic_shortcut_operator_fails_gate(exercise, tmp_path, monkeypatch, strategy):
    # Keep synthetic detector controls out of the product-observation census.
    monkeypatch.setattr(consumption, "record", lambda *args, **kwargs: None)
    bound = corpora.bind_operator_exercise(exercise, tmp_path / "presentation.jsonl")
    start = datetime(2026, 9, 9, tzinfo=timezone.utc)
    responses = [{
        "item_id": bound.ids.token(item["item_id"]),
        "decision": "approve" if strategy == "rubber_stamp" or item["proposed_destination"] in {"company", "codebase"} else "reject",
        "decided_at": (start + timedelta(seconds=20 * index)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    } for index, item in enumerate(exercise["items"])]
    monkeypatch.setattr(fatigue, "_operator_responses", lambda: responses)
    roots = ProofRoots.create(tmp_path / "proof", company_port=0)
    with pytest.raises(ProductFailure, match="accuracy"):
        fatigue.test_blinded_operator_exercise_accuracy_and_median_time(roots)
