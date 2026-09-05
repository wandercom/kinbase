"""V-7 --- set-conditional projection and VOI stop (`P-7`, Critical).

``spec/verification.md`` V-7 is explicit about what this gate does and does not
establish:

    This fixture proves selector mechanics only. Causal evidence for set selection
    comes from `topk-maintained` versus `full-system` in V-10, with natural-corpus
    redundancy cluster sizes and source dependence reported rather than
    manufactured.

so every assertion here is about mechanics --- marginal value recomputed against
the current set, complementarity, redundancy penalty, distortion ordering and
the VOI stopping rule --- and none of them is presented as causal evidence.

The frozen candidate set, from V-7:

    Construct a candidate set with high-scoring paraphrases, one distinct
    high-distortion compatibility invariant, one complementary test/rationale
    pair, one stale fact, and one high-distortion Unknown.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import synth
from ._harness.cli import Guildhall
from ._harness.gitfix import GitRepo
from ._harness.hosts import PROJECTION_BYTES, PROJECTION_FACTS
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    SRC,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots

pytestmark = [pytest.mark.v7, pytest.mark.requires_product]

#: The frozen candidate-set roles the V-7 fixture must contain.
CANDIDATE_ROLES: tuple[str, ...] = (
    "high_scoring_paraphrase",
    "high_distortion_compatibility_invariant",
    "complementary_test",
    "complementary_rationale",
    "stale_fact",
    "high_distortion_unknown",
)

#: Evidence tiers, ``spec/architecture.md`` section 8.
EVIDENCE_TIERS: tuple[str, ...] = (
    "facts_and_unknowns",
    "summary",
    "exact_code_span",
    "history_adr",
    "test_runtime_evidence",
    "authority_answer",
    "broad_search",
)

#: Marginal-value terms, ``spec/architecture.md`` section 8.
MARGINAL_TERMS: tuple[str, ...] = (
    "newly_covered_distortion",
    "authority_and_validity_gain",
    "complementarity_gain",
    "uncertainty_reduction",
    "redundancy",
    "retrieval_and_residency_cost",
    "stale_or_conflict_risk",
)

TASK = "extend the scheduler diagnosis path"
DECISION = "which compatibility invariant constrains the change"


@pytest.fixture()
def projector_repo(roots: ProofRoots) -> GitRepo:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.commit("initialise")
    return repo


def _project(guildhall: Guildhall, *, working_set: tuple[str, ...] = (), **env: str) -> dict:
    argv = [
        "project",
        "--repo",
        str(guildhall.cwd),
        "--task",
        TASK,
        "--decision",
        DECISION,
    ]
    for fact_id in working_set:
        argv += ["--working-set", fact_id]
    argv.append("--json")
    result = guildhall.run(
        *argv,
        env={"GUILDHALL_ACCEPTANCE_V7_FIXTURE": "1", **env},
        check=False,
    )
    assert result.returncode != 1, "`project` returned the reserved ambiguous exit 1"
    if result.returncode not in (0, 3):
        raise ProductFailure(
            f"`project` refused with {result.code}; V-7 requires an inspectable "
            "selection trace"
        )
    return result.json


@spec_ref(
    SRC(
        "V-7",
        "SRC-3",
        "The structure needs to be what's optimal for improving brownfield performance.",
    ),
    VERIFY(
        "V-7",
        "fixture",
        "Construct a candidate set with high-scoring paraphrases, one distinct high-distortion "
        "compatibility invariant, one complementary test/rationale pair, one stale fact, and one "
        "high-distortion Unknown.",
    ),
)
def test_frozen_candidate_set_contains_every_declared_role(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    candidates = payload.get("candidates") or []
    assert candidates, "the projector must expose its candidate set"
    roles = {c.get("fixture_role") for c in candidates}
    missing = [role for role in CANDIDATE_ROLES if role not in roles]
    assert not missing, (
        f"the frozen V-7 candidate set is missing {missing}; observed {sorted(roles)}"
    )
    paraphrases = [c for c in candidates if c.get("fixture_role") == "high_scoring_paraphrase"]
    assert len(paraphrases) >= 2, (
        "the fixture requires high-scoring paraphrases (plural) so redundancy is "
        "genuinely exercised"
    )


@spec_ref(
    PRODUCT(
        "V-7",
        "P-7",
        "The projector selects a set, not independently weighted nodes.",
    ),
    VERIFY(
        "V-7",
        "selection",
        "Assert selection changes when working-set IDs change; duplicates show diminishing returns; "
        "the invariant is selected; complementarity is visible; stale fact is not trusted; and the "
        "retrieval trace either reaches sufficiency or asks authority.",
    ),
)
def test_selection_changes_when_working_set_ids_change(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    cold = _project(guildhall)
    cold_ids = tuple(f["fact_id"] for f in cold.get("selected") or [])
    assert cold_ids, "the projector selected nothing on a cold working set"

    warm = _project(guildhall, working_set=cold_ids[:2])
    warm_ids = tuple(f["fact_id"] for f in warm.get("selected") or [])
    assert warm_ids != cold_ids, (
        "selection must change when the current working-set IDs change; the projector "
        "is scoring nodes independently of the set"
    )
    overlap = set(cold_ids[:2]) & set(warm_ids)
    assert not overlap, (
        "a fact already in the working set must not be re-selected at full value; "
        f"re-selected {sorted(overlap)}"
    )


@spec_ref(
    PRODUCT(
        "V-7",
        "P-7",
        "It must demonstrate that redundant high-similarity facts do not crowd out a distinct "
        "high-distortion constraint and that adding the same fact to a warm working set has "
        "near-zero marginal value.",
    ),
    VERIFY(
        "V-7",
        "mutation",
        "Mutation: independent scalar rank/top-k; V-7 fails because duplicates crowd out the "
        "invariant.",
    ),
)
def test_duplicates_do_not_crowd_out_the_high_distortion_invariant(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    selected = payload.get("selected") or []
    roles = [f.get("fixture_role") for f in selected]
    assert "high_distortion_compatibility_invariant" in roles, (
        "the distinct high-distortion compatibility invariant must be selected; "
        f"observed {roles}"
    )
    paraphrase_count = roles.count("high_scoring_paraphrase")
    assert paraphrase_count <= 1, (
        f"{paraphrase_count} redundant paraphrases were selected; duplicates must show "
        "diminishing returns rather than crowd out the invariant"
    )
    invariant_rank = roles.index("high_distortion_compatibility_invariant")
    if "high_scoring_paraphrase" in roles:
        assert invariant_rank < roles.index("high_scoring_paraphrase") or paraphrase_count == 1, (
            "the high-distortion invariant must not be ordered below a redundant "
            "paraphrase"
        )


@spec_ref(
    ARCH(
        "V-7",
        "set-conditional-projector",
        "A deterministic greedy selector recalculates marginal value after each addition, honors "
        "hard byte/item/cost ceilings, and stops on sufficiency or nonpositive net gain.",
    ),
    ARCH(
        "V-7",
        "set-conditional-projector",
        "The trace records the terms, not just a score.",
    ),
)
def test_marginal_value_is_recomputed_against_the_current_set(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    trace = payload.get("selection_trace") or []
    assert trace, "the projector must emit a selection trace"
    for step in trace:
        terms = step.get("marginal_terms") or {}
        missing = [t for t in MARGINAL_TERMS if t not in terms]
        assert not missing, (
            "the trace records the terms, not just a score; step "
            f"{step.get('fact_id')} is missing {missing}"
        )
        assert step.get("current_set_size") is not None, (
            "each step must record the set it was scored against"
        )

    # Adding the same fact to a warm set must have near-zero marginal value.
    first_id = trace[0]["fact_id"]
    warm = _project(guildhall, working_set=(first_id,))
    warm_trace = {s["fact_id"]: s for s in warm.get("selection_trace") or []}
    if first_id in warm_trace:
        gain = warm_trace[first_id].get("marginal_value")
        assert gain is not None and gain <= 0.05, (
            f"adding {first_id} to a warm working set yielded marginal value {gain}; "
            "it must be near zero"
        )


@spec_ref(
    ARCH(
        "V-7",
        "set-conditional-projector",
        "Complementarity permits a test plus rationale to be jointly useful.",
    ),
    ARCH(
        "V-7",
        "set-conditional-projector",
        "Redundancy uses explicit edges, shared provenance, and semantic similarity.",
    ),
)
def test_complementarity_is_visible_and_redundancy_is_penalised(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    trace = {s["fact_id"]: s for s in payload.get("selection_trace") or []}
    selected = payload.get("selected") or []
    roles = {f.get("fixture_role"): f.get("fact_id") for f in selected}

    complementary = [r for r in ("complementary_test", "complementary_rationale") if r in roles]
    assert len(complementary) == 2, (
        "the complementary test/rationale pair must be jointly selected; observed "
        f"{complementary}"
    )
    for role in complementary:
        step = trace.get(roles[role]) or {}
        gain = (step.get("marginal_terms") or {}).get("complementarity_gain")
        assert gain is not None and gain > 0, (
            f"{role} must show a positive complementarity gain; observed {gain}"
        )

    penalised = [
        step
        for step in payload.get("selection_trace") or []
        if (step.get("marginal_terms") or {}).get("redundancy", 0) > 0
    ]
    assert penalised, (
        "at least one candidate must carry a positive redundancy penalty; the fixture "
        "deliberately contains high-scoring paraphrases"
    )
    for step in penalised:
        basis = step.get("redundancy_basis") or []
        assert set(basis) & {"explicit_edge", "shared_provenance", "semantic_similarity"}, (
            f"redundancy for {step.get('fact_id')} must name its basis; observed {basis}"
        )


@spec_ref(
    PRODUCT(
        "V-7",
        "P-7",
        "It uses conditional distortion cost (expected loss if a fact is absent when the dependent "
        "decision fires), typed redundancy/complementarity, authority/validity, and evidence cost.",
    ),
    ARCH(
        "V-7",
        "set-conditional-projector",
        "Distortion is tied to a named dependent decision/trigger and severity; it is not a generic "
        "node weight.",
    ),
)
def test_distortion_is_tied_to_a_named_trigger_not_a_generic_weight(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    for candidate in payload.get("candidates") or []:
        distortion = candidate.get("distortion") or {}
        for field in ("trigger", "loss_if_absent", "rationale"):
            assert field in distortion, (
                f"{candidate.get('fact_id')}: distortion must name {field}; observed "
                f"{sorted(distortion)}"
            )
        assert distortion["trigger"], (
            "distortion must be tied to a named dependent decision/trigger"
        )
    ordered = [
        c
        for c in sorted(
            payload.get("candidates") or [],
            key=lambda c: (c.get("distortion") or {}).get("severity_rank", 0),
            reverse=True,
        )
    ]
    if ordered and ordered[0].get("fixture_role"):
        assert ordered[0]["fixture_role"] in {
            "high_distortion_compatibility_invariant",
            "high_distortion_unknown",
        }, (
            "the highest-distortion candidate must be the invariant or the Unknown; "
            f"observed {ordered[0].get('fixture_role')}"
        )


@spec_ref(
    VERIFY(
        "V-7",
        "stale",
        "stale fact is not trusted",
    ),
    PRODUCT(
        "V-7",
        "P-4",
        "A stale or disputed fact is worse than a missing fact: it is withheld from trusted "
        "projection and produces an owned Unknown.",
    ),
)
def test_stale_fact_is_withheld_and_produces_an_owned_unknown(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    selected_roles = {f.get("fixture_role") for f in payload.get("selected") or []}
    assert "stale_fact" not in selected_roles, (
        "a stale fact must be withheld from trusted projection"
    )
    unknowns = payload.get("unknowns") or []
    assert unknowns, "the withheld stale fact must produce an owned Unknown"
    for unknown in unknowns:
        assert unknown.get("owner_identity"), "a blocking Unknown always names a person"


@spec_ref(
    PRODUCT(
        "V-7",
        "P-7",
        "The retrieval loop escalates from constraint/Unknown through summary, exact span, history, "
        "tests/runtime trace, and broader search, stopping when estimated value of the next "
        "retrieval is no greater than its cost or when an explicit sufficiency predicate is met.",
    ),
    VERIFY(
        "V-7",
        "stop",
        "Escalate evidence tiers and assert the loop stops on net marginal value, not a filled token "
        "window.",
    ),
)
def test_loop_stops_on_net_marginal_value_not_a_filled_window(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    escalation = payload.get("tier_escalation") or []
    assert escalation, "the retrieval loop must record its tier escalation"
    seen = [step.get("tier") for step in escalation]
    for tier in seen:
        assert tier in EVIDENCE_TIERS, f"unknown evidence tier {tier!r}"
    assert seen == sorted(seen, key=EVIDENCE_TIERS.index), (
        f"tiers must escalate in the frozen order; observed {seen}"
    )

    stop = payload.get("stopping_reason")
    assert stop in {
        "nonpositive_net_marginal_value",
        "sufficiency_predicate_met",
        "authority_question_raised",
    }, (
        f"the loop must stop on net marginal value, sufficiency, or an authority "
        f"question; observed {stop!r}"
    )
    assert stop != "token_window_full", (
        "stopping because the token window filled is exactly the failure V-7 forbids"
    )

    used_bytes = payload.get("projection_bytes")
    used_facts = len(payload.get("selected") or [])
    if used_bytes is not None:
        assert used_bytes <= PROJECTION_BYTES, (
            f"projection exceeded the 128 KiB ceiling: {used_bytes}"
        )
        assert used_bytes < PROJECTION_BYTES * 0.95 or stop == "sufficiency_predicate_met", (
            "a projection that stops only at the byte ceiling is filling a window, not "
            "computing net marginal value"
        )
    assert used_facts <= PROJECTION_FACTS, (
        f"projection exceeded the 32-fact ceiling: {used_facts}"
    )


@spec_ref(
    PRODUCT(
        "V-7",
        "P-7",
        "The system records requested, returned, resident-at-dependent-edit, used, marginal gain, "
        "stopping reason, question, and task outcome.",
    ),
    ARCH(
        "V-7",
        "set-conditional-projector",
        "Query logs record retrievals, returned and selected IDs, working set, edit-time residency, "
        "declared use, outcome, and cost.",
    ),
)
def test_query_log_records_every_declared_field(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    _project(guildhall)
    status = guildhall.run(
        "status", "--repo", str(guildhall.cwd), "--json", check=False
    )
    assert status.returncode != 1
    payload = status.json if status.stdout.strip() else {}
    logs = payload.get("query_log") or payload.get("query_traces") or []
    assert logs, "query logs are the future compiler specification and must be recorded"
    entry = logs[-1]
    for field in (
        "requested",
        "returned",
        "selected_ids",
        "working_set",
        "resident_at_dependent_edit",
        "declared_use",
        "marginal_gain",
        "stopping_reason",
        "question",
        "outcome",
        "cost",
    ):
        assert field in entry, (
            f"the query log must record {field}; observed {sorted(entry)}"
        )


@spec_ref(
    PRODUCT(
        "V-7",
        "P-7",
        "The implementation may use an explicit, inspectable approximation to VOI; it may not claim "
        "calibrated causal VOI without the experiment.",
    ),
    VERIFY(
        "V-7",
        "scope",
        "This fixture proves selector mechanics only. Causal evidence for set selection comes from "
        "`topk-maintained` versus `full-system` in V-10, with natural-corpus redundancy cluster sizes "
        "and source dependence reported rather than manufactured.",
    ),
)
def test_no_calibrated_causal_voi_claim_is_made(
    guildhall: Guildhall, projector_repo: GitRepo
) -> None:
    payload = _project(guildhall)
    rendered = json.dumps(payload).lower()
    for forbidden in ("calibrated causal voi", "calibrated_causal_voi", "proven voi"):
        assert forbidden not in rendered, (
            f"the projector must not claim {forbidden!r} without the V-10 experiment"
        )
    approximation = payload.get("voi_approximation") or payload.get("objective")
    assert approximation is not None, (
        "the VOI approximation must be explicit and inspectable"
    )
