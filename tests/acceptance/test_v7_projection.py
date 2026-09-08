"""V-7 --- set-conditional projection and VOI stop (`P-7`, Critical).

Detector Reviewer finding 14: every V-7 assertion came from the product after
a fixture-mode environment flag was set over an empty repository. An
implementation could detect the flag and emit exactly the roles, selection trace
and stopping reason the tests expected, without a corpus existing.

The rewrite ingests the frozen candidate set as real signed events through the
ordinary corpus surface. The product receives no role labels and no fixture
mode; role attribution happens afterwards in the harness, from its own
logical-key map. If the projector selects nothing, or selects without a trace,
the obligation fails --- there is no branch on which absence passes.

``spec/verification.md`` V-7 bounds what this gate may claim:

    This fixture proves selector mechanics only. Causal evidence for set
    selection comes from `topk-maintained` versus `full-system` in V-10
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import obligations as O
from ._harness import trust
from ._harness.cli import Guildhall
from ._harness.evidence_model import Origin, require_all, require_nonempty
from ._harness.hosts import PROJECTION_BYTES
from ._harness.requirements import (
    ARCH,
    PRODUCT,
    SRC,
    VERIFY,
    HarnessInvalid,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.worldbuilder import (
    V7_CANDIDATES,
    SignedWorld,
    plant_v7_corpus,
    role_of,
)

pytestmark = [pytest.mark.v7, pytest.mark.requires_product]

TASK = "extend the scheduler diagnosis path"
DECISION = "which compatibility invariant constrains the change"

EVIDENCE_TIERS: tuple[str, ...] = (
    "facts_and_unknowns", "summary", "exact_code_span", "history_adr",
    "test_runtime_evidence", "authority_answer", "broad_search",
)

MARGINAL_TERMS: tuple[str, ...] = (
    "newly_covered_distortion", "authority_and_validity_gain",
    "complementarity_gain", "uncertainty_reduction", "redundancy",
    "retrieval_and_residency_cost", "stale_or_conflict_risk",
)


@pytest.fixture()
def ingested(roots: ProofRoots, guildhall: Guildhall):
    """The frozen candidate set, really planted and really ingested.

    Validator ruling C3: the world establishes every trust anchor first, so the
    Company-store candidates are admitted through the service and the Codebase
    candidates are signed by a registered maintainer under a certified UUID.
    """
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(guildhall, roots, world)
    planted = plant_v7_corpus(world)
    world.verify_planted()
    if len(planted) != len(V7_CANDIDATES):
        raise HarnessInvalid(
            f"planted {len(planted)} of {len(V7_CANDIDATES)} frozen candidates"
        )
    result = guildhall.run(
        "ingest", "kindex", str(world.repo.path / ".kin"),
        "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path, check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`ingest kindex` returned the reserved ambiguous exit 1")
    return world, planted, anchors


def _project(guildhall: Guildhall, repo: Path, working_set: tuple[str, ...] = ()) -> dict:
    argv = ["project", "--repo", str(repo), "--task", TASK, "--decision", DECISION]
    for fact_id in working_set:
        argv += ["--working-set", fact_id]
    argv.append("--json")
    result = guildhall.run(*argv, cwd=repo, check=False)
    if result.returncode == 1:
        raise ProductFailure("`project` returned the reserved ambiguous exit 1")
    if result.returncode not in (0, 3):
        raise ProductFailure(
            f"`project` refused with {result.code}; V-7 requires an inspectable "
            "selection trace over the ingested corpus"
        )
    payload = result.json
    if not isinstance(payload, dict):
        raise ProductFailure("`project --json` did not return an object")
    return payload


def _roles(entries) -> list[str]:
    """Recover the frozen role of each entry from the harness-held key map."""
    out: list[str] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        key = entry.get("logical_key")
        if key is None:
            continue
        try:
            out.append(role_of(key))
        except HarnessInvalid:
            continue
    return out



def _list(payload: dict, *keys: str) -> list:
    """First present list among ``keys``; empty when none exist.

    Emptiness reaches the catalogue clause, which refuses it, instead of being
    substituted at the read site inside a gate test.
    """
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


#: Claims this fixture may never make; the causal evidence lives in V-10.
FORBIDDEN_VOI_CLAIMS: tuple[str, ...] = (
    "calibrated causal voi", "calibrated_causal_voi", "proven voi",
)


def _first(payload: dict, *keys: str):
    """First present value among ``keys``; ``None`` when none exist."""
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def _terms(step: dict) -> dict:
    value = step.get("marginal_terms")
    return value if isinstance(value, dict) else {}

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
    guildhall: Guildhall, ingested
) -> None:
    world, planted, _anchors = ingested
    payload = _project(guildhall, world.repo.path)
    candidates = payload.get("candidates")
    require_nonempty(
        candidates if isinstance(candidates, list) else [],
        obligation="V-7.candidate-set",
        why="the projector must expose the candidate set it ingested",
        origin=Origin.PRODUCT,
    )
    roles = _roles(candidates)
    O.check(
        "V-7.candidate-set",
        {
            "ingested_through_shipping_surface": True,
            "ingested_record_count": len(planted),
            "roles_present": sorted(set(roles)),
            "paraphrase_count": roles.count("high_scoring_paraphrase"),
            "fixture_mode_selector_used": False,
        },
        label="frozen candidate roles recovered from the ingested corpus",
    )


@spec_ref(
    PRODUCT("V-7", "P-7", "The projector selects a set, not independently weighted nodes."),
    VERIFY(
        "V-7",
        "selection",
        "Assert selection changes when working-set IDs change; duplicates show diminishing returns; "
        "the invariant is selected; complementarity is visible; stale fact is not trusted; and the "
        "retrieval trace either reaches sufficiency or asks authority.",
    ),
)
def test_selection_changes_when_working_set_ids_change(
    guildhall: Guildhall, ingested
) -> None:
    world, _, _anchors = ingested
    cold = _project(guildhall, world.repo.path)
    cold_selected = cold.get("selected")
    require_nonempty(
        cold_selected if isinstance(cold_selected, list) else [],
        obligation="V-7.set-conditional",
        why="a cold projection over a non-empty corpus must select something",
        origin=Origin.PRODUCT,
    )
    cold_ids = tuple(
        f["fact_id"] for f in cold_selected if isinstance(f, dict) and "fact_id" in f
    )
    if len(cold_ids) < 2:
        raise ProductFailure(
            f"cold projection returned {len(cold_ids)} identified facts; at least two "
            "are needed to vary the working set"
        )
    warm = _project(guildhall, world.repo.path, working_set=cold_ids[:2])
    warm_selected = _list(warm, "selected")
    warm_ids = tuple(
        f["fact_id"] for f in warm_selected if isinstance(f, dict) and "fact_id" in f
    )
    O.check(
        "V-7.set-conditional",
        {
            "cold_selection": list(cold_ids),
            "selection_changed_with_working_set": warm_ids != cold_ids,
            "reselected_working_set_members": len(set(cold_ids[:2]) & set(warm_ids)),
        },
        label="cold versus warm working set",
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
    guildhall: Guildhall, ingested
) -> None:
    world, _, _anchors = ingested
    payload = _project(guildhall, world.repo.path)
    selected = _list(payload, "selected")
    roles = _roles(selected)
    trace = _list(payload, "selection_trace")
    first_id = None
    for step in trace:
        if isinstance(step, dict) and "fact_id" in step:
            first_id = step["fact_id"]
            break
    warm_gain = None
    if first_id is not None:
        warm = _project(guildhall, world.repo.path, working_set=(first_id,))
        for step in _list(warm, "selection_trace"):
            if isinstance(step, dict) and step.get("fact_id") == first_id:
                warm_gain = step.get("marginal_value")
    O.check(
        "V-7.no-crowding",
        {
            "invariant_selected": "high_distortion_compatibility_invariant" in roles,
            "selected_paraphrase_count": roles.count("high_scoring_paraphrase"),
            "warm_readd_marginal_value": warm_gain if warm_gain is not None else 1.0,
        },
        label="redundant paraphrases versus the distinct invariant",
    )


@spec_ref(
    ARCH(
        "V-7",
        "set-conditional-projector",
        "A deterministic greedy selector recalculates marginal value after each addition, honors hard "
        "byte/item/cost ceilings, and stops on sufficiency or nonpositive net gain.",
    ),
    ARCH("V-7", "set-conditional-projector", "The trace records the terms, not just a score."),
)
def test_marginal_value_is_recomputed_against_the_current_set(
    guildhall: Guildhall, ingested
) -> None:
    world, _, _anchors = ingested
    payload = _project(guildhall, world.repo.path)
    trace = payload.get("selection_trace")
    require_nonempty(
        trace if isinstance(trace, list) else [],
        obligation="V-7.marginal-terms",
        why="the projector must emit a selection trace over the ingested corpus",
        origin=Origin.PRODUCT,
    )
    O.check("V-7.marginal-terms", {"trace": trace}, label="greedy selection trace")


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
    guildhall: Guildhall, ingested
) -> None:
    world, _, _anchors = ingested
    payload = _project(guildhall, world.repo.path)
    selected = _list(payload, "selected")
    trace = _list(payload, "selection_trace")
    by_id = {
        s["fact_id"]: s for s in trace if isinstance(s, dict) and "fact_id" in s
    }
    complementary_ids = [
        f.get("fact_id")
        for f in selected
        if isinstance(f, dict)
        and f.get("logical_key") in {
            "scheduler/test/wire-format", "scheduler/rationale/wire-format"
        }
    ]
    complementary_steps = [
        _terms(by_id[i]) for i in complementary_ids if i in by_id
    ]
    penalised = [
        {
            "redundancy": _terms(s).get("redundancy"),
            "redundancy_basis": s.get("redundancy_basis"),
        }
        for s in trace
        if isinstance(s, dict)
        and isinstance(_terms(s).get("redundancy"), (int, float))
        and _terms(s).get("redundancy") > 0
    ]
    O.check(
        "V-7.complementarity",
        {
            "complementary_pair_selected": len(complementary_ids),
            "complementary_steps": complementary_steps,
            "penalised_steps": penalised,
        },
        label="complementary pair and redundancy penalty",
    )


@spec_ref(
    PRODUCT(
        "V-7",
        "P-7",
        "The retrieval loop escalates from constraint/Unknown through summary, exact span, history, "
        "tests/runtime trace, and broader search, stopping when estimated value of the next retrieval "
        "is no greater than its cost or when an explicit sufficiency predicate is met.",
    ),
    VERIFY(
        "V-7",
        "stop",
        "Escalate evidence tiers and assert the loop stops on net marginal value, not a filled token "
        "window.",
    ),
)
def test_loop_stops_on_net_marginal_value_not_a_filled_window(
    guildhall: Guildhall, ingested
) -> None:
    world, _, _anchors = ingested
    payload = _project(guildhall, world.repo.path)
    escalation = payload.get("tier_escalation")
    require_nonempty(
        escalation if isinstance(escalation, list) else [],
        obligation="V-7.voi-stop",
        why="the retrieval loop must record its tier escalation",
        origin=Origin.PRODUCT,
    )
    tiers = [
        s.get("tier") for s in escalation if isinstance(s, dict) and "tier" in s
    ]
    require_all(
        tiers,
        lambda t: t in EVIDENCE_TIERS,
        obligation="V-7.voi-stop",
        why="every escalated tier must come from the frozen ordered set",
        minimum=1,
    )
    used_bytes = payload.get("projection_bytes")
    selected = _list(payload, "selected")
    O.check(
        "V-7.voi-stop",
        {
            "tier_escalation": escalation,
            "tiers_in_frozen_order": tiers == sorted(tiers, key=EVIDENCE_TIERS.index),
            "stopping_reason": payload.get("stopping_reason"),
            "selected_fact_count": len(selected),
            "projection_bytes": used_bytes if used_bytes is not None else 0,
            "stopped_at_byte_ceiling": (
                isinstance(used_bytes, int)
                and used_bytes >= PROJECTION_BYTES * 0.95
                and payload.get("stopping_reason") != "sufficiency_predicate_met"
            ),
        },
        label="VOI stopping rule",
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
def test_query_log_records_every_declared_field(guildhall: Guildhall, ingested) -> None:
    world, _, _anchors = ingested
    _project(guildhall, world.repo.path)
    result = guildhall.run(
        "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path, check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`status` returned the reserved ambiguous exit 1")
    payload = result.json if result.stdout.strip() else {}
    if not isinstance(payload, dict):
        raise ProductFailure("`status --json` did not return an object")
    logs = payload.get("query_log") or payload.get("query_traces")
    require_nonempty(
        logs if isinstance(logs, list) else [],
        obligation="V-7.query-log",
        why="query logs are the future compiler specification and must be recorded",
        origin=Origin.PRODUCT,
    )
    O.check("V-7.query-log", {"query_log": logs}, label="projection query log")


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
    guildhall: Guildhall, ingested
) -> None:
    world, _, _anchors = ingested
    payload = _project(guildhall, world.repo.path)
    roles = _roles(_list(payload, "selected"))
    unknowns = _list(payload, "unknowns")
    require_nonempty(
        unknowns, obligation="V-7.stale-fact",
        why="the withheld stale fact and the planted high-distortion Unknown must "
            "produce owned Unknowns",
        origin=Origin.PRODUCT,
    )
    O.check(
        "V-7.stale-fact",
        {
            "stale_fact_selected": "stale_fact" in roles,
            "owned_unknown_count": len(unknowns),
            "owned_unknowns": [u for u in unknowns if isinstance(u, dict)],
        },
        label="the stale fact is withheld and opens an owned Unknown",
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
def test_no_calibrated_causal_voi_claim_is_made(guildhall: Guildhall, ingested) -> None:
    world, _, _anchors = ingested
    payload = _project(guildhall, world.repo.path)
    rendered = json.dumps(payload).lower()
    found = [f for f in FORBIDDEN_VOI_CLAIMS if f in rendered]
    approximation = _first(payload, "voi_approximation", "objective")
    O.check(
        "V-7.no-voi-claim",
        {
            "forbidden_claims_found": len(found),
            "voi_approximation": approximation,
            "scope_limited_to_selector_mechanics": True,
        },
        label="no calibrated causal VOI claim is made by this fixture",
    )
