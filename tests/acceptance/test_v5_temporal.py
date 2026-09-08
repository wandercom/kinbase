"""V-5 --- temporal discernment (`P-5`, Critical).

Detector Reviewer finding 12: every V-5 assertion was selected by
a case-identity environment selector over an empty repository. Holding raw
state fixed and changing only the case identifier changed the asserted state,
fragment and counterfactual, so the gate measured nothing.

The rewrite removes the selector entirely. Each of the nine ratified rows is
established by *planted signed event history*: authority, scope, disposition,
explicit validity, supersession parentage and branch reachability are written
into real content-addressed events, and the reducer must reach the ratified
answer from those alone. The product never learns which row it is looking at.

``spec/product.md`` P-5 states the principle the gate defends:

    Recency is evidence, never authority by itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import obligations as O
from ._harness import trust
from ._harness.cli import Guildhall
from ._harness.evidence_model import (
    Origin,
    require_all,
    require_nonempty,
)
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    SRC,
    VERIFY,
    HarnessInvalid,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.worldbuilder import (
    TEMPORAL_CASES,
    SignedWorld,
    plant_temporal_history,
    temporal_extra_authorities,
)

pytestmark = [pytest.mark.v5, pytest.mark.requires_product]

AS_OF = "2026-03-05T00:00:00.000Z"
AUTHORITY_CURSOR = "1500"


def _world(roots: ProofRoots, guildhall: Guildhall) -> tuple[SignedWorld, trust.TrustAnchors]:
    """A certified world with every trust anchor in place (Validator ruling C3).

    The ``environment:prod-eu`` deploy owner is published through the registry
    so rows 5 and 8 range over a *registered* runtime signer; the
    ``environment:staging-xx`` signer of row 9 is deliberately absent.
    """
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(
        guildhall, roots, world, extra_authorities=temporal_extra_authorities(),
    )
    return world, anchors


def _explain(guildhall: Guildhall, repo: Path, logical_key: str, decision: str) -> dict:
    """Ask the product to explain one logical key.

    The invocation carries only the logical key, the decision text, the frozen
    ``as_of`` and the authority cursor. No case identity, expected state or
    scenario string is passed.
    """
    result = guildhall.run(
        "explain", logical_key,
        "--repo", str(repo),
        "--decision", decision,
        "--as-of", AS_OF,
        "--authority-cursor", AUTHORITY_CURSOR,
        "--json",
        cwd=repo,
        check=False,
    )
    if result.returncode == 1:
        raise ProductFailure(
            f"`explain {logical_key}` returned the reserved ambiguous exit 1"
        )
    if result.returncode not in (0, 3):
        raise ProductFailure(
            f"`explain {logical_key}` refused with {result.code}; V-5 requires an "
            "inspectable evidence trace for every planted history"
        )
    payload = result.json
    if not isinstance(payload, dict):
        raise ProductFailure(f"`explain` returned {type(payload).__name__}, not an object")
    return payload


def _ingest_planted(guildhall: Guildhall, world: SignedWorld) -> None:
    """Admit the planted events through the ordinary shipping surface."""
    result = guildhall.run(
        "ingest", "kindex", str(world.repo.path / ".kin"),
        "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path, check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`ingest kindex` returned the reserved ambiguous exit 1")


@pytest.fixture()
def planted_world(roots: ProofRoots, guildhall: Guildhall):
    """All nine histories planted into one repository, verified before use."""
    world, anchors = _world(roots, guildhall)
    per_case: dict[str, list[dict]] = {}
    for case in TEMPORAL_CASES:
        per_case[case.case_id] = plant_temporal_history(world, case)
    world.verify_planted()
    if len(world.planted) < 2 * len(TEMPORAL_CASES):
        raise HarnessInvalid(
            f"only {len(world.planted)} events were planted for "
            f"{len(TEMPORAL_CASES)} cases; each case needs a real history"
        )
    _ingest_planted(guildhall, world)
    return world, per_case



def _text(payload: dict, *keys: str) -> str:
    """First present string among ``keys``, lowercased; empty when none exist.

    Emptiness is preserved for the catalogue clause, which refuses it. The
    normalisation lives here rather than in a test so no gate body carries a
    fallback that could satisfy an assertion on its own.
    """
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value.lower()
    return ""


def _list(payload: dict, *keys: str) -> list:
    """First nonempty evidence list among public aliases; empty if all are empty."""
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list) and value:
            return value
    return []

@spec_ref(
    SRC(
        "V-5",
        "SRC-7",
        "be tested for appropriate recency bias, discernment and discrimination between temporary "
        "or ill-conceived shifts",
    ),
    PRODUCT(
        "V-5",
        "P-5",
        "Expected results must demonstrate neither newest-wins nor oldest/highest-authority-wins "
        "blindly. Every decision emits an inspectable evidence trace and uncertainty state.",
    ),
    VERIFY("V-5", "table", "Table-driven and narrative cases include:"),
    CLI(
        "V-5",
        "corpus-and-inspection",
        "`explain` shows reducer steps, rejected events, current/conflict/Unknown state, and "
        "evidence that would change it.",
    ),
)
def test_frozen_temporal_case(guildhall: Guildhall, planted_world) -> None:
    """All nine rows, decided from planted history, checked in one total pass.

    The obligation is quantified over every case; a single case that cannot be
    decided from its own history fails the gate. There is no per-case early
    return, so an undecidable case cannot pass by producing nothing.
    """
    world, per_case = planted_world
    cases: list[dict] = []
    for case in TEMPORAL_CASES:
        payload = _explain(guildhall, world.repo.path, case.logical_key, case.decision)
        rendered = json.dumps(payload).lower()
        trace = payload.get("trace") or payload.get("reducer_trace")
        counterfactual = payload.get("evidence_that_would_change_the_result") or (
            payload.get("counterfactual")
        )
        cases.append({
            "case_id": case.case_id,
            "planted_event_count": len(per_case[case.case_id]),
            "observed_state": payload.get("state"),
            "expected_state": case.expected_state,
            "state_matches": payload.get("state") == case.expected_state,
            "trace": trace if isinstance(trace, list) else ([trace] if trace else []),
            "uncertainty_state": payload.get("uncertainty_state"),
            "counterfactual": (
                counterfactual if isinstance(counterfactual, list)
                else ([counterfactual] if counterfactual else [])
            ),
            "rejected_events": payload.get("rejected_events"),
            "case_identity_disclosed": case.case_id in rendered,
            "expected_fragment_present": case.expected_fragment.lower() in rendered,
        })

    O.check("V-5.cases", {"cases": cases}, label="nine frozen temporal rows")

    # The fragment check is a second, independent reading of the same evidence:
    # the correct state must be reached *for the ratified reason*, not by luck.
    require_all(
        cases,
        lambda c: c["expected_fragment_present"],
        obligation="V-5.cases",
        why="each decision must cite the evidence the ratified row names",
        minimum=len(TEMPORAL_CASES),
    )


@spec_ref(
    ARCH(
        "V-5",
        "reduction-algorithm",
        "A recent rejected/reverted proposal is negative evidence, not a current rule.",
    ),
    VERIFY(
        "V-5",
        "mutation",
        "Mutations newest-wins, highest-authority-always-wins, and repetition-as-independence must "
        "each fail.",
    ),
)
def test_newest_wins_is_not_the_rule(guildhall: Guildhall, planted_world) -> None:
    world, _ = planted_world
    case = TEMPORAL_CASES[0]
    payload = _explain(guildhall, world.repo.path, case.logical_key, case.decision)
    selection_reason = _text(payload, "selection_reason", "selected_by")
    negative = _list(payload, "negative_evidence", "rejected_events")
    O.check(
        "V-5.no-newest-wins",
        {
            "newest_wins": "rejected" in str(payload.get("current_statement")).lower(),
            "selection_reason_is_timestamp": (
                "timestamp" in selection_reason or "newest" in selection_reason
            ),
            "negative_evidence": list(negative),
        },
        label="newer rejected PR versus current accepted ADR",
    )


@spec_ref(
    VERIFY(
        "V-5",
        "case",
        "newer rejected PR vs current accepted ADR | ADR remains current; rejection is evidence",
    )
)
def test_rejected_pr_does_not_displace_current_adr(
    guildhall: Guildhall, planted_world
) -> None:
    world, per_case = planted_world
    case = TEMPORAL_CASES[0]
    payload = _explain(guildhall, world.repo.path, case.logical_key, case.decision)
    rejected = _list(payload, "rejected_events", "negative_evidence")
    require_nonempty(
        rejected, obligation="V-5.rejected-pr",
        why="the rejection must be retained as evidence, not discarded",
        origin=Origin.PRODUCT,
    )
    current = str(_text(payload, "current_statement"))
    O.check(
        "V-5.rejected-pr",
        {
            "state": payload.get("state"),
            "rejection_recorded_as_evidence": len(rejected) > 0,
            "rejection_promoted": "reject" in current,
            "reducer_trace": _list(payload, "reducer_trace", "selection_trace"),
        },
        label="a newer rejected PR does not displace the current ADR",
    )


@spec_ref(
    VERIFY(
        "V-5",
        "case",
        "ten copied recent comments vs one independent authoritative decision | copied chorus adds "
        "little; no vote-count winner",
    ),
    ARCH(
        "V-5",
        "reduction-algorithm",
        "distinguish independent corroboration from common-source repetition;",
    ),
)
def test_copied_chorus_does_not_outweigh_one_independent_decision(
    guildhall: Guildhall, planted_world
) -> None:
    world, per_case = planted_world
    case = TEMPORAL_CASES[1]
    payload = _explain(guildhall, world.repo.path, case.logical_key, case.decision)
    reason = _text(payload, "selection_reason")
    O.check(
        "V-5.independence",
        {
            "repetition_count": 10,
            "independent_source_count": 1,
            "independent_corroboration_count": payload.get(
                "independent_corroboration_count"
            ),
            "vote_count_winner": "vote" in reason or "count" in reason,
        },
        label="ten copies of one prior versus one independent decision",
    )


@spec_ref(
    ARCH(
        "V-5",
        "authority-seeking-loop",
        "The mapping resolves to exactly one authority identity for an exact scope; role prestige "
        "and recency are not an implicit lattice.",
    ),
    PRODUCT("V-5", "P-5", "Recency is evidence, never authority by itself."),
)
def test_scope_bounds_authority_rather_than_prestige(
    guildhall: Guildhall, planted_world
) -> None:
    world, _ = planted_world
    case = TEMPORAL_CASES[5]
    payload = _explain(guildhall, world.repo.path, case.logical_key, case.decision)
    unknowns = payload.get("unknowns")
    O.check(
        "V-5.scope",
        {
            "state": payload.get("state"),
            "unknowns": unknowns if isinstance(unknowns, list) else [],
            "silent_local_override": payload.get("state") == "current"
            and "locally" in json.dumps(payload).lower(),
        },
        label="repository code contradicting current Company architecture",
    )


@spec_ref(
    VERIFY(
        "V-5",
        "case",
        "deployed config 568 vs code default 90 | operational diagnosis uses live 568; "
        "architecture authority unchanged",
    ),
    ARCH(
        "V-5",
        "reduction-algorithm",
        "Live runtime configuration may defeat a code-default diagnosis for an operational question "
        "without acquiring authority to rewrite a Company architecture decision.",
    ),
)
def test_runtime_config_wins_diagnosis_without_acquiring_architecture_authority(
    guildhall: Guildhall, planted_world
) -> None:
    world, _ = planted_world
    operational = _explain(
        guildhall, world.repo.path, TEMPORAL_CASES[4].logical_key,
        TEMPORAL_CASES[4].decision,
    )
    architecture = _explain(
        guildhall, world.repo.path, TEMPORAL_CASES[5].logical_key,
        TEMPORAL_CASES[5].decision,
    )
    rendered_ops = json.dumps(operational)
    scope = _text(operational, "authority_scope")
    O.check(
        "V-5.runtime-vs-architecture",
        {
            "operational_value": "568" if "568" in rendered_ops else "absent",
            "architecture_rewritten": "568" in json.dumps(architecture),
            "scope_is_architecture": scope.startswith("architecture:"),
            "environment_owner": operational.get("environment_owner")
            or operational.get("owner_identity"),
        },
        label="deployed 568 versus source default 90",
    )


@spec_ref(
    ARCH(
        "V-5",
        "authority-seeking-loop",
        "The runtime adapter refuses trusted admission for an unregistered environment and creates a "
        "Company-steward registry Unknown instead; it never admits an observation carrying only a "
        "free-form owner string.",
    ),
    VERIFY(
        "V-5",
        "case",
        "runtime observation names an unregistered environment | observation is untrusted; "
        "Company-steward registry Unknown",
    ),
)
def test_unregistered_environment_is_untrusted_with_a_steward_unknown(
    guildhall: Guildhall, planted_world
) -> None:
    world, _ = planted_world
    case = TEMPORAL_CASES[8]
    payload = _explain(guildhall, world.repo.path, case.logical_key, case.decision)
    unknowns = payload.get("unknowns")
    unknowns = unknowns if isinstance(unknowns, list) else []
    O.check(
        "V-5.unregistered-environment",
        {
            "state": payload.get("state"),
            "unknowns": unknowns,
            "unknown_owner_roles": [u.get("owner_role") for u in unknowns
                                    if isinstance(u, dict)],
            "free_form_owner_admitted": bool(payload.get("trusted")),
        },
        label="runtime observation naming an unregistered environment",
    )
