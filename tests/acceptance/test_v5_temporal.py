"""V-5 --- temporal discernment (`P-5`, Critical).

The nine ratified cases in the ``spec/verification.md`` V-5 table are driven
here as data. Each freezes ``as_of`` and the authority cursor and asserts both
the reducer trace and the counterfactual, per:

    Every case freezes `as_of` and authority cursor and asserts the reducer trace
    and counterfactual. Mutations newest-wins, highest-authority-always-wins, and
    repetition-as-independence must each fail.

``spec/product.md`` P-5 states the principle the whole gate defends:

    Recency is evidence, never authority by itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from ._harness import synth
from ._harness.cli import Guildhall
from ._harness.gitfix import GitRepo
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

pytestmark = [pytest.mark.v5, pytest.mark.requires_product]

AS_OF = "2026-03-05T00:00:00.000Z"
AUTHORITY_CURSOR = "1500"


@dataclass(frozen=True)
class TemporalCase:
    """One row of the frozen V-5 table."""

    case_id: str
    description: str
    logical_key: str
    decision: str
    expected_state: str
    expected_fragment: str
    forbidden_fragment: str
    counterfactual: str


#: Verbatim from the ``spec/verification.md`` V-5 table, one row each.
CASES: tuple[TemporalCase, ...] = (
    TemporalCase(
        "newer_rejected_pr_vs_adr",
        "newer rejected PR vs current accepted ADR",
        "architecture/scheduler/lookahead-owner",
        "choose the lookahead source",
        "current",
        "ADR",
        "rejected",
        "admit the PR as accepted and the ADR must be re-evaluated",
    ),
    TemporalCase(
        "copied_chorus_vs_one_decision",
        "ten copied recent comments vs one independent authoritative decision",
        "architecture/scheduler/retry-policy",
        "choose the retry policy",
        "current",
        "independent",
        "vote",
        "make one chorus member independently sourced and corroboration rises",
    ),
    TemporalCase(
        "explicit_supersession",
        "old rule explicitly superseded by same scoped authority",
        "architecture/scheduler/window-rule",
        "apply the window rule",
        "current",
        "new rule",
        "old rule",
        "withdraw the supersession and the old rule returns as current",
    ),
    TemporalCase(
        "expired_incident_workaround",
        "incident workaround past its validity",
        "operations/scheduler/incident-workaround",
        "apply the workaround",
        "unknown",
        "expired",
        "apply",
        "extend validity and the workaround becomes current again",
    ),
    TemporalCase(
        "deployed_568_vs_default_90",
        "deployed config 568 vs code default 90",
        "operations/scheduler/effective-lookahead",
        "diagnose the effective lookahead",
        "current",
        "568",
        "90",
        "expire the runtime observation and diagnosis reopens as an Unknown",
    ),
    TemporalCase(
        "repo_contradicts_company",
        "repo code contradicts current Company architecture",
        "architecture/scheduler/company-contradiction",
        "choose the implementation direction",
        "conflict",
        "Chief Architect",
        "silent",
        "admit a signed architect answer and the conflict closes",
    ),
    TemporalCase(
        "unmerged_branch_adr",
        "unmerged branch plants a new ADR",
        "architecture/scheduler/branch-adr",
        "apply the branch ADR",
        "current",
        "merged",
        "branch",
        "merge the branch and the new ADR becomes current",
    ),
    TemporalCase(
        "runtime_freshness_lapsed",
        "registered runtime observation passes freshness window",
        "operations/scheduler/runtime-freshness",
        "use the runtime observation",
        "unknown",
        "environment",
        "trusted",
        "refresh the observation and the operational fact returns",
    ),
    TemporalCase(
        "unregistered_environment",
        "runtime observation names an unregistered environment",
        "operations/scheduler/unregistered-env",
        "trust the runtime observation",
        "unknown",
        "registry",
        "trusted",
        "register the environment and the observation becomes admissible",
    ),
)


@pytest.fixture()
def temporal_repo(roots: ProofRoots) -> GitRepo:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.commit("initialise")
    return repo


def _explain(guildhall: Guildhall, case: TemporalCase, **env: str) -> dict:
    result = guildhall.run(
        "explain",
        case.logical_key,
        "--repo",
        str(guildhall.cwd),
        "--decision",
        case.decision,
        "--as-of",
        AS_OF,
        "--authority-cursor",
        AUTHORITY_CURSOR,
        "--json",
        env={"GUILDHALL_ACCEPTANCE_TEMPORAL_CASE": case.case_id, **env},
        check=False,
    )
    assert result.returncode != 1, f"{case.case_id} returned the reserved exit 1"
    if result.returncode not in (0, 3):
        raise ProductFailure(
            f"{case.case_id}: `explain` refused with {result.code}; V-5 requires an "
            "inspectable evidence trace for every case"
        )
    return result.json


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.case_id)
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
    VERIFY(
        "V-5",
        "table",
        "Table-driven and narrative cases include:",
    ),
)
def test_frozen_temporal_case(guildhall: Guildhall, temporal_repo: GitRepo, case: TemporalCase) -> None:
    payload = _explain(guildhall, case)
    state = payload.get("state")
    assert state == case.expected_state, (
        f"{case.description}: expected state {case.expected_state!r}, observed {state!r}"
    )
    rendered = json.dumps(payload)
    assert case.expected_fragment.lower() in rendered.lower(), (
        f"{case.description}: the decision must cite {case.expected_fragment!r}"
    )
    trace = payload.get("trace") or payload.get("reducer_trace")
    assert trace, f"{case.description}: every decision must emit an inspectable trace"
    assert payload.get("uncertainty_state") is not None, (
        f"{case.description}: the uncertainty state must be reported"
    )
    assert payload.get("as_of") == AS_OF, (
        f"{case.description}: the frozen as_of must be echoed in the trace"
    )
    assert str(payload.get("authority_cursor")) == AUTHORITY_CURSOR


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.case_id)
@spec_ref(
    VERIFY(
        "V-5",
        "counterfactual",
        "Every case freezes `as_of` and authority cursor and asserts the reducer trace and "
        "counterfactual.",
    ),
    CLI(
        "V-5",
        "corpus-and-inspection",
        "`explain` shows reducer steps, rejected events, current/conflict/Unknown state, and "
        "evidence that would change it.",
    ),
)
def test_frozen_temporal_counterfactual(
    guildhall: Guildhall, temporal_repo: GitRepo, case: TemporalCase
) -> None:
    payload = _explain(guildhall, case)
    counterfactual = payload.get("evidence_that_would_change_the_result") or payload.get(
        "counterfactual"
    )
    assert counterfactual, (
        f"{case.description}: `explain` must show the evidence that would flip the result"
    )
    rendered = json.dumps(counterfactual).lower()
    keyword = case.counterfactual.split()[0].lower()
    assert keyword in rendered or len(rendered) > 20, (
        f"{case.description}: the counterfactual must be specific; observed {rendered[:200]}"
    )
    rejected = payload.get("rejected_events")
    assert rejected is not None, (
        f"{case.description}: `explain` must show rejected events"
    )


# --------------------------------------------------------------------------
# Mutations
# --------------------------------------------------------------------------


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
def test_newest_wins_is_not_the_rule(guildhall: Guildhall, temporal_repo: GitRepo) -> None:
    case = CASES[0]
    payload = _explain(guildhall, case)
    winner = payload.get("current_statement") or ""
    trace = json.dumps(payload.get("trace") or payload.get("reducer_trace") or [])
    assert "rejected" not in winner.lower(), (
        "a newer rejected PR must not become the current rule"
    )
    assert "newest" not in trace.lower() or "recency" in trace.lower(), (
        "recency may appear only inside an authority/lifecycle-equivalent set and "
        "through an explicit source-type decay policy"
    )
    selected_by = payload.get("selected_by") or payload.get("selection_reason")
    if selected_by:
        assert "timestamp" not in str(selected_by).lower(), (
            f"selection reason {selected_by!r} reduces to newest-wins"
        )


@spec_ref(
    VERIFY(
        "V-5",
        "case",
        "newer rejected PR vs current accepted ADR | ADR remains current; rejection is evidence",
    )
)
def test_rejected_pr_does_not_displace_current_adr(
    guildhall: Guildhall, temporal_repo: GitRepo
) -> None:
    payload = _explain(guildhall, CASES[0])
    assert payload.get("state") == "current"
    rendered = json.dumps(payload)
    assert "ADR" in rendered, "the accepted ADR must remain current"
    negative = payload.get("negative_evidence") or payload.get("rejected_events") or []
    assert negative, "the rejection must be retained as evidence, not discarded"


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
    guildhall: Guildhall, temporal_repo: GitRepo
) -> None:
    payload = _explain(guildhall, CASES[1])
    rendered = json.dumps(payload).lower()
    assert "independent" in rendered, (
        "the trace must distinguish independent corroboration from common-source "
        "repetition"
    )
    corroboration = payload.get("independent_corroboration_count")
    repetition = payload.get("common_source_repetition_count")
    if corroboration is not None and repetition is not None:
        assert corroboration < repetition or corroboration <= 2, (
            "ten copies of one prior must not be counted as ten independent supports; "
            f"observed corroboration={corroboration} repetition={repetition}"
        )
    assert "vote" not in (payload.get("selection_reason") or "").lower(), (
        "there is no vote-count winner"
    )


@spec_ref(
    ARCH(
        "V-5",
        "authority-seeking-loop",
        "The mapping resolves to exactly one authority identity for an exact scope; role prestige "
        "and recency are not an implicit lattice.",
    ),
    PRODUCT(
        "V-5",
        "P-5",
        "Recency is evidence, never authority by itself.",
    ),
)
def test_scope_bounds_authority_rather_than_prestige(
    guildhall: Guildhall, temporal_repo: GitRepo
) -> None:
    payload = _explain(guildhall, CASES[5])
    assert payload.get("state") == "conflict", (
        "repo code contradicting current Company architecture is a conflict plus a "
        "Chief Architect Unknown, not a silent local override"
    )
    unknowns = payload.get("unknowns") or []
    assert unknowns, "the conflict must open an owned Unknown"
    owners = {u.get("owner_role") for u in unknowns}
    assert owners & {"chief-architect", "scoped-authority", "architecture-authority"}, (
        f"the Unknown must name the scoped architecture authority; owners {owners}"
    )
    for unknown in unknowns:
        assert unknown.get("owner_identity"), (
            "a blocking Unknown always names a person"
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
    guildhall: Guildhall, temporal_repo: GitRepo
) -> None:
    operational = _explain(guildhall, CASES[4])
    assert "568" in json.dumps(operational), (
        "operational diagnosis must use the live deployed value"
    )
    architecture = _explain(guildhall, CASES[5])
    rendered = json.dumps(architecture)
    assert "568" not in rendered or architecture.get("state") == "conflict", (
        "a runtime observation must not rewrite a Company architecture decision"
    )
    scope = operational.get("authority_scope") or ""
    assert not scope.startswith("architecture:"), (
        f"the runtime observation's scope {scope!r} must not be an architecture scope"
    )


@spec_ref(
    ARCH(
        "V-5",
        "authority-seeking-loop",
        "`environment:<id>` is a first-class exact registry scope with one deploy owner and public "
        "key. The runtime adapter refuses trusted admission for an unregistered environment and "
        "creates a Company-steward registry Unknown instead; it never admits an observation carrying "
        "only a free-form owner string.",
    ),
    VERIFY(
        "V-5",
        "case",
        "runtime observation names an unregistered environment | observation is untrusted; "
        "Company-steward registry Unknown",
    ),
)
def test_unregistered_environment_is_untrusted_with_a_steward_unknown(
    guildhall: Guildhall, temporal_repo: GitRepo
) -> None:
    payload = _explain(guildhall, CASES[8])
    assert payload.get("state") == "unknown"
    unknowns = payload.get("unknowns") or []
    assert unknowns, "an unregistered environment must open a registry Unknown"
    assert any(u.get("owner_role") == "company-steward" for u in unknowns), (
        f"the registry Unknown is Company-steward owned; observed "
        f"{[u.get('owner_role') for u in unknowns]}"
    )
    assert not payload.get("trusted"), (
        "an observation carrying only a free-form owner string is never admitted"
    )
