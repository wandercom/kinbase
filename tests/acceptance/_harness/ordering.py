"""V-10 phase-ordering ledger and denial checks.

The Tester dispatch forbids authoring or exposing the final V-10 task corpus:
under the ratified protocol that corpus is built only after V-1 through V-9 pass
and the reducer freezes, by a separate schema-blind Corpus Builder, before task
exposure. This module is the *harness and denial checks that enforce that
ordering*, which the dispatch does require.

The frozen order, from ``spec/product.md`` P-10 and ``spec/verification.md``
V-10 "Task freeze":

    Only after V-1 through V-9 pass and the adapter/reducer digest freezes, but
    before the Oracle Curator receives issues, accepted changes, hidden tests, or
    eligibility/load-bearing labels, the isolated Corpus Builder runs the frozen
    adapters/reducer for every candidate parent revision in the complete
    date-bounded census and seals a content-addressed Company/Codebase snapshot
    map. It also freezes the one repository-agnostic static-prior document (at
    most 2 KiB).

and:

    A pre-task reducer repair discards and rebuilds every census-parent snapshot;
    a repair after Builder task exposure invalidates the run and requires a fresh
    blind Builder, never a drawn-task-only reseal.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

from .requirements import ProductFailure

#: ``spec/product.md`` P-10: "one task-independent, repository-agnostic
#: conventions document of at most 2 KiB".
STATIC_PRIOR_MAX_BYTES = 2048

#: The eleven arms, verbatim from ``spec/product.md`` P-10.
ARMS: tuple[str, ...] = (
    "baseline",
    "null-system",
    "static-prior",
    "distractor",
    "topk-raw",
    "topk-maintained",
    "authority-only",
    "codebase-only",
    "company-only",
    "full-system",
    "oracle-spec",
)

#: ``spec/architecture.md`` section 10 composite weights. They must sum to 1.00
#: and no arm-specific weighting is allowed.
COMPOSITE_WEIGHTS: dict[str, float] = {
    "held_out_functional_behavior": 0.50,
    "architecture_invariant_conformance": 0.20,
    "internal_api_reuse_and_absence_of_duplication": 0.10,
    "false_completion_verification_behavior": 0.10,
    "efficiency_and_constraint_residency": 0.10,
}


class Phase(Enum):
    """Ordered V-10 protocol phases. Lower value strictly precedes higher."""

    GATES_V1_V9 = 10
    ADAPTER_REDUCER_FREEZE = 20
    CORPUS_BUILDER_SEAL = 30
    STATIC_PRIOR_FREEZE = 31
    CURATOR_CENSUS = 40
    CURATOR_ELIGIBILITY_INPUTS = 41
    ORACLE_SPEC_SEAL = 45
    PUBLIC_SEED_DRAW = 50
    PILOT_EXECUTION = 55
    BUDGET_RATIFICATION = 56
    CALIBRATION_FREEZE = 60
    POWER_FREEZE = 62
    MANIFEST_FREEZE = 65
    MEASUREMENT_LAUNCH = 70
    SCORING = 80
    ARM_GUESS_SEAL = 85
    INTEGRITY_AUDIT_SEAL = 88
    UNBLINDING = 90
    VERDICT = 95


#: Knowledge the Corpus Builder must not have when it seals snapshots.
#: ``spec/verification.md`` "Role separation": the Builder "seals every historical
#: Company/Codebase snapshot and the generic static prior before seeing issues,
#: accepted patches, hidden tests, eligibility labels, seeds, arms, or scores."
BUILDER_FORBIDDEN_INPUTS: tuple[str, ...] = (
    "issues",
    "accepted_patches",
    "hidden_tests",
    "eligibility_labels",
    "load_bearing_labels",
    "seeds",
    "arms",
    "scores",
)

#: Knowledge the Oracle Curator must not have.
#: ``spec/product.md`` P-10: "The Oracle Curator receives a date-bounded census of
#: every merged change in the two declared repositories and no Kinbase schema,
#: retrieval design, candidate, or arm output."
CURATOR_FORBIDDEN_INPUTS: tuple[str, ...] = (
    "kinbase_schema",
    "retrieval_design",
    "candidates",
    "arm_outputs",
    "scores",
)

#: Published exclusion reason code the census must be able to emit.
SINGLE_ARTIFACT_SPEC = "SINGLE_ARTIFACT_SPEC"

#: Terminal diagnostics that must never be converted into a smaller proof.
UNFUNDED_OR_UNDERPOWERED = "UNFUNDED_OR_UNDERPOWERED"


class OrderingViolation(ProductFailure):
    """A V-10 phase happened out of the ratified order."""


@dataclass
class LedgerEntry:
    phase: Phase
    label: str
    payload_digest: str
    sequence: int


@dataclass
class PhaseLedger:
    """Append-only ordering ledger with a monotonic phase invariant.

    ``spec/verification.md`` V-10 "Execution": "Every launch or score against a
    ratified measurement task appends a signed census record first and consumes
    that scheduled seed. 'Smoke' and 'debug' are not exemptions."
    """

    entries: list[LedgerEntry] = field(default_factory=list)
    builder_task_exposed: bool = False

    def record(self, phase: Phase, label: str, payload: object = None) -> LedgerEntry:
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        if self.entries and phase.value < self.entries[-1].phase.value:
            raise OrderingViolation(
                f"phase {phase.name} recorded after {self.entries[-1].phase.name}; "
                "the V-10 protocol order is strict"
            )
        entry = LedgerEntry(
            phase=phase,
            label=label,
            payload_digest=digest,
            sequence=len(self.entries),
        )
        self.entries.append(entry)
        return entry

    def reached(self, phase: Phase) -> bool:
        return any(e.phase is phase for e in self.entries)

    def index_of(self, phase: Phase) -> int:
        for entry in self.entries:
            if entry.phase is phase:
                return entry.sequence
        raise OrderingViolation(f"phase {phase.name} never happened")

    def assert_before(self, earlier: Phase, later: Phase) -> None:
        if self.index_of(earlier) >= self.index_of(later):
            raise OrderingViolation(
                f"{earlier.name} must strictly precede {later.name}"
            )

    def assert_corpus_ordering(self) -> None:
        """Assert the complete frozen ordering chain."""
        self.assert_before(Phase.GATES_V1_V9, Phase.ADAPTER_REDUCER_FREEZE)
        self.assert_before(Phase.ADAPTER_REDUCER_FREEZE, Phase.CORPUS_BUILDER_SEAL)
        self.assert_before(Phase.CORPUS_BUILDER_SEAL, Phase.STATIC_PRIOR_FREEZE)
        self.assert_before(Phase.STATIC_PRIOR_FREEZE, Phase.CURATOR_ELIGIBILITY_INPUTS)
        self.assert_before(Phase.CURATOR_ELIGIBILITY_INPUTS, Phase.PUBLIC_SEED_DRAW)
        self.assert_before(Phase.PUBLIC_SEED_DRAW, Phase.MANIFEST_FREEZE)
        self.assert_before(Phase.MANIFEST_FREEZE, Phase.MEASUREMENT_LAUNCH)
        self.assert_before(Phase.MEASUREMENT_LAUNCH, Phase.SCORING)
        self.assert_before(Phase.SCORING, Phase.ARM_GUESS_SEAL)
        self.assert_before(Phase.ARM_GUESS_SEAL, Phase.INTEGRITY_AUDIT_SEAL)
        self.assert_before(Phase.INTEGRITY_AUDIT_SEAL, Phase.UNBLINDING)


@dataclass
class ReducerRepair:
    """Outcome of an adapter/reducer repair, per the frozen recovery rule."""

    before_task_exposure: bool

    @property
    def action(self) -> str:
        if self.before_task_exposure:
            return "DISCARD_AND_REBUILD_EVERY_CENSUS_PARENT_SNAPSHOT"
        return "INVALID_RUN_REQUIRES_FRESH_BLIND_BUILDER"

    @property
    def permits_drawn_task_only_reseal(self) -> bool:
        """Never.

        ``spec/verification.md`` V-10: "a repair after Builder task exposure
        invalidates the run and requires a fresh blind Builder, never a
        drawn-task-only reseal."
        """
        return False


def assert_builder_blind(inputs: Iterable[str]) -> None:
    leaked = sorted(set(inputs) & set(BUILDER_FORBIDDEN_INPUTS))
    if leaked:
        raise OrderingViolation(
            "the schema-blind Corpus Builder received forbidden task knowledge: "
            f"{leaked}"
        )


def assert_curator_blind(inputs: Iterable[str]) -> None:
    leaked = sorted(set(inputs) & set(CURATOR_FORBIDDEN_INPUTS))
    if leaked:
        raise OrderingViolation(
            f"the schema-blind Oracle Curator received forbidden inputs: {leaked}"
        )


@dataclass
class StratificationPlan:
    """The frozen source-lineage stratification for the seeded draw.

    ``spec/verification.md`` V-10: "at least one third of selected tasks require a
    Company fact unavailable in Codebase, at least one third require a Codebase
    fact unavailable in Company, and at least one task requires complementary
    facts from both. At least one third also form an authorization-restricted
    stratum."
    """

    total: int
    company_unique: int
    codebase_unique: int
    complementary: int
    authorization_restricted: int

    def violations(self) -> list[str]:
        problems: list[str] = []
        third = self.total / 3.0
        if self.company_unique < third:
            problems.append("company_unique stratum below one third")
        if self.codebase_unique < third:
            problems.append("codebase_unique stratum below one third")
        if self.complementary < 1:
            problems.append("no task requires complementary facts from both stores")
        if self.authorization_restricted < third:
            problems.append("authorization-restricted stratum below one third")
        return problems


@dataclass
class DenialStratum:
    """Authorization-restricted stratum density bounds.

    ``spec/product.md`` P-10: "20-40% of otherwise eligible Company facts are
    denied by count and byte volume, and at least one load-bearing fact is
    initially denied but resolvable only by that task's frozen scoped-authority
    answer path."
    """

    denied_fact_fraction: float
    denied_byte_fraction: float
    load_bearing_initially_denied: bool
    resolvable_only_via_scoped_authority: bool

    def violations(self) -> list[str]:
        problems: list[str] = []
        if not 0.20 <= self.denied_fact_fraction <= 0.40:
            problems.append(
                f"denied fact fraction {self.denied_fact_fraction} outside 20-40%"
            )
        if not 0.20 <= self.denied_byte_fraction <= 0.40:
            problems.append(
                f"denied byte fraction {self.denied_byte_fraction} outside 20-40%"
            )
        if not self.load_bearing_initially_denied:
            problems.append("no load-bearing fact is initially denied")
        if not self.resolvable_only_via_scoped_authority:
            problems.append(
                "the denied load-bearing fact is resolvable outside the frozen "
                "scoped-authority path"
            )
        return problems


#: Arm-difference table. ``spec/verification.md`` V-10: "Each arm difference is
#: enumerated. Any unbound difference or runtime drift is ``INVALID_RUN``."
ARM_DIFFERENCES: dict[str, dict[str, object]] = {
    "baseline": {
        "corpus": "none",
        "projector": False,
        "authority_service": "none",
        "static_prior": False,
    },
    "null-system": {
        "corpus": "empty",
        "projector": True,
        "authority_service": "typed_empty",
        "static_prior": False,
        "full_host_path": True,
    },
    "static-prior": {
        "corpus": "none",
        "projector": False,
        "authority_service": "none",
        "static_prior": True,
    },
    "distractor": {
        "corpus": "token_matched_irrelevant_same_repository",
        "projector": False,
        "authority_service": "none",
        "static_prior": False,
    },
    "topk-raw": {
        "corpus": "raw_repo_search_chunks",
        "projector": False,
        "authority_service": "none",
        "static_prior": False,
    },
    "topk-maintained": {
        "corpus": "maintained",
        "projector": "scalar_similarity_only",
        "authority_service": "none",
        "static_prior": False,
    },
    "authority-only": {
        "corpus": "none",
        "projector": False,
        "authority_service": "frozen_required_one_or_two_calls",
        "static_prior": False,
    },
    "codebase-only": {
        "corpus": "codebase_only",
        "projector": True,
        "authority_service": "withheld",
        "static_prior": False,
        "company_references": False,
    },
    "company-only": {
        "corpus": "company_only",
        "projector": True,
        "authority_service": "frozen",
        "static_prior": False,
    },
    "full-system": {
        "corpus": "maintained",
        "projector": True,
        "authority_service": "frozen_max_two_calls",
        "static_prior": False,
    },
    "oracle-spec": {
        "corpus": "preregistered_load_bearing_pre_change_facts",
        "projector": False,
        "authority_service": "none",
        "static_prior": False,
    },
}


def unbound_arm_differences(manifest_fields: Sequence[str]) -> list[str]:
    """Fields an arm can differ on that the manifest fails to bind."""
    required = {
        "coding_model_artifact_or_snapshot",
        "decoding_settings",
        "system_prompt",
        "tool_schema_and_permissions",
        "policy_bundle",
        "host_adapter",
        "retriever",
        "index_and_corpus_snapshot",
        "task_repository_inputs",
        "worktree_revision",
        "as_of",
        "authority_cursor",
        "authority_service",
        "authority_replies",
        "task_principal_and_scopes",
        "denial_density",
        "budgets",
        "seeds",
        "blinding",
        "aggregation_and_scoring",
        "grader_model_fingerprints",
        "grader_decoding_settings",
        "grader_system_rubric_prompt",
        "grader_parser",
        "grader_calibration_set_digest",
        "grader_packet_schema",
        "gold_annotator_identities_and_receipts",
        "adjudicated_gold_digest",
        "authority_artifact_digests",
        "threat_and_attack_catalog_digests",
        "auxiliary_corpus_digest",
        "canary_registry_ciphertext_metadata",
    }
    return sorted(required - set(manifest_fields))
