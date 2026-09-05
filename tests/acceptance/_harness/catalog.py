"""The total, machine-readable per-obligation acceptance catalog.

``spec/verification.md`` "Instrument validity":

    Every V-1 through V-9 gate freezes its threshold, positive control, negative
    control, and detector mutation in the preregistered acceptance catalog before
    implementation is combined.

The Detector Reviewer found that V-1, V-2 and V-4 through V-9 froze none of the
four, and that the only catalog present listed prose mutations with no executable
planter. This module is the replacement: every obligation declares its clauses
once, and :mod:`acceptance._harness.clauses` derives the threshold, positive
control, negative control, product mutation and detector mutation from that one
declaration, so none of the four can drift away from the others.

Each obligation also names:

* the ratified artifact and a verbatim requirement quote, validated against the
  ratified bytes by ``test_catalog_completeness.py``;
* the surfaces and vectors the obligation ranges over;
* the fail-closed classification, so an unmet obligation lands in the right
  channel rather than defaulting to a product accusation;
* the product-facing test nodes that consume the same checker, so the executable
  kill ledger and the gate suite cannot diverge.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .clauses import (
    ClauseSet,
    absent,
    at_least,
    at_most,
    clauses,
    covers,
    distinct,
    equals,
    every,
    is_false,
    is_true,
    member,
    nonempty,
    present,
)
from .requirements import HarnessInvalid

#: Fail-closed channel for an unmet obligation.
PRODUCT = "PRODUCT_FAILURE"
INSTRUMENT = "INVALID_HARNESS"


@dataclass(frozen=True)
class Obligation:
    """One ratified obligation with all four frozen elements derived."""

    oid: str
    gate: str
    title: str
    artifact: str
    anchor: str
    requirement: str
    clause_set: ClauseSet
    surfaces: tuple[str, ...]
    vectors: tuple[str, ...]
    fail_closed: str
    nodes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.fail_closed not in (PRODUCT, INSTRUMENT):
            raise HarnessInvalid(f"{self.oid}: bad fail_closed {self.fail_closed!r}")
        for name, value in (
            ("surfaces", self.surfaces),
            ("vectors", self.vectors),
            ("nodes", self.nodes),
        ):
            if not value:
                raise HarnessInvalid(f"{self.oid}: {name} must be non-empty")
            # Detector Reviewer finding 5: `vectors=("...")` without a trailing
            # comma is a string, and `tuple()` of it silently becomes one entry
            # per character. Every element must be a non-trivial string.
            for element in value:
                if not isinstance(element, str) or len(element) < 2:
                    raise HarnessInvalid(
                        f"{self.oid}: {name} element {element!r} is malformed; a "
                        "missing trailing comma turns a string into characters"
                    )
        if not self.requirement.strip():
            raise HarnessInvalid(f"{self.oid}: requirement quote is empty")

    # -- the four frozen elements, derived ---------------------------------

    @property
    def thresholds(self) -> tuple[str, ...]:
        return self.clause_set.tags()

    def positive_control(self, tag: str) -> str:
        return f"{self.oid}#pc:{tag}"

    def negative_control(self, tag: str) -> str:
        return f"{self.oid}#nc:{tag}"

    def product_mutation(self, tag: str) -> str:
        return f"{self.oid}#pm:{tag}"

    def detector_mutation(self, tag: str) -> str:
        return f"{self.oid}#dm:{tag}"

    def as_json(self) -> dict:
        return {
            "oid": self.oid,
            "gate": self.gate,
            "title": self.title,
            "artifact": self.artifact,
            "anchor": self.anchor,
            "requirement": self.requirement,
            "surfaces": list(self.surfaces),
            "vectors": list(self.vectors),
            "fail_closed": self.fail_closed,
            "nodes": list(self.nodes),
            "thresholds": [
                {
                    "tag": c.tag,
                    "kind": c.kind,
                    "path": c.path,
                    "bound": c.value if not isinstance(c.value, tuple) else list(c.value),
                    "min_len": c.min_len,
                    "why": c.why,
                    "positive_control": self.positive_control(c.tag),
                    "negative_control": self.negative_control(c.tag),
                    "product_mutation": self.product_mutation(c.tag),
                    "detector_mutation": self.detector_mutation(c.tag),
                }
                for c in self.clause_set.clauses
            ],
        }


_OBLIGATIONS: list[Obligation] = []


def _o(
    oid: str,
    gate: str,
    title: str,
    artifact: str,
    anchor: str,
    requirement: str,
    clause_set: ClauseSet,
    surfaces: Sequence[str],
    vectors: Sequence[str],
    nodes: Sequence[str],
    fail_closed: str = PRODUCT,
) -> Obligation:
    obligation = Obligation(
        oid=oid,
        gate=gate,
        title=title,
        artifact=artifact,
        anchor=anchor,
        requirement=requirement,
        clause_set=clause_set,
        surfaces=tuple(surfaces),
        vectors=tuple(vectors),
        fail_closed=fail_closed,
        nodes=tuple(nodes),
    )
    _OBLIGATIONS.append(obligation)
    return obligation


V = "spec/verification.md"
P = "spec/product.md"
A = "spec/architecture.md"
T = "spec/threat-model.md"
L = "spec/cli.md"

ADAPTERS = (
    "codex_jsonl", "claude_jsonl", "repo_code", "repo_tests", "git_history",
    "docs_adr", "github_export", "runtime_evidence", "kindex", "authority_answer",
)

# ==========================================================================
# V-1 — real heterogeneous corpus
# ==========================================================================

_o(
    "V-1.adapters-native", "V-1", "all ten adapters run against native formats",
    V, "acceptance-map",
    "Run all ten adapters against native-format sources in isolated fixtures; at "
    "least seven participate in the recorded end-to-end build.",
    clauses(
        covers("adapters_executed", ADAPTERS,
               "all ten ratified adapters must execute against native sources"),
        at_least("participating_count", 7,
                 "at least seven source classes participate in the recorded build"),
        every("receipts", "each adapter emits a receipt naming its native source",
              present("adapter", "receipt names its adapter"),
              present("source_identity", "receipt binds a stable native source identity"),
              nonempty("observations", "receipt lists observations, never a bare count"),
              min_len=10),
    ),
    surfaces=("guildhall ingest", "guildhall corpus rebuild"),
    vectors=ADAPTERS,
    nodes=("test_v1_ingestion.py::test_all_ten_adapters_run_against_native_sources",),
)

_o(
    "V-1.receipt-not-count", "V-1", "receipts list observations, not counts",
    A, "source-adapter-contract",
    "A source-class count alone does not pass P-1: the evidence report lists "
    "native observations and derived facts.",
    clauses(
        every("observations", "every observation carries full ratified provenance",
              present("source_kind", "source class"),
              present("source_identity", "stable native identity"),
              present("content_digest", "content digest"),
              present("observed_at", "observed time"),
              present("disposition", "lifecycle disposition"),
              present("extraction_version", "extraction version"),
              min_len=1),
        nonempty("derived_facts", "the report lists derived facts"),
        absent("observations_count_only",
               "a bare source count may not stand in for observations"),
    ),
    surfaces=("guildhall ingest --json",),
    vectors=ADAPTERS,
    nodes=("test_v1_ingestion.py::test_adapter_receipt_reports_observations_not_counts",),
)

_o(
    "V-1.build-manifest", "V-1", "build manifest binds provenance",
    V, "build-manifest",
    "Build manifest binds observation IDs, source revisions, digests, checkpoints, "
    "and fact derivations.",
    clauses(
        nonempty("build_manifest.observation_ids", "manifest binds observation IDs"),
        nonempty("build_manifest.source_revisions", "manifest binds source revisions"),
        nonempty("build_manifest.digests", "manifest binds digests"),
        nonempty("build_manifest.checkpoints", "manifest binds checkpoints"),
        nonempty("build_manifest.fact_derivations", "manifest binds fact derivations"),
    ),
    surfaces=("guildhall corpus rebuild --json",),
    vectors=("end-to-end build",),
    nodes=("test_v1_ingestion.py::test_end_to_end_build_uses_at_least_seven_source_classes",),
)

_o(
    "V-1.idempotence", "V-1", "re-ingest is idempotent and byte-identical",
    V, "idempotence",
    "Re-run unchanged ingestion: no duplicate observations/facts and byte-identical "
    "current views.",
    clauses(
        nonempty("current_view_digest", "the current view must exist to be compared"),
        is_true("current_view_byte_identical",
                "an unchanged re-ingest yields a byte-identical current view"),
        equals("duplicate_observations", 0, "no duplicate observations"),
        equals("duplicate_facts", 0, "no duplicate facts"),
        at_least("observation_count", 1,
                 "an empty corpus cannot demonstrate idempotence"),
    ),
    surfaces=("guildhall corpus rebuild --json",),
    vectors=("unchanged re-ingest",),
    nodes=("test_v1_ingestion.py::test_reingest_unchanged_is_idempotent_and_byte_identical",),
)

_o(
    "V-1.disposition-change", "V-1", "history survives, disposition changes explicitly",
    V, "disposition-change",
    "Change, delete, reject/revert, and re-run representative sources: history "
    "remains, current disposition changes explicitly.",
    clauses(
        is_true("history_retained",
                "every historical observation remains addressable"),
        every("changed_dispositions", "each change names its new disposition",
              present("observation_id", "which observation"),
              present("from_disposition", "prior disposition"),
              present("to_disposition", "new disposition"),
              min_len=1),
    ),
    surfaces=("guildhall corpus rebuild --json",),
    vectors=("change", "delete", "reject", "revert"),
    nodes=("test_v1_ingestion.py::test_change_delete_reject_revert_preserve_history_and_change_disposition",),
)

_o(
    "V-1.lifecycle-matrix", "V-1", "every frozen lifecycle cell is executed",
    V, "lifecycle-matrix",
    "Every declared cell has an expected observation/current-fact/Unknown state and "
    "at least one negative mutation.",
    clauses(
        # Detector Reviewer finding 11: the ratified table sums to 64 cells and
        # the catalog required 61, so three cells could silently disappear. The
        # count is now exact and each cell must carry its own native format, its
        # three expected states, the states actually observed, and its own
        # negative mutation, so no two cells share one defect.
        equals("declared_cell_count", 64,
               "the ratified adapter lifecycle table sums to exactly 64 cells"),
        covers("adapters_covered", ADAPTERS,
               "every ratified adapter contributes its own cells"),
        every("cells", "each declared cell is executed with a real native transition",
              present("adapter", "which adapter"),
              present("cell", "which lifecycle cell"),
              present("native_format",
                      "the adapter's own source format, not a generic JSON stand-in"),
              present("expected_observation_state", "frozen expected observation state"),
              present("expected_fact_state", "frozen expected current-fact state"),
              present("expected_unknown_state", "frozen expected Unknown state"),
              present("observed_observation_state", "observed observation state"),
              present("observed_fact_state", "observed current-fact state"),
              present("observed_unknown_state", "observed Unknown state"),
              is_true("states_match",
                      "the observed triple equals the frozen expected triple"),
              is_true("transition_executed_natively",
                      "the transition ran in the adapter's native format; naming a "
                      "cell is not executing it"),
              present("source_tree_before", "raw source digest before the transition"),
              present("source_tree_after", "raw source digest after the transition"),
              present("negative_mutation", "this cell's own negative mutation"),
              is_true("negative_mutation_killed",
                      "the declared negative mutation must actually be caught"),
              min_len=64),
    ),
    surfaces=("guildhall ingest", "guildhall status --json"),
    vectors=("64 frozen adapter lifecycle cells",),
    nodes=("test_v1_ingestion.py::test_lifecycle_matrix_executes_every_declared_cell",),
)

_o(
    "V-1.support-retirement", "V-1", "retiring supports recomputes then withdraws",
    V, "support-retirement",
    "the first recomputes provenance while retaining the fact, the second withdraws "
    "the fact and reopens every dependent decision",
    clauses(
        at_least("initial_support_count", 2,
                 "the fixture must establish a multiply supported fact"),
        equals("after_first_retirement.state", "current",
               "an independently supported fact stays current"),
        is_true("after_first_retirement.provenance_recomputed",
                "provenance is recomputed when one support retires"),
        member("after_final_retirement.state", ("withdrawn", "unknown"),
               "the fact withdraws when its final admissible support disappears"),
        nonempty("after_final_retirement.reopened_decisions",
                 "every dependent decision reopens"),
    ),
    surfaces=("guildhall explain --json",),
    vectors=("multiply supported derived fact",),
    nodes=("test_v1_ingestion.py::test_retiring_supports_one_at_a_time_recomputes_then_withdraws",),
)

_o(
    "V-1.clock-skew", "V-1", "out-of-order and skew quarantine on all three cursors",
    V, "ordering",
    "Out-of-order delivery and positive/negative clock skew run across Personal, "
    "Company, and Codebase cursors.",
    clauses(
        covers("skew_dispositions", ("CLOCK_SKEW",),
               "events outside the five-minute bound quarantine as CLOCK_SKEW"),
        covers("cursors_exercised", ("personal", "company", "codebase"),
               "all three store cursors are exercised"),
        every("cursors_exercised_detail", "each cursor sees both skew polarities",
              present("cursor", "which cursor"),
              is_true("positive_skew_quarantined", "future-dated event quarantined"),
              is_true("negative_skew_quarantined", "back-dated event quarantined"),
              is_true("out_of_order_handled", "out-of-order delivery handled"),
              min_len=3),
    ),
    surfaces=("guildhall ingest --json", "guildhall status --json"),
    vectors=("positive skew", "negative skew", "out-of-order delivery"),
    nodes=("test_v1_ingestion.py::test_out_of_order_and_clock_skew_quarantine_across_all_three_cursors",),
)

_o(
    "V-1.misextraction", "V-1", "misextraction withholds without semantic withdrawal",
    V, "misextraction",
    "it asserts only evidence/byte mismatch, withholds the fact, and reopens a "
    "subject-matter-authority Unknown",
    clauses(
        is_true("notice_admitted", "the approver-signed notice is admitted"),
        equals("asserted_claim", "evidence_byte_mismatch",
               "the approver asserts only an evidence/byte mismatch"),
        is_true("fact_withheld", "the fact is withheld"),
        is_false("semantic_withdrawal",
                 "the approver may not perform semantic withdrawal"),
        present("reopened_unknown.owner_identity",
                "a subject-matter-authority Unknown names a person"),
    ),
    surfaces=("guildhall ingest authority_answer",),
    vectors=("approver-signed misextraction notice",),
    nodes=("test_v1_ingestion.py::test_misextraction_notice_is_approver_owned_and_withholds_only",),
)

_o(
    "V-1.never-true-authority", "V-1", "only the subject-matter authority may withdraw",
    A, "session-candidate",
    "Only that subject-matter authority may sign the semantic `never_true` withdrawal.",
    clauses(
        is_false("approver_minted_accepted",
                 "an approver-minted never_true must be refused"),
        member("refusal_code", ("AUTHORITY_WRONG_SCOPE", "SIGNATURE_INVALID"),
               "a typed authority refusal"),
        is_true("steward_minted_accepted",
                "the in-scope steward/maintainer may perform the withdrawal"),
    ),
    surfaces=("guildhall ingest kindex",),
    vectors=("approver-signed never_true", "steward-signed never_true"),
    nodes=("test_v1_ingestion.py::test_never_true_requires_subject_matter_authority",),
)

_o(
    "V-1.origin-trust", "V-1", "origin trust class bounds durable direction",
    A, "source-adapter-contract",
    "Anything below `merged-default` is ineligible for trusted durable direction "
    "unless a separately authorized event cites it; merely checking out an attacker "
    "branch cannot promote its ADR.",
    clauses(
        covers("observed_classes", ("merged-default", "unreviewed-branch"),
               "both a trusted and an untrusted origin class are observed"),
        every("observations", "each repository observation carries an origin class",
              member("origin_trust_class",
                     ("merged-default", "approved-pr", "unreviewed-branch",
                      "uncommitted-worktree"),
                     "closed origin trust class set"),
              min_len=2),
        is_false("branch_adr_promoted",
                 "an ADR on an unmerged branch must not reach trusted direction"),
    ),
    surfaces=("guildhall ingest docs_adr", "guildhall explain --json"),
    vectors=("merged default branch", "attacker unmerged branch"),
    nodes=("test_v1_ingestion.py::test_origin_trust_class_is_derived_and_bounds_trusted_direction",),
)

# ==========================================================================
# V-2 — classification and fan-out
# ==========================================================================

_o(
    "V-2.corpus-floors", "V-2", "held-out corpus meets every frozen floor",
    V, "held-out-corpus",
    "Tester freezes at least 120 held-out natural messages with gold atom boundaries "
    "and destination sets; at least 40 are mixed and at least 100 contain varied "
    "private/safety canaries or transformations.",
    clauses(
        at_least("held_out_messages", 120, "at least 120 held-out messages"),
        at_least("mixed_messages", 40, "at least 40 mixed-scope messages"),
        at_least("canary_bearing_messages", 100, "at least 100 carry canaries"),
        at_least("seeded_canaries", 30, "at least 30 seeded private canaries"),
        covers("strata",
               ("ambiguous_non_fact", "temporary_suggestion", "codebase_fact",
                "company_architecture"),
               "every required stratum is present"),
        is_true("gold_withheld_from_product",
                "gold atoms and destinations never reach the product input"),
    ),
    surfaces=("tester-held corpus",),
    vectors=("held-out routing corpus",),
    nodes=("test_v2_classification.py::test_held_out_corpus_meets_every_frozen_floor",),
    fail_closed=INSTRUMENT,
)

_o(
    "V-2.annotators", "V-2", "annotator agreement gates the gate",
    V, "annotators",
    "Cohen's kappa must be at least 0.80 per destination; disagreements are "
    "adjudicated and the adjudication digest freezes before classifier runs.",
    clauses(
        every("per_destination_kappa", "every destination clears the frozen floor",
              present("destination", "which destination"),
              at_least("kappa", 0.80, "Cohen's kappa floor per destination"),
              min_len=4),
        present("adjudication_digest", "the adjudication digest is frozen"),
        is_true("frozen_before_classifier_runs",
                "adjudication freezes before any classifier run"),
    ),
    surfaces=("tester-held gold",),
    vectors=("personal", "company", "codebase", "none"),
    nodes=("test_v2_classification.py::test_annotator_agreement_and_frozen_adjudication_digest",),
    fail_closed=INSTRUMENT,
)

_o(
    "V-2.pinned-runs", "V-2", "five pinned runs and harness-computed bounds",
    P, "P-2",
    "Required macro-F1 across destination labels is 0.90 and each shared-destination "
    "precision is at least 0.95 across the preregistered 95% lower bound of at least "
    "five pinned live-model runs.",
    clauses(
        at_least("run_count", 5, "at least five preregistered runs"),
        equals("distinct_model_fingerprints", 1, "one pinned model identity"),
        equals("replay_frozen_from_run", 1, "replay freezes from run 1, never the best"),
        at_least("macro_f1_lower_bound", 0.90, "macro-F1 95% lower bound floor"),
        equals("macro_f1_interval_method", "message_stratified_bootstrap",
               "message-stratified bootstrap is the frozen method"),
        every("shared_precision_lower_bound", "each shared destination clears 0.95",
              present("destination", "which shared destination"),
              at_least("value", 0.95, "shared precision floor"),
              min_len=2),
        equals("shared_precision_interval_method", "wilson",
               "Wilson interval over pooled frozen predictions"),
        is_true("computed_by_harness_from_raw_predictions",
                "metrics are computed by the instrument from raw predictions, never "
                "self-reported by the product"),
    ),
    surfaces=("guildhall session observe --json",),
    vectors=("five pinned classifier runs",),
    nodes=("test_v2_classification.py::test_five_pinned_runs_lower_bound_meets_macro_f1_and_shared_precision",),
)

_o(
    "V-2.calibration", "V-2", "excluded calibration corpus gates measurement",
    V, "calibration",
    "Before V-10, run a separate excluded 60-message calibration corpus through the "
    "same five-run configuration.",
    clauses(
        equals("calibration_message_count", 60, "exactly 60 calibration messages"),
        equals("overlap_with_held_out", 0, "the calibration corpus is disjoint"),
        is_true("calibration_input_exists",
                "the frozen calibration input must exist to be run"),
        at_least("macro_f1_lower_bound", 0.90, "calibration macro-F1 floor"),
        every("shared_precision_lower_bound", "each shared destination clears 0.95",
              present("destination", "which destination"),
              at_least("value", 0.95, "shared precision floor"),
              min_len=2),
    ),
    surfaces=("guildhall experiment calibrate",),
    vectors=("excluded 60-message calibration corpus",),
    nodes=("test_v2_classification.py::test_excluded_calibration_corpus_gates_measurement",),
)

_o(
    "V-2.atomisation", "V-2", "mixed text splits rather than takes one label",
    P, "P-2",
    "Mixed text must split rather than force one label on the whole message.",
    clauses(
        every("mixed_messages", "every mixed message splits into independent atoms",
              present("message_id", "which message"),
              at_least("atom_count", 2, "a mixed message yields at least two atoms"),
              at_least("distinct_destination_count", 2,
                       "a mixed message yields at least two destinations"),
              min_len=40),
        at_least("exact_match_atomization", 0.0,
                 "exact-match atomization is computed and reported"),
    ),
    surfaces=("guildhall session observe --json",),
    vectors=("at least 40 mixed-scope messages",),
    nodes=("test_v2_classification.py::test_mixed_messages_atomise_rather_than_take_one_label",),
)

_o(
    "V-2.metrics", "V-2", "every declared metric is computed",
    V, "metrics",
    "Compute exact-match atomization, per-label precision/recall/F1, macro-F1, "
    "shared precision, private-to-shared detection, and calibration/abstention.",
    clauses(
        covers("per_label_destinations", ("personal", "company", "codebase", "none"),
               "per-label metrics cover every destination"),
        every("per_label", "each label reports precision, recall and F1",
              present("destination", "which label"),
              present("precision", "precision"),
              present("recall", "recall"),
              present("f1", "F1"),
              min_len=4),
        present("private_to_shared_detection", "private-to-shared detection reported"),
        present("calibration_and_abstention", "calibration and abstention reported"),
        is_true("harness_recomputation_agrees",
                "the instrument's independent recomputation agrees with the report"),
    ),
    surfaces=("harness recomputation over raw predictions",),
    vectors=("personal", "company", "codebase", "none"),
    nodes=("test_v2_classification.py::test_exact_match_atomization_and_per_label_metrics",),
)

_o(
    "V-2.low-confidence", "V-2", "low-confidence shared labels demote",
    P, "P-2",
    "A low-confidence shared label is demoted to `none`/Unknown rather than guessed.",
    clauses(
        at_least("low_confidence_atom_count", 1,
                 "the corpus must contain low-confidence atoms to demote"),
        every("low_confidence_atoms", "each demotes rather than guesses",
              present("atom_id", "which atom"),
              member("destination", ("none", "personal"),
                     "a low-confidence shared label demotes to none/Unknown"),
              min_len=1),
    ),
    surfaces=("guildhall session observe --json",),
    vectors=("low-confidence shared candidates",),
    nodes=("test_v2_classification.py::test_low_confidence_shared_label_demotes_to_none_or_unknown",),
)

_o(
    "V-2.independent-candidates", "V-2", "distinct minimized bytes per destination",
    V, "fan-out",
    "One mixed message must yield independent Personal and Codebase candidates; "
    "another yields Personal, Company, and Codebase candidates with distinct "
    "minimized bytes.",
    clauses(
        at_least("two_store_messages", 1,
                 "a message yields independent Personal and Codebase candidates"),
        at_least("three_store_messages", 1,
                 "a message yields Personal, Company and Codebase candidates"),
        every("three_store_detail", "the three payload digests are pairwise distinct",
              present("message_id", "which message"),
              distinct("payload_digests", "distinct minimized bytes per destination",
                       min_len=3),
              min_len=1),
    ),
    surfaces=("guildhall proposals list --json",),
    vectors=("two-store fan-out", "three-store fan-out"),
    nodes=("test_v2_classification.py::test_independent_candidates_with_distinct_minimized_bytes",),
)

_o(
    "V-2.partial-fanout", "V-2", "partial failure never rolls back a durable write",
    V, "apology",
    "receipts expose partial success and an apology Unknown names the approver as "
    "responsible and destination maintainer as closing authority, withholds the "
    "orphaned Codebase fact, and reaches an explicit reconcile/abandon state",
    clauses(
        equals("codebase_receipt_state", "committed",
               "the durable Codebase write survives the Company failure"),
        member("company_receipt_state", ("refused", "pending", "abandoned"),
               "the failed destination reports its own state"),
        at_least("apology_count", 1, "a terminally divergent fan-out emits an apology"),
        equals("apology.responsible_party_role", "approving-principal",
               "the apology names the approving principal as responsible"),
        member("apology.closing_authority_role",
               ("repository-maintainer", "company-steward"),
               "the apology names the in-scope closing authority"),
        is_true("apology.orphaned_fact_withheld", "the orphaned fact is withheld"),
        member("apology.state",
               ("awaiting_reconcile_or_abandon", "reconciled", "abandoned"),
               "an explicit reconcile/abandon state is reached"),
    ),
    surfaces=("guildhall proposals decide", "guildhall status --json"),
    vectors=("Codebase commit then terminal Company failure",),
    nodes=("test_v2_classification.py::test_partial_fanout_failure_does_not_roll_back_committed_destination",),
)

_o(
    "V-2.retry-receipt", "V-2", "retry returns the original receipt",
    P, "P-2",
    "A retry of an already committed exact event returns the original commit receipt "
    "even after token expiry; it cannot create a second event or pretend the first "
    "commit did not happen.",
    clauses(
        is_true("receipt_ids_equal", "the retry returns the original receipt"),
        is_false("second_event_created", "no second event is created"),
        equals("duplicate_events", 0, "no duplicate events exist afterwards"),
        is_true("retry_after_token_expiry",
                "the retry is exercised after token expiry, per the ratified text"),
    ),
    surfaces=("guildhall proposals decide --json",),
    vectors=("committed retry", "committed retry after token expiry"),
    nodes=("test_v2_classification.py::test_retry_returns_original_receipt_without_duplication",),
)

_o(
    "V-2.orphan-abandoned", "V-2", "one signed orphan_abandoned on deadline expiry",
    V, "orphan-abandoned",
    "the destination service emits one signed `orphan_abandoned`, names the "
    "unresponsive authority, keeps the fact withdrawn, and leaves no pending orphan "
    "forever",
    clauses(
        equals("orphan_abandoned_count", 1, "exactly one terminal event"),
        present("event.unresponsive_closing_authority",
                "the event names the unresponsive closing authority"),
        present("event.signature", "the terminal event is signed"),
        equals("event.fact_state", "withdrawn", "the fact stays withdrawn"),
        equals("pending_orphans_after_deadline", 0,
               "no orphan remains in an ownerless pending state"),
    ),
    surfaces=("guildhall status --json",),
    vectors=("expired closing deadline",),
    nodes=("test_v2_classification.py::test_expired_closing_deadline_emits_one_signed_orphan_abandoned",),
)

_o(
    "V-2.crash-recovery", "V-2", "every journal transition recovers exactly once",
    V, "crash-recovery",
    "Kill each destination between nonce reservation, event append/rename, manifest, "
    "receipt, and apology transitions, then retry concurrently.",
    clauses(
        every("transitions", "each frozen crash point recovers exactly once",
              present("transition", "which transition"),
              is_true("crash_witnessed",
                      "the crash is independently witnessed, not merely requested"),
              equals("duplicate_events", 0, "no duplicate event"),
              equals("recursive_apologies", 0, "no recursive apology"),
              is_true("recovered", "restart completes or rolls back the journal"),
              min_len=5),
        equals("total_events_after_recovery", 1,
               "exactly one content-addressed event survives"),
    ),
    surfaces=("guildhall proposals decide", "guildhall fsck --json"),
    vectors=("nonce_reservation", "event_append", "event_rename", "manifest",
             "receipt", "apology"),
    nodes=("test_v2_classification.py::test_kill_at_every_transition_then_concurrent_retry",),
)

_o(
    "V-2.no-cross-store", "V-2", "no cross-store transaction or accept-all",
    P, "P-2",
    "One source may fan out to multiple stores, but no cross-store transaction, "
    "shared private lineage token, or accept-all operation exists.",
    clauses(
        every("receipts", "each destination returns its own saga receipt",
              present("destination", "which destination"),
              member("state", ("committed", "refused", "pending", "abandoned"),
                     "closed saga receipt state set"),
              absent("global_rollback", "no global rollback is claimed"),
              min_len=2),
        equals("accept_all_surfaces_found", 0,
               "no accept-all surface exists in Core or CLI"),
    ),
    surfaces=("guildhall proposals --help", "guildhall status --json"),
    vectors=("cross-destination fan-out",),
    nodes=("test_v2_classification.py::test_no_cross_store_transaction_exists",
           "test_v2_classification.py::test_no_accept_all_path_is_reachable"),
)

# ==========================================================================
# V-3 — privacy and authority boundary
# ==========================================================================

_o(
    "V-3.lifecycle-scan", "V-3", "no canary on any shared surface across the lifecycle",
    P, "P-3",
    "One seeded private canary or deterministic lineage on any unauthorized shared "
    "surface is an immediate proof failure",
    clauses(
        equals("findings", 0, "zero canary recoveries on shared surfaces"),
        at_least("surfaces_scanned", 1, "the scan must cover a non-empty surface set"),
        covers("surface_families_scanned",
               ("company_sqlite", "codebase_git_worktree", "codebase_git_objects",
                "kin_events", "shared_outbox", "receipts", "logs", "caches",
                "host_projection", "process_artifacts", "evidence_packet"),
               "every declared shared surface family is traversed"),
        covers("lifecycle_stages_executed",
               ("classification", "approval", "rejection", "defer", "expiry",
                "fan-out", "host projection", "logs", "receipts", "caches",
                "service", "kin", "restart", "cleanup"),
               "every ratified lifecycle stage is executed"),
        is_true("scan_fail_closed",
                "an unreadable surface fails the scan closed rather than being skipped"),
    ),
    surfaces=("every persistent and shared byte",),
    vectors=("seeded raw messages through the full lifecycle",),
    nodes=("test_v3_privacy.py::test_no_canary_reaches_any_shared_surface_across_the_full_lifecycle",),
)

_o(
    "V-3.positive-control", "V-3", "positive control licenses the clean assertion",
    V, "positive-control",
    "Plant known canaries in every scanned surface and encoding during a "
    "positive-control run, including packed Git objects and SQLite blobs, and require "
    "each exact detector/location receipt before trusting a clean run.",
    clauses(
        every("planted", "every planted control yields an exact location receipt",
              present("surface_family", "which surface"),
              present("encoding_class", "which encoding"),
              present("location_digest", "an exact location receipt"),
              is_true("detected", "the planted control is detected"),
              min_len=12),
        covers("planted_surface_families",
               ("company_sqlite", "codebase_git_objects", "caches", "logs",
                "shared_outbox", "evidence_packet"),
               "the control run covers the declared surfaces"),
        is_true("controls_removed_before_clean_assertion",
                "planted controls are removed before the no-leakage assertion"),
        equals("clean_findings_after_removal", 0,
               "the clean assertion runs only after removal"),
    ),
    surfaces=("packed Git objects", "SQLite blobs", "caches", "logs"),
    vectors=("twelve frozen transformation families",),
    nodes=("test_v3_privacy.py::test_positive_control_precedes_and_licenses_the_clean_assertion",),
    fail_closed=INSTRUMENT,
)

_o(
    "V-3.qualification", "V-3", "randomized sensitivity and false-positive bounds",
    V, "randomized-sensitivity",
    "The Wilson 95% lower bound on randomized sensitivity must be at least 0.98 and "
    "the Wilson 95% upper bound on false-positive rate at most 0.01.",
    clauses(
        at_least("positives", 300, "at least 300 randomized positive variants"),
        at_least("decoys", 500, "at least 500 randomized true-negative decoys"),
        at_least("sensitivity_wilson_lower", 0.98, "sensitivity lower bound"),
        at_most("false_positive_wilson_upper", 0.01, "false-positive upper bound"),
        is_true("stratification_met",
                "at least ten per declared surface/encoding family"),
        equals("deterministic_controls_missed", 0,
               "every deterministic catalog control must be detected"),
        present("false_negative_bound", "the resulting false-negative bound is published"),
        is_true("registry_values_not_exposed",
                "registry plaintext is never exposed to improve the score"),
    ),
    surfaces=("twelve encoding families", "twelve surface families"),
    vectors=("300 randomized positives", "500 randomized decoys"),
    nodes=("test_v3_qualification.py::test_randomized_qualification_publishes_every_denominator",),
    fail_closed=INSTRUMENT,
)

_o(
    "V-3.capability", "V-3", "shared writer has no Personal capability",
    V, "capability",
    "Verify the shared writer process/call graph has no Personal-store capability.",
    clauses(
        every("shared_processes", "no shared process holds a Personal capability",
              present("role", "which shared role"),
              nonempty("granted_capabilities", "capabilities are enumerated"),
              is_false("holds_personal_capability", "no Personal capability"),
              is_false("personal_root_in_serialized_config",
                       "no Personal root in the serialized config"),
              min_len=1),
    ),
    surfaces=("guildhall doctor --json",),
    vectors=("shared projector", "shared writer"),
    nodes=("test_v3_privacy.py::test_shared_writer_has_no_personal_capability",),
)

_o(
    "V-3.sandbox", "V-3", "OS policy denies the Personal root or shared work disables",
    A, "one-protocol",
    "If no supported kernel enforcement is available or the probe succeeds in reading "
    "Personal, shared projection/publication is disabled with a typed failure.",
    clauses(
        present("personal_denial_probe", "the startup denial probe result is reported"),
        is_false("personal_root_readable",
                 "the shared process cannot read the Personal root"),
        is_true("enforcement_or_disabled",
                "either kernel enforcement holds or shared work is disabled"),
        is_false("stolen_bytes_promoted",
                 "bytes recovered by a same-UID process are still rejected"),
    ),
    surfaces=("guildhall doctor --json", "guildhall proposals decide"),
    vectors=("sandboxed agent read", "arbitrary same-UID process"),
    nodes=("test_v3_privacy.py::test_sandbox_denies_personal_root_for_shared_processes",),
)

_o(
    "V-3.inherited-fd", "V-3", "an inherited Personal descriptor fails startup",
    V, "descriptors",
    "Pass an open Personal directory descriptor while pathname denial still succeeds; "
    "descriptor enumeration/attestation must fail startup before shared work.",
    clauses(
        is_true("descriptor_actually_inherited",
                "the descriptor is genuinely passed to the child, not merely opened"),
        is_true("startup_failed", "startup fails before any shared work"),
        member("refusal_code",
               ("CONFIG_INVARIANT", "PERSONAL_TAINT_BLOCKED", "PROCESSOR_UNAUTHORIZED"),
               "a typed refusal from the closed taxonomy"),
        is_false("shared_work_performed", "no shared work happened first"),
    ),
    surfaces=("guildhall project",),
    vectors=("inherited open Personal directory descriptor",),
    nodes=("test_v3_privacy.py::test_inherited_personal_descriptor_fails_startup",),
)

_o(
    "V-3.process-artifacts", "V-3", "no Personal root in any process artifact",
    V, "process-dump",
    "Dump argv, environment, file-descriptor metadata, serialized config, errors, and "
    "child inputs for every shared process; the Personal-root canary must be absent.",
    clauses(
        every("inspected_processes", "every shared process is inspected totally",
              present("label", "which process"),
              nonempty("argv", "argv captured"),
              present("environ", "environment captured"),
              present("fds", "descriptor metadata captured"),
              min_len=2),
        equals("findings", 0, "the Personal-root canary is absent everywhere"),
        covers("artifact_classes",
               ("argv", "environ", "fds", "config", "stderr", "child_input"),
               "every declared artifact class is dumped"),
    ),
    surfaces=("every shared writer and projector process",),
    vectors=("argv", "environ", "fds", "config", "errors", "child inputs"),
    nodes=("test_v3_privacy.py::test_process_artifacts_contain_no_personal_root_canary",),
)

_o(
    "V-3.taint", "V-3", "hard-blocking taint is never cleared",
    A, "routing-policy",
    "Taint is never described as cleared; its policy consequence differs by class.",
    clauses(
        at_least("candidate_count", 1,
                 "candidates must exist for the taint policy to be observed"),
        every("candidates", "hard-blocking taint yields no shared candidate",
              present("candidate_id", "which candidate"),
              is_false("taint_cleared", "taint is never reported as cleared"),
              is_true("hard_block_respected",
                      "a hard-blocking taint yields no shared destination"),
              min_len=1),
        is_true("deidentify_retains_taint",
                "de-identification does not remove the private audit record's taint"),
    ),
    surfaces=("guildhall proposals list --json",),
    vectors=("secret", "credential", "configured-canary", "forbidden-identifier"),
    nodes=("test_v3_privacy.py::test_hard_blocking_taint_is_never_cleared_by_deidentification",),
)

_o(
    "V-3.paraphrase", "V-3", "paraphrase-only output stays private by taint policy",
    V, "paraphrase",
    "The entire observation must remain private by taint policy; the scanner is "
    "defense in depth, not the claimed semantic boundary.",
    clauses(
        is_true("observation_processed",
                "the seeded observation is genuinely processed"),
        equals("shared_candidates", 0,
               "the whole observation stays private under taint policy"),
        is_true("output_contains_no_matching_string",
                "the model output carries only a paraphrase, so the scanner alone "
                "would miss it"),
    ),
    surfaces=("guildhall proposals list --json",),
    vectors=("hard-blocking canary with paraphrase-only output",),
    nodes=("test_v3_privacy.py::test_paraphrase_only_output_stays_private_by_taint_policy",),
)

_o(
    "V-3.egress", "V-3", "egress to an unnamed processor fails",
    V, "egress",
    "a send to an unnamed processor, a separate unapproved classifier provider, or a "
    "scope-ineligible request must fail",
    clauses(
        is_true("private_input_present",
                "a real private input is offered, so the refusal is meaningful"),
        equals("refusal_code", "PROCESSOR_UNAUTHORIZED", "the frozen typed refusal"),
        is_false("retryable", "a processor-scope refusal is not retryable"),
        is_true("no_bytes_left_the_boundary",
                "no private byte reached the unnamed processor"),
    ),
    surfaces=("guildhall session observe",),
    vectors=("unnamed provider", "unapproved classifier provider", "scope-ineligible"),
    nodes=("test_v3_privacy.py::test_egress_to_unnamed_processor_fails_with_typed_refusal",),
)

_o(
    "V-3.claim", "V-3", "the V-3 claim is digest-qualified",
    V, "claim",
    "An unqualified “zero leakage” claim is a reporting failure.",
    clauses(
        is_true("uses_qualified_template", "the qualified claim template is used"),
        present("threat_model_sha256", "the exact ratified threat-model digest"),
        present("execution_census_digest", "the frozen execution census digest"),
        equals("forbidden_phrases_found", 0, "no unqualified phrase appears"),
    ),
    surfaces=("guildhall status --json",),
    vectors=("published privacy claim",),
    nodes=("test_v3_privacy.py::test_v3_claim_is_digest_qualified_and_never_unqualified",),
)

_o(
    "V-3.auxiliary-corpus", "V-3",
    "the auxiliary corpus is generated, digest bound and rights complete",
    T, "auxiliary-corpus",
    "The Reviewer records selection procedure, source rights, contents, versions, "
    "and digest.",
    clauses(
        at_least("candidate_count", 5,
                 "the pool must offer the Reviewer a real choice"),
        is_true("deterministic_components_reproduced",
                "every generated component must reproduce byte for byte from its "
                "named seed"),
        present("generation_recipe", "the derivation recipe is recorded"),
        present("pool_digest", "one digest binds manifest, rights and candidates"),
        is_true("selection_protocol_present",
                "the Reviewer's selection procedure is committed"),
        is_true("grant_template_present",
                "the unsigned rights-grant template is committed"),
        is_true("named_rightsholder_grant_present",
                "a named human rightsholder must sign the grant; the Tester may "
                "not author or fabricate it"),
        is_true("selectable",
                "the pool is selectable only once its rights are complete"),
    ),
    surfaces=("tests/fixtures/auxiliary/",),
    vectors=("licensed public sources", "generated dictionaries",
             "correlation records", "decoy records"),
    nodes=("test_v3_qualification.py::"
           "test_auxiliary_corpus_selection_record_is_complete_and_frozen",),
    fail_closed=INSTRUMENT,
)

_o(
    "V-3.attack-families", "V-3", "every frozen attack family is executed",
    T, "attack-catalog",
    "Every family has an exact positive control, negative control, and detector "
    "mutation.",
    clauses(
        every("families", "each of the nineteen families is executed totally",
              present("family", "family number"),
              is_true("executed", "the family probe actually ran"),
              is_true("positive_control_detected",
                      "the family's exact positive control is detected"),
              is_true("negative_control_clean",
                      "the family's exact negative control stays clean"),
              is_true("detector_mutation_blinds",
                      "the family's detector mutation genuinely blinds"),
              present("surfaces", "the surfaces the family ranges over"),
              min_len=19),
    ),
    surfaces=("all shared surfaces",),
    vectors=tuple(f"family-{i}" for i in range(1, 20)),
    nodes=("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
    fail_closed=INSTRUMENT,
)

_o(
    "V-3.reconstructor", "V-3", "an independent reconstructor emits sealed findings",
    T, "adjudication",
    "Tester and reconstructor emit independent, content-addressed findings before "
    "seeing one another's conclusions.",
    clauses(
        present("tester_finding_digest", "the Tester finding is content-addressed"),
        present("reconstructor_finding_digest",
                "the reconstructor finding is content-addressed"),
        is_true("sealed_before_comparison",
                "both are sealed before either sees the other"),
        is_false("registry_capability_granted",
                 "the reconstructor receives no canary-registry capability"),
        present("auxiliary_corpus_digest",
                "the reconstructor receives the frozen auxiliary corpus"),
        present("exact_recovery", "exact/deterministic recovery recorded separately"),
        present("semantic_guesses", "semantic guesses recorded separately"),
    ),
    surfaces=("all shared surfaces", "frozen auxiliary corpus"),
    vectors=("correlated reconstruction",),
    nodes=("test_v3_privacy.py::test_reconstructor_findings_are_independent_and_content_addressed",),
)

# ==========================================================================
# V-4 — corpus maintenance and distributed conflicts
# ==========================================================================

_o(
    "V-4.incremental-cycle", "V-4", "the repeated incremental cycle is bounded",
    V, "cycle",
    "Repeated incremental cycle: create, duplicate, edit, supersede, retract, revoke, "
    "expire, branch, merge, conflict, resolve, rebuild, restart.",
    clauses(
        every("stages", "each stage performs a real state transition",
              present("stage", "which stage"),
              is_true("state_changed",
                      "the stage changed real repository/event state"),
              present("post_state_digest", "the post-stage state is content-addressed"),
              min_len=13),
        is_true("view_stabilises", "the derived view stabilises across repeats"),
        is_true("growth_bounded", "storage growth stays bounded"),
        distinct("cycle_state_digests",
                 "the cycle actually advanced state rather than idling", min_len=3),
    ),
    surfaces=("guildhall corpus rebuild --json", "repository state"),
    vectors=("create", "duplicate", "edit", "supersede", "retract", "revoke",
             "expire", "branch", "merge", "conflict", "resolve", "rebuild", "restart"),
    nodes=("test_v4_maintenance.py::test_repeated_incremental_cycle_is_restart_safe_and_bounded",),
)

_o(
    "V-4.conflict", "V-4", "incompatible heads remain conflict",
    V, "merge",
    "Both events survive; incompatible facts remain conflict/Unknown until an "
    "authorized parent-bound event.",
    clauses(
        at_least("surviving_event_count", 2, "both events survive the union"),
        member("state", ("conflict", "unknown"),
               "incompatible heads remain conflict/Unknown"),
        at_least("surviving_head_count", 2, "both heads are surfaced"),
        is_false("resolved_by_time",
                 "timestamps and file order never choose among incompatible heads"),
        is_true("authorized_parent_bound_event_resolves",
                "an authorized parent-bound event does resolve the conflict"),
    ),
    surfaces=("guildhall explain --json", ".kin/events"),
    vectors=("two clones, disjoint events, incompatible heads",),
    nodes=("test_v4_maintenance.py::test_incompatible_heads_remain_conflict_until_authorized_parent_bound_event",),
)

_o(
    "V-4.manifest-comparison", "V-4", "manifest comparison classifies all four cases",
    V, "manifest",
    "local strict superset within freshness is normal lag, missing expected heads is "
    "repository-owned `INCOMPLETE`, and expired expected state is a Company "
    "publication Unknown rather than an integrity accusation",
    clauses(
        every("scenarios", "each comparison case is built from real manifest state",
              present("scenario", "which comparison case"),
              is_true("state_constructed",
                      "the manifest/reachability state is really constructed"),
              present("classification", "the resulting classification"),
              min_len=4),
        equals("superset_classification", "normal_lag",
               "a local strict superset within freshness is normal lag"),
        equals("missing_head_classification", "INCOMPLETE",
               "a missing published reachable head is repository-owned INCOMPLETE"),
        equals("expired_owner_role", "company-steward",
               "expired expected state is a Company-steward publication Unknown"),
    ),
    surfaces=("guildhall fsck --json", ".kin/manifests"),
    vectors=("equal", "strict superset", "strict subset", "incomparable"),
    nodes=("test_v4_maintenance.py::test_manifest_comparison_classifies_lag_incomplete_and_expiry",),
)

_o(
    "V-4.normalisation", "V-4", "only lowercase digest paths admit",
    V, "case-normalisation",
    "Only computed lowercase ASCII digest paths admit; canonical bytes remain "
    "identical.",
    clauses(
        every("admitted_paths", "every admitted path is lowercase ASCII",
              is_true("lowercase", "computed lowercase ASCII digest path"),
              min_len=1),
        is_true("canonical_bytes_identical",
                "canonical bytes survive autocrlf and macOS normalisation"),
        is_false("uppercase_alias_admitted", "an uppercase digest alias is refused"),
        is_true("ineffective_attributes_detected",
                "missing or ineffective Git attributes are caught by fsck"),
    ),
    surfaces=(".kin/events", "git attributes"),
    vectors=("core.ignorecase", "core.autocrlf", "macOS NFD", "uppercase alias"),
    nodes=("test_v4_maintenance.py::test_case_crlf_normalisation_and_uppercase_alias_are_refused",),
)

_o(
    "V-4.determinism", "V-4", "rebuild is deterministic over the four frozen inputs",
    V, "determinism",
    "Rebuild with fixed `(events, reducer version, as_of, authority cursor)` twice and "
    "vary each input once.",
    clauses(
        is_true("identical_under_identical_inputs",
                "two rebuilds with the same inputs are byte-identical"),
        nonempty("current_view_digest", "the view must be non-empty to be compared"),
        every("varied_inputs", "each of the four inputs is varied exactly once",
              present("input", "which input was varied"),
              is_true("observed_effect",
                      "varying the input has an observable, recorded effect"),
              min_len=4),
    ),
    surfaces=("guildhall corpus rebuild --json",),
    vectors=("events", "reducer version", "as_of", "authority cursor"),
    nodes=("test_v4_maintenance.py::test_rebuild_is_deterministic_over_frozen_inputs",),
)

_o(
    "V-4.as-of", "V-4", "ambient as_of is refused",
    A, "reduction-algorithm",
    "`as_of` is an explicit RFC 3339 UTC millisecond timestamp, never an ambient "
    "wall-clock read.",
    clauses(
        is_true("explicit_as_of_recorded",
                "the rebuild records the explicit as_of it used"),
        is_true("rfc3339_millisecond_format", "the recorded value has the frozen shape"),
        is_false("ambient_clock_read", "no ambient wall-clock read occurs"),
    ),
    surfaces=("guildhall corpus rebuild --json",),
    vectors=("omitted as_of",),
    nodes=("test_v4_maintenance.py::test_omitting_as_of_breaks_determinism_and_is_refused",),
)

_o(
    "V-4.ceiling", "V-4", "10x the ceiling refuses writes but still diagnoses",
    V, "ceiling",
    "Intake refuses new writes while bounded incremental `fsck`/diagnosis remains "
    "available; SessionStart latency and full-rebuild time are recorded rather than "
    "allowed to hang.",
    clauses(
        at_least("event_count_constructed", 100000,
                 "a real corpus at ten times the 10,000-event ceiling is built"),
        equals("intake_refusal_code", "LIMIT_EXCEEDED", "intake refuses new writes"),
        is_true("diagnosis_available", "bounded incremental fsck remains available"),
        present("full_rebuild_seconds", "full-rebuild time is recorded"),
        present("session_start_seconds", "SessionStart latency is recorded"),
    ),
    surfaces=("guildhall ingest", "guildhall fsck --json"),
    vectors=("100,000-event corpus",),
    nodes=("test_v4_maintenance.py::test_ten_times_the_admission_ceiling_refuses_writes_but_still_diagnoses",),
)

_o(
    "V-4.cascade", "V-4", "revocation cascade completes in bound or fails closed",
    V, "cascade",
    "completion must be within 120 seconds or the typed fail-closed limit state "
    "persists with remaining count",
    clauses(
        at_least("dense_graph_event_count", 10000,
                 "the dense derivation graph is built at the ceiling"),
        is_true("key_revoked", "a supporting key is genuinely revoked"),
        member("cascade_state", ("complete", "REVOCATION_CASCADE_INCOMPLETE"),
               "closed cascade state set"),
        is_true("bound_respected_or_fail_closed",
                "completion inside 120s, or fail-closed with a remaining count"),
        is_true("unchecked_facts_withheld",
                "not-yet-rechecked facts are withheld, never assumed unaffected"),
    ),
    surfaces=("guildhall corpus rebuild --json",),
    vectors=("10,000-event dense derivation graph",),
    nodes=("test_v4_maintenance.py::test_revocation_cascade_completes_in_bound_or_stays_fail_closed",),
)

_o(
    "V-4.replay", "V-4", "pre-revocation replay returns history without re-admission",
    V, "replay",
    "a path-exists fast path may return a historical receipt only to the original "
    "scoped client and must not re-admit/project it",
    clauses(
        is_true("revocation_observed", "the revocation cursor is genuinely observed"),
        is_true("historical_receipt_returned", "the historical receipt is returned"),
        is_false("readmitted", "the event is not re-admitted"),
        is_false("projected", "the event is not projected"),
        is_true("returned_to_original_scoped_client_only",
                "only the original scoped client receives the receipt"),
    ),
    surfaces=("guildhall status --json",),
    vectors=("pre-revocation event replayed after the revocation cursor",),
    nodes=("test_v4_maintenance.py::test_pre_revocation_replay_returns_history_without_readmission",),
)

_o(
    "V-4.common-dir-lock", "V-4", "linked worktrees contend on one common-dir lock",
    V, "lock",
    "Admit concurrently from two linked worktrees and prove one exclusive lock in "
    "Git's common directory serializes one manifest lineage.",
    clauses(
        is_true("common_dir_shared", "the linked worktree shares the common directory"),
        present("lock_path", "the exclusive lock is located"),
        is_true("lock_in_common_dir", "the lock lives in Git's common directory"),
        equals("worktree_local_locks", 0, "no per-worktree lock exists"),
        equals("manifest_lineages", 1, "one manifest lineage results"),
        at_least("concurrent_admissions", 2, "admission is genuinely concurrent"),
    ),
    surfaces=("git common directory", "guildhall repo publish-manifest"),
    vectors=("two linked worktrees admitting concurrently",),
    nodes=("test_v4_maintenance.py::test_linked_worktrees_serialize_on_one_common_dir_lock",),
)

_o(
    "V-4.kindex-compat", "V-4", "legacy Kindex bytes preserved, collision refused",
    V, "kindex-collision",
    "Initialize against a fully populated real pinned-Kindex `.kin/` inventory and "
    "prove byte preservation; inject a collision between an enumerated Kindex path and "
    "a Guildhall reserved path and require typed no-write refusal.",
    clauses(
        at_least("legacy_files", 4, "a fully populated legacy inventory is present"),
        equals("legacy_bytes_changed", 0, "every legacy byte is preserved"),
        is_true("collision_refused", "the injected collision produces a typed refusal"),
        equals("bytes_changed_by_refused_init", 0, "the refusal changes no byte"),
    ),
    surfaces=(".kin/ legacy inventory", "guildhall repo init"),
    vectors=("populated pinned-Kindex repository", "reserved-path collision"),
    nodes=("test_v4_maintenance.py::test_legacy_kindex_bytes_preserved_and_collision_refuses",),
)

# ==========================================================================
# V-5 — temporal discernment
# ==========================================================================

_o(
    "V-5.cases", "V-5", "every frozen temporal case decides correctly from real history",
    V, "table",
    "Table-driven and narrative cases include:",
    clauses(
        every("cases", "each case is established by real planted history",
              present("case_id", "which frozen case"),
              at_least("planted_event_count", 2,
                       "each case is established by planted signed events"),
              present("observed_state", "the reducer's decision"),
              present("expected_state", "the tester-held expectation"),
              is_true("state_matches", "the decision matches the frozen expectation"),
              nonempty("trace", "an inspectable evidence trace is emitted"),
              present("uncertainty_state", "the uncertainty state is reported"),
              nonempty("counterfactual",
                       "the evidence that would flip the result is shown"),
              nonempty("rejected_events", "rejected events are shown"),
              is_false("case_identity_disclosed",
                       "the case identity never reaches the product"),
              min_len=9),
    ),
    surfaces=("guildhall explain --json", "planted signed event histories"),
    vectors=("nine frozen temporal rows",),
    nodes=("test_v5_temporal.py::test_frozen_temporal_case",),
)

_o(
    "V-5.no-newest-wins", "V-5", "recency alone never selects",
    P, "P-5",
    "Recency is evidence, never authority by itself.",
    clauses(
        is_false("newest_wins", "the newest event does not win by recency"),
        is_false("selection_reason_is_timestamp",
                 "the selection reason is not a timestamp comparison"),
        nonempty("negative_evidence",
                 "the rejected proposal is retained as negative evidence"),
    ),
    surfaces=("guildhall explain --json",),
    vectors=("newer rejected PR versus current accepted ADR",),
    nodes=("test_v5_temporal.py::test_newest_wins_is_not_the_rule",),
)

_o(
    "V-5.rejected-pr", "V-5", "a newer rejected PR does not displace a current ADR",
    V, "case",
    "newer rejected PR vs current accepted ADR | ADR remains current; rejection is evidence",
    clauses(
        equals("state", "current", "the accepted ADR remains current"),
        is_true("rejection_recorded_as_evidence",
                "the rejection is retained as evidence, not discarded"),
        is_false("rejection_promoted",
                 "a rejected change never becomes the current decision"),
        nonempty("reducer_trace", "the reducer trace must be inspectable"),
    ),
    surfaces=("guildhall explain --json",),
    vectors=("newer rejected PR", "current accepted ADR"),
    nodes=("test_v5_temporal.py::test_rejected_pr_does_not_displace_current_adr",),
)

_o(
    "V-5.independence", "V-5", "copied repetition is not independent corroboration",
    A, "reduction-algorithm",
    "distinguish independent corroboration from common-source repetition;",
    clauses(
        at_least("repetition_count", 10, "ten copied comments are planted"),
        equals("independent_source_count", 1, "one independent decision is planted"),
        at_most("independent_corroboration_count", 2,
                "copies are not counted as independent supports"),
        is_false("vote_count_winner", "there is no vote-count winner"),
    ),
    surfaces=("guildhall explain --json",),
    vectors=("ten copies of one prior versus one independent decision",),
    nodes=("test_v5_temporal.py::test_copied_chorus_does_not_outweigh_one_independent_decision",),
)

_o(
    "V-5.scope", "V-5", "scope bounds authority, not prestige",
    A, "authority-seeking-loop",
    "The mapping resolves to exactly one authority identity for an exact scope; role "
    "prestige and recency are not an implicit lattice.",
    clauses(
        equals("state", "conflict",
               "repo code contradicting Company architecture is a conflict"),
        every("unknowns", "each blocking Unknown names a person",
              present("owner_identity", "a blocking Unknown always names a person"),
              present("owner_role", "and its role"),
              min_len=1),
        is_false("silent_local_override", "no silent local override occurs"),
    ),
    surfaces=("guildhall explain --json",),
    vectors=("repository code contradicting current Company architecture",),
    nodes=("test_v5_temporal.py::test_scope_bounds_authority_rather_than_prestige",),
)

_o(
    "V-5.runtime-vs-architecture", "V-5", "runtime wins diagnosis without authority",
    A, "reduction-algorithm",
    "Live runtime configuration may defeat a code-default diagnosis for an operational "
    "question without acquiring authority to rewrite a Company architecture decision.",
    clauses(
        equals("operational_value", "568", "diagnosis uses the live deployed value"),
        is_false("architecture_rewritten",
                 "the runtime observation does not rewrite architecture"),
        is_false("scope_is_architecture",
                 "the runtime observation's scope is not an architecture scope"),
        present("environment_owner", "the operational fact names its environment owner"),
    ),
    surfaces=("guildhall explain --json",),
    vectors=("deployed config 568 versus code default 90",),
    nodes=("test_v5_temporal.py::test_runtime_config_wins_diagnosis_without_acquiring_architecture_authority",),
)

_o(
    "V-5.unregistered-environment", "V-5", "unregistered environments are untrusted",
    A, "authority-seeking-loop",
    "The runtime adapter refuses trusted admission for an unregistered environment and "
    "creates a Company-steward registry Unknown instead; it never admits an observation "
    "carrying only a free-form owner string.",
    clauses(
        equals("state", "unknown", "the observation is untrusted"),
        nonempty("unknowns", "a registry Unknown is opened"),
        covers("unknown_owner_roles", ("company-steward",),
               "the registry Unknown is Company-steward owned"),
        is_false("free_form_owner_admitted",
                 "a free-form owner string is never admitted"),
    ),
    surfaces=("guildhall explain --json",),
    vectors=("runtime observation naming an unregistered environment",),
    nodes=("test_v5_temporal.py::test_unregistered_environment_is_untrusted_with_a_steward_unknown",),
)

# ==========================================================================
# V-6 — real authority round trip
# ==========================================================================

_o(
    "V-6.registration", "V-6", "a named Chief Architect is really registered",
    V, "setup",
    "Start `guildhalld` and register a named Chief Architect with a test signing key "
    "and a live channel endpoint/process separate from the caller.",
    clauses(
        is_true("service_started", "guildhalld is genuinely running"),
        is_true("registration_performed",
                "the authority is registered through a shipping surface"),
        present("registry_entry.authority_id", "a stable authority ID"),
        present("registry_entry.public_key", "the registered public key"),
        present("registry_entry.channel_reference", "an opaque channel reference"),
        equals("registered_public_key_matches_helper", True,
               "the registered key is the one the separate process holds"),
        absent("registry_entry.email", "contact data is not a registry value"),
        absent("registry_entry.private_key", "private keys are never registry values"),
    ),
    surfaces=("guildhalld", "authority registry"),
    vectors=("architecture:scheduling Chief Architect",),
    nodes=("test_v6_authority.py::test_service_starts_and_registers_a_named_chief_architect",),
)

_o(
    "V-6.question", "V-6", "a targeted question is delivered and guidance withheld",
    V, "delivery",
    "Assert a targeted question is delivered to that authority, dependent trusted "
    "guidance is withheld, and another role's signature is rejected.",
    clauses(
        at_least("question_count", 1, "a targeted question is created"),
        present("question.decision", "the decision at stake"),
        present("question.evidence_examined", "the evidence examined"),
        present("question.remaining_alternatives", "the remaining alternatives"),
        present("question.distortion_if_wrong", "the distortion if wrong"),
        present("question.question", "one precise question"),
        is_true("delivered", "the question is delivered through the registry channel"),
        present("delivery_receipt", "a delivery receipt is recorded"),
        is_false("trusted_recommendation_present",
                 "dependent trusted guidance is withheld"),
    ),
    surfaces=("guildhall questions ask", "guildhall project --json"),
    vectors=("high-distortion architectural ambiguity",),
    nodes=("test_v6_authority.py::test_high_distortion_unknown_sends_a_targeted_question_and_withholds_guidance",),
)

_o(
    "V-6.round-trip", "V-6", "the signed answer materially changes the decision",
    P, "P-6",
    "detect it, address the registered authority, ingest a signed answer, "
    "close/supersede the Unknown, rebuild the view, and materially change the "
    "projected guidance or decision",
    clauses(
        is_true("answer_from_separate_process",
                "the answer is signed by a process separate from the caller"),
        is_true("answer_admitted", "the signed in-scope answer is admitted"),
        member("unknown_status", ("closed", "superseded"), "the exact Unknown closes"),
        present("closure_event_id", "closure names the answer event"),
        is_true("decision_changed", "the projected decision materially changes"),
        is_true("decision_cites_answer", "the decision cites the answer"),
        is_true("trusted_recommendation_released",
                "dependent guidance is released once the Unknown closes"),
        present("authority_process_log_digest",
                "the authority process independently logs the round trip"),
    ),
    surfaces=("separate signing process", "guildhall ingest authority_answer"),
    vectors=("signed scoped answer",),
    nodes=("test_v6_authority.py::test_signed_answer_from_a_separate_process_materially_changes_the_decision",),
)

_o(
    "V-6.wrong-role", "V-6", "another role's signature is rejected",
    L, "questions",
    "Only the resolved named in-scope authority may answer.",
    clauses(
        is_true("attempt_made", "an out-of-scope answer is genuinely attempted"),
        member("refusal_code", ("AUTHORITY_WRONG_SCOPE", "SIGNATURE_INVALID"),
               "a typed authority refusal"),
        is_false("unknown_closed", "the Unknown does not close"),
    ),
    surfaces=("guildhall questions answer",),
    vectors=("repository maintainer answering an architecture question",),
    nodes=("test_v6_authority.py::test_another_roles_signature_is_rejected",),
)

_o(
    "V-6.degraded", "V-6", "unavailable authority yields a declared policy",
    P, "P-6",
    "Offline or unavailable authority does not become permission.",
    clauses(
        is_true("cache_state_constructed",
                "a real cache is built and then expired, not merely declared"),
        member("degraded_policy",
               ("block_dependent_decision", "reversible_sandbox_only_experiment",
                "named_human_granted_exception"),
               "one explicitly declared policy is chosen"),
        is_false("trusted_recommendation_present",
                 "offline authority does not become permission"),
        is_false("model_prior_answer", "guidance is never filled from the model prior"),
    ),
    surfaces=("guildhall project --json",),
    vectors=("authority unavailable and cache expired",),
    nodes=("test_v6_authority.py::test_unavailable_authority_yields_declared_degraded_policy",),
)

_o(
    "V-6.call-ceiling", "V-6", "the frozen service refuses the third call",
    P, "P-10",
    "The full system may ask at most two fact-only questions per task and receives no "
    "code, patch, or hidden-test advice.",
    clauses(
        equals("accepted_calls", 2, "exactly two calls per task are accepted"),
        equals("third_call_refusal_code", "LIMIT_EXCEEDED", "the third call refuses"),
        every("responses", "each reply contains fact and rationale only",
              present("answer", "a fact"),
              present("rationale", "a rationale"),
              is_false("contains_code", "never code or a solution"),
              min_len=2),
        present("service_request_log_digest",
                "the frozen service independently logs its requests"),
    ),
    surfaces=("frozen answer service",),
    vectors=("three calls for one task",),
    nodes=("test_v6_authority.py::test_frozen_answer_service_refuses_the_third_call_and_returns_no_code",),
)

# ==========================================================================
# V-7 — set-conditional projection
# ==========================================================================

_o(
    "V-7.candidate-set", "V-7", "the frozen candidate set is ingested, not selected",
    V, "fixture",
    "Construct a candidate set with high-scoring paraphrases, one distinct "
    "high-distortion compatibility invariant, one complementary test/rationale pair, "
    "one stale fact, and one high-distortion Unknown.",
    clauses(
        is_true("ingested_through_shipping_surface",
                "candidates are ingested through the ordinary corpus surface"),
        at_least("ingested_record_count", 6,
                 "every declared candidate role is really ingested"),
        covers("roles_present",
               ("high_scoring_paraphrase", "high_distortion_compatibility_invariant",
                "complementary_test", "complementary_rationale", "stale_fact",
                "high_distortion_unknown"),
               "every frozen role is present in the ingested corpus"),
        at_least("paraphrase_count", 2,
                 "plural paraphrases so redundancy is genuinely exercised"),
        is_false("fixture_mode_selector_used",
                 "no fixture-mode flag substitutes for ingested state"),
    ),
    surfaces=("guildhall ingest", "guildhall project --json"),
    vectors=("six frozen candidate roles",),
    nodes=("test_v7_projection.py::test_frozen_candidate_set_contains_every_declared_role",),
)

_o(
    "V-7.set-conditional", "V-7", "selection is conditional on the working set",
    P, "P-7",
    "The projector selects a set, not independently weighted nodes.",
    clauses(
        nonempty("cold_selection", "a cold projection selects something"),
        is_true("selection_changed_with_working_set",
                "selection changes when working-set IDs change"),
        equals("reselected_working_set_members", 0,
               "a fact already in the working set is not re-selected at full value"),
    ),
    surfaces=("guildhall project --working-set",),
    vectors=("cold working set", "warm working set"),
    nodes=("test_v7_projection.py::test_selection_changes_when_working_set_ids_change",),
)

_o(
    "V-7.no-crowding", "V-7", "duplicates do not crowd out the invariant",
    P, "P-7",
    "It must demonstrate that redundant high-similarity facts do not crowd out a "
    "distinct high-distortion constraint and that adding the same fact to a warm "
    "working set has near-zero marginal value.",
    clauses(
        is_true("invariant_selected",
                "the distinct high-distortion invariant is selected"),
        at_most("selected_paraphrase_count", 1, "duplicates show diminishing returns"),
        at_most("warm_readd_marginal_value", 0.05,
                "re-adding a resident fact has near-zero marginal value"),
    ),
    surfaces=("guildhall project --json",),
    vectors=("redundant paraphrases versus one invariant",),
    nodes=("test_v7_projection.py::test_duplicates_do_not_crowd_out_the_high_distortion_invariant",),
)

_o(
    "V-7.marginal-terms", "V-7", "the trace records the terms, not just a score",
    A, "set-conditional-projector",
    "The trace records the terms, not just a score.",
    clauses(
        every("trace", "every step records every marginal term",
              present("fact_id", "which candidate"),
              present("marginal_terms.newly_covered_distortion", "distortion term"),
              present("marginal_terms.authority_and_validity_gain", "authority term"),
              present("marginal_terms.complementarity_gain", "complementarity term"),
              present("marginal_terms.uncertainty_reduction", "uncertainty term"),
              present("marginal_terms.redundancy", "redundancy term"),
              present("marginal_terms.retrieval_and_residency_cost", "cost term"),
              present("marginal_terms.stale_or_conflict_risk", "risk term"),
              present("current_set_size", "the set it was scored against"),
              min_len=1),
    ),
    surfaces=("guildhall project --json",),
    vectors=("greedy selection trace",),
    nodes=("test_v7_projection.py::test_marginal_value_is_recomputed_against_the_current_set",),
)

_o(
    "V-7.complementarity", "V-7", "complementarity visible, redundancy penalised",
    A, "set-conditional-projector",
    "Complementarity permits a test plus rationale to be jointly useful.",
    clauses(
        equals("complementary_pair_selected", 2,
               "the test/rationale pair is jointly selected"),
        every("complementary_steps", "each shows a positive complementarity gain",
              at_least("complementarity_gain", 0.000001, "positive complementarity"),
              min_len=2),
        every("penalised_steps", "each redundancy penalty names its basis",
              at_least("redundancy", 0.000001, "a positive redundancy penalty"),
              nonempty("redundancy_basis", "explicit edge, provenance or similarity"),
              min_len=1),
    ),
    surfaces=("guildhall project --json",),
    vectors=("complementary test/rationale pair", "high-similarity paraphrases"),
    nodes=("test_v7_projection.py::test_complementarity_is_visible_and_redundancy_is_penalised",),
)

_o(
    "V-7.stale-fact", "V-7", "a stale fact is withheld and opens an owned Unknown",
    P, "P-4",
    "A stale or disputed fact is worse than a missing fact: it is withheld from "
    "trusted projection and produces an owned Unknown.",
    clauses(
        is_false("stale_fact_selected",
                 "a stale fact never enters trusted projection"),
        at_least("owned_unknown_count", 1,
                 "withholding must open an owned Unknown, not silently drop"),
        every("owned_unknowns", "each Unknown names its owner",
              present("owner_role", "owning role"),
              present("owner_identity", "owning identity"),
              min_len=1),
    ),
    surfaces=("guildhall project --json",),
    vectors=("stale fact",),
    nodes=("test_v7_projection.py::"
           "test_stale_fact_is_withheld_and_produces_an_owned_unknown",),
)

_o(
    "V-7.no-voi-claim", "V-7", "no calibrated causal VOI claim is made here",
    V, "scope",
    "This fixture proves selector mechanics only. Causal evidence for set "
    "selection comes from `topk-maintained` versus `full-system` in V-10, with "
    "natural-corpus redundancy cluster sizes and source dependence reported "
    "rather than manufactured.",
    clauses(
        equals("forbidden_claims_found", 0,
               "the projector may not claim calibrated causal VOI"),
        present("voi_approximation",
                "the approximation actually used must be inspectable"),
        is_true("scope_limited_to_selector_mechanics",
                "this fixture's claim is bounded to selector mechanics"),
    ),
    surfaces=("guildhall project --json",),
    vectors=("selector mechanics",),
    nodes=("test_v7_projection.py::test_no_calibrated_causal_voi_claim_is_made",),
)

_o(
    "V-7.voi-stop", "V-7", "the loop stops on net marginal value",
    V, "stop",
    "Escalate evidence tiers and assert the loop stops on net marginal value, not a "
    "filled token window.",
    clauses(
        nonempty("tier_escalation", "the tier escalation is recorded"),
        is_true("tiers_in_frozen_order", "tiers escalate in the frozen order"),
        member("stopping_reason",
               ("nonpositive_net_marginal_value", "sufficiency_predicate_met",
                "authority_question_raised"),
               "the loop stops on value, sufficiency or an authority question"),
        at_most("selected_fact_count", 32, "the 32-fact projection ceiling"),
        at_most("projection_bytes", 131072, "the 128 KiB projection ceiling"),
        is_false("stopped_at_byte_ceiling",
                 "stopping only because the window filled is the forbidden case"),
    ),
    surfaces=("guildhall project --json",),
    vectors=("seven frozen evidence tiers",),
    nodes=("test_v7_projection.py::test_loop_stops_on_net_marginal_value_not_a_filled_window",),
)

_o(
    "V-7.query-log", "V-7", "the query log records every declared field",
    A, "set-conditional-projector",
    "Query logs record retrievals, returned and selected IDs, working set, edit-time "
    "residency, declared use, outcome, and cost.",
    clauses(
        every("query_log", "each entry records every declared field",
              present("requested", "requested"),
              present("returned", "returned"),
              present("selected_ids", "selected IDs"),
              present("working_set", "working set"),
              present("resident_at_dependent_edit", "edit-time residency"),
              present("declared_use", "declared use"),
              present("marginal_gain", "marginal gain"),
              present("stopping_reason", "stopping reason"),
              present("outcome", "outcome"),
              present("cost", "cost"),
              min_len=1),
    ),
    surfaces=("guildhall status --json",),
    vectors=("projection query log",),
    nodes=("test_v7_projection.py::test_query_log_records_every_declared_field",),
)

# ==========================================================================
# V-8 — Company references from .kin/
# ==========================================================================

_o(
    "V-8.fresh-clone", "V-8", "a fresh clone resolves without copying prose",
    V, "fresh-clone",
    "From a fresh clone, resolve a valid Company architecture reference and project "
    "its live statement without copying it into Git.",
    clauses(
        is_true("company_service_running",
                "a real Company service serves the reference"),
        is_true("reference_resolved", "the reference resolves from a fresh clone"),
        nonempty("projected_statement", "the live statement is projected"),
        equals("git_object_findings", 0,
               "no Company prose is copied into any Git object"),
        equals("kin_event_prose_hits", 0, "no Company prose is copied into .kin/"),
    ),
    surfaces=("git objects", "guildhall project --json", "Company service"),
    vectors=("fresh clone with a valid reference",),
    nodes=("test_v8_company_refs.py::test_fresh_clone_resolves_the_reference_without_copying_prose",),
)

_o(
    "V-8.reference-fields", "V-8", "the reference carries exactly Company-owned fields",
    A, "company-reference",
    "`CompanyReference` copies the Company-published Company ID, fact ID, "
    "semantic-content digest, `digest_alg_version`, authority, observed valid interval, "
    "`company_criticality`, and relation.",
    clauses(
        is_true("event_signature_valid",
                "the referencing event is genuinely signed and verifies"),
        is_true("event_path_matches_digest",
                "the event is stored at its computed content-addressed path"),
        present("reference.company_id", "Company ID"),
        present("reference.fact_id", "fact ID"),
        present("reference.semantic_digest", "semantic digest"),
        present("reference.digest_alg_version", "digest algorithm version"),
        present("reference.authority", "authority"),
        present("reference.valid_from", "validity start"),
        present("reference.valid_until", "validity end"),
        member("reference.relation",
               ("applies", "specializes", "implements", "contradicts",
                "exception_request"),
               "a typed relationship"),
        absent("reference.local_dependence_class",
               "local dependence is a separate maintainer-owned fact"),
        absent("reference.statement", "the reference does not copy Company prose"),
    ),
    surfaces=(".kin/events",),
    vectors=("signed CompanyReference event",),
    nodes=("test_v8_company_refs.py::test_reference_carries_exactly_the_company_owned_field_set",),
)

_o(
    "V-8.stricter-class", "V-8", "the stricter class controls freshness",
    A, "company-reference",
    "Projection uses the stricter of Company criticality and local dependence; raising "
    "the local class records its maintainer, and a missing local owner is a "
    "repository-maintainer Unknown.",
    clauses(
        every("combinations", "each class combination derives the stricter result",
              present("company_class", "Company criticality"),
              present("local_class", "local dependence"),
              present("effective_class", "derived effective class"),
              is_true("is_stricter", "the derived value is the stricter input"),
              present("dominating_input", "the trace records which input dominated"),
              present("company_owner", "both input owners are recorded"),
              present("local_owner", "both input owners are recorded"),
              is_true("planted_as_signed_state",
                      "both classes come from signed state, not a selector"),
              min_len=3),
    ),
    surfaces=("guildhall explain --json", "signed Company and Codebase facts"),
    vectors=("advisory+safety", "safety+advisory", "advisory+advisory"),
    nodes=("test_v8_company_refs.py::test_stricter_of_company_and_local_class_controls_freshness",),
)

_o(
    "V-8.steward-only-exception", "V-8", "only a steward may sign a relaxation",
    P, "P-8",
    "Only a Company steward can authorize an exception to Company architecture. A "
    "Codebase maintainer or Factory role may request one but cannot mint it.",
    clauses(
        is_true("request_accepted", "a maintainer exception request is accepted"),
        is_false("maintainer_minted_accepted",
                 "a maintainer-minted relaxation is refused"),
        member("refusal_code", ("AUTHORITY_WRONG_SCOPE", "SIGNATURE_INVALID"),
               "a typed authority refusal"),
        is_true("steward_relaxation_admitted",
                "the steward-signed relaxation is admitted"),
        is_true("expiry_restores_company_class",
                "expiry restores the unrelaxed Company class"),
    ),
    surfaces=("guildhall ingest kindex", "guildhall explain --json"),
    vectors=("maintainer request", "maintainer mint", "steward relaxation", "expiry"),
    nodes=("test_v8_company_refs.py::test_only_company_steward_may_sign_a_relaxation",
           "test_v8_company_refs.py::test_maintainer_may_request_but_not_mint_an_exception"),
)

_o(
    "V-8.digest-attribution", "V-8", "digest mismatch attribution truth table",
    A, "company-reference",
    "A differing historical digest means a changed/corrupt reference and a "
    "steward-owned Unknown; a matching historical digest means a client "
    "canonicalization defect and a client-owned Unknown; unavailable or "
    "no-longer-retained historical version yields a Company publication-retention "
    "Unknown without accusing the client.",
    clauses(
        every("scenarios", "each attribution case is built from live Company state",
              present("scenario", "which case"),
              is_true("company_queried",
                      "the client actually queries Company for the historical digest"),
              present("owner_role", "the resulting Unknown owner"),
              is_true("owner_matches_expected", "the attribution is correct"),
              min_len=4),
        is_false("unavailable_company_accuses",
                 "an unavailable Company withholds without accusation"),
    ),
    surfaces=("Company service", "guildhall explain --json"),
    vectors=("historical differs", "historical matches", "version missing",
             "Company unavailable"),
    nodes=("test_v8_company_refs.py::test_digest_mismatch_attribution_truth_table",),
)

_o(
    "V-8.uncertified", "V-8", "uncertified clone and attacker fork yield zero trusted",
    V, "uncertified",
    "Fresh clone with no certificate or Company access yields zero trusted facts and "
    "one actionable certificate Unknown.",
    clauses(
        equals("trusted_facts", 0, "an uncertified clone yields zero trusted facts"),
        equals("certificate_unknown_count", 1, "exactly one certificate Unknown"),
        present("certificate_unknown.owner_identity", "the Unknown names its owner"),
        present("certificate_unknown.response_due_at", "with a deadline"),
        equals("fork_trusted_facts", 0,
               "a self-issued certificate produces no trusted facts"),
        at_least("fork_foreign_event_count", 1,
                 "foreign parent events are counted and reported"),
    ),
    surfaces=("guildhall status --json",),
    vectors=("uncertified clone", "attacker fork with a self-issued certificate"),
    nodes=("test_v8_company_refs.py::test_uncertified_clone_and_attacker_fork_both_yield_zero_trusted_facts",),
)

_o(
    "V-8.identity", "V-8", "identity is stable and never silently repins",
    A, "entity-ownership",
    "A later hint returning a different UUID or certificate blocks with a "
    "steward-owned identity Unknown; it never silently repins.",
    clauses(
        is_true("uuid_stable_under_hint_change",
                "changing the discovery hint does not change identity"),
        is_false("silently_repinned", "a differing UUID never silently repins"),
        covers("repin_unknown_owner_roles", ("company-steward",),
               "a steward-owned identity Unknown blocks"),
        is_true("two_certificates_fail_fsck",
                "two certificates for one UUID fail fsck"),
    ),
    surfaces=("guildhall status --json", "guildhall fsck"),
    vectors=("changed hint", "hint resolving to a different UUID",
             "two certificates for one UUID"),
    nodes=("test_v8_company_refs.py::test_identity_is_stable_under_hint_change_and_blocks_on_uuid_change",),
)

_o(
    "V-8.publish-manifest", "V-8", "monotonic manifest admission",
    L, "error-contract",
    "`MANIFEST_HEAD_REGRESSION` | published reachable lineage lowers event count "
    "without rewrite event | 4",
    clauses(
        is_true("first_publication_admitted",
                "a maintainer-signed publication is admitted"),
        equals("regression_refusal_code", "MANIFEST_HEAD_REGRESSION",
               "a count regression is refused"),
        is_true("remediation_names_rollback_event",
                "the remediation names the signed rollback/rewrite event"),
        is_true("signed_rewrite_admitted",
                "a separately signed rewrite event does explain the regression"),
    ),
    surfaces=("guildhall repo publish-manifest", "Company service"),
    vectors=("monotonic publication", "count regression", "signed rewrite"),
    nodes=("test_v8_company_refs.py::test_publish_manifest_enforces_monotonic_counts",),
)

_o(
    "V-8.expiry", "V-8", "Company emits its own observation-expired event",
    V, "expiry",
    "On `fresh_until`, Company itself emits one observation-expired event, retires the "
    "old observation to historical-only, and opens its steward-owned publication "
    "Unknown without waiting for maintainer/clone activity.",
    clauses(
        equals("observation_expired_events", 1, "exactly one expiry event"),
        equals("observation_status", "historical-only",
               "the old observation is retired to historical-only"),
        covers("unknown_owner_roles", ("company-steward",),
               "a Company-steward publication Unknown opens"),
        is_true("emitted_without_clone_activity",
                "Company does not wait for a clone or maintainer to notice"),
    ),
    surfaces=("Company service", "guildhall status --json"),
    vectors=("fresh_until lapse",),
    nodes=("test_v8_company_refs.py::test_company_emits_its_own_observation_expired_event",),
)

_o(
    "V-8.cache-table", "V-8", "the cache truth table is exhausted",
    V, "truth-table",
    "Exhaust the revocation-fresh/stale × fact-fresh/stale × safety/advisory truth "
    "table; stale revocation dominates safety projection.",
    clauses(
        every("rows", "each row is produced from real signed cache state",
              present("revocation", "revocation snapshot state"),
              present("fact_validity", "fact validity state"),
              present("dependence", "dependence class"),
              present("projection", "the resulting projection"),
              is_true("state_constructed",
                      "the cache state is really constructed, not selected"),
              is_true("matches_expected", "the projection matches the frozen row"),
              min_len=6),
        is_true("stale_revocation_dominates_safety",
                "stale revocation dominates safety projection"),
    ),
    surfaces=("Company cache", "guildhall project --json"),
    vectors=("six frozen truth-table rows",),
    nodes=("test_v8_company_refs.py::test_cache_disagreement_truth_table",),
)

_o(
    "V-8.counts-only", "V-8", "uncertified mode emits counts and status only",
    A, "entity-ownership",
    "Event bodies are visible only through an explicit diagnostic inspect command and "
    "never enter SessionStart, a host projection, model request, or tool-result "
    "envelope.",
    clauses(
        at_least("event_count_in_repository", 1,
                 "events must exist for the counts-only claim to mean anything"),
        equals("event_bodies_in_payload", 0, "no event body reaches the host payload"),
        present("counts", "counts and status are present"),
        is_true("no_statement_leaked", "no unverified statement text appears"),
    ),
    surfaces=("guildhall hooks dispatch",),
    vectors=("uncertified Codebase-only SessionStart",),
    nodes=("test_v8_company_refs.py::test_uncertified_codebase_only_mode_emits_counts_and_status_only",),
)

# ==========================================================================
# V-9 — real host lifecycle
# ==========================================================================

_o(
    "V-9.setup", "V-9", "dry run changes nothing; approval installs expected files",
    V, "setup",
    "Verify setup dry-run exposes permission needs and changes nothing; explicit "
    "approval installs only expected files.",
    clauses(
        is_true("host_executable_resolved", "a real host executable is resolved"),
        present("plan.files", "the plan lists exact files"),
        present("plan.commands", "the plan lists exact commands"),
        present("plan.permissions", "the plan lists permissions"),
        equals("files_changed_by_plan", 0, "the dry run changes nothing"),
        equals("denied_install_refusal_code", "HOOK_APPROVAL_REQUIRED",
               "an unapproved install refuses"),
        equals("files_changed_by_denied_install", 0,
               "a refused install leaves config untouched"),
        is_true("approved_install_performed",
                "an approved install is genuinely performed"),
        nonempty("files_installed_by_approval",
                 "approval installs the expected files"),
        equals("unexpected_files_installed", 0, "only expected files are installed"),
        equals("bypass_flags_found", 0,
               "no --yes, silent write or permission bypass exists"),
    ),
    surfaces=("guildhall hooks plan", "guildhall hooks install", "isolated HOME"),
    vectors=("codex", "claude"),
    nodes=("test_v9_host_lifecycle.py::test_hooks_plan_is_read_only_and_install_requires_native_approval",),
)

_o(
    "V-9.native-events", "V-9", "native host events prime, capture and exclude Personal",
    V, "events",
    "Invoke native SessionStart, prompt/observation, pre-edit, PreCompact, and Stop/end "
    "payloads.",
    clauses(
        covers("events_dispatched",
               ("SessionStart", "UserPromptSubmit", "PreToolUse", "PreCompact", "Stop",
                "SessionEnd"),
               "every native host event is dispatched"),
        at_least("host_invocation_records", 1,
                 "a real host executable invocation is witnessed"),
        is_true("not_mocked", "the invocation witness proves a real execution"),
        present("session_start.repository_root", "SessionStart resolves the Git root"),
        present("session_start.company_state", "Company access is resolved"),
        equals("personal_root_occurrences", 0,
               "no host payload carries the Personal root"),
        is_true("capture_continued", "capture continues during the session"),
        is_true("stop_checkpointed", "Stop/SessionEnd checkpoints observations"),
    ),
    surfaces=("guildhall hooks dispatch", "installed host config"),
    vectors=("codex", "claude"),
    nodes=("test_v9_host_lifecycle.py::test_native_host_events_prime_capture_and_exclude_personal",),
)

_o(
    "V-9.parity", "V-9", "matched conversations produce identical canonical payloads",
    V, "parity",
    "For matched conversations, canonical facts/projections/receipts match across hosts.",
    clauses(
        equals("hosts_observed", 2, "both hosts must produce a payload to compare"),
        nonempty("canonical_facts", "canonical facts are non-empty"),
        is_true("facts_match", "canonical facts match across hosts"),
        is_true("decisions_match", "canonical decisions match across hosts"),
        is_true("receipts_match", "canonical receipts match across hosts"),
    ),
    surfaces=("guildhall session observe --json",),
    vectors=("matched Codex and Claude conversation",),
    nodes=("test_v9_host_lifecycle.py::test_matched_conversations_produce_identical_canonical_payloads",),
)

_o(
    "V-9.latency", "V-9", "every start state clears the two-second p95",
    V, "latency",
    "Measure warm, cold, invalid-cache, and full-fsck-required SessionStart separately; "
    "run at least 200 invocations per host/state on the recorded proof machine, report "
    "CPU/RAM/filesystem, and require every state's p95 under two seconds.",
    clauses(
        every("states", "each start state is really constructed and measured",
              present("state", "which start state"),
              is_true("state_constructed",
                      "the cache/fsck precondition is genuinely created"),
              at_least("invocations", 200, "at least 200 invocations per host/state"),
              at_most("p95_seconds", 2.0, "the two-second p95 budget"),
              equals("refusals", 0,
                     "latency may not pass by refusing every invocation"),
              min_len=4),
        present("machine.cpu", "CPU is reported"),
        present("machine.ram", "RAM is reported"),
        present("machine.filesystem", "filesystem is reported"),
    ),
    surfaces=("guildhall hooks dispatch SessionStart",),
    vectors=("warm", "cold", "invalid-cache", "full-fsck-required"),
    nodes=("test_v9_host_lifecycle.py::test_session_start_p95_under_two_seconds_in_every_state",),
)

_o(
    "V-9.blackhole", "V-9", "a blackholed endpoint degrades loudly inside budget",
    A, "host-lifecycle",
    "It uses a previously verified cache and launches asynchronous Company refresh with "
    "a 250-millisecond connection budget; a blackholed endpoint cannot hold the host "
    "open.",
    clauses(
        is_true("blackhole_active", "the endpoint genuinely accepts and never answers"),
        at_most("p95_seconds", 2.0, "SessionStart stays inside the two-second p95"),
        at_most("connect_budget_seconds", 0.250, "the 250 ms Company connect budget"),
        at_least("payload_count", 1, "SessionStart still produces a payload"),
        is_true("degraded_loudly", "affected facts are withheld and loudly degraded"),
        equals("trusted_company_facts_while_refreshing", 0,
               "no fact becomes trusted while asynchronous work is running"),
    ),
    surfaces=("guildhall hooks dispatch SessionStart",),
    vectors=("blackholed Company endpoint",),
    nodes=("test_v9_host_lifecycle.py::test_blackholed_company_endpoint_degrades_loudly_inside_the_budget",),
)

_o(
    "V-9.topology", "V-9", "worktrees share identity, nested roots do not",
    V, "topology",
    "Launch inside a normal clone, linked worktree, submodule, and nested repository: "
    "common-dir worktrees share UUID, while nested/submodule roots require independent "
    "certificates and never inherit superproject fact bodies.",
    clauses(
        covers("topologies",
               ("clone", "linked_worktree", "submodule", "nested"),
               "all four topologies are launched"),
        is_true("worktree_shares_uuid",
                "a linked worktree shares the certified repository UUID"),
        is_true("nested_identity_independent",
                "a nested repository is an independent identity"),
        is_true("submodule_identity_independent",
                "a submodule is an independent identity"),
        equals("inherited_superproject_facts", 0,
               "nested roots never inherit superproject fact bodies"),
    ),
    surfaces=("guildhall doctor --json",),
    vectors=("clone", "linked worktree", "submodule", "nested repository"),
    nodes=("test_v9_host_lifecycle.py::test_worktrees_share_uuid_while_nested_roots_require_their_own_certificate",),
)

_o(
    "V-9.soak", "V-9", "the 20-session soak meets warm-path and fsck bounds",
    V, "soak",
    "Across the 20-session private soak, at least 90% of starts must take the warm "
    "verified path and deliver nonempty trusted context when eligible facts exist; "
    "after the first cold start, at most 5% of ordinary append/branch-switch/restart/"
    "linked-worktree starts may require a full fsck.",
    clauses(
        equals("sessions", 20, "exactly the twenty-session soak"),
        at_least("eligible_facts_present", 1,
                 "eligible facts must exist for the context claim to bind"),
        at_least("warm_path_fraction", 0.90, "at least 90% take the warm verified path"),
        at_most("full_fsck_fraction", 0.05,
                "at most 5% of ordinary starts require a full fsck"),
        at_least("nonempty_trusted_context_sessions", 1,
                 "latency may not pass by always degrading"),
        equals("refused_starts", 0, "a refusing start is not a warm start"),
    ),
    surfaces=("guildhall hooks dispatch SessionStart",),
    vectors=("append", "branch switch", "restart", "linked worktree"),
    nodes=("test_v9_host_lifecycle.py::test_twenty_session_soak_warm_path_and_fsck_incidence",),
)

_o(
    "V-9.prompt-budget", "V-9", "four total prompts per sliding hour across destinations",
    P, "P-9",
    "Destinations share that four-slot ceiling and may have stricter sublimits; two "
    "concurrent Codex/Claude sessions on the same host instance share the serialized "
    "shard.",
    clauses(
        at_least("eligible_candidates", 5,
                 "more eligible candidates than slots, so the ceiling binds"),
        at_least("rendered", 1,
                 "at least one prompt renders; zero prompts is not compliance"),
        at_most("rendered", 4, "at most four total prompts per sliding hour"),
        at_least("suppressed", 1, "excess proposals are suppressed, not dropped"),
        present("shard.shard_id", "the host instance owns its shard"),
        is_true("shard.signed", "the shard observation is host-signed"),
        is_true("unknown_global_total_warning",
                "doctor warns that no global cross-machine total is known"),
    ),
    surfaces=("guildhall proposals list", "guildhall doctor --json"),
    vectors=("company", "codebase", "interleaved Codex and Claude sessions"),
    nodes=("test_v9_fatigue.py::test_four_total_per_hour_shared_across_destinations",),
)

_o(
    "V-9.reset", "V-9", "reset clears only the consecutive counter, once per hour",
    L, "reset",
    "`reset` only clears the three- consecutive counter after a real new primary-task "
    "event, is limited to once per hour, and records its closed reason code.",
    clauses(
        is_true("first_reset_accepted", "a reset after a new primary task is accepted"),
        equals("second_reset_refusal_code", "LIMIT_EXCEEDED",
               "a second reset inside the cooldown refuses"),
        is_true("hourly_ceiling_preserved", "a reset never clears the hourly ceiling"),
        equals("consecutive_after_reset", 0, "the consecutive counter clears"),
        is_false("free_text_reason_accepted", "reason codes are a closed set"),
    ),
    surfaces=("guildhall proposals reset",),
    vectors=("new-primary-task", "operator-recovery", "host-restart"),
    nodes=("test_v9_fatigue.py::test_reset_clears_only_the_consecutive_counter_once_per_hour",),
)

_o(
    "V-9.reissue-atomicity", "V-9", "reissue and reservation commit in one transaction",
    V, "reissue",
    "Reissue eligibility, unique digest lock, total slot reservation, and consecutive "
    "count must commit in one `BEGIN IMMEDIATE`;",
    clauses(
        at_least("eligible_candidates", 1,
                 "an eligible candidate must exist for a reissue race to mean anything"),
        at_least("issued", 1, "at least one reissue succeeds; zero is not compliance"),
        is_true("candidate_ids_distinct", "each reissue creates a new candidate ID"),
        is_true("digests_distinct", "no two reissues commit the same digest"),
        at_most("hourly_consumed", 4, "the racing reissues do not over-reserve"),
        is_false("untrusted_churn_triggered_reissue",
                 "untrusted branch churn cannot trigger byte-change reissue"),
    ),
    surfaces=("guildhall proposals reissue", "guildhall doctor --json"),
    vectors=("four racing reissues", "untrusted branch churn"),
    nodes=("test_v9_fatigue.py::test_reissue_and_reservation_commit_in_one_immediate_transaction",),
)

_o(
    "V-9.interleave", "V-9", "interleaved sessions never exceed the shard ceiling",
    V, "interleave",
    "Force Codex and Claude sessions on one host instance to interleave exactly between "
    "slot check and render.",
    clauses(
        at_least("eligible_candidates", 6,
                 "more eligible work than slots so the ceiling binds"),
        at_least("rendered", 1, "prompts genuinely render"),
        at_most("rendered", 4, "the shard ceiling holds under interleaving"),
        is_true("interleaving_witnessed",
                "the interleaving is independently witnessed, not merely requested"),
        is_true("crash_after_reservation_counted",
                "a crash after reservation remains counted until expiry"),
        present("delivery_loss_rate", "delivery-loss rate is explicit"),
    ),
    surfaces=("guildhall proposals list", "guildhall doctor --json"),
    vectors=("Codex and Claude on one host instance",),
    nodes=("test_v9_fatigue.py::test_interleaved_sessions_never_exceed_four_prompts_per_window",),
)

_o(
    "V-9.operator", "V-9", "the blinded operator exercise is completed",
    P, "P-9",
    "A 20-item blinded operator exercise must achieve at least 95% correct "
    "approve/reject decisions with median decision time at most 30 seconds.",
    clauses(
        equals("item_count", 20, "exactly twenty items"),
        is_true("blinded", "the exercise is blinded"),
        equals("decisions_recorded", 20, "every item receives a real decision"),
        at_least("accuracy", 0.95, "at least 95% correct decisions"),
        at_most("median_decision_seconds", 30.0, "median decision time at most 30s"),
        is_true("gold_withheld_from_operator_input",
                "the gold decision never reaches the operator input"),
    ),
    surfaces=("operator exercise transcript",),
    vectors=("twenty blinded approve/reject items",),
    nodes=("test_v9_fatigue.py::test_blinded_operator_exercise_accuracy_and_median_time",),
)

_o(
    "V-9.adequacy", "V-9", "corpus growth is adequate under the fatigue ceiling",
    P, "P-9",
    "the distortion/authority queue must place at least 18 of those facts into a human "
    "decision slot within five simulated sliding-hour windows, admit at least 17 correct "
    "facts after decisions, and surface no more than four total prompts in any window",
    clauses(
        equals("observations_ingested", 100, "the frozen 100-observation workload runs"),
        equals("durable_facts", 20, "twenty independently gold-labelled durable facts"),
        at_least("decision_slots", 18, "at least 18 facts receive a decision slot"),
        at_least("admitted_correct", 17, "at least 17 correct facts admit"),
        every("windows", "no window exceeds the four-prompt ceiling",
              at_most("prompts", 4, "four total prompts per window"),
              min_len=5),
        is_false("low_authority_churn_displaced_high_distortion",
                 "low-authority churn cannot displace a higher-distortion fact"),
        is_true("gold_withheld_from_product",
                "the gold labels never reach the product input"),
    ),
    surfaces=("guildhall session observe", "guildhall status --json"),
    vectors=("100 observations across five sliding-hour windows",),
    nodes=("test_v9_fatigue.py::test_corpus_growth_adequacy_under_the_fatigue_ceiling",),
)


_o(
    "V-10.envelope", "V-10", "the eleven arms and the call envelope are enumerated",
    V, "envelope",
    "Before author-lane ratification, the Validator publishes this unavoidable call-count "
    "envelope for eleven arms, three seeds, twelve all-arm pilot tasks, two graders, and the "
    "full 10% block reserve (gate/calibration calls are additional):",
    clauses(
        covers("arms",
               ("baseline", "null-system", "static-prior", "distractor", "topk-raw",
                "topk-maintained", "authority-only", "codebase-only", "company-only",
                "full-system", "oracle-spec"),
               "every one of the eleven ratified arms is enumerated"),
        every("envelope_rows", "each published row matches the frozen formula",
              present("n", "powered task N"),
              present("reserved_coding_calls", "reserved coding calls"),
              present("reserved_scorer_calls", "reserved scorer calls"),
              is_true("matches_formula", "the row matches 396 + 33*N + 11*ceil(0.10*3*N)"),
              min_len=4),
    ),
    surfaces=("frozen experiment manifest",),
    vectors=("eleven arms", "N in {8, 32, 71, 126}"),
    nodes=("test_v10_protocol.py::test_eleven_arms_are_frozen_and_enumerated",
           "test_v10_protocol.py::test_published_call_envelope_matches_the_formula"),
    fail_closed=INSTRUMENT,
)


# --------------------------------------------------------------------------
# Registry access
# --------------------------------------------------------------------------

# ==========================================================================
# Nonfunctional proof gates
# ==========================================================================

_o("NF.help", "NONFUNCTIONAL", "commands have bounded help", V, "packaging",
   "Python package installs in a clean environment and commands have bounded help.",
   clauses(every("commands", "each command exposes bounded help",
                 present("command", "command name"),
                 at_most("help_bytes", 65536, "help output is bounded"),
                 equals("exit_code", 0, "help exits zero"), min_len=5)),
   surfaces=("guildhall --help",), vectors=("top-level commands",),
   nodes=("test_nonfunctional.py::test_commands_have_bounded_help",))

_o("NF.roots", "NONFUNCTIONAL", "roots are explicit and escapes fail closed",
   V, "roots",
   "All service/data roots are explicit; default bind is loopback; filesystem "
   "modes are asserted; symlinks and escapes fail closed.",
   clauses(is_true("loopback_only", "the default bind is loopback"),
           every("roots", "each root is explicit and restrictively moded",
                 present("root", "root path"), present("mode", "observed mode"),
                 is_true("restrictive", "mode is no broader than declared"),
                 min_len=3),
           every("escape_probes", "each escape probe fails closed",
                 present("probe", "what was attempted"),
                 is_true("refused", "the escape was refused"), min_len=2)),
   surfaces=("guildhall status", "filesystem"), vectors=("symlink", "path escape"),
   nodes=("test_nonfunctional.py::"
          "test_roots_are_explicit_modes_restrictive_and_escapes_fail_closed",))

_o("NF.determinism", "NONFUNCTIONAL", "validation and rebuild are deterministic",
   V, "determinism",
   "Schema validation, canonicalization, migrations, and rebuilds are deterministic.",
   clauses(is_true("rebuild_identical", "two identical rebuilds agree"),
           nonempty("rebuild_digest", "the rebuild must produce a digest"),
           is_true("canonicalisation_identical", "canonical bytes are stable"),
           equals("schema_refusals", 0, "a valid document is not refused")),
   surfaces=("guildhall corpus rebuild",), vectors=("rebuild", "canonicalisation"),
   nodes=("test_nonfunctional.py::test_schema_validation_and_rebuild_are_deterministic",))

_o("NF.logs", "NONFUNCTIONAL", "logs are structured and carry no raw private bytes",
   V, "logs",
   "Logs are structured and contain IDs/digests/statuses, never raw private messages.",
   clauses(at_least("log_lines", 1, "there must be log output to inspect"),
           is_true("structured", "every line parses as a structured record"),
           equals("raw_private_findings", 0, "no raw private byte appears")),
   surfaces=("guildhall doctor", "log files"), vectors=("structured log",),
   nodes=("test_nonfunctional.py::"
          "test_logs_are_structured_and_carry_no_raw_private_messages",))

_o("NF.timeouts", "NONFUNCTIONAL", "external calls time out and failed writes do not admit",
   V, "timeouts",
   "Every external/model/process call has a timeout and typed failure; failed "
   "writes do not become admitted facts.",
   clauses(is_true("timeout_observed", "a hung dependency times out"),
           present("timeout_refusal_code", "the timeout is typed"),
           at_most("observed_seconds", 120.0, "the call returns within its bound"),
           equals("admitted_after_failed_write", 0,
                  "a failed write never becomes an admitted fact")),
   surfaces=("guildhall status",), vectors=("hung dependency", "failed write"),
   nodes=("test_nonfunctional.py::"
          "test_external_calls_have_timeouts_and_failed_writes_are_not_admitted",))

_o("NF.diagnostics", "NONFUNCTIONAL", "diagnostics are executable after restart",
   V, "diagnostics",
   "`fsck`, `doctor`, corpus status, question status, and experiment status are "
   "executable and useful after restart.",
   clauses(every("diagnostics", "each diagnostic runs after restart",
                 present("command", "which diagnostic"),
                 is_true("executable", "it ran"),
                 is_true("useful", "it emitted an inspectable object"), min_len=4),
           is_true("survives_restart", "the diagnostics run after a restart")),
   surfaces=("guildhall fsck", "guildhall doctor", "guildhall explain"),
   vectors=("restart",),
   nodes=("test_nonfunctional.py::test_diagnostics_are_executable_and_useful_after_restart",))

_o("NF.http", "NONFUNCTIONAL", "HTTP rejects every declared probe", V, "http",
   "Guildhall HTTP rejects unauthenticated reads, non-loopback Host, "
   "Origin-bearing requests, and non-JSON writes; all receive typed "
   "remediation-safe errors.",
   clauses(every("probes", "each declared probe is refused with a typed error",
                 present("probe", "which probe"),
                 is_true("refused", "the probe was refused"),
                 is_true("bounded_body", "the error body is bounded"), min_len=4)),
   surfaces=("guildhalld HTTP",), vectors=("unauthenticated read", "non-loopback host",
                                           "origin header", "non-JSON write"),
   nodes=("test_nonfunctional.py::test_http_rejects_every_declared_probe",))

_o("NF.ceilings", "NONFUNCTIONAL", "every ceiling refuses with an omitted count",
   V, "operational-limits",
   "shared event: 64 KiB; `.kin/` intake: 10,000 events / 128 MiB;",
   clauses(every("ceilings", "each ceiling refuses and reports its omitted count",
                 present("ceiling", "which ceiling"),
                 is_true("constructed", "the input really reached the ceiling"),
                 is_true("refused", "the ceiling refused"),
                 present("omitted_count", "the omitted count is reported"),
                 min_len=5)),
   surfaces=("guildhall ingest", "guildhall project"),
   vectors=("source body", "observation batch", "shared event", "kin intake",
            "projection call"),
   nodes=("test_nonfunctional.py::test_every_operational_ceiling_refuses_with_an_omitted_count",))

_o("NF.lifetimes", "NONFUNCTIONAL", "candidate lifetime and private retention hold",
   V, "operational-limits", "candidate and approval lifetime: 15 minutes;",
   clauses(equals("candidate_lifetime_seconds", 900,
                  "the ratified candidate lifetime is fifteen minutes"),
           equals("private_retention_seconds", 86400,
                  "private raw-session retention is twenty-four hours"),
           equals("expired_approval_refusal_code", "APPROVAL_EXPIRED",
                  "an expired candidate refuses with its typed code"),
           is_true("raw_removed_after_retention",
                   "raw private session bytes are gone after retention")),
   surfaces=("guildhall proposals decide",), vectors=("expiry", "retention"),
   nodes=("test_nonfunctional.py::test_candidate_lifetime_and_private_retention_are_enforced",))

_o("NF.exit-boundary", "NONFUNCTIONAL", "uncaught exceptions exit seventy",
   L, "error-contract",
   "The CLI installs one top-level exception boundary that emits the typed "
   "internal error and exits 70 for every caught application exception.",
   clauses(equals("exit_code", 70, "the boundary exits seventy"),
           present("error.code", "the internal error is typed"),
           equals("stack_trace_leaked", 0, "no raw trace reaches the operator")),
   surfaces=("guildhall",), vectors=("uncaught application exception",),
   nodes=("test_nonfunctional.py::test_uncaught_application_exceptions_exit_seventy",))

_o("NF.token-mode", "NONFUNCTIONAL", "a broad token mode is refused with remediation",
   L, "first-run-failures", "| token/key mode broader than 0600 | exit 4; chmod remediation |",
   clauses(equals("exit_code", 4, "a broad token mode exits four"),
           is_true("remediation_names_chmod", "the remediation names chmod"),
           is_true("mode_observed_broad", "the mode really was broader than 0600"),
           equals("secret_bytes_leaked", 0, "the secret is not echoed")),
   surfaces=("guildhall status",), vectors=("token mode 0644",),
   nodes=("test_nonfunctional.py::test_broad_token_mode_is_refused_with_chmod_remediation",))

# ==========================================================================
# Evidence packet
# ==========================================================================

_o("EV.custody", "EVIDENCE", "the packet root is private and outside Git",
   V, "custody",
   "The packet is Validator-owned mode-0700 run state outside Git during "
   "execution and is transferred only to the founder/security custodian.",
   clauses(equals("mode", 448, "the packet root is mode 0700"),
           is_false("inside_git_worktree", "the packet is outside every worktree"),
           is_true("outside_repository", "the packet root is not under a repository")),
   surfaces=("evidence packet root",), vectors=("custody",),
   nodes=("test_evidence_packet.py::test_packet_root_is_private_and_outside_git",),
   fail_closed=INSTRUMENT)

_o("EV.retention", "EVIDENCE", "retention and incident-hold fields are enforced",
   V, "retention",
   "Per-arm worktrees, agent homes, model transcripts, raw Git history, and raw "
   "tool logs are private run evidence and expire after sanitized "
   "scoring/evidence extraction and no later than 24 hours after terminal "
   "verdict unless a separately authorized incident hold applies.",
   clauses(at_most("raw_evidence_age_seconds", 86400,
                   "raw evidence expires within twenty-four hours"),
           every("incident_hold_fields", "each hold field is present and typed",
                 present("field", "field name"),
                 is_true("present", "the field exists"), min_len=4),
           is_true("hold_requires_two_named_authorities",
                   "a hold needs founder and named security custodian")),
   surfaces=("evidence packet",), vectors=("retention", "incident hold"),
   nodes=("test_evidence_packet.py::test_retention_and_incident_hold_fields_are_enforced",),
   fail_closed=INSTRUMENT)

_o("EV.method-label", "EVIDENCE", "Factory method evidence is labelled METHOD_POC",
   V, "method-label",
   "The role arrangement uses tmux and an interactive Claude Tester, so Factory "
   "method evidence is labeled `METHOD_POC`, never `CLEAN_QUALIFIED`.",
   clauses(equals("method_label", "METHOD_POC", "the required label is used"),
           equals("forbidden_label_occurrences", 0,
                  "CLEAN_QUALIFIED never appears for Factory method evidence")),
   surfaces=("evidence packet",), vectors=("method label",),
   nodes=("test_evidence_packet.py::test_factory_method_evidence_is_labelled_method_poc",),
   fail_closed=INSTRUMENT)

_o("EV.ciphertext-only", "EVIDENCE", "only ciphertext metadata reaches the manifest",
   T, "custody",
   "Raw registry plaintext, raw fixture instantiations, and decryption keys are "
   "destroyed within 24 hours of terminal verdict unless an explicitly "
   "authorized incident hold applies.",
   clauses(present("ciphertext_digest", "the manifest binds the ciphertext digest"),
           present("schema", "the manifest binds the registry schema"),
           at_least("count", 1, "the manifest binds the registry count"),
           equals("plaintext_values_in_manifest", 0, "no raw value is bound"),
           equals("key_material_in_manifest", 0, "no key material is bound")),
   surfaces=("tester vault", "manifest"), vectors=("canary registry",),
   nodes=("test_evidence_packet.py::test_only_ciphertext_metadata_reaches_the_manifest",),
   fail_closed=INSTRUMENT)

# ==========================================================================
# V-10 protocol denial checks (no task corpus is authored or exposed)
# ==========================================================================

_o("V10.freeze-order", "V-10", "freeze refuses before gates, census, power and budget",
   L, "hosts-and-experiments",
   "`freeze` refuses without census, power/MDE/cost results, valid calibration, "
   "and exact human budget ratification.",
   clauses(every("preconditions", "each missing precondition refuses freeze",
                 present("missing", "which precondition was withheld"),
                 is_true("refused", "freeze refused"),
                 present("refusal_code", "the refusal is typed"), min_len=4)),
   surfaces=("guildhall experiment freeze",),
   vectors=("census", "power", "calibration", "budget"),
   nodes=("test_v10_protocol.py::test_experiment_freeze_refuses_before_gates_census_power_and_budget",))

_o("V10.census-row", "V-10", "launch without a signed census row is refused",
   L, "error-contract",
   "`RUN_CENSUS_MISSING` | benchmark action lacks its pre-launch signed census row | 70",
   clauses(equals("refusal_code", "RUN_CENSUS_MISSING", "the typed code is required"),
           equals("exit_code", 70, "the ratified exit status"),
           is_false("smoke_exemption_accepted", "smoke and debug are not exemptions")),
   surfaces=("guildhall experiment run",), vectors=("missing census row",),
   nodes=("test_v10_protocol.py::test_launch_without_a_signed_census_row_is_refused",))

_o("V10.human-bytes", "V-10", "human bytes after freeze must be zero",
   V, "human-bytes",
   "The broker records `human_bytes_after_freeze`; any value other than zero is "
   "`INVALID_RUN`.",
   clauses(equals("human_bytes_after_freeze", 0, "the required value is zero"),
           is_true("nonzero_yields_invalid_run",
                   "a nonzero value must classify the run INVALID_RUN")),
   surfaces=("guildhall experiment run",), vectors=("post-freeze human bytes",),
   nodes=("test_v10_protocol.py::test_human_bytes_after_freeze_must_be_zero",))

_o("V10.principal", "V-10", "administrative principals cannot run a measurement task",
   A, "brownfield-harness",
   "Administrative or broad service-reader identities cannot run a measurement task.",
   clauses(every("principals", "each forbidden principal is refused",
                 present("principal", "which identity"),
                 is_true("refused", "the run was refused"),
                 present("refusal_code", "the refusal is typed"), min_len=2),
           is_true("least_privilege_principal_accepted",
                   "a realistic least-privilege principal is accepted")),
   surfaces=("guildhall experiment run",),
   vectors=("administrative identity", "broad service reader"),
   nodes=("test_v10_protocol.py::"
          "test_administrative_or_broad_reader_principals_cannot_run_a_measurement_task",))

_o("V10.ceiling", "V-10", "the aggregate ceiling is reserved atomically",
   V, "ceiling",
   "The harness atomically reserves and enforces the aggregate ceiling.",
   clauses(is_true("reserved_atomically", "the ceiling is reserved in one commit"),
           is_true("increase_refused", "an increase for this run is refused"),
           present("increase_refusal_code", "the refusal is typed"),
           equals("ceiling_raised", False, "the ceiling never rises mid-run")),
   surfaces=("guildhall experiment freeze",), vectors=("aggregate budget",),
   nodes=("test_v10_protocol.py::test_aggregate_ceiling_is_reserved_atomically_and_cannot_be_raised",))

_o("V10.claim", "V-10", "the published conclusion uses only the licensed claim",
   V, "claim",
   "The published conclusion must use the exact licensed-claim template in P-10 "
   "with run-specific digests and metrics.",
   clauses(is_true("uses_licensed_template", "the licensed template is used"),
           equals("forbidden_claims_found", 0, "no broader claim appears"),
           present("run_digest", "the claim carries run-specific digests")),
   surfaces=("guildhall experiment verdict",), vectors=("published conclusion",),
   nodes=("test_v10_protocol.py::test_published_conclusion_uses_only_the_licensed_claim",))



OBLIGATIONS: tuple[Obligation, ...] = tuple(_OBLIGATIONS)

BY_ID: Mapping[str, Obligation] = {o.oid: o for o in OBLIGATIONS}

def _gate_order(gate: str) -> tuple[int, str]:
    """Numbered V-gates first, then the auxiliary reporting groups."""
    parts = gate.split("-")
    if len(parts) == 2 and parts[0] == "V" and parts[1].isdigit():
        return (int(parts[1]), "")
    return (99, gate)


GATES_COVERED: tuple[str, ...] = tuple(
    sorted({o.gate for o in OBLIGATIONS}, key=_gate_order)
)

#: Gates that ``spec/verification.md`` "Instrument validity" requires to freeze
#: all four elements before combination.
REQUIRED_GATES: tuple[str, ...] = tuple(f"V-{i}" for i in range(1, 10))


def for_gate(gate: str) -> tuple[Obligation, ...]:
    return tuple(o for o in OBLIGATIONS if o.gate == gate)


def all_nodes() -> frozenset[str]:
    nodes: set[str] = set()
    for obligation in OBLIGATIONS:
        nodes.update(obligation.nodes)
    return frozenset(nodes)


def catalog_json() -> dict:
    return {
        "schema": "guildhall-acceptance-obligation-catalog/1",
        "obligation_count": len(OBLIGATIONS),
        "gates": list(GATES_COVERED),
        "obligations": [o.as_json() for o in OBLIGATIONS],
    }


def catalog_digest() -> str:
    import hashlib

    return hashlib.sha256(
        json.dumps(catalog_json(), sort_keys=True).encode("utf-8")
    ).hexdigest()


if __name__ == "__main__":  # pragma: no cover - regeneration helper
    print(json.dumps(catalog_json(), indent=1, sort_keys=True))
