"""Frozen mutation catalog and the mutation-run protocol.

``spec/verification.md`` "Instrument validity" requires every gate to freeze
"its threshold, positive control, negative control, and detector mutation in the
preregistered acceptance catalog before implementation is combined". This module
*is* that catalog for mutations.

Role boundary. ``spec/verification.md`` "Role separation" assigns mutation
testing to the Validator, and the Tester is implementation-blind, so a mutation
that can only be expressed as a source change is declared here with an exact
semantic description and its must-fail node set rather than applied by the
Tester. Mutations expressible through ratified levers -- fixture bytes, config
values, filesystem state, or the Tester's own detectors -- are driven directly
by the suite.

Mutation-run protocol
---------------------

``GUILDHALL_ACCEPT_MUTATION=<id>`` selects one catalog entry. Under a mutation
run the polarity of the named nodes inverts: each listed node **must fail**. A
mutation under which every named node still passes means the gate cannot detect
the defect it claims to detect, which is ``INVALID_HARNESS`` -- never a pass.

``GUILDHALL_ACCEPT_DETECTOR_MUTATION=<id>`` selects a detector mutation instead;
those are applied inside :mod:`acceptance._harness.detectors` because the Tester
owns the detectors.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

from .requirements import HarnessInvalid

MUTATION_ENV = "GUILDHALL_ACCEPT_MUTATION"

Method = Literal["fixture", "config", "detector", "validator_source_patch"]


@dataclass(frozen=True)
class Mutation:
    """One frozen mutation obligation."""

    mutation_id: str
    gate: str
    #: The ratified sentence that requires this mutation to fail its gate.
    requirement_quote: str
    #: Exactly what is changed.
    semantics: str
    method: Method
    #: pytest node ids (module::function) that must fail under this mutation.
    must_fail_nodes: tuple[str, ...]
    notes: str = field(default="")


def active_mutation() -> str | None:
    value = os.environ.get(MUTATION_ENV, "").strip()
    if not value:
        return None
    if value not in CATALOG:
        raise HarnessInvalid(
            f"unknown mutation {value!r}; frozen catalog is {sorted(CATALOG)}"
        )
    return value


def _m(
    mutation_id: str,
    gate: str,
    quote: str,
    semantics: str,
    method: Method,
    nodes: tuple[str, ...],
    notes: str = "",
) -> tuple[str, Mutation]:
    return mutation_id, Mutation(
        mutation_id=mutation_id,
        gate=gate,
        requirement_quote=quote,
        semantics=semantics,
        method=method,
        must_fail_nodes=nodes,
        notes=notes,
    )


CATALOG: dict[str, Mutation] = dict(
    [
        # ---- V-1 -------------------------------------------------------
        _m(
            "v1.adapter_count_without_observations",
            "V-1",
            "Mutation: make one adapter return a source count without observations; V-1 fails.",
            "One adapter's receipt reports a source count while emitting an empty "
            "observation batch.",
            "validator_source_patch",
            (
                "test_v1_ingestion.py::test_adapter_receipt_reports_observations_not_counts",
                "test_v1_ingestion.py::test_end_to_end_build_uses_at_least_seven_source_classes",
            ),
        ),
        _m(
            "v1.approver_mints_never_true",
            "V-1",
            "A distinct steward/maintainer `never_true` event performs semantic withdrawal; mutation that lets the approver mint it must fail.",
            "The approver principal is permitted to sign a `never_true` semantic "
            "withdrawal instead of only a `misextraction` notice.",
            "fixture",
            (
                "test_v1_ingestion.py::test_misextraction_notice_is_approver_owned_and_withholds_only",
                "test_v1_ingestion.py::test_never_true_requires_subject_matter_authority",
            ),
        ),
        # ---- V-2 -------------------------------------------------------
        _m(
            "v2.whole_message_single_label",
            "V-2",
            "Mutations: whole-message single label; shared-by-default under low confidence; common fan-out transaction; remove nonce uniqueness/recovery. Each must fail.",
            "Classification assigns one destination label to the entire message "
            "instead of atomising mixed scope.",
            "validator_source_patch",
            (
                "test_v2_classification.py::test_mixed_messages_atomise_rather_than_take_one_label",
                "test_v2_classification.py::test_exact_match_atomization_and_per_label_metrics",
            ),
        ),
        _m(
            "v2.shared_by_default_low_confidence",
            "V-2",
            "Mutations: whole-message single label; shared-by-default under low confidence; common fan-out transaction; remove nonce uniqueness/recovery. Each must fail.",
            "A low-confidence shared label is emitted as a shared candidate "
            "instead of being demoted to `none`/Unknown.",
            "validator_source_patch",
            (
                "test_v2_classification.py::test_low_confidence_shared_label_demotes_to_none_or_unknown",
            ),
        ),
        _m(
            "v2.common_fanout_transaction",
            "V-2",
            "Mutations: whole-message single label; shared-by-default under low confidence; common fan-out transaction; remove nonce uniqueness/recovery. Each must fail.",
            "Fan-out uses one cross-destination transaction with global rollback "
            "instead of per-destination sagas.",
            "validator_source_patch",
            (
                "test_v2_classification.py::test_partial_fanout_failure_does_not_roll_back_committed_destination",
                "test_v2_classification.py::test_no_cross_store_transaction_exists",
            ),
        ),
        _m(
            "v2.remove_nonce_uniqueness_recovery",
            "V-2",
            "Mutations: whole-message single label; shared-by-default under low confidence; common fan-out transaction; remove nonce uniqueness/recovery. Each must fail.",
            "The `(destination, nonce)` uniqueness constraint and the recoverable "
            "destination journal are removed.",
            "validator_source_patch",
            (
                "test_v2_classification.py::test_kill_at_every_transition_then_concurrent_retry",
                "test_v2_classification.py::test_retry_returns_original_receipt_without_duplication",
            ),
        ),
        # ---- V-3 -------------------------------------------------------
        _m(
            "v3.transcript_digest_in_receipt",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "The destination receipt carries the raw transcript content digest.",
            "validator_source_patch",
            ("test_v3_privacy.py::test_no_canary_reaches_any_shared_surface_across_the_full_lifecycle",),
        ),
        _m(
            "v3.mount_personal_in_coding_query",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "The coding projection process is given a Personal store handle.",
            "validator_source_patch",
            (
                "test_v3_privacy.py::test_shared_writer_has_no_personal_capability",
                "test_v3_privacy.py::test_sandbox_denies_personal_root_for_shared_processes",
            ),
        ),
        _m(
            "v3.trust_kin_trust_json",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "A worktree `.kin/trust.json` is accepted as a trust root.",
            "fixture",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.clear_taint_after_deidentification",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "`deidentify` clears provenance taint on the candidate record.",
            "validator_source_patch",
            (
                "test_v3_privacy.py::test_hard_blocking_taint_is_never_cleared_by_deidentification",
                "test_v3_privacy.py::test_paraphrase_only_output_stays_private_by_taint_policy",
            ),
        ),
        _m(
            "v3.reread_candidate_path_after_approval",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "The destination writer resolves and re-reads the candidate pathname "
            "instead of committing the inline approved buffer.",
            "validator_source_patch",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.worktree_only_key_admission",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "An event signed by a key present only inside the worktree is admitted.",
            "fixture",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.signature_reuse_across_message_types",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "Domain separation is dropped so one signature verifies under a "
            "different `message_type`.",
            "fixture",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.verify_one_parse_apply_another",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "Verification and semantic use read two different parses of the buffer.",
            "fixture",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.wildcard_authority_scope",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "Authority scope matching accepts a wildcard, prefix or glob instead of "
            "canonical exact byte equality.",
            "fixture",
            (
                "test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",
                "test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",
            ),
        ),
        _m(
            "v3.sql_interpolation",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "A scope or logical key is interpolated into SQL rather than bound.",
            "fixture",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.personal_path_in_shared_argv_config",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "The shared process configuration or argv carries the Personal root.",
            "validator_source_patch",
            ("test_v3_privacy.py::test_process_artifacts_contain_no_personal_root_canary",),
        ),
        _m(
            "v3.remove_scoped_token_enforcement",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "Capability-scope enforcement on service tokens is removed.",
            "validator_source_patch",
            (
                "test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",
                "test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",
            ),
        ),
        _m(
            "v3.remove_nonce_uniqueness",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "The unique `(destination, nonce)` constraint is dropped.",
            "validator_source_patch",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.race_concurrent_approvals",
            "V-3",
            "Mutations: add transcript digest to receipt; mount Personal in coding query; trust `.kin/trust.json`; clear taint after de-identification; re-read candidate path after approval; accept an event from a worktree-only key; reuse a signature across message types; verify one parse and apply another; wildcard an authority scope; interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.",
            "Concurrent approvals for one candidate are not serialised.",
            "fixture",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        _m(
            "v3.raw_terminal_output",
            "V-3",
            "Mutation to raw terminal output must fail.",
            "The approval preview emits raw terminal bytes instead of the frozen "
            "bijective escaped form.",
            "validator_source_patch",
            ("test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe",),
        ),
        # ---- V-4 -------------------------------------------------------
        _m(
            "v4.greatest_timestamp_wins",
            "V-4",
            "Mutation: choose the greatest timestamp/latest file on conflict, omit `as_of`, or treat a stale Company head observation as Git authority; V-4 fails.",
            "Conflicting heads are resolved by greatest timestamp or newest file.",
            "validator_source_patch",
            (
                "test_v4_maintenance.py::test_incompatible_heads_remain_conflict_until_authorized_parent_bound_event",
                "test_v5_temporal.py::test_newest_wins_is_not_the_rule",
            ),
        ),
        _m(
            "v4.omit_as_of",
            "V-4",
            "Mutation: choose the greatest timestamp/latest file on conflict, omit `as_of`, or treat a stale Company head observation as Git authority; V-4 fails.",
            "The reducer reads an ambient wall clock instead of an explicit `as_of`.",
            "validator_source_patch",
            (
                "test_v4_maintenance.py::test_rebuild_is_deterministic_over_frozen_inputs",
                "test_v4_maintenance.py::test_omitting_as_of_breaks_determinism_and_is_refused",
            ),
        ),
        _m(
            "v4.stale_company_head_as_git_authority",
            "V-4",
            "Mutation: choose the greatest timestamp/latest file on conflict, omit `as_of`, or treat a stale Company head observation as Git authority; V-4 fails.",
            "An expired Company manifest observation is treated as repository "
            "authority rather than dated maintainer testimony.",
            "fixture",
            ("test_v4_maintenance.py::test_manifest_comparison_classifies_lag_incomplete_and_expiry",),
        ),
        _m(
            "v4.worktree_local_lock",
            "V-4",
            "A worktree-local lock mutation must fail.",
            "The admission lock lives in the per-worktree directory instead of "
            "Git's common directory.",
            "validator_source_patch",
            ("test_v4_maintenance.py::test_linked_worktrees_serialize_on_one_common_dir_lock",),
        ),
        _m(
            "v4.content_path_before_revocation",
            "V-4",
            "Mutation that checks content path before authority/ revocation admission fails.",
            "The path-exists fast path runs before authority and revocation "
            "admission, so a revoked event is re-admitted.",
            "validator_source_patch",
            ("test_v4_maintenance.py::test_pre_revocation_replay_returns_history_without_readmission",),
        ),
        # ---- V-5 -------------------------------------------------------
        _m(
            "v5.newest_wins",
            "V-5",
            "Mutations newest-wins, highest-authority-always-wins, and repetition-as-independence must each fail.",
            "The reducer selects the newest event for a logical key.",
            "validator_source_patch",
            (
                "test_v5_temporal.py::test_newest_wins_is_not_the_rule",
                "test_v5_temporal.py::test_rejected_pr_does_not_displace_current_adr",
            ),
        ),
        _m(
            "v5.highest_authority_always_wins",
            "V-5",
            "Mutations newest-wins, highest-authority-always-wins, and repetition-as-independence must each fail.",
            "The reducer selects by authority rank regardless of scope, validity "
            "or supersession.",
            "validator_source_patch",
            ("test_v5_temporal.py::test_scope_bounds_authority_rather_than_prestige",),
        ),
        _m(
            "v5.repetition_as_independence",
            "V-5",
            "Mutations newest-wins, highest-authority-always-wins, and repetition-as-independence must each fail.",
            "Repeated copies of one prior are counted as independent corroboration.",
            "validator_source_patch",
            ("test_v5_temporal.py::test_copied_chorus_does_not_outweigh_one_independent_decision",),
        ),
        # ---- V-6 -------------------------------------------------------
        _m(
            "v6.synthesize_answer_from_model_prior",
            "V-6",
            "Mutation: locally synthesize an answer from model prior; V-6 fails.",
            "An unresolved authority Unknown is closed from the model prior "
            "instead of a signed in-scope answer.",
            "validator_source_patch",
            (
                "test_v6_authority.py::test_signed_answer_from_a_separate_process_materially_changes_the_decision",
                "test_v6_authority.py::test_unavailable_authority_yields_declared_degraded_policy",
            ),
        ),
        # ---- V-7 -------------------------------------------------------
        _m(
            "v7.independent_scalar_topk",
            "V-7",
            "Mutation: independent scalar rank/top-k; V-7 fails because duplicates crowd out the invariant.",
            "The projector ranks candidates independently by scalar score and "
            "takes the top k, with no set-conditional recomputation.",
            "validator_source_patch",
            (
                "test_v7_projection.py::test_duplicates_do_not_crowd_out_the_high_distortion_invariant",
                "test_v7_projection.py::test_marginal_value_is_recomputed_against_the_current_set",
            ),
        ),
        # ---- V-8 -------------------------------------------------------
        _m(
            "v8.codebase_authorizes_exception_to",
            "V-8",
            "Mutation: let Codebase authorize `exception_to`; V-8 fails.",
            "A Codebase maintainer signature is accepted for a Company exception.",
            "fixture",
            (
                "test_v8_company_refs.py::test_only_company_steward_may_sign_a_relaxation",
                "test_v8_company_refs.py::test_maintainer_may_request_but_not_mint_an_exception",
            ),
        ),
        # ---- V-9 -------------------------------------------------------
        _m(
            "v9.disable_mid_session_capture",
            "V-9",
            "Mutation: disable mid-session capture while keeping SessionStart green; V-9 fails.",
            "Prompt/observation and pre-edit events stop capturing while "
            "SessionStart still returns a healthy payload.",
            "validator_source_patch",
            (
                "test_v9_host_lifecycle.py::test_native_host_events_prime_capture_and_exclude_personal",
                "test_v9_host_lifecycle.py::test_native_host_events_prime_capture_and_exclude_personal",
            ),
        ),
        _m(
            "v9.reservation_after_render",
            "V-9",
            "Moving the reservation increment after render must produce more than four prompts and make the mutation fail",
            "The prompt-slot reservation increments after the prompt renders.",
            "validator_source_patch",
            (
                "test_v9_fatigue.py::test_interleaved_sessions_never_exceed_four_prompts_per_window",
            ),
        ),
        _m(
            "v9.check_outside_transaction",
            "V-9",
            "moving any check outside the transaction must produce a failing duplicate/starvation mutation",
            "Reissue eligibility, digest lock, slot reservation or consecutive "
            "count is checked outside the single `BEGIN IMMEDIATE`.",
            "validator_source_patch",
            (
                "test_v9_fatigue.py::test_reissue_and_reservation_commit_in_one_immediate_transaction",
            ),
        ),
        # ---- detector mutations (Tester-owned) -------------------------
        _m(
            "detector.disable_archive_scan",
            "V-3",
            "Mutations target detectors as well as product code---for example, disable archive scanning, SQLite blob scanning, normalization decoding, or manifest comparison and require the planted defect to escape the detector's own self-test while causing the gate to reject the instrument.",
            "The scanner stops expanding archive containers and packed objects.",
            "detector",
            ("test_harness_selftest.py::test_detector_mutations_miss_their_positive_control",),
        ),
        _m(
            "detector.disable_sqlite_blob_scan",
            "V-3",
            "Mutations target detectors as well as product code---for example, disable archive scanning, SQLite blob scanning, normalization decoding, or manifest comparison and require the planted defect to escape the detector's own self-test while causing the gate to reject the instrument.",
            "The scanner stops reading SQLite BLOB cells.",
            "detector",
            ("test_harness_selftest.py::test_detector_mutations_miss_their_positive_control",),
        ),
        _m(
            "detector.disable_normalization_decoding",
            "V-3",
            "Mutations target detectors as well as product code---for example, disable archive scanning, SQLite blob scanning, normalization decoding, or manifest comparison and require the planted defect to escape the detector's own self-test while causing the gate to reject the instrument.",
            "The detector stops decoding NFC/NFD, hex, base64, percent and JSON "
            "escape forms.",
            "detector",
            ("test_harness_selftest.py::test_detector_mutations_miss_their_positive_control",),
        ),
        _m(
            "detector.disable_manifest_comparison",
            "V-3",
            "Mutations target detectors as well as product code---for example, disable archive scanning, SQLite blob scanning, normalization decoding, or manifest comparison and require the planted defect to escape the detector's own self-test while causing the gate to reject the instrument.",
            "The instrument stops comparing published and local manifests.",
            "detector",
            ("test_harness_selftest.py::test_detector_mutations_miss_their_positive_control",),
        ),
        _m(
            "detector.disable_partial_match",
            "V-3",
            "a partial sequence meeting the frozen length/rarity rule",
            "The detector stops applying the frozen partial length/rarity rule.",
            "detector",
            ("test_harness_selftest.py::test_detector_mutations_miss_their_positive_control",),
        ),
        _m(
            "detector.disable_fail_closed",
            "V-3",
            "fail closed on scanner error",
            "The scanner swallows read errors instead of failing closed.",
            "detector",
            ("test_harness_selftest.py::test_scanner_error_fails_closed",),
        ),
    ]
)


def catalog_for_gate(gate: str) -> tuple[Mutation, ...]:
    return tuple(m for m in CATALOG.values() if m.gate == gate)


def all_must_fail_nodes() -> frozenset[str]:
    nodes: set[str] = set()
    for mutation in CATALOG.values():
        nodes.update(mutation.must_fail_nodes)
    return frozenset(nodes)


#: Gates that ``spec/verification.md`` gives an explicit ``Mutation:`` obligation.
GATES_WITH_FROZEN_MUTATIONS: tuple[str, ...] = (
    "V-1",
    "V-2",
    "V-3",
    "V-4",
    "V-5",
    "V-6",
    "V-7",
    "V-8",
    "V-9",
)
