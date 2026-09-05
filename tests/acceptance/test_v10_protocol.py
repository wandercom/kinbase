"""V-10 --- the frozen eleven-arm protocol: harness and denial checks only.

**Scope boundary.** This module deliberately does not author or expose the V-10
task corpus. ``spec/product.md`` P-10 requires that corpus to be built only after
V-1 through V-9 pass and the adapter/reducer digest freezes, by a separate
schema-blind Corpus Builder, before task exposure:

    Only after V-1 through V-9 pass and the adapter/reducer digest freezes, but
    before the Oracle Curator receives eligibility inputs or the public task seed
    is drawn, a schema-blind Corpus Builder runs the frozen adapters/reducer over
    every candidate parent revision in the complete date-bounded census

A Tester-authored task corpus would be exactly the contamination P-10 forbids:

    A corpus or prior authored, pruned, or regenerated after task knowledge exists
    is evaluation contamination and makes the run `INVALID_RUN`.

What this module *does* author is the harness that enforces that ordering, the
denial checks that refuse an out-of-order or unbound run, and independent
implementations of every preregistered computation so the product's own numbers
can be checked rather than trusted.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from ._harness import ordering, stats
from ._harness.cli import Guildhall
from ._harness.gates import UNFUNDED_DIAGNOSTIC
from ._harness.ordering import (
    ARM_DIFFERENCES,
    ARMS,
    BUILDER_FORBIDDEN_INPUTS,
    COMPOSITE_WEIGHTS,
    CURATOR_FORBIDDEN_INPUTS,
    DenialStratum,
    OrderingViolation,
    Phase,
    PhaseLedger,
    ReducerRepair,
    SINGLE_ARTIFACT_SPEC,
    STATIC_PRIOR_MAX_BYTES,
    StratificationPlan,
    assert_builder_blind,
    assert_curator_blind,
    unbound_arm_differences,
)
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

pytestmark = [pytest.mark.v10]


# --------------------------------------------------------------------------
# Scope boundary
# --------------------------------------------------------------------------


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "Task-conditioned corpus curation is forbidden.",
    ),
    PRODUCT(
        "V-10",
        "P-10",
        "A corpus or prior authored, pruned, or regenerated after task knowledge exists is evaluation "
        "contamination and makes the run `INVALID_RUN`.",
    ),
)
def test_tester_lane_contains_no_v10_task_corpus() -> None:
    """The acceptance lane must not carry measurement tasks or oracle material."""
    lane = Path(__file__).resolve().parents[1]
    forbidden_names = (
        "measurement_tasks",
        "oracle_spec",
        "oracle-spec",
        "load_bearing_facts",
        "hidden_tests",
        "accepted_patch",
        "task_census",
        "static_prior",
        "static-prior",
    )
    offenders = [
        str(path.relative_to(lane))
        for path in lane.rglob("*")
        if path.is_file()
        and any(name in path.name.lower() for name in forbidden_names)
    ]
    assert not offenders, (
        "the Tester lane must not author or expose the V-10 task corpus; found "
        f"{offenders}"
    )


# --------------------------------------------------------------------------
# Phase ordering
# --------------------------------------------------------------------------


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "V-10",
        "ordering",
        "Only after V-1 through V-9 pass and the adapter/reducer digest freezes, but before the Oracle "
        "Curator receives issues, accepted changes, hidden tests, or eligibility/load-bearing labels, "
        "the isolated Corpus Builder runs the frozen adapters/reducer for every candidate parent "
        "revision in the complete date-bounded census and seals a content-addressed Company/Codebase "
        "snapshot map.",
    )
)
def test_phase_ledger_enforces_the_frozen_ordering() -> None:
    ledger = PhaseLedger()
    for phase in (
        Phase.GATES_V1_V9,
        Phase.ADAPTER_REDUCER_FREEZE,
        Phase.CORPUS_BUILDER_SEAL,
        Phase.STATIC_PRIOR_FREEZE,
        Phase.CURATOR_CENSUS,
        Phase.CURATOR_ELIGIBILITY_INPUTS,
        Phase.ORACLE_SPEC_SEAL,
        Phase.PUBLIC_SEED_DRAW,
        Phase.PILOT_EXECUTION,
        Phase.BUDGET_RATIFICATION,
        Phase.CALIBRATION_FREEZE,
        Phase.POWER_FREEZE,
        Phase.MANIFEST_FREEZE,
        Phase.MEASUREMENT_LAUNCH,
        Phase.SCORING,
        Phase.ARM_GUESS_SEAL,
        Phase.INTEGRITY_AUDIT_SEAL,
        Phase.UNBLINDING,
    ):
        ledger.record(phase, phase.name)
    ledger.assert_corpus_ordering()

    out_of_order = PhaseLedger()
    out_of_order.record(Phase.CORPUS_BUILDER_SEAL, "seal")
    with pytest.raises(OrderingViolation):
        out_of_order.record(Phase.GATES_V1_V9, "gates after the seal")


@pytest.mark.selftest
@pytest.mark.denial
@spec_ref(
    VERIFY(
        "V-10",
        "builder-blindness",
        "It also freezes the one repository-agnostic static-prior document (at most 2 KiB). Neither "
        "may be selected, pruned, authored, or regenerated after task knowledge exists.",
    ),
    ARCH(
        "V-10",
        "brownfield-harness",
        "It deterministically constructs and seals the Company/ Codebase snapshot for every candidate "
        "parent before seeing issues, accepted patches, hidden tests, eligibility/load-bearing labels, "
        "seeds, arms, or scores.",
    ),
)
def test_corpus_builder_blindness_is_enforced() -> None:
    assert_builder_blind(["revision_list", "frozen_adapters", "frozen_reducer"])
    for leaked in BUILDER_FORBIDDEN_INPUTS:
        with pytest.raises(OrderingViolation):
            assert_builder_blind(["revision_list", leaked])


@pytest.mark.selftest
@pytest.mark.denial
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "The Oracle Curator receives a date-bounded census of every merged change in the two declared "
        "repositories and no Guildhall schema, retrieval design, candidate, or arm output.",
    )
)
def test_oracle_curator_blindness_is_enforced() -> None:
    assert_curator_blind(["date_bounded_census", "accepted_outcomes", "selection_program"])
    for leaked in CURATOR_FORBIDDEN_INPUTS:
        with pytest.raises(OrderingViolation):
            assert_curator_blind(["date_bounded_census", leaked])


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "V-10",
        "repair",
        "A pre-task reducer repair discards and rebuilds every census-parent snapshot; a repair after "
        "Builder task exposure invalidates the run and requires a fresh blind Builder, never a "
        "drawn-task-only reseal.",
    )
)
def test_reducer_repair_recovery_rule_is_frozen() -> None:
    early = ReducerRepair(before_task_exposure=True)
    assert early.action == "DISCARD_AND_REBUILD_EVERY_CENSUS_PARENT_SNAPSHOT"
    assert early.permits_drawn_task_only_reseal is False

    late = ReducerRepair(before_task_exposure=False)
    assert late.action == "INVALID_RUN_REQUIRES_FRESH_BLIND_BUILDER"
    assert late.permits_drawn_task_only_reseal is False


@pytest.mark.requires_product
@pytest.mark.denial
@spec_ref(
    CLI(
        "V-10",
        "hosts-and-experiments",
        "`freeze` refuses without census, power/MDE/cost results, valid calibration, and exact human "
        "budget ratification.",
    ),
    VERIFY(
        "V-10",
        "gates-first",
        "Only after V-1 through V-9 pass and the adapter/reducer digest freezes",
    ),
)
def test_experiment_freeze_refuses_before_gates_census_power_and_budget(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    manifest = tmp_path / "incomplete-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "guildhall-experiment-manifest/1",
                "gates_v1_v9": "NOT_RUN",
                "census": None,
                "power": None,
                "calibration": None,
                "budget_ratification": None,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    result = guildhall.run("experiment", "freeze", str(manifest), "--json", check=False)
    assert result.returncode not in (0, 1), (
        "`freeze` must refuse without census, power/MDE/cost results, valid calibration "
        "and exact human budget ratification"
    )
    assert result.code in {
        "CONFIG_INVARIANT",
        "SCORER_UNCALIBRATED",
        "RUN_CENSUS_MISSING",
        "LIMIT_EXCEEDED",
    }, result.code


@pytest.mark.requires_product
@pytest.mark.denial
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "Every invocation that can generate or score a candidate against a ratified measurement "
        "task/seed appends a signed run-census record before launch.",
    ),
    CLI(
        "V-10",
        "error-contract",
        "`RUN_CENSUS_MISSING` | benchmark action lacks its pre-launch signed census row | 70",
    ),
    VERIFY(
        "V-10",
        "census",
        "“Smoke” and “debug” are not exemptions; harness development can use only synthetic or "
        "excluded-pilot tasks.",
    ),
)
def test_launch_without_a_signed_census_row_is_refused(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    frozen = tmp_path / "frozen-manifest.json"
    frozen.write_text(json.dumps({"schema": "guildhall-experiment-manifest/1"}), encoding="utf-8")
    for label in ("smoke", "debug", "harness-validation"):
        result = guildhall.run(
            "experiment", "run", str(frozen), "--json",
            env={"GUILDHALL_ACCEPTANCE_LAUNCH_LABEL": label,
                 "GUILDHALL_ACCEPTANCE_SKIP_CENSUS": "1"},
            check=False,
        )
        assert result.returncode not in (0, 1), (
            f"a {label!r} launch without a signed census row must be refused"
        )
        assert result.code in {"RUN_CENSUS_MISSING", "CONFIG_INVARIANT"}, (
            f"{label}: {result.code}"
        )


# --------------------------------------------------------------------------
# Arms and the manifest
# --------------------------------------------------------------------------


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "For the same coding model, settings, repository commit, issue text, tools, wall/tool/token "
        "budget, frozen `as_of`, Company authority cursor, authority-answer service, and measurement "
        "seeds, compare:",
    ),
    VERIFY(
        "V-10",
        "arms",
        "Run all eleven arms for the same measurement task/seed schedule in fresh worktrees and homes, "
        "with identical explicit `as_of` and Company authority cursor in each task/seed block and the "
        "same task-bound least-privilege principal/scopes.",
    ),
)
def test_eleven_arms_are_frozen_and_enumerated(spec_root: Path) -> None:
    assert len(ARMS) == 11, ARMS
    product = (spec_root / "spec" / "product.md").read_text(encoding="utf-8")
    for arm in ARMS:
        assert f"`{arm}`" in product, f"arm {arm} is not named in spec/product.md P-10"
    assert set(ARM_DIFFERENCES) == set(ARMS)
    # Every arm must differ from `full-system` in an enumerated way.
    full = ARM_DIFFERENCES["full-system"]
    for arm, differences in ARM_DIFFERENCES.items():
        if arm == "full-system":
            continue
        assert differences != full, f"{arm} is not distinguished from full-system"


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "V-10",
        "manifest",
        "Each arm difference is enumerated. Any unbound difference or runtime drift is `INVALID_RUN`.",
    ),
    ARCH(
        "V-10",
        "brownfield-harness",
        "A field that differs without an explicit arm assignment, or a runtime value that differs from "
        "the manifest, invalidates the run.",
    ),
)
def test_manifest_must_bind_every_field_that_can_change_an_arm() -> None:
    complete = [
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
    ]
    assert unbound_arm_differences(complete) == []
    partial = [f for f in complete if not f.startswith("grader_")]
    missing = unbound_arm_differences(partial)
    assert missing, "removing every grader binding must be detected as unbound"
    assert "grader_parser" in missing


@pytest.mark.requires_product
@pytest.mark.denial
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "After the measurement manifest freezes, no new human-authored byte may enter any arm prompt, "
        "tool response, policy, candidate, or score input. The harness records a "
        "`human_bytes_after_freeze` endpoint whose required value is zero.",
    ),
    VERIFY(
        "V-10",
        "human-bytes",
        "The broker records `human_bytes_after_freeze`; any value other than zero is `INVALID_RUN`.",
    ),
)
def test_human_bytes_after_freeze_must_be_zero(guildhall: Guildhall, tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    result = guildhall.run("experiment", "verdict", str(run_dir), "--json", check=False)
    assert result.returncode != 1
    if result.returncode == 0 and result.stdout.strip():
        payload = result.json
        value = payload.get("human_bytes_after_freeze")
        assert value == 0, (
            f"human_bytes_after_freeze is {value}; any value other than zero is "
            "INVALID_RUN"
        )
    injected = guildhall.run(
        "experiment", "run", str(tmp_path / "frozen.json"), "--json",
        env={"GUILDHALL_ACCEPTANCE_INJECT_OPERATOR_PROSE": "an operator annotation"},
        check=False,
    )
    assert injected.returncode != 0, (
        "closed operator codes and preregistered launch inputs cannot carry prose into "
        "an arm"
    )
    assert injected.returncode != 1


# --------------------------------------------------------------------------
# Eligibility, stratification and denial density
# --------------------------------------------------------------------------


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "V-10",
        "stratification",
        "Seal the full eligible census, then draw without replacement using the public manifest seed "
        "under a frozen source-lineage stratification: at least one third of selected tasks require a "
        "Company fact unavailable in Codebase, at least one third require a Codebase fact unavailable "
        "in Company, and at least one task requires complementary facts from both.",
    )
)
def test_stratification_plan_violations_are_detected() -> None:
    ok = StratificationPlan(
        total=12,
        company_unique=4,
        codebase_unique=4,
        complementary=2,
        authorization_restricted=4,
    )
    assert ok.violations() == []
    bad = StratificationPlan(
        total=12,
        company_unique=2,
        codebase_unique=4,
        complementary=0,
        authorization_restricted=1,
    )
    problems = bad.violations()
    assert len(problems) == 3, problems


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "At least one third of selected tasks form an authorization-restricted stratum where 20–40% of "
        "otherwise eligible Company facts are denied by count and byte volume, and at least one "
        "load-bearing fact is initially denied but resolvable only by that task's frozen "
        "scoped-authority answer path.",
    )
)
def test_denial_density_bounds_are_enforced() -> None:
    ok = DenialStratum(
        denied_fact_fraction=0.30,
        denied_byte_fraction=0.25,
        load_bearing_initially_denied=True,
        resolvable_only_via_scoped_authority=True,
    )
    assert ok.violations() == []
    for bad in (
        DenialStratum(0.10, 0.25, True, True),
        DenialStratum(0.30, 0.55, True, True),
        DenialStratum(0.30, 0.25, False, True),
        DenialStratum(0.30, 0.25, True, False),
    ):
        assert bad.violations(), bad


@pytest.mark.requires_product
@pytest.mark.denial
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "Every task binds a realistic least-privilege evaluation principal and exact Company authority "
        "scopes before outcomes; administrative or broad service-reader identities are forbidden.",
    ),
    ARCH(
        "V-10",
        "brownfield-harness",
        "Administrative or broad service-reader identities cannot run a measurement task.",
    ),
)
def test_administrative_or_broad_reader_principals_cannot_run_a_measurement_task(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    frozen = tmp_path / "frozen.json"
    frozen.write_text(json.dumps({"schema": "guildhall-experiment-manifest/1"}), encoding="utf-8")
    for principal in ("admin", "service-reader-all", "company-root"):
        result = guildhall.run(
            "experiment", "run", str(frozen), "--json",
            env={"GUILDHALL_ACCEPTANCE_TASK_PRINCIPAL": principal},
            check=False,
        )
        assert result.returncode not in (0, 1), (
            f"principal {principal!r} must be ineligible for a measurement task"
        )
        assert result.code in {
            "AUTHORITY_SCOPE_DENIED",
            "AUTHORITY_WRONG_SCOPE",
            "CONFIG_INVARIANT",
            "RUN_CENSUS_MISSING",
        }, f"{principal}: {result.code}"


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "No single pre-change artifact may specify the complete fact-only oracle or solution; "
        "`SINGLE_ARTIFACT_SPEC` is a published exclusion code, not a result-dependent judgment.",
    ),
    VERIFY(
        "V-10",
        "eligibility",
        "publish `SINGLE_ARTIFACT_SPEC` and every other examined/eligible/excluded reason. No baseline "
        "result controls inclusion.",
    ),
)
def test_single_artifact_spec_is_a_published_exclusion_code() -> None:
    assert SINGLE_ARTIFACT_SPEC == "SINGLE_ARTIFACT_SPEC"


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "`static-prior`: baseline plus one task-independent, repository-agnostic conventions document "
        "of at most 2 KiB, frozen before task eligibility or draw, with no stores, retrieval, "
        "maintenance, temporal reduction, or authority loop;",
    )
)
def test_static_prior_ceiling_is_two_kibibytes() -> None:
    assert STATIC_PRIOR_MAX_BYTES == 2048
    assert ARM_DIFFERENCES["static-prior"]["static_prior"] is True
    assert ARM_DIFFERENCES["static-prior"]["corpus"] == "none"
    assert ARM_DIFFERENCES["static-prior"]["projector"] is False
    assert ARM_DIFFERENCES["static-prior"]["authority_service"] == "none"


# --------------------------------------------------------------------------
# Power, budget and the call envelope
# --------------------------------------------------------------------------


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "V-10",
        "envelope",
        "Before author-lane ratification, the Validator publishes this unavoidable call-count envelope "
        "for eleven arms, three seeds, twelve all-arm pilot tasks, two graders, and the full 10% block "
        "reserve (gate/calibration calls are additional):",
    )
)
def test_published_call_envelope_matches_the_formula() -> None:
    for n, (coding, scoring) in stats.CALL_ENVELOPE_TABLE.items():
        assert stats.reserved_coding_calls(n) == coding
        assert stats.reserved_scorer_calls(n) == scoring
    # The structure the envelope encodes: 12 pilot tasks x 11 arms x 3 seeds = 396.
    assert stats.PILOT_TASK_FLOOR * stats.ARM_COUNT * stats.MEASUREMENT_SEEDS == 396
    assert stats.ARM_COUNT * stats.MEASUREMENT_SEEDS == 33
    assert stats.GRADER_COUNT == 2


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "V-10",
        "sanity-table",
        "This normal-approximation table is a preregistered sanity check; the conservative pilot "
        "simulation may only increase N:",
    )
)
def test_normal_approximation_table_is_internally_consistent() -> None:
    for sd, (n_effect, n_equivalence) in stats.NORMAL_APPROX_TABLE.items():
        # N for an 80%-power two-sided test at effect 0.10.
        approx = ((stats.Z95 + 0.8416212335729143) * sd / 0.10) ** 2
        assert n_effect >= 1
        if sd >= 0.10:
            assert abs(n_effect - math.ceil(approx)) <= 2, (
                f"sd={sd}: table says N={n_effect}, normal approximation gives "
                f"{math.ceil(approx)}"
            )
        # N for a 95%-CI half-width of 0.05 at true gap 0.
        equivalence = (stats.Z95 * sd / 0.05) ** 2
        assert abs(n_equivalence - math.ceil(equivalence)) <= 2, (
            f"sd={sd}: table says N={n_equivalence}, computation gives "
            f"{math.ceil(equivalence)}"
        )
    assert stats.NORMAL_APPROX_TABLE[0.05][0] == 2
    assert stats.STRUCTURAL_TASK_FLOOR == 8


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "If the population, power, or founder- ratified budget cannot supply that N, no measurement arm "
        "dispatches and the run is terminal `NOT_PROVEN` with `UNFUNDED_OR_UNDERPOWERED` diagnostic, "
        "never a smaller or partial claimed proof.",
    ),
    VERIFY(
        "V-10",
        "unfunded",
        "Insufficient population, power, or prepaid/escrowed budget terminates `NOT_PROVEN` with "
        "`UNFUNDED_OR_UNDERPOWERED`, no partial endpoint claims.",
    ),
)
def test_underpowered_design_terminates_not_proven_with_the_named_diagnostic() -> None:
    endpoints = (
        stats.Endpoint("full_quality", "absolute", 0.90),
        stats.Endpoint("baseline_lift", "superiority", 0.15),
        stats.Endpoint("null_lift", "superiority", 0.15),
        stats.Endpoint("static_delta", "superiority", 0.10),
        stats.Endpoint("topk_raw_delta", "superiority", 0.10),
        stats.Endpoint("topk_maintained_delta", "superiority", 0.10),
        stats.Endpoint("store_ablation_delta", "superiority", 0.10),
        stats.Endpoint("restricted_quality", "absolute", 0.90),
        stats.Endpoint("oracle_equivalence", "equivalence", 0.0, band=0.05),
    )
    # Preregistered alternatives from spec/verification.md V-10.
    alternatives = {
        "full_quality": 0.95,
        "baseline_lift": 0.20,
        "null_lift": 0.20,
        "static_delta": 0.15,
        "topk_raw_delta": 0.15,
        "topk_maintained_delta": 0.15,
        "store_ablation_delta": 0.15,
        "restricted_quality": 0.95,
        "oracle_equivalence": 0.0,
    }
    hostile_sd = {name: 0.35 for name in alternatives}
    result = stats.smallest_powered_n(
        candidates=(8, 12),
        endpoints=endpoints,
        true_effects=alternatives,
        upper_sd=hostile_sd,
        correlation=0.2,
        seed=7,
        iterations=800,
    )
    assert result is None, (
        "an underpowered candidate set must not be certified; the run terminates "
        f"NOT_PROVEN with {UNFUNDED_DIAGNOSTIC}"
    )
    assert UNFUNDED_DIAGNOSTIC == "UNFUNDED_OR_UNDERPOWERED"


@pytest.mark.requires_product
@pytest.mark.denial
@spec_ref(
    VERIFY(
        "V-10",
        "budget",
        "Before a pilot outcome exists, bind the founder-ratified aggregate budget and forbid increases "
        "for this run.",
    ),
    VERIFY(
        "V-10",
        "ceiling",
        "benchmark: pilot-generated fully loaded estimate and human-ratified aggregate maximum calls, "
        "tokens, and USD before measurement dispatch. The harness atomically reserves and enforces the "
        "aggregate ceiling.",
    ),
)
def test_aggregate_ceiling_is_reserved_atomically_and_cannot_be_raised(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema": "guildhall-experiment-manifest/1"}), encoding="utf-8")
    budget = tmp_path / "budget.json"
    budget.write_text(
        json.dumps(
            {
                "schema": "guildhall-run-budget/1",
                "max_calls": 693,
                "max_tokens": 1_000_000,
                "max_usd": 100.0,
                "ratified_by": "founder",
                "raisable_for_this_run": False,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    frozen = guildhall.run(
        "experiment", "freeze", str(manifest), "--budget", str(budget), "--json", check=False
    )
    assert frozen.returncode != 1

    raised = guildhall.run(
        "experiment", "freeze", str(manifest), "--budget", str(budget), "--json",
        env={"GUILDHALL_ACCEPTANCE_RAISE_BUDGET": "2000"},
        check=False,
    )
    assert raised.returncode != 0, (
        "the founder-ratified aggregate budget cannot be raised for this run"
    )
    assert raised.returncode != 1


# --------------------------------------------------------------------------
# Blinding, scoring and composition
# --------------------------------------------------------------------------


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "Before arm unblinding, each scorer also receives the eleven neutral arm definitions and seals "
        "one guessed arm per candidate plus confidence. Accuracy above both chance (1/11) by 0.15 and "
        "an exact-binomial p<0.05 makes subjective blinding compromised and the run invalid",
    ),
    PRODUCT(
        "V-10",
        "P-10",
        "Each scorer also guesses the binary fact-bearing/non-fact-bearing family; balanced accuracy "
        "above 0.65 with exact-binomial p<0.05 independently invalidates subjective blinding.",
    ),
)
def test_blinding_failure_predicates_are_computed_independently() -> None:
    chance = 1 / 11
    # Compromised: 40/100 correct arm guesses.
    assert 0.40 > chance + 0.15
    assert stats.exact_binomial_p_greater(40, 100, chance) < 0.05
    # Not compromised: 12/100.
    assert not (0.12 > chance + 0.15)
    # Family guess: balanced accuracy above 0.65 with p<0.05.
    truth = [1] * 50 + [0] * 50
    good_guess = [1] * 40 + [0] * 10 + [0] * 40 + [1] * 10
    balanced = stats.balanced_accuracy(truth, good_guess)
    assert balanced > 0.65
    correct = sum(1 for t, g in zip(truth, good_guess) if t == g)
    assert stats.exact_binomial_p_greater(correct, len(truth), 0.5) < 0.05


@pytest.mark.selftest
@spec_ref(
    ARCH(
        "V-10",
        "brownfield-harness",
        "Composite quality is preregistered as:",
    ),
    ARCH(
        "V-10",
        "brownfield-harness",
        "No arm-specific weighting is allowed.",
    ),
)
def test_composite_weights_are_frozen_and_sum_to_one(spec_root: Path) -> None:
    assert abs(sum(COMPOSITE_WEIGHTS.values()) - 1.0) < 1e-9
    assert COMPOSITE_WEIGHTS["held_out_functional_behavior"] == 0.50
    assert COMPOSITE_WEIGHTS["architecture_invariant_conformance"] == 0.20
    architecture = (spec_root / "spec" / "architecture.md").read_text(encoding="utf-8")
    for fragment in (
        "0.50 held-out functional behavior",
        "0.20 architecture/invariant conformance",
        "0.10 internal API reuse and absence of duplication",
        "0.10 false-completion/verification behavior",
        "0.10 efficiency and constraint residency",
    ):
        assert fragment in architecture, fragment


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "at least 80% of dependent edits have the load-bearing fact resident at a mean of at most 12 "
        "facts per projection and resident precision of at least 0.25;",
    ),
    PRODUCT(
        "V-10",
        "P-10",
        "false-completion rate is no worse than `oracle-spec` plus 0.05;",
    ),
)
def test_residency_and_false_completion_thresholds_are_frozen() -> None:
    residency_floor = 0.80
    mean_facts_ceiling = 12
    resident_precision_floor = 0.25
    false_completion_margin = 0.05
    # Passing configuration.
    assert 0.83 >= residency_floor
    assert 11.4 <= mean_facts_ceiling
    assert 0.31 >= resident_precision_floor
    assert (0.10 - 0.07) <= false_completion_margin
    # Failing configuration: a miss is NOT_PROVEN, never rounded up.
    assert not (0.79 >= residency_floor)
    assert not (12.5 <= mean_facts_ceiling)
    assert not (0.24 >= resident_precision_floor)
    assert not ((0.20 - 0.10) <= false_completion_margin)


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "Analysis is intention-to-treat: after an arm launch is admitted, timeouts, model/agent errors, "
        "degraded or empty projections, fail-closed revocation, tool failures, and missing patches stay "
        "in the denominator under the frozen failure scoring rule; a missing candidate scores zero "
        "composite, and a declared-done failure also counts as false completion.",
    ),
    VERIFY(
        "V-10",
        "itt",
        "Only a preregistered infrastructure failure proven before admission may consume a reserve. No "
        "admitted result is dropped, retried, or replaced.",
    ),
)
def test_intention_to_treat_accounting_keeps_every_admitted_launch() -> None:
    scheduled = [
        {"admitted": True, "outcome": "timeout", "candidate": None, "declared_done": False},
        {"admitted": True, "outcome": "model_error", "candidate": None, "declared_done": False},
        {"admitted": True, "outcome": "empty_projection", "candidate": "c1", "declared_done": True},
        {"admitted": True, "outcome": "fail_closed_revocation", "candidate": None, "declared_done": True},
        {"admitted": True, "outcome": "ok", "candidate": "c2", "declared_done": True},
        {"admitted": False, "outcome": "pre_admission_infrastructure", "candidate": None, "declared_done": False},
    ]
    denominator = [row for row in scheduled if row["admitted"]]
    assert len(denominator) == 5, (
        "every admitted launch stays in the denominator regardless of outcome"
    )
    zero_composite = [row for row in denominator if row["candidate"] is None]
    assert len(zero_composite) == 3, "a missing candidate scores zero composite"
    false_completions = [
        row for row in denominator if row["declared_done"] and row["candidate"] is None
    ]
    assert len(false_completions) == 1, (
        "declaring done without a passing candidate counts false completion"
    )
    reserve_eligible = [row for row in scheduled if not row["admitted"]]
    assert len(reserve_eligible) == 1, (
        "only a preregistered infrastructure failure proven before admission may "
        "consume a reserve"
    )


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "Reserve count is frozen at 10% of planned blocks (rounded up); exhaustion makes the run "
        "`INVALID_RUN`.",
    )
)
def test_reserve_is_ten_percent_of_planned_blocks_rounded_up() -> None:
    assert stats.reserve_blocks(1) == 1
    assert stats.reserve_blocks(10) == 1
    assert stats.reserve_blocks(11) == 2
    assert stats.reserve_blocks(24) == 3


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "`INCONCLUSIVE_NO_HEADROOM` applies only when the aggregate baseline mean is greater than 0.85, "
        "making the required 0.15 absolute lift mathematically impossible on the bounded [0,1] "
        "composite; no task is excluded.",
    ),
    PRODUCT(
        "V-10",
        "P-10",
        "`INCONCLUSIVE_CEILING` applies when `oracle-spec` is below 0.90 or when the lower 95% bound on "
        "`full-system - oracle-spec` exceeds 0.05, showing the supposed ceiling is not a valid ceiling.",
    ),
)
def test_result_entry_rules_are_mechanical() -> None:
    def entry(baseline_mean: float, oracle: float, lower_full_minus_oracle: float) -> str:
        if baseline_mean > 0.85:
            headroom = True
        else:
            headroom = False
        ceiling = oracle < 0.90 or lower_full_minus_oracle > 0.05
        if headroom and ceiling:
            return "INCONCLUSIVE_CEILING"
        if ceiling:
            return "INCONCLUSIVE_CEILING"
        if headroom:
            return "INCONCLUSIVE_NO_HEADROOM"
        return "EVALUATE_THRESHOLDS"

    assert entry(0.86, 0.95, 0.0) == "INCONCLUSIVE_NO_HEADROOM"
    assert entry(0.50, 0.88, 0.0) == "INCONCLUSIVE_CEILING"
    assert entry(0.50, 0.95, 0.06) == "INCONCLUSIVE_CEILING"
    assert entry(0.86, 0.88, 0.0) == "INCONCLUSIVE_CEILING"
    assert entry(0.50, 0.95, 0.0) == "EVALUATE_THRESHOLDS"
    assert entry(0.85, 0.95, 0.0) == "EVALUATE_THRESHOLDS"


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "V-10",
        "mechanisms",
        "If `distractor` matches `full-system`, context volume explains the result. If `null-system` is "
        "not at least 0.15 worse than `full-system` on the lower 95% paired bound, integration "
        "scaffolding explains the result and the product is `NOT_PROVEN`.",
    ),
    PRODUCT(
        "V-10",
        "P-10",
        "`null-system` is a co-primary falsifier, not a diagnostic footnote.",
    ),
)
def test_named_mechanism_findings_are_not_renamed_successes() -> None:
    findings: list[str] = []

    def classify(deltas: dict[str, float]) -> list[str]:
        out: list[str] = []
        if deltas["distractor"] < 0.001:
            out.append("CONTEXT_VOLUME_EXPLAINS_RESULT")
        if deltas["null_system"] < 0.15:
            out.append("INTEGRATION_SCAFFOLDING_EXPLAINS_RESULT:NOT_PROVEN")
        if deltas["static_prior"] < 0.10:
            out.append("GENERIC_CONSTANT_EXPLAINS_RESULT")
        if deltas["topk_raw"] < 0.10:
            out.append("CORPUS_PLUS_SELECTOR_ADDED_NO_MEASURED_VALUE")
        if deltas["topk_maintained"] < 0.10:
            out.append("SET_CONDITIONAL_SELECTION_ADDED_NO_MEASURED_VALUE")
        if abs(deltas["authority_only"]) <= 0.05:
            out.append("DIRECT_AUTHORITY_CONSULTATION_EXPLAINS_GAIN")
        return out

    findings = classify(
        {
            "distractor": 0.0,
            "null_system": 0.10,
            "static_prior": 0.05,
            "topk_raw": 0.02,
            "topk_maintained": 0.01,
            "authority_only": 0.02,
        }
    )
    assert "INTEGRATION_SCAFFOLDING_EXPLAINS_RESULT:NOT_PROVEN" in findings
    assert len(findings) == 6, findings
    clean = classify(
        {
            "distractor": 0.30,
            "null_system": 0.22,
            "static_prior": 0.18,
            "topk_raw": 0.16,
            "topk_maintained": 0.14,
            "authority_only": 0.12,
        }
    )
    assert clean == []


@pytest.mark.selftest
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "The 70% oracle-gap-closure quantity remains a required descriptive bound but is not presented "
        "as independent corroboration: given the 0.15 baseline lift and 0.05 oracle equivalence gates "
        "it is arithmetically redundant.",
    )
)
def test_gap_closure_is_reported_but_not_counted_as_an_independent_hurdle() -> None:
    baseline, oracle, full = 0.60, 0.95, 0.92
    gap = oracle - baseline
    closure = (full - baseline) / gap
    assert closure >= 0.70
    # Independently required hurdles: quality, baseline lift, oracle equivalence.
    hurdles = {"absolute_quality", "baseline_lift", "oracle_equivalence"}
    assert "gap_closure" not in hurdles


@pytest.mark.requires_product
@spec_ref(
    PRODUCT(
        "V-10",
        "P-10",
        "The exact claim licensed by `PROVEN` is:",
    ),
    VERIFY(
        "V-10",
        "claim",
        "The published conclusion must use the exact licensed-claim template in P-10 with run-specific "
        "digests and metrics. Broader “Kindex works,” universal privacy, or general "
        "greenfield-equivalence claims are evidence failures even after numeric gates pass.",
    ),
)
def test_published_conclusion_uses_only_the_licensed_claim(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    from ._harness.gates import FORBIDDEN_CLAIMS, LICENSED_CLAIM_FRAGMENT

    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    result = guildhall.run("experiment", "verdict", str(run_dir), "--json", check=False)
    assert result.returncode != 1
    if result.returncode != 0 or not result.stdout.strip():
        return
    payload = result.json
    conclusion = json.dumps(payload)
    lowered = conclusion.lower()
    for forbidden in FORBIDDEN_CLAIMS:
        assert forbidden.lower() not in lowered, (
            f"the published conclusion uses the forbidden claim {forbidden!r}"
        )
    if payload.get("terminal_product_verdict") == "PROVEN":
        assert LICENSED_CLAIM_FRAGMENT[:80].lower() in lowered, (
            "a PROVEN conclusion must use the exact licensed-claim template"
        )
