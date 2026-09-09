"""V-3 --- stochastic detector qualification and the auxiliary corpus.

Detector Reviewer finding 13, second half: qualification labelled in-memory
payloads with a surface name. A "SQLite blob" positive and a "packed object"
positive were the same ``bytes`` object with two different strings attached, so
the sensitivity bound described the matcher, not the sweep.

Every randomized variant here is written **through the surface's own native
writer** --- a row in a real SQLite file, a member inside a real archive, a file
under the real cache root, an event at its content path --- and then found (or
missed) by the real sweep over that surface. The denominators, the Wilson
bounds, the stratification and the deterministic-control result are all computed
from those sweeps.

Finding 21's supplied grant is recorded. The second test verifies reproducible
content identity and refuses missing current-digest re-attestation or independent
Reviewer selection; it never fabricates either human act.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import auxgen, auxsel, canaries, matrix as MX
from ._harness import obligations as O
from ._harness import prereq, scanners
from ._harness.canaries import TRANSFORMATION_FAMILIES
from ._harness.detectors import stratification_ok, wilson_interval
from ._harness.evidence_model import Origin, require_nonempty
from ._harness.requirements import (
    HarnessInvalid,
    THREAT,
    VERIFY,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.vault import CanaryVault, VaultEntry

pytestmark = [pytest.mark.v3, pytest.mark.slow, pytest.mark.selftest]

#: Ratified qualification floors.
POSITIVE_VARIANTS = 300
DECOY_VARIANTS = 500
PER_FAMILY_MINIMUM = 10
SENSITIVITY_FLOOR = 0.98
FALSE_POSITIVE_CEILING = 0.01

#: Frozen qualification seed.
QUALIFICATION_SEED = 20260907

#: The auxiliary corpus fixture directory.
AUXILIARY = Path(__file__).resolve().parents[1] / "fixtures" / "auxiliary"

#: Surfaces the matrix can write natively. The stratified plan draws from these
#: so every planted variant lands on a real surface.
PLANTABLE_SURFACES: tuple[str, ...] = tuple(sorted(MX.WRITERS))


@spec_ref(
    VERIFY("V-3", "qualification",
           "Qualify stochastic detection with at least 300 independently randomized planted "
           "positive variants, stratified with at least ten per declared surface/encoding "
           "family, and at least 500 randomized true-negative decoys."),
)
def test_randomized_qualification_publishes_every_denominator(
    roots: ProofRoots, vault: CanaryVault, tmp_path: Path
) -> None:
    """300 native positives, 500 native decoys, every denominator published."""
    surfaces = MX.SurfaceRoots.create(roots)
    rng = canaries.make_rng(QUALIFICATION_SEED)
    plan = canaries.stratified_positive_plan(
        rng, total=POSITIVE_VARIANTS, per_family_minimum=PER_FAMILY_MINIMUM,
        surfaces=PLANTABLE_SURFACES, encodings=TRANSFORMATION_FAMILIES,
    )
    prereq.corpus_at_scale(
        len(plan), POSITIVE_VARIANTS, what="randomized positive plan",
        why="V-3 requires at least 300 independently randomized positive variants",
    )

    registry: dict[str, str] = {}
    planted: list[dict] = []
    for index, (surface, encoding) in enumerate(plan):
        canary = canaries.generate_canary(rng, index=index, family=surface)
        registry[canary.canary_id] = canary.value
        MX.WRITERS[surface](
            surfaces, "q" + format(index, "05d"),
            canaries.transform(canary.value, encoding),
        )
        planted.append({"canary_id": canary.canary_id, "surface_family": surface,
                        "encoding_class": encoding})
        vault.add(VaultEntry(
            canary_id=canary.canary_id, raw_value=canary.value,
            transformation_family=encoding, planted_surfaces=(surface,),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="private", gold_destination_labels=("personal",),
        ))

    matrix = MX.Matrix(roots=surfaces, seed=QUALIFICATION_SEED, registry=registry)
    detector = matrix.detector()
    found = set()
    for surface in sorted({s for s, _ in plan}):
        result = scanners.sweep(detector, matrix.surfaces_for(surface, detector))
        for finding in result.findings:
            found.add(finding.canary_id)
    successes = sum(1 for row in planted if row["canary_id"] in found)
    sensitivity_lower, _ = wilson_interval(successes, len(planted))

    # True negatives: 500 randomized decoys planted on the same real surfaces,
    # swept for canaries that were never planted at all.
    decoy_registry: dict[str, str] = {}
    for index in range(DECOY_VARIANTS):
        surface = PLANTABLE_SURFACES[index % len(PLANTABLE_SURFACES)]
        MX.WRITERS[surface](surfaces, "n" + format(index, "05d"),
                            canaries.generate_decoy(rng, index))
        absent = canaries.generate_canary(rng, index=900000 + index, family=surface)
        decoy_registry[absent.canary_id] = absent.value
    decoy_matrix = MX.Matrix(roots=surfaces, seed=QUALIFICATION_SEED,
                             registry=decoy_registry)
    decoy_detector = decoy_matrix.detector()
    false_positives = 0
    for surface in PLANTABLE_SURFACES:
        result = scanners.sweep(
            decoy_detector, decoy_matrix.surfaces_for(surface, decoy_detector)
        )
        false_positives += len(result.findings)
    _, false_positive_upper = wilson_interval(false_positives, DECOY_VARIANTS)

    # Every deterministic catalog control must be detected, without exception.
    deterministic = MX.Matrix.plant(surfaces, seed=QUALIFICATION_SEED + 1)
    receipts = deterministic.receipts(deterministic.detector())
    missed = [r for r in receipts if not r["detected"]]

    stratified, per_family = stratification_ok(
        plan, families=PLANTABLE_SURFACES + TRANSFORMATION_FAMILIES,
        minimum=PER_FAMILY_MINIMUM,
    )
    vault.seal()
    O.check(
        "V-3.qualification",
        {
            "positives": len(planted),
            "decoys": DECOY_VARIANTS,
            "sensitivity_wilson_lower": sensitivity_lower,
            "false_positive_wilson_upper": false_positive_upper,
            "stratification_met": stratified,
            "per_family_counts": per_family,
            "deterministic_controls_missed": len(missed),
            "false_negative_bound": {
                "successes": successes,
                "trials": len(planted),
                "upper_bound_on_false_negative_rate": 1.0 - sensitivity_lower,
            },
            "registry_values_not_exposed": all(
                "raw_value" not in row for row in planted
            ),
        },
        label="randomized qualification over native surfaces",
    )


@spec_ref(
    THREAT("V-3", "auxiliary-corpus",
           "The reconstructor gets all shared surfaces and that exact corpus, no labels, "
           "registry, hidden tests, or arm identity."),
)
def test_auxiliary_corpus_selection_record_is_complete_and_frozen() -> None:
    """Verify the frozen pool, then require the independent human evidence."""
    pool_raw = prereq.fixture_file(
        AUXILIARY / "pool.json",
        why="the auxiliary pool manifest the Detector Reviewer selects from",
        minimum_bytes=256,
    )
    pool = json.loads(pool_raw.decode("utf-8"))
    try:
        verified_digest = auxsel.verify(AUXILIARY)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise HarnessInvalid(f"auxiliary pool verification failed: {exc}") from exc
    candidates = require_nonempty(
        pool["candidates"], obligation="V-3.auxiliary-corpus",
        why="a pool with no candidate cannot be selected from",
        origin=Origin.HARNESS,
    )
    regenerated = auxgen.regenerate()
    # ``regenerate`` yields components keyed by stem; the committed files are
    # ``<stem>.json`` in the serialisation ``recipe()`` records. Compare the
    # same serialisation, not a raw dict against file bytes.
    diverged = [
        name for name, component in regenerated.items()
        if not (AUXILIARY / f"{name}.json").is_file()
        or (AUXILIARY / f"{name}.json").read_text(encoding="utf-8")
        != auxgen.serialise(component)
    ]
    recorded = auxgen.recipe()
    grant = AUXILIARY / "GRANT.md"
    O.check(
        "V-3.auxiliary-corpus",
        {
            "candidate_count": len(candidates),
            "deterministic_components_reproduced": len(diverged) == 0,
            "generation_recipe": recorded,
            "pool_digest": verified_digest,
            "selection_protocol_present": (AUXILIARY / "SELECTION-PROTOCOL.md").is_file(),
            "grant_template_present": (AUXILIARY / "GRANT-TEMPLATE.md").is_file(),
            "named_rightsholder_grant_present": grant.is_file(),
            "selectable": bool(pool["selectable"]),
        },
        label="auxiliary corpus provenance, generation and selection record",
    )

    auxsel.require_review(AUXILIARY, pool, verified_digest)
