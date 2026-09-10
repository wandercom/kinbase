"""V-3 --- the nineteen frozen threat-model attack families, actually executed.

Detector Reviewer finding 13, first half. Family coverage was established by
scanning the registered ``spec_ref`` anchors for a family's name: a docstring
mentioning "signed prompt injection" made the family covered. Nothing ran.

Every family here executes. Each declares the surfaces it ranges over, plants a
positive control **as native bytes on one of those surfaces**, plants a true
negative decoy, and runs three sweeps:

* the unmutated detector must find the control (positive control detected);
* the unmutated detector must not find the decoy (negative control clean);
* a named detector mutation must miss the control (the mutation blinds).

Families whose attack is an *action* rather than a *disclosure* additionally
drive the real refusal through the ratified surface and record the typed code,
so the family is exercised end to end rather than asserted.

The result is one row per family, and ``V-3.attack-families`` requires all
nineteen rows to carry all four true flags. A family that cannot demonstrate its
own blindness is ``INVALID_HARNESS``: it certifies a sensitivity the instrument
does not have.
"""

from __future__ import annotations

import os

import pytest

from ._harness import canaries, matrix as MX
from ._harness import obligations as O
from ._harness import prereq, scanners, trust
from ._harness.cli import Kinbase
from ._harness.evidence_model import Origin, field, require_all
from ._harness.requirements import (
    THREAT,
    VERIFY,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.vault import CanaryVault, VaultEntry
from ._harness.worldbuilder import SignedWorld

pytestmark = [pytest.mark.v3, pytest.mark.denial, pytest.mark.requires_product]

#: The nineteen frozen families, indexed as ``spec/threat-model.md`` numbers them.
ATTACK_FAMILIES: dict[int, str] = {
    1: "exact/partial/substring and deterministic-lineage disclosure",
    2: "reversible encoding and normalisation transformations",
    3: "admission replay, content substitution and symlink swap",
    4: "malicious clone root, unauthorized/rotated/revoked signer, stale revocation, foreign branch",
    5: "signed prompt-injection prose",
    6: "deletion, packed object, missing manifest, forged completeness, shallow/sparse, rebase, squash, union",
    7: "oversized/boundary events, duplicate keys, noncanonical numbers, retries, crash/restart, backup replay",
    8: "accidental disclosure through errors, traces, telemetry, receipts, packets, caches, cleanup, argv",
    9: "sandboxed agent Personal reads and same-UID acquisition then promotion",
    10: "correlated reconstruction with the frozen auxiliary corpus",
    11: "SQL/LIKE/GLOB/FTS, wildcard scope, NUL, separators, malicious .kin/config, type confusion",
    12: "signature/parser differential and cross-domain reuse",
    13: "stolen base bearer token: directory read, answer admission, scope escalation, replay",
    14: "process-capability inspection",
    15: "concurrent admission, double submission and crash recovery",
    16: "classifier-executable substitution",
    17: "terminal question deception",
    18: "saturated signed-insider prompt injection at the projection ceiling",
    19: "check/execute classifier swaps and inherited open-Personal descriptors",
}

#: Per family: the surface the control is planted on, the encoding it is planted
#: in, and the detector mutation that must miss it. Each triple is verified to
#: blind: the unmutated detector finds the control on that exact surface and the
#: mutated one does not. Percent and JSON-escape forms leave the canary body
#: legible without decoding, so they cannot demonstrate a decoding mutation and
#: are exercised by the surface x encoding matrix instead.
FAMILY_PROBE: dict[int, tuple[str, str, str]] = {
    1: ("kin_events", "fragmentation", "disable_partial_match"),
    2: ("receipts", "base64", "disable_normalization_decoding"),
    3: ("shared_outbox", "base64", "disable_normalization_decoding"),
    4: ("caches", "base64", "disable_normalization_decoding"),
    5: ("kin_events", "base64", "disable_normalization_decoding"),
    6: ("codebase_git_worktree", "base64", "disable_normalization_decoding"),
    7: ("kin_events", "hex", "disable_normalization_decoding"),
    8: ("logs", "base64", "disable_normalization_decoding"),
    9: ("process_artifacts", "base64", "disable_normalization_decoding"),
    10: ("caches", "base64", "disable_normalization_decoding"),
    11: ("company_sqlite", "exact", "disable_sqlite_blob_scan"),
    12: ("kin_events", "hex", "disable_normalization_decoding"),
    13: ("service_response", "exact", "disable_archive_scan"),
    14: ("process_artifacts", "hex", "disable_normalization_decoding"),
    15: ("receipts", "hex", "disable_normalization_decoding"),
    16: ("host_projection", "base64", "disable_normalization_decoding"),
    17: ("logs", "base64", "disable_normalization_decoding"),
    18: ("host_projection", "hex", "disable_normalization_decoding"),
    19: ("process_artifacts", "base64", "disable_normalization_decoding"),
}

#: Families whose attack is an action against the product, and the ratified
#: surface each one is driven through.
ACTION_FAMILIES: dict[int, tuple[str, ...]] = {
    3: ("session", "checkpoint"),
    4: ("ingest", "kindex"),
    5: ("project",),
    11: ("explain",),
    12: ("ingest", "kindex"),
    13: ("status",),
    15: ("session", "checkpoint"),
    16: ("doctor",),
    17: ("questions", "show"),
    19: ("doctor",),
}

MATRIX_SEED = 20260907


@pytest.fixture()
def anchored(roots: ProofRoots, kinbase: Kinbase):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(kinbase, roots, world)
    return world, anchors


def _detector_for(surfaces: MX.SurfaceRoots, registry: dict[str, str],
                  mutation: str | None):
    return MX.Matrix(roots=surfaces, seed=MATRIX_SEED,
                     registry=dict(registry)).detector(mutation=mutation)


def _sweep_one(surfaces: MX.SurfaceRoots, registry: dict[str, str],
               surface: str, mutation: str | None) -> int:
    """Findings on exactly one surface family, with an optionally blinded detector."""
    matrix = MX.Matrix(roots=surfaces, seed=MATRIX_SEED, registry=dict(registry))
    detector = matrix.detector(mutation=mutation)
    if surface == "company_sqlite":
        # The mutation governs the SQL column scanner. `sqlite_surfaces` also
        # yields the database file's raw bytes as defence in depth, which is
        # deliberate; excluding it here scopes the demonstration to the detector
        # the mutation actually disables.
        stream = (
            s for s in matrix.surfaces_for(surface, detector)
            if not s.label.startswith("sqlite-raw:")
            and not s.label.startswith("sqlite-sidecar:")
        )
    else:
        stream = matrix.surfaces_for(surface, detector)
    return len(scanners.sweep(detector, stream).findings)


def _drive_action(kinbase: Kinbase, world, family: int) -> dict:
    """Execute the family's real attack action through a ratified surface."""
    argv = ACTION_FAMILIES[family]
    payload = {
        3: ("s" + os.urandom(6).hex(), "--json"),
        4: (str(world.repo.path / ".kin"), "--repo", str(world.repo.path), "--json"),
        5: ("--repo", str(world.repo.path), "--task", "diagnose the scheduler",
            "--decision", "which invariant constrains the change", "--json"),
        11: ("architecture/'; DROP TABLE facts; --", "--repo", str(world.repo.path),
             "--decision", "which rule applies", "--json"),
        12: (str(world.repo.path / ".kin"), "--repo", str(world.repo.path), "--json"),
        13: ("--repo", str(world.repo.path), "--json"),
        15: ("s" + os.urandom(6).hex(), "--json"),
        16: ("--repo", str(world.repo.path), "--json"),
        17: ("q" + os.urandom(6).hex(), "--json"),
        19: ("--repo", str(world.repo.path), "--json"),
    }[family]
    result = kinbase.run(*argv, *payload, cwd=world.repo.path, check=False)
    body = result.json if isinstance(result.json, dict) else {}
    return {
        "argv": list(argv) + list(payload),
        "exit": result.returncode,
        "refusal_code": field(body, "error", "code"),
        "reserved_exit_1": result.returncode == 1,
    }


@spec_ref(
    THREAT("V-3", "attack-families",
           "V-3 must execute, at minimum:"),
    VERIFY("V-3", "attack-families",
           "Give an adversarial reconstructor all shared surfaces plus the Detector Reviewer-"
           "selected, preregistered auxiliary corpus; record exact/deterministic recovery "
           "separately from semantic guesses."),
)
def test_every_frozen_attack_family_has_a_probe(
    kinbase: Kinbase, roots: ProofRoots, anchored, vault: CanaryVault
) -> None:
    """Nineteen families, each executed with its own control, decoy and blinding."""
    world, anchors = anchored
    surfaces = MX.SurfaceRoots.create(roots)
    rng = canaries.make_rng(MATRIX_SEED)

    families = sorted(ATTACK_FAMILIES)
    prereq.collected(
        families, what="frozen threat-model families", minimum=19,
        why="spec/threat-model.md freezes nineteen families and each needs a probe",
    )

    executed: dict[int, dict] = {}
    for number in families:
        surface, encoding, mutation = FAMILY_PROBE[number]
        canary = canaries.generate_canary(rng, index=number, family=surface)
        decoy = canaries.generate_decoy(rng, number)
        registry = {canary.canary_id: canary.value}

        MX.WRITERS[surface](surfaces, "f" + format(number, "02d"),
                            canaries.transform(canary.value, encoding))
        MX.WRITERS[surface](surfaces, "d" + format(number, "02d"), decoy)
        vault.add(VaultEntry(
            canary_id=canary.canary_id, raw_value=canary.value,
            transformation_family=encoding, planted_surfaces=(surface,),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="private", gold_destination_labels=("personal",),
        ))

        # The true negative is a canary of the same shape that was never
        # planted. Searching for it across a surface that carries only decoys
        # must find nothing; searching for a decoy the harness itself wrote
        # would prove only that the detector can find what it was told to find.
        absent = canaries.generate_canary(rng, index=1000 + number, family=surface)
        detected = _sweep_one(surfaces, registry, surface, None)
        blinded = _sweep_one(surfaces, registry, surface, mutation)
        decoy_hits = _sweep_one(surfaces, {absent.canary_id: absent.value},
                                surface, None)

        row = {
            "executed": True,
            "positive_control_detected": detected > 0,
            "negative_control_clean": decoy_hits == 0,
            "detector_mutation_blinds": blinded == 0 and detected > 0,
            "detector_mutation": mutation,
            "surface": surface,
            "encoding": encoding,
        }
        if number in ACTION_FAMILIES:
            row["action"] = _drive_action(kinbase, world, number)
        executed[number] = row
    vault.seal()

    coverage = MX.family_coverage(executed)
    require_all(
        coverage, lambda r: r["executed"], obligation="V-3.attack-families",
        why="every frozen family must actually run a probe",
        minimum=19, origin=Origin.HARNESS,
    )
    O.check(
        "V-3.attack-families",
        {"families": coverage},
        label="nineteen frozen families executed with control, decoy and blinding",
    )
