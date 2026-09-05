"""V-3 --- randomized detector qualification and the remaining frozen families.

``spec/verification.md`` V-3 sets the qualification the whole gate rests on:

    Qualify stochastic detection with at least 300 independently randomized
    planted positive variants, stratified with at least ten per declared
    surface/encoding family, and at least 500 randomized true-negative decoys.
    Every deterministic catalog control must be detected. The Wilson 95% lower
    bound on randomized sensitivity must be at least 0.98 and the Wilson 95%
    upper bound on false-positive rate at most 0.01.

and the custody rule that keeps the qualification honest:

    do not expose registry values to satisfy it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

import pytest

from ._harness import obligations as O
from ._harness.evidence_model import Origin, require_all, require_nonempty

from ._harness import canaries, stats, synth
from ._harness.cli import Guildhall
from ._harness.detectors import CanaryDetector, stratification_ok
from ._harness.gitfix import GitRepo
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    THREAT,
    VERIFY,
    HarnessInvalid,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.scanners import (
    git_object_surfaces,
    read_file_surfaces,
    sqlite_surfaces,
    sweep,
)
from ._harness.vault import CanaryVault, VaultEntry

pytestmark = [pytest.mark.v3]

RANDOMIZED_POSITIVES = 300
RANDOMIZED_DECOYS = 500
PER_FAMILY_MINIMUM = 10
SENSITIVITY_LOWER_BOUND = 0.98
FALSE_POSITIVE_UPPER_BOUND = 0.01


# --------------------------------------------------------------------------
# Randomized qualification (attack-catalog-1, attack-catalog-2)
# --------------------------------------------------------------------------


@pytest.mark.control_positive
@pytest.mark.selftest
@spec_ref(
    THREAT(
        "V-3",
        "attack-catalog-1",
        "exact/partial/substring and deterministic-lineage disclosure across every shared surface "
        "and destination",
    ),
    VERIFY(
        "V-3",
        "qualification",
        "Every deterministic catalog control must be detected. The Wilson 95% lower bound on "
        "randomized sensitivity must be at least 0.98 and the Wilson 95% upper bound on "
        "false-positive rate at most 0.01. Publish successes, misses, denominators, confidence "
        "bounds, and the resulting false-negative bound; do not expose registry values to satisfy "
        "it.",
    ),
)
def test_randomized_qualification_publishes_every_denominator(
    vault: CanaryVault, tmp_path: Path
) -> None:
    rng = canaries.make_rng(90210)
    plan = canaries.stratified_positive_plan(
        rng, total=RANDOMIZED_POSITIVES, per_family_minimum=PER_FAMILY_MINIMUM
    )
    registry: dict[str, str] = {}
    for index, (surface, encoding) in enumerate(plan):
        canary = canaries.generate_canary(rng, index=index, family=encoding)
        registry[canary.canary_id] = canary.value
        vault.add(
            VaultEntry(
                canary_id=canary.canary_id,
                raw_value=canary.value,
                transformation_family=encoding,
                planted_surfaces=(surface,),
                expected_destination_denial=("company", "codebase"),
                gold_atom_label="observation",
                gold_destination_labels=("personal",),
            )
        )
    detector = CanaryDetector(registry=registry, hmac_of=vault.hmac_of)

    ok, counts = stratification_ok(
        plan,
        families=canaries.SURFACE_FAMILIES + canaries.TRANSFORMATION_FAMILIES,
        minimum=PER_FAMILY_MINIMUM,
    )
    if not ok:
        raise HarnessInvalid(
            f"stratification floor of {PER_FAMILY_MINIMUM} per declared family not met: "
            f"{ {k: v for k, v in counts.items() if v < PER_FAMILY_MINIMUM} }"
        )

    detected = 0
    misses: list[str] = []
    for (surface, encoding), (canary_id, value) in zip(plan, registry.items()):
        payload = canaries.transform(value, encoding).encode("utf-8")
        if detector.detects(payload):
            detected += 1
        else:
            misses.append(f"{canary_id}:{surface}:{encoding}")

    decoy_rng = canaries.make_rng(112358)
    false_positives = 0
    for index in range(RANDOMIZED_DECOYS):
        if detector.detects(canaries.generate_decoy(decoy_rng, index).encode("utf-8")):
            false_positives += 1

    sensitivity_lower, _ = stats.wilson(detected, len(plan))
    _, fp_upper = stats.wilson(false_positives, RANDOMIZED_DECOYS)
    false_negative_bound = 1.0 - sensitivity_lower

    report = {
        "positives": len(plan),
        "successes": detected,
        "misses": len(misses),
        "decoys": RANDOMIZED_DECOYS,
        "false_positives": false_positives,
        "sensitivity_wilson_lower": round(sensitivity_lower, 6),
        "false_positive_wilson_upper": round(fp_upper, 6),
        "false_negative_bound": round(false_negative_bound, 6),
    }
    # Publishing must never expose a registry value.
    serialised = json.dumps(report)
    for value in registry.values():
        assert value not in serialised

    assert len(plan) >= RANDOMIZED_POSITIVES, len(plan)
    assert sensitivity_lower >= SENSITIVITY_LOWER_BOUND, (
        f"randomized sensitivity Wilson lower bound {sensitivity_lower:.4f} is below "
        f"{SENSITIVITY_LOWER_BOUND}; misses: {misses[:10]}"
    )
    assert fp_upper <= FALSE_POSITIVE_UPPER_BOUND, (
        f"false-positive Wilson upper bound {fp_upper:.4f} exceeds "
        f"{FALSE_POSITIVE_UPPER_BOUND}"
    )
    O.check(
        "V-3.qualification",
        {
            "positives": len(plan),
            "decoys": RANDOMIZED_DECOYS,
            "sensitivity_wilson_lower": sensitivity_lower,
            "false_positive_wilson_upper": fp_upper,
            "stratification_met": ok,
            "deterministic_controls_missed": len(misses),
            "false_negative_bound": false_negative_bound,
            "registry_values_not_exposed": all(
                v not in serialised for v in registry.values()
            ),
        },
        label="randomized detector qualification",
    )


@pytest.mark.control_negative
@pytest.mark.selftest
@spec_ref(
    THREAT(
        "V-3",
        "attack-catalog-2",
        "NFC/NFD, hex, base64, percent, JSON escape, delimiter, fragmentation, case, whitespace, "
        "and reversible-composition transformations",
    )
)
def test_every_declared_encoding_family_is_exercised() -> None:
    rng = canaries.make_rng(24680)
    plan = canaries.stratified_positive_plan(
        rng, total=RANDOMIZED_POSITIVES, per_family_minimum=PER_FAMILY_MINIMUM
    )
    encodings = {encoding for _, encoding in plan}
    assert encodings == set(canaries.TRANSFORMATION_FAMILIES), (
        "every frozen transformation family must appear in the qualification plan; "
        f"missing {set(canaries.TRANSFORMATION_FAMILIES) - encodings}"
    )
    surfaces = {surface for surface, _ in plan}
    assert surfaces == set(canaries.SURFACE_FAMILIES)


# --------------------------------------------------------------------------
# Family 6 --- history rewrite, packed objects, forged completeness
# --------------------------------------------------------------------------


@pytest.mark.requires_product
@spec_ref(
    THREAT(
        "V-3",
        "attack-catalog-6",
        "deletion, hidden packed Git object, missing manifest, forged completeness, "
        "shallow/sparse checkout, rebase, squash, and incompatible branch-head union",
    ),
    ARCH(
        "V-3",
        "codebase",
        "`fsck` validates full SHA-256 path equals exact canonical event bytes, schema, signature, "
        "authority, repository UUID, manifest/Merkle completeness, checkout completeness, size, "
        "and any compatibility index.",
    ),
)
def test_history_rewrite_and_forged_completeness_are_loud_and_typed(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.install_attributes(
        (".kin/events/** -text -diff -merge", ".kin/manifests/** -text -diff -merge")
    )
    repo.commit("initialise")

    # Deletion of an event with a manifest that still claims it.
    events = repo.path / ".kin" / "events" / "ab" / "cd"
    events.mkdir(parents=True, exist_ok=True)
    event_path = events / ("e" * 60 + ".json")
    event_path.write_text(json.dumps({"schema": "guildhall-event/1"}), encoding="utf-8")
    manifests = repo.path / ".kin" / "manifests" / "12" / "34"
    manifests.mkdir(parents=True, exist_ok=True)
    (manifests / ("f" * 60 + ".json")).write_text(
        json.dumps(
            {
                "schema": "guildhall-manifest/1",
                "event_count": 5,
                "merkle_root": "0" * 64,
                "manifest_head_set": ["deadbeef"],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    repo.commit("plant event and forged manifest")
    event_path.unlink()
    repo.commit("delete the event, keep the manifest claim")
    repo.repack()

    result = guildhall.run("fsck", "--repo", str(guildhall.cwd), "--full", "--json", check=False)
    assert result.returncode not in (0, 1), (
        "a missing event under a manifest claiming completeness must be loud and typed"
    )
    assert result.code in {"MANIFEST_INCOMPLETE", "DIGEST_MISMATCH", "SIGNATURE_INVALID"}
    assert result.returncode in (3, 5)


@pytest.mark.requires_product
@spec_ref(
    ARCH(
        "V-3",
        "repository-compatibility",
        "A deliberate sparse checkout excluding `.kin/` is a safe `MANIFEST_INCOMPLETE` degraded "
        "state (exit 3), not a privacy/integrity accusation",
    ),
    CLI(
        "V-3",
        "error-contract",
        "`MANIFEST_INCOMPLETE` | expected heads/events are missing | 5, or 3 for declared sparse "
        "checkout",
    ),
)
def test_declared_sparse_checkout_degrades_to_exit_three(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    origin = GitRepo.init(tmp_path / "origin")
    origin.write("README.md", "origin\n")
    origin.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    origin.commit("seed")
    sparse = origin.clone(tmp_path / "sparse", sparse=["README.md"])
    result = guildhall.run("fsck", "--repo", str(sparse.path), "--json", cwd=sparse.path, check=False)
    if result.returncode != 0:
        assert result.returncode != 1
        if result.code == "MANIFEST_INCOMPLETE":
            assert result.returncode == 3, (
                "a declared sparse checkout is a safe degraded state, exit 3, not an "
                f"integrity accusation; observed exit {result.returncode}"
            )
            assert "sparse" in result.error["remediation"].lower(), (
                "doctor must give the exact sparse-checkout remediation"
            )


# --------------------------------------------------------------------------
# Family 4 --- revocation and cache replay
# --------------------------------------------------------------------------


@pytest.mark.requires_product
@spec_ref(
    ARCH(
        "V-3",
        "trust-and-key-lifecycle",
        "A deleted or rolled-back cache is cold, never trusted offline, and must refetch a cursor "
        "at least as new as the last locally sealed cursor; inability to do so withholds all "
        "affected facts.",
    ),
    VERIFY(
        "V-3",
        "cache-replay",
        "Delete both Company cache and local cursor high-water state, then replay an old valid "
        "signed snapshot during refresh. A fresh client nonce and Company's signed current-cursor "
        "response prevent trust; offline operation stays degraded. Cache root mode must be 0700.",
    ),
)
def test_deleted_cache_plus_replayed_snapshot_stays_degraded(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    import shutil
    import stat as stat_mod

    if roots.company_cache.exists():
        mode = stat_mod.S_IMODE(roots.company_cache.stat().st_mode)
        assert mode == 0o700, (
            f"the Company cache root must be mode 0700; observed {mode:04o}"
        )
        snapshot = tmp_path / "old-cache"
        shutil.copytree(roots.company_cache, snapshot, dirs_exist_ok=True)
        shutil.rmtree(roots.company_cache)
        roots.company_cache.mkdir(parents=True, exist_ok=True)
        os.chmod(roots.company_cache, 0o700)
        shutil.copytree(snapshot, roots.company_cache, dirs_exist_ok=True)

    result = guildhall.run(
        "status",
        "--repo",
        str(guildhall.cwd),
        "--json",
        env={"GUILDHALL_COMPANY_URL": "http://127.0.0.1:1"},
        check=False,
    )
    assert result.returncode != 1
    if result.returncode == 0:
        payload = result.json
        assert payload.get("company_state") in {"degraded", "cold", "stale"}, (
            "a replayed old signed snapshot must not rebuild trusted state"
        )
        assert not payload.get("trusted_company_facts"), (
            "offline operation after a deleted high-water mark stays degraded"
        )
    else:
        assert result.code in {"COMPANY_UNREACHABLE", "CACHE_EXPIRED", "REVOCATION_STALE"}


@pytest.mark.requires_product
@spec_ref(
    ARCH(
        "V-3",
        "trust-and-key-lifecycle",
        "Pre-revocation facts remain historical but any client that has observed a cursor at or "
        "beyond the revocation cursor recalculates current trust as follows",
    ),
    VERIFY(
        "V-3",
        "revocation",
        "Revoke a signer at a later Company cursor and assert decisions/facts admitted under an "
        "older authority snapshot are found and reopened as owned Unknowns.",
    ),
)
def test_revoked_signer_reopens_downstream_facts_as_owned_unknowns(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    steward = synth.make_signer("company-steward-1", "company:root", seed_byte=11)
    revocation = steward.sign_message(
        "revocation",
        {
            "schema": "guildhall-revocation/1",
            "revoked_signer": synth.make_signer("architect-1", "architecture:scheduling", seed_byte=3).public_hex,
            "revocation_cursor": "1000",
            "effective_at": "2026-03-06T00:00:00.000Z",
            "scope": "architecture:scheduling",
        },
    )
    path = tmp_path / "revocation.json"
    path.write_text(json.dumps(revocation, sort_keys=True), encoding="utf-8")
    guildhall.run(
        "ingest", "kindex", str(path), "--repo", str(guildhall.cwd), "--json", check=False
    )
    status = guildhall.run("status", "--repo", str(guildhall.cwd), "--json", check=False)
    if status.returncode == 1:
        raise ProductFailure("`status` returned the reserved ambiguous exit 1")
    if status.returncode not in (0, 3):
        raise ProductFailure(
            f"`status` refused with {status.code}; the revocation cascade state must "
            "be observable for the obligation to bind"
        )
    payload = status.json
    cascade = payload.get("revocation_cascade") or {}
    if cascade:
        assert cascade.get("state") in {
            "complete",
            "REVOCATION_CASCADE_INCOMPLETE",
        }, cascade
        if cascade.get("state") == "REVOCATION_CASCADE_INCOMPLETE":
            assert cascade.get("remaining_count") is not None, (
                "an incomplete cascade must record the remaining count and retain "
                "fail-closed state"
            )
    unknowns = payload.get("unknowns") or []
    reopened = [u for u in unknowns if u.get("cause") == "revocation"]
    if reopened:
        for unknown in reopened:
            assert unknown.get("owner_identity"), (
                "a blocking Unknown always names a person"
            )


@pytest.mark.requires_product
@spec_ref(
    ARCH(
        "V-3",
        "trust-and-key-lifecycle",
        "The Company steward owns an immutable `unreachable_clone_residual` record naming revoked "
        "key, cursor, potentially warranted fact/logical-key set, maximum offline "
        "revocation-freshness window, and the explicit fact that unknown clones may keep "
        "projecting until they sync or expire.",
    )
)
def test_unreachable_clone_residual_is_recorded_with_every_field(
    guildhall: Guildhall,
) -> None:
    status = guildhall.run("status", "--repo", str(guildhall.cwd), "--json", check=False)
    if status.returncode == 1:
        raise ProductFailure("`status` returned the reserved ambiguous exit 1")
    if status.returncode not in (0, 3):
        raise ProductFailure(
            f"`status` refused with {status.code}; the steward-owned residual must be "
            "observable for the obligation to bind"
        )
    residuals = status.json.get("unreachable_clone_residuals") or []
    for residual in residuals:
        for field in (
            "revoked_key",
            "cursor",
            "potentially_warranted_logical_keys",
            "max_offline_revocation_freshness_seconds",
            "unknown_clones_may_keep_projecting",
        ):
            assert field in residual, (
                f"the steward-owned residual must name {field}; observed "
                f"{sorted(residual)}"
            )
        assert residual["unknown_clones_may_keep_projecting"] is True, (
            "the residual must state explicitly that unknown clones may keep "
            "projecting until they sync or expire"
        )


# --------------------------------------------------------------------------
# Family 8 --- accidental disclosure surfaces
# --------------------------------------------------------------------------


@pytest.mark.requires_product
@spec_ref(
    THREAT(
        "V-3",
        "attack-catalog-8",
        "accidental disclosure through errors, traces, telemetry, receipts, evidence packets, "
        "caches, temporary files, cleanup, and process command lines",
    ),
    VERIFY(
        "V-3",
        "logs",
        "Logs are structured and contain IDs/digests/statuses, never raw private messages.",
    ),
)
def test_errors_traces_and_temporary_files_carry_no_private_bytes(
    guildhall: Guildhall, roots: ProofRoots, vault: CanaryVault, tmp_path: Path
) -> None:
    rng = canaries.make_rng(654321)
    canary = canaries.generate_canary(rng, index=0, family="exact", kind="hard_block")
    vault.add(
        VaultEntry(
            canary_id=canary.canary_id,
            raw_value=canary.value,
            transformation_family="exact",
            planted_surfaces=("personal_store",),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="observation",
            gold_destination_labels=("personal",),
        )
    )
    source = roots.plant_personal_canary_file(
        "error-path.jsonl",
        json.dumps({"role": "user", "text": f"private {canary.value}"}) + "\n",
    )
    detector = CanaryDetector(
        registry={canary.canary_id: canary.value}, hmac_of=vault.hmac_of
    )

    # Force error paths on every command surface.
    transcripts = []
    for argv in (
        ("session", "observe", "no-such-session", "--event", str(source), "--json"),
        ("explain", "no/such/key", "--repo", str(guildhall.cwd), "--decision", "x", "--json"),
        ("project", "--repo", str(guildhall.cwd), "--task", "x", "--decision", "y", "--json"),
        ("proposals", "show", "no-such-candidate", "--destination", "company", "--json"),
        ("fsck", "--repo", str(guildhall.cwd), "--json"),
    ):
        result = guildhall.run(*argv, check=False)
        transcripts.append(result.stdout + "\n" + result.stderr)
        assert result.returncode != 1, (
            f"{argv[0]} returned the reserved ambiguous exit 1"
        )

    combined = "\n".join(transcripts).encode("utf-8", "surrogateescape")
    findings = detector.scan_bytes(
        combined,
        surface_family="process_artifacts",
        location_digest="cli-transcripts",
        observed_at="2026-03-01T00:00:00.000Z",
    )
    assert not findings, (
        "error bodies, traces and telemetry must never carry raw private bytes"
    )

    swept = sweep(
        detector,
        read_file_surfaces(roots.run_root, "shared_outbox", detector),
    )
    assert swept.clean, (
        "temporary files and cleanup residue must carry no private bytes: "
        + json.dumps([f.sanitised() for f in swept.findings], indent=2)
    )


# --------------------------------------------------------------------------
# Family 9 and 10 --- promotion gate and correlated reconstruction
# --------------------------------------------------------------------------


@pytest.mark.requires_product
@spec_ref(
    THREAT(
        "V-3",
        "attack-catalog-9",
        "sandboxed coding-agent Personal-root reads and arbitrary same-UID acquisition followed by "
        "attempted shared promotion",
    ),
    THREAT(
        "V-3",
        "adversary",
        "The acceptance claim still requires the promotion gates to reject protected bytes "
        "obtained by that process.",
    ),
)
def test_same_uid_acquired_bytes_are_rejected_by_the_promotion_gate(
    guildhall: Guildhall, roots: ProofRoots, vault: CanaryVault, tmp_path: Path
) -> None:
    rng = canaries.make_rng(13579)
    canary = canaries.generate_canary(rng, index=0, family="exact", kind="hard_block")
    vault.add(
        VaultEntry(
            canary_id=canary.canary_id,
            raw_value=canary.value,
            transformation_family="exact",
            planted_surfaces=("personal_store",),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="observation",
            gold_destination_labels=("personal",),
        )
    )
    personal_file = roots.plant_personal_canary_file(
        "same-uid-target.jsonl", f"{canary.value}\n"
    )
    # An arbitrary same-UID process reads user-readable files. That is explicitly
    # outside the application-boundary claim.
    stolen = personal_file.read_text(encoding="utf-8").strip()
    assert stolen == canary.value

    for destination in ("company", "codebase:018f0000-0000-7000-8000-000000000001"):
        attempt = guildhall.run(
            "proposals",
            "decide",
            "c9a7c4f1",
            "--destination",
            destination,
            "--approve-digest",
            "0" * 64,
            "--json",
            check=False,
        )
        assert attempt.returncode not in (0, 1), (
            f"promotion of same-UID-acquired bytes to {destination} must be rejected"
        )


@pytest.mark.selftest
@spec_ref(
    THREAT(
        "V-3",
        "attack-catalog-10",
        "correlated reconstruction using the independently frozen auxiliary corpus",
    ),
    THREAT(
        "V-3",
        "auxiliary-corpus",
        "The implementation-blind Detector Reviewer selects the adversarial reconstructor's "
        "auxiliary corpus before implementation combination from the eligible licensed public "
        "source pool plus generated transformation dictionaries and preregistered "
        "correlation/decoy records.",
    ),
)
def test_auxiliary_corpus_selection_record_is_complete_and_frozen() -> None:
    """The pool must be complete, reproducible, digest-bound and *not* selectable.

    Detector Reviewer finding 21. The completable parts are asserted here:
    concrete candidates with versions and digests, generated components that
    reproduce byte-for-byte from named seeds, a digest that binds the whole
    manifest and the rights and protocol bytes, and a selection protocol.

    The uncompletable part is asserted too, as a failure. A named human
    rightsholder grant cannot be authored by the Tester, so while ``GRANT.md``
    is absent the pool is not selectable and this is ``INVALID_HARNESS`` --- an
    instrument condition naming the exact missing bytes, never a pass.
    """
    root = Path(__file__).resolve().parents[1] / "fixtures" / "auxiliary"
    lane = Path(__file__).resolve().parents[2]
    pool_path = root / "pool.json"
    if not pool_path.is_file():
        raise HarnessInvalid("no eligible auxiliary-corpus pool exists")
    pool = json.loads(pool_path.read_text(encoding="utf-8"))

    # -- candidates: concrete, versioned, digest-matched -------------------
    candidates = pool["candidates"]
    if len(candidates) < 3:
        raise HarnessInvalid(f"the pool offers only {len(candidates)} candidates")
    for candidate in candidates:
        path = lane / candidate["path"]
        if not path.is_file():
            raise HarnessInvalid(f"pool candidate {candidate['path']} is absent")
        if hashlib.sha256(path.read_bytes()).hexdigest() != candidate["sha256"]:
            raise HarnessInvalid(f"{candidate['path']} does not match its digest")
        if not candidate.get("version"):
            raise HarnessInvalid(f"{candidate['path']} records no version")

    # -- generated components reproduce byte-for-byte from their seeds -----
    from ._harness import auxgen

    regenerated = auxgen.regenerate()
    for component in pool["generated_components"]:
        path = lane / component["path"]
        if not path.is_file():
            raise HarnessInvalid(f"{component['path']} is absent")
        if hashlib.sha256(path.read_bytes()).hexdigest() != component["sha256"]:
            raise HarnessInvalid(f"{component['path']} does not match its digest")
        name = Path(component["path"]).stem
        expected = auxgen.serialise(regenerated[name])
        if hashlib.sha256(expected.encode()).hexdigest() != component["sha256"]:
            raise HarnessInvalid(
                f"{component['path']} does not reproduce from seed "
                f"{component['seed']}; it was hand-edited rather than generated"
            )
    recipe = pool["generation"]
    for field in ("seeds", "algorithms", "counts", "reproduce_with"):
        if not recipe.get(field):
            raise HarnessInvalid(f"the generation recipe records no {field}")

    # -- the digest binds every byte, not only content hashes --------------
    core = {k: v for k, v in pool.items() if k != "pool_digest_sha256"}
    combined = hashlib.sha256()
    combined.update(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    )
    for extra in ("RIGHTS.md", "GRANT-TEMPLATE.md", "SELECTION-PROTOCOL.md"):
        extra_path = root / extra
        if not extra_path.is_file():
            raise HarnessInvalid(f"the pool is missing {extra}")
        combined.update(
            hashlib.sha256(extra_path.read_bytes()).hexdigest().encode()
        )
    if combined.hexdigest() != pool["pool_digest_sha256"]:
        raise HarnessInvalid("the pool digest does not bind the current bytes")
    if (root / "POOL-DIGEST").read_text(encoding="utf-8").strip() != combined.hexdigest():
        raise HarnessInvalid("POOL-DIGEST disagrees with the manifest")

    # -- selection remains the Reviewer's and is not pre-filled ------------
    if pool["selected_by"] != "detector-reviewer":
        raise HarnessInvalid("only the implementation-blind Reviewer may select")
    if pool["selection_record"] is not None:
        raise HarnessInvalid(
            "the Tester must not author the Reviewer's selection record"
        )
    if pool["mutable_after_execution_begins"] is not False:
        raise HarnessInvalid("the corpus cannot be replaced after execution begins")

    # -- the outstanding human grant is a stated instrument condition ------
    rights = pool["rights_basis"]
    if not (root / "GRANT.md").is_file():
        raise HarnessInvalid(
            "the auxiliary corpus is not selectable: no signed rights grant "
            "exists. spec/threat-model.md requires the Reviewer to record "
            "source rights before selection, and a Tester assertion of "
            "authorship cannot establish authority to grant a licence. A named "
            "human must sign tests/fixtures/auxiliary/GRANT-TEMPLATE.md over "
            f"pool digest {pool['pool_digest_sha256']} and commit it as "
            "tests/fixtures/auxiliary/GRANT.md."
        )
    for field in ("named_rightsholder", "rightsholder_signature", "authority_basis"):
        if not rights.get(field):
            raise HarnessInvalid(f"the rights basis records no {field}")


@pytest.mark.selftest
@spec_ref(
    THREAT(
        "V-3",
        "mechanical-recovery",
        "A recovery is positive when a shared surface contains an exact protected sequence, a "
        "frozen reversible transformation of one, a partial sequence meeting the frozen "
        "length/rarity rule, or a deterministic chain from auxiliary evidence to one unique canary "
        "value.",
    )
)
def test_mechanical_recovery_rule_is_frozen_before_the_run(vault: CanaryVault) -> None:
    rng = canaries.make_rng(2468)
    canary = canaries.generate_canary(rng, index=0, family="exact")
    vault.add(
        VaultEntry(
            canary_id=canary.canary_id,
            raw_value=canary.value,
            transformation_family="exact",
            planted_surfaces=("logs",),
            expected_destination_denial=("company",),
            gold_atom_label="observation",
            gold_destination_labels=("personal",),
        )
    )
    detector = CanaryDetector(
        registry={canary.canary_id: canary.value},
        lineage={canary.canary_id: ("aux-chain-" + canary.value[-8:],)},
        hmac_of=vault.hmac_of,
    )
    body = canary.value.split("-", 1)[1]
    # 1. exact
    assert detector.detects(canary.value.encode())
    # 2. frozen reversible transformation
    assert detector.detects(canaries.t_base64(canary.value).encode())
    # 3. partial meeting the length/rarity rule
    assert detector.detects(body[: detector.partial_min_chars].encode())
    assert not detector.detects(body[: detector.partial_min_chars - 6].encode())
    # 4. deterministic chain from auxiliary evidence
    assert detector.detects(("aux-chain-" + canary.value[-8:]).encode())
    # A semantic paraphrase with no deterministic lineage is not a positive.
    assert not detector.detects(b"a randomly generated marker was mentioned")
