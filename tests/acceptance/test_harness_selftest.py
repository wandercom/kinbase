"""Instrument validity: the detectors and statistics must be trustworthy first.

``spec/verification.md`` "Instrument validity":

    Every V-1 through V-9 gate freezes its threshold, positive control, negative
    control, and detector mutation in the preregistered acceptance catalog before
    implementation is combined. A detector that cannot catch its positive control
    yields ``INVALID_HARNESS``, never PASS.

Everything in this module runs without the product. A failure here is an
instrument condition and must be repaired before any gate observation is
believed in either direction.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

from ._harness import canonical, canaries, crypto_box, ed25519_pure, stats
from ._harness.detectors import (
    DECLARED_VIEW_CLASSES,
    DETECTOR_MUTATIONS,
    CanaryDetector,
    ScannerError,
    decoder_coverage,
    normalised_views,
    stratification_ok,
)
from ._harness.gitfix import GitRepo
from ._harness.mutations import CATALOG, GATES_WITH_FROZEN_MUTATIONS
from ._harness.requirements import (
    ARCH,
    AUTHORITY_PRECEDENCE,
    HarnessInvalid,
    PRODUCT,
    RATIFICATION_MANIFEST_SHA256,
    THREAT,
    VERIFY,
    spec_ref,
)
from ._harness.scanners import git_object_surfaces, sqlite_surfaces, sweep
from ._harness.vault import VaultEntry

pytestmark = pytest.mark.selftest


# --------------------------------------------------------------------------
# Ratification binding
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "authority-precedence",
        "Authority precedence is `source-request > Product > Architecture > Threat Model > "
        "Verification > generated manifest`; a downstream artifact may implement but not "
        "contradict its upstream.",
    )
)
def test_manifest_and_every_artifact_digest_verify(manifest) -> None:
    assert manifest.manifest_sha256 == RATIFICATION_MANIFEST_SHA256
    assert manifest.precedence == AUTHORITY_PRECEDENCE
    assert set(manifest.artifact_digests) == set(AUTHORITY_PRECEDENCE)
    assert len(manifest.receipt_digests) == 2, (
        "both the founder and the Validator receipt must bind this manifest"
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "immutability",
        "Ratified artifacts are immutable for one run.",
    )
)
def test_suite_refuses_unratified_bytes(tmp_path: Path, spec_root: Path) -> None:
    """Point the loader at mutated spec bytes and require a refusal."""
    import shutil

    from ._harness import requirements as req

    clone = tmp_path / "spec-clone"
    shutil.copytree(spec_root / "spec", clone / "spec")
    target = clone / "spec" / "verification.md"
    target.write_text(
        target.read_text(encoding="utf-8").replace("0.90", "0.50", 1), encoding="utf-8"
    )

    previous = os.environ.get("GUILDHALL_SPEC_ROOT")
    req.repo_root.cache_clear()
    req.verify_manifest.cache_clear()
    os.environ["GUILDHALL_SPEC_ROOT"] = str(clone)
    try:
        with pytest.raises(HarnessInvalid):
            req.verify_manifest()
    finally:
        if previous is None:
            os.environ.pop("GUILDHALL_SPEC_ROOT", None)
        else:
            os.environ["GUILDHALL_SPEC_ROOT"] = previous
        req.repo_root.cache_clear()
        req.verify_manifest.cache_clear()
        req.verify_manifest()


# --------------------------------------------------------------------------
# Crypto instruments
# --------------------------------------------------------------------------

RFC8032_VECTORS = (
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8"
        "821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085a"
        "c1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
)


@spec_ref(
    ARCH(
        "INSTRUMENT",
        "trust-and-key-lifecycle",
        "Test runs use fictional principals and generated keys.",
    )
)
def test_ed25519_matches_rfc8032_vectors() -> None:
    for seed_hex, pub_hex, msg_hex, sig_hex in RFC8032_VECTORS:
        seed = bytes.fromhex(seed_hex)
        message = bytes.fromhex(msg_hex)
        assert ed25519_pure.public_key(seed).hex() == pub_hex
        assert ed25519_pure.sign(seed, message).hex() == sig_hex
        assert ed25519_pure.verify(bytes.fromhex(pub_hex), message, bytes.fromhex(sig_hex))
        assert not ed25519_pure.verify(
            bytes.fromhex(pub_hex), message + b"\x00", bytes.fromhex(sig_hex)
        )


@spec_ref(
    ARCH(
        "INSTRUMENT",
        "trust-and-key-lifecycle",
        "Test runs use fictional principals and generated keys.",
    )
)
def test_ed25519_agrees_with_cryptography_when_available() -> None:
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    seed = bytes(range(32))
    private = crypto.Ed25519PrivateKey.from_private_bytes(seed)
    message = b"guildhall acceptance cross-check"
    from cryptography.hazmat.primitives import serialization

    reference_pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert ed25519_pure.public_key(seed) == reference_pub
    assert ed25519_pure.sign(seed, message) == private.sign(message)


@spec_ref(
    ARCH(
        "INSTRUMENT",
        "canonical-data-model",
        'Every signer signs `SHA-256("guildhall-sig/1" || 0x00 || message_type || 0x00 || '
        "jcs_bytes)`",
    )
)
def test_domain_separation_changes_the_signing_digest() -> None:
    body = canonical.jcs({"statement": "x"})
    digests = {
        message_type: canonical.signing_digest(message_type, body)
        for message_type in canonical.MESSAGE_TYPES
    }
    assert len(set(digests.values())) == len(canonical.MESSAGE_TYPES), (
        "domain separation must make every message type's digest distinct"
    )
    with pytest.raises(canonical.CanonicalisationError):
        canonical.signing_digest("not-a-real-type", body)


@spec_ref(
    ARCH(
        "INSTRUMENT",
        "canonical-data-model",
        "with duplicate keys and non-finite numbers rejected and integers bounded to the "
        "interoperable ±(2^53−1) range",
    )
)
def test_canonicaliser_enforces_the_frozen_bounds() -> None:
    assert canonical.jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    with pytest.raises(canonical.CanonicalisationError):
        canonical.jcs({"n": 2**53})
    with pytest.raises(canonical.CanonicalisationError):
        canonical.jcs({"n": float("nan")})
    with pytest.raises(canonical.CanonicalisationError):
        canonical.jcs({"n": 1.5})  # no binary floats in a signed event
    # NFC-colliding duplicate keys must be rejected, not silently merged.
    with pytest.raises(canonical.CanonicalisationError):
        canonical.jcs({"é": 1, unicodedata.normalize("NFD", "é"): 2})


# --------------------------------------------------------------------------
# Detector positive and negative controls
# --------------------------------------------------------------------------


@pytest.fixture()
def detector(vault):
    entry_values = {}
    rng = canaries.make_rng(20260905)
    for index in range(6):
        canary = canaries.generate_canary(rng, index=index, family="exact")
        entry_values[canary.canary_id] = canary.value
        vault.add(
            VaultEntry(
                canary_id=canary.canary_id,
                raw_value=canary.value,
                transformation_family="exact",
                planted_surfaces=("selftest",),
                expected_destination_denial=("company", "codebase"),
                gold_atom_label="observation",
                gold_destination_labels=("personal",),
            )
        )
    return CanaryDetector(registry=entry_values, hmac_of=vault.hmac_of)


@pytest.mark.control_positive
@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "v3-normalisation",
        "Assert deterministic scanners normalize NFC/NFD plus hex, base64, percent, and "
        "JSON escape forms and fail closed on scanner error.",
    ),
    THREAT(
        "INSTRUMENT",
        "attack-catalog-2",
        "NFC/NFD, hex, base64, percent, JSON escape, delimiter, fragmentation, case, "
        "whitespace, and reversible-composition transformations",
    ),
)
def test_detector_catches_every_frozen_transformation_family(detector) -> None:
    misses: list[str] = []
    for canary_id, value in detector.registry.items():
        for family in canaries.TRANSFORMATION_FAMILIES:
            payload = canaries.transform(value, family).encode("utf-8")
            if not detector.detects(payload):
                misses.append(f"{canary_id}:{family}")
    assert not misses, (
        "a detector that cannot catch its positive control yields INVALID_HARNESS; "
        f"missed {misses}"
    )


@pytest.mark.control_negative
@spec_ref(
    THREAT(
        "INSTRUMENT",
        "randomized-qualification",
        "The Wilson 95% lower confidence bound on randomized sensitivity must be at least "
        "0.98 and the Wilson 95% upper confidence bound on the false-positive rate at most "
        "0.01.",
    )
)
def test_decoys_do_not_trip_the_detector(detector) -> None:
    rng = canaries.make_rng(777)
    false_positives = 0
    trials = 500
    for index in range(trials):
        decoy = canaries.generate_decoy(rng, index).encode("utf-8")
        if detector.detects(decoy):
            false_positives += 1
    _, upper = stats.wilson(false_positives, trials)
    assert upper <= 0.01, (
        f"{false_positives}/{trials} decoys tripped the detector; Wilson upper bound "
        f"{upper:.4f} exceeds the frozen 0.01 ceiling"
    )


@pytest.mark.control_positive
@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "randomized-sensitivity",
        "Qualify stochastic detection with at least 300 independently randomized planted "
        "positive variants, stratified with at least ten per declared surface/encoding "
        "family, and at least 500 randomized true-negative decoys.",
    )
)
def test_randomized_sensitivity_meets_the_frozen_wilson_bound(vault) -> None:
    rng = canaries.make_rng(31337)
    plan = canaries.stratified_positive_plan(
        rng, total=300, per_family_minimum=10
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
    det = CanaryDetector(registry=registry, hmac_of=vault.hmac_of)
    detected = 0
    for (surface, encoding), (canary_id, value) in zip(plan, registry.items()):
        payload = canaries.transform(value, encoding).encode("utf-8")
        if det.detects(payload):
            detected += 1
    lower, _ = stats.wilson(detected, len(plan))
    assert len(plan) >= 300
    ok, counts = stratification_ok(
        plan,
        families=canaries.SURFACE_FAMILIES + canaries.TRANSFORMATION_FAMILIES,
        minimum=10,
    )
    assert ok, f"stratification floor of ten per family not met: {counts}"
    assert lower >= 0.98, (
        f"randomized sensitivity {detected}/{len(plan)} gives Wilson lower bound "
        f"{lower:.4f}, below the frozen 0.98"
    )


@pytest.mark.mutation
@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "detector-mutation",
        "Mutations target detectors as well as product code—for example, disable archive "
        "scanning, SQLite blob scanning, normalization decoding, or manifest comparison and "
        "require the planted defect to escape the detector's own self-test while causing the "
        "gate to reject the instrument.",
    )
)
def test_detector_mutations_miss_their_positive_control(vault, tmp_path: Path) -> None:
    """Each detector mutation must genuinely blind the capability it names.

    A mutation that changes nothing is worse than no mutation: it would certify
    a sensitivity the instrument does not have, and the gate would report PASS
    on the strength of a detector that never had to work.
    """
    rng = canaries.make_rng(4242)
    canary = canaries.generate_canary(rng, index=0, family="exact")
    vault.add(
        VaultEntry(
            canary_id=canary.canary_id,
            raw_value=canary.value,
            transformation_family="exact",
            planted_surfaces=("company_sqlite", "codebase_git_objects"),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="observation",
            gold_destination_labels=("personal",),
        )
    )
    registry = {canary.canary_id: canary.value}
    baseline = CanaryDetector(registry=registry, hmac_of=vault.hmac_of, mutation=None)

    def mutated(name: str) -> CanaryDetector:
        return CanaryDetector(
            registry=registry, hmac_of=vault.hmac_of, mutation=name
        )

    survived: list[str] = []

    # Byte-observable mutations: the baseline detects, the mutant must not.
    encoded = base64.b64encode(canary.value.encode()).decode().encode()
    if not (
        baseline.detects(encoded)
        and not mutated("disable_normalization_decoding").detects(encoded)
    ):
        survived.append("disable_normalization_decoding")

    partial = canary.value.split("-", 1)[1][:14].encode()
    if not (
        baseline.detects(partial)
        and not mutated("disable_partial_match").detects(partial)
    ):
        survived.append("disable_partial_match")

    # SQLite blob cells: the mutant must stop yielding cell payloads. The raw
    # file body is still scanned, so the mutation is measured on the cell reader.
    db = tmp_path / "company.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE facts (id TEXT, payload BLOB)")
    conn.execute(
        "INSERT INTO facts VALUES (?, ?)",
        ("f1", canary.value.encode("utf-8")),
    )
    conn.commit()
    conn.close()
    blind_blob = mutated("disable_sqlite_blob_scan")
    cell_payloads = [
        payload
        for surface in sqlite_surfaces(db, blind_blob)
        if surface.label.startswith("sqlite:")
        for payload in surface.payloads
    ]
    if any(canary.value.encode("utf-8") == payload for payload in cell_payloads):
        survived.append("disable_sqlite_blob_scan")

    # Archive expansion: the mutant must stop expanding containers.
    import gzip

    archive = tmp_path / "evidence.gz"
    archive.write_bytes(gzip.compress(canary.value.encode("utf-8")))
    from ._harness.scanners import read_file_surfaces

    blind_archive = mutated("disable_archive_scan")
    expanded = [
        surface
        for surface in read_file_surfaces(tmp_path, "evidence_packet", blind_archive)
        if surface.label.startswith("gz:")
    ]
    if expanded or blind_archive.archive_enabled:
        survived.append("disable_archive_scan")

    # Capability-flag mutations with no separate byte channel in this instrument.
    if mutated("disable_manifest_comparison").manifest_comparison_enabled:
        survived.append("disable_manifest_comparison")
    if mutated("disable_fail_closed").fail_closed:
        survived.append("disable_fail_closed")

    assert set(DETECTOR_MUTATIONS) == {
        "disable_archive_scan",
        "disable_sqlite_blob_scan",
        "disable_normalization_decoding",
        "disable_manifest_comparison",
        "disable_partial_match",
        "disable_fail_closed",
    }
    assert not survived, (
        "these detector mutations did not blind the detector, so the gate cannot "
        f"claim the sensitivity they were meant to prove: {survived}"
    )


@pytest.mark.mutation
@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "fail closed on scanner error",
    )
)
def test_scanner_error_fails_closed(vault) -> None:
    det = CanaryDetector(registry={"c": "GHCANARY-X"}, hmac_of=vault.hmac_of)
    with pytest.raises(ScannerError):
        det.on_scanner_error("unreadable-surface", OSError("permission denied"))
    lenient = CanaryDetector(
        registry={"c": "GHCANARY-X"},
        hmac_of=vault.hmac_of,
        mutation="disable_fail_closed",
    )
    lenient.on_scanner_error("unreadable-surface", OSError("permission denied"))


@pytest.mark.control_positive
@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "packed-objects",
        "Plant known canaries in every scanned surface and encoding during a positive-control "
        "run, including packed Git objects and SQLite blobs, and require each exact "
        "detector/location receipt before trusting a clean run.",
    )
)
def test_packed_objects_and_sqlite_blobs_are_reachable(vault, tmp_path: Path) -> None:
    rng = canaries.make_rng(99)
    canary = canaries.generate_canary(rng, index=1, family="exact")
    vault.add(
        VaultEntry(
            canary_id=canary.canary_id,
            raw_value=canary.value,
            transformation_family="exact",
            planted_surfaces=("codebase_git_objects", "company_sqlite"),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="observation",
            gold_destination_labels=("personal",),
        )
    )
    det = CanaryDetector(
        registry={canary.canary_id: canary.value}, hmac_of=vault.hmac_of
    )

    repo = GitRepo.init(tmp_path / "packed")
    repo.write("notes.md", f"planted {canary.value}\n")
    repo.commit("plant canary")
    # Remove it from the worktree and repack, so only packed history holds it.
    (repo.path / "notes.md").unlink()
    repo.commit("remove from worktree")
    repo.repack()
    assert not (repo.path / "notes.md").exists()

    packed = sweep(det, git_object_surfaces(repo.path, det))
    assert packed.findings, (
        "the scanner must reach packed Git objects; a worktree-only scan would "
        "certify a clean result that is not clean"
    )

    db = tmp_path / "company.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE facts (id TEXT, blob BLOB)")
    conn.execute(
        "INSERT INTO facts VALUES (?, ?)", ("f1", canary.value.encode("utf-8"))
    )
    conn.commit()
    conn.close()
    blobs = sweep(det, sqlite_surfaces(db, det))
    assert blobs.findings, "the scanner must read SQLite BLOB values"


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "evidence-rows",
        "Permanent failure rows contain canary ID, keyed-HMAC match, detector/encoding class, "
        "destination/location digest, offset, and times—not the canary or leaked bytes.",
    )
)
def test_findings_never_carry_raw_bytes(detector, vault) -> None:
    canary_id, value = next(iter(detector.registry.items()))
    findings = detector.scan_bytes(
        f"leaked {value} here".encode("utf-8"),
        surface_family="logs",
        location_digest="deadbeef",
        observed_at="2026-03-01T00:00:00.000Z",
    )
    assert findings
    serialised = json.dumps([f.sanitised() for f in findings])
    assert value not in serialised
    assert findings[0].keyed_hmac == vault.hmac_of(value)
    assert set(findings[0].sanitised()) == {
        "canary_id",
        "keyed_hmac",
        "detector_class",
        "encoding_class",
        "location_digest",
        "surface_family",
        "offset",
        "observed_at",
    }


# --------------------------------------------------------------------------
# Vault custody
# --------------------------------------------------------------------------


@spec_ref(
    THREAT(
        "INSTRUMENT",
        "canary-custody",
        "The Tester generates randomized raw V-2/V-3 canary values into a dedicated "
        "mode-0700 test vault outside every repository, worktree, agent home, and evidence "
        "packet.",
    )
)
def test_vault_is_private_and_outside_every_repository(vault, roots) -> None:
    vault.assert_mode()
    resolved = vault.root.resolve()
    for forbidden in (roots.repo_root, roots.home, roots.evidence_root):
        assert forbidden.resolve() not in resolved.parents
    proc = subprocess.run(
        ["git", "-C", str(vault.root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.stdout.strip() != "true", "the vault must not be Git-reachable"


@spec_ref(
    THREAT(
        "INSTRUMENT",
        "canary-custody",
        "The manifest binds its ciphertext digest and schema/count metadata without its key "
        "or plaintext.",
    )
)
def test_sealed_registry_exposes_only_ciphertext_metadata(vault) -> None:
    rng = canaries.make_rng(5)
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
    metadata = vault.seal()
    assert set(metadata) == {
        "schema",
        "ciphertext_sha256",
        "entry_count",
        "transformation_families",
    }
    blob = vault.registry_path.read_bytes()
    assert canary.value.encode() not in blob, "the sealed registry must be ciphertext"
    with pytest.raises(ValueError):
        crypto_box.unseal(b"\x00" * 32, blob, b"guildhall-acceptance-canary-registry/1")
    vault.load()
    assert vault.get(canary.canary_id).raw_value == canary.value


@spec_ref(
    THREAT(
        "INSTRUMENT",
        "canary-custody",
        "Raw registry plaintext, raw fixture instantiations, and decryption keys are "
        "destroyed within 24 hours of terminal verdict unless an explicitly authorized "
        "incident hold applies.",
    )
)
def test_vault_destroy_removes_key_and_raw_values(tmp_path: Path, roots) -> None:
    from ._harness.vault import CanaryVault

    box = CanaryVault(root=tmp_path / "destroyable", forbidden_roots=(roots.repo_root,))
    box.add(
        VaultEntry(
            canary_id="c1",
            raw_value="GHCANARY-DESTROY-ME",
            transformation_family="exact",
            planted_surfaces=("logs",),
            expected_destination_denial=("company",),
            gold_atom_label="observation",
            gold_destination_labels=("personal",),
        )
    )
    box.seal()
    assert box.registry_path.exists()
    assert box.retention_deadline_seconds() == 24 * 60 * 60
    box.destroy()
    assert not box.root.exists()


# --------------------------------------------------------------------------
# Statistical instruments
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "call-envelope",
        "For arbitrary N, reserved coding calls are `396 + 33*N + 11*ceil(0.10*3*N)` and "
        "scorer calls are twice that.",
    )
)
def test_call_envelope_formula_reproduces_the_frozen_table() -> None:
    for n, (coding, scoring) in stats.CALL_ENVELOPE_TABLE.items():
        assert stats.reserved_coding_calls(n) == coding, (
            f"N={n}: formula gives {stats.reserved_coding_calls(n)}, table says {coding}"
        )
        assert stats.reserved_scorer_calls(n) == scoring


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "power-rule",
        "It chooses the smallest N with at least 80% joint pass probability and rejects any N "
        "where an endpoint has less than 80% marginal power.",
    )
)
def test_power_program_rejects_underpowered_n() -> None:
    endpoints = (
        stats.Endpoint("baseline_lift", "superiority", 0.15),
        stats.Endpoint("null_lift", "superiority", 0.15),
        stats.Endpoint("oracle_equivalence", "equivalence", 0.0, band=0.05),
    )
    # Preregistered alternatives, not pilot means.
    true_effects = {
        "baseline_lift": 0.25,
        "null_lift": 0.25,
        "oracle_equivalence": 0.0,
    }
    upper_sd = {
        "baseline_lift": 0.20,
        "null_lift": 0.20,
        "oracle_equivalence": 0.15,
    }
    tiny = stats.monte_carlo_power(
        n=4,
        endpoints=endpoints,
        true_effects=true_effects,
        upper_sd=upper_sd,
        correlation=0.3,
        seed=11,
        iterations=1500,
    )
    assert not tiny.acceptable(), "N=4 must not be certified as powered here"
    chosen = stats.smallest_powered_n(
        candidates=(8, 32, 71, 126, 200, 300),
        endpoints=endpoints,
        true_effects=true_effects,
        upper_sd=upper_sd,
        correlation=0.3,
        seed=11,
        iterations=1500,
    )
    assert chosen is not None and chosen.acceptable()
    assert chosen.n >= stats.STRUCTURAL_TASK_FLOOR


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "stratum-power",
        "The power program computes effective N separately for each source stratum; a "
        "one-third stratum has roughly N/3 observations and cannot borrow the aggregate "
        "denominator.",
    )
)
def test_stratum_effective_n_does_not_borrow_the_aggregate() -> None:
    assert stats.stratum_effective_n(126, 1 / 3) == 42
    assert stats.stratum_effective_n(8, 1 / 3) == 2
    assert stats.stratum_effective_n(71, 1 / 3) < 71


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "tost",
        "Alpha is 0.05; equivalence uses two one-sided tests and the reported 95% interval "
        "must lie inside the band.",
    )
)
def test_tost_requires_the_whole_interval_inside_the_band() -> None:
    assert stats.tost((-0.02, 0.03)).equivalent
    assert not stats.tost((-0.06, 0.01)).equivalent
    assert not stats.tost((-0.01, 0.051)).equivalent


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "blinding",
        "Guess accuracy greater than 1/11 + 0.15 with exact-binomial p<0.05 is a preregistered "
        "blinding failure and yields `INVALID_HARNESS`; high kappa cannot override it.",
    )
)
def test_blinding_failure_arithmetic() -> None:
    chance = 1 / 11
    threshold = chance + 0.15
    # 40 of 100 correct is far above the threshold and significant.
    p = stats.exact_binomial_p_greater(40, 100, chance)
    assert 40 / 100 > threshold and p < 0.05
    # 12 of 100 is above chance but neither above the margin nor significant.
    p2 = stats.exact_binomial_p_greater(12, 100, chance)
    assert 12 / 100 <= threshold or p2 >= 0.05


@spec_ref(
    PRODUCT(
        "INSTRUMENT",
        "kappa",
        "Non-mechanical rubric levels are ordinal 0–4 and use quadratic-weighted Cohen's "
        "kappa.",
    )
)
def test_quadratic_weighted_kappa_behaves() -> None:
    perfect = [0, 1, 2, 3, 4] * 8
    assert stats.quadratic_weighted_kappa(perfect, perfect) == pytest.approx(1.0)
    inverted = [4, 3, 2, 1, 0] * 8
    assert stats.quadratic_weighted_kappa(perfect, inverted) < 0.0


# --------------------------------------------------------------------------
# Mutation catalog completeness
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "frozen-catalog",
        "Every V-1 through V-9 gate freezes its threshold, positive control, negative control, "
        "and detector mutation in the preregistered acceptance catalog before implementation is "
        "combined.",
    )
)
def test_every_gate_with_a_frozen_mutation_has_catalog_entries(spec_root: Path) -> None:
    covered = {mutation.gate for mutation in CATALOG.values()}
    missing = [gate for gate in GATES_WITH_FROZEN_MUTATIONS if gate not in covered]
    assert not missing, f"gates without a catalogued mutation: {missing}"
    text = (spec_root / "spec" / "verification.md").read_text(encoding="utf-8")
    # Every literal "Mutation:"/"Mutations:" obligation in the ratified text must
    # have at least one catalog entry quoting it.
    quoted = {m.requirement_quote for m in CATALOG.values()}
    obligations = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("- Mutation:", "- Mutations:"))
    ]
    assert obligations, "expected explicit Mutation obligations in verification.md"
    uncovered = []
    for obligation in obligations:
        body = obligation.lstrip("- ").strip()
        if not any(body[:60] in q or q[:60] in body for q in quoted):
            uncovered.append(body[:90])
    assert not uncovered, f"mutation obligations without a catalog entry: {uncovered}"


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "mutation-nodes",
        "require the planted defect to escape the detector's own self-test while causing the "
        "gate to reject the instrument",
    )
)
def test_every_catalog_mutation_names_must_fail_nodes() -> None:
    for mutation in CATALOG.values():
        assert mutation.must_fail_nodes, f"{mutation.mutation_id} names no must-fail node"
        for node in mutation.must_fail_nodes:
            assert "::" in node, f"{mutation.mutation_id} node {node!r} is not a node id"
            assert node.startswith("test_"), node


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "mutation-nodes",
        "require the planted defect to escape the detector's own self-test while causing the "
        "gate to reject the instrument",
    )
)
def test_catalog_must_fail_nodes_resolve_to_real_tests() -> None:
    here = Path(__file__).parent
    missing: list[str] = []
    for mutation in CATALOG.values():
        for node in mutation.must_fail_nodes:
            module_name, func = node.split("::", 1)
            module_path = here / module_name
            if not module_path.is_file():
                missing.append(f"{mutation.mutation_id}: no module {module_name}")
                continue
            source = module_path.read_text(encoding="utf-8")
            if f"def {func}(" not in source:
                missing.append(f"{mutation.mutation_id}: {module_name} lacks {func}")
    assert not missing, "\n".join(missing)


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "normalisation-views",
        "Assert deterministic scanners normalize NFC/NFD plus hex, base64, percent, and JSON "
        "escape forms and fail closed on scanner error.",
    )
)
def test_normalised_views_cover_the_declared_encodings() -> None:
    """Every declared decoder must actually fire, not merely exist.

    A decoder that raises and is silently swallowed leaves its transformation
    family unscanned while the suite still reports green. Asserting published
    coverage over a buffer built to exercise each family closes that route.
    """
    payload = "GHCANARY-ABCDEFGHIJKLMNOPQRSTUVWX-é"
    probe = (
        payload
        + " "
        + canaries.t_hex(payload)
        + " "
        + canaries.t_base64(payload)
        + " "
        + canaries.t_percent(payload)
        + " "
        + canaries.t_json_escape(payload)
        + " "
        + canaries.t_reversible_composition(payload)
    ).encode("utf-8")

    published = decoder_coverage(probe)
    missing = sorted(set(DECLARED_VIEW_CLASSES) - published)
    assert not missing, (
        "these declared encoding classes were never published, so their "
        f"transformation family is unscanned: {missing}"
    )

    blinded = {
        cls
        for cls, _ in normalised_views(canaries.t_hex(payload).encode(), decode=False)
    }
    assert blinded == {"literal", "nfc", "nfd"}, (
        f"decode=False must publish only the literal and normalisation views; "
        f"observed {sorted(blinded)}"
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "v3-normalisation",
        "Assert deterministic scanners normalize NFC/NFD plus hex, base64, percent, and "
        "JSON escape forms and fail closed on scanner error.",
    )
)
def test_decoded_views_preserve_surrounding_context() -> None:
    """A decoded view must keep the canary whole, not collapse to a fragment.

    Percent and JSON-escape forms only escape the non-ASCII tail of a canary.
    Decoding the escaped *run* in isolation would publish a bare ``é`` and lose
    the identifying body, so the exact-match detector class would silently stop
    working for those families and only the weaker partial rule would remain.
    """
    payload = "GHCANARY-ABCDEFGHIJKLMNOPQRSTUVWX-é"
    for family in ("percent", "json_escape", "reversible_composition"):
        encoded = canaries.transform(payload, family).encode("utf-8")
        recovered = [
            text
            for _, text in normalised_views(encoded)
            if payload in text
        ]
        assert recovered, (
            f"no view of the {family} form contains the whole canary; the decoder "
            "collapsed it to a fragment"
        )
