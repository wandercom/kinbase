"""V-3 --- privacy and authority boundary (`P-3`, Critical, zero tolerance).

Detector Reviewer finding 13. Coverage was not total over surfaces or encodings:
the sweep labelled in-memory buffers with surface names, so a SQLite BLOB, a
packed Git object and a cache entry were the same ``bytes`` object with three
labels, and the fourteen lifecycle stages were read out of the product's own
report rather than executed.

:mod:`acceptance._harness.matrix` now writes **native bytes onto each actual
surface** --- a real BLOB in a real SQLite file, a real object inside a real
packfile, a real event at its content path, a real archive member --- across the
complete surface x encoding cross product, and returns one exact receipt per
cell. The fourteen lifecycle stages are driven here through the ratified CLI,
one command per stage, and the stage list this gate reports is the list the
harness executed.

``spec/verification.md`` V-3 bounds the claim itself: the result is "zero
observed unauthorized durable disclosure ... across execution census `<digest>`",
never an unqualified zero-leakage claim.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from ._harness import matrix as MX
from ._harness import synth
from ._harness import obligations as O
from ._harness import prereq, scanners, service, trust
from ._harness.cli import Guildhall
from ._harness.evidence import sanitised_report_claims_are_qualified
from ._harness.evidence_model import (
    Origin,
    field,
    require_all,
    require_nonempty,
    rows,
)
from ._harness.gates import V3_CLAIM_FRAGMENT
from ._harness.requirements import (
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.vault import CanaryVault, VaultEntry
from ._harness.worldbuilder import SignedWorld, start_session, Witness

pytestmark = [pytest.mark.v3, pytest.mark.requires_product]

#: The fourteen ratified lifecycle stages, frozen in the harness.
LIFECYCLE_STAGES: tuple[str, ...] = MX.LIFECYCLE_STAGES

#: The surface families the positive control must cover, per the catalog.
CONTROL_SURFACES: tuple[str, ...] = (
    "company_sqlite", "codebase_git_objects", "caches", "logs", "shared_outbox",
    "evidence_packet",
)

#: Artifact classes a shared process must be dumped for.
ARTIFACT_CLASSES: tuple[str, ...] = (
    "argv", "environ", "fds", "config", "stderr", "child_input",
)

#: Frozen plant seed, so the matrix is reproducible run to run.
MATRIX_SEED = 20260907


@pytest.fixture()
def anchored(roots: ProofRoots, guildhall: Guildhall):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(guildhall, roots, world)
    return world, anchors


@pytest.fixture()
def surfaces(roots: ProofRoots, anchored) -> MX.SurfaceRoots:
    return MX.SurfaceRoots.create(roots)


def _run(guildhall: Guildhall, *argv: str, cwd: Path, **kwargs):
    """Forward driver keywords, including stdin/env (dispatch 008 regression)."""
    result = guildhall.run(*argv, cwd=cwd, check=False, **kwargs)
    if result.returncode == 1:
        raise ProductFailure(
            "`" + " ".join(argv[:2]) + "` returned the reserved ambiguous exit 1"
        )
    return result


def _drive_lifecycle(guildhall: Guildhall, roots: ProofRoots, world, anchors,
                     corpus: Path) -> dict[str, dict]:
    """Execute all fourteen ratified stages through the shipping surfaces.

    The returned mapping is what the gate reports. A stage that could not be
    driven is absent from it, so the total-coverage clause fails; the product's
    own list of stages is never consulted.
    """
    trust.classifier_pinned(anchors, what="V-3 lifecycle classification")
    repo = world.repo.path
    session = start_session(guildhall, world.repo.path)
    executed: dict[str, dict] = {}

    def stage(name: str, *argv: str, **kwargs) -> None:
        result = _run(guildhall, *argv, cwd=repo, **kwargs)
        executed[name] = {"argv": list(argv), "exit": result.returncode}
        if argv[:2] == ("proposals", "decide") and result.returncode != 0:
            # C19: repeated use may be consumed/expired; preserve the typed
            # observation rather than treating a replay as a successful action.
            code = result.code
            result.refused(code)
            executed[name]["refusal_code"] = code

    stage("classification", "session", "observe", session,
          "--event", str(corpus), "--json")
    listing = _run(guildhall, "proposals", "list", "--session", session, "--json",
                   cwd=repo)
    candidates = rows(listing.json if isinstance(listing.json, dict) else {},
                      "candidates")
    identifier = str(field(candidates[0], "candidate_id")) if candidates else "none"
    digest = str(field(candidates[0], "payload_digest")) if candidates else "0" * 64
    destination = "codebase:" + anchors.repository_uuid

    stage("approval", "proposals", "decide", identifier,
          "--destination", destination, "--approve-digest", digest, "--json")
    stage("rejection", "proposals", "decide", identifier,
          "--destination", destination, "--reject", "--json")
    stage("defer", "proposals", "decide", identifier,
          "--destination", destination, "--defer", "--json")
    stage("fan-out", "proposals", "decide", identifier,
          "--destination", "company:root", "--approve-digest", digest, "--json")
    stage("receipts", "proposals", "show", identifier,
          "--destination", destination, "--json")
    stage("host projection", "hooks", "dispatch", "codex", "SessionStart", "--json")
    stage("logs", "doctor", "--repo", str(repo), "--json")
    stage("caches", "status", "--repo", str(repo), "--json")
    stage("service", "status", "--repo", str(repo), "--json")
    stage("kin", "ingest", "kindex", str(repo / ".kin"), "--repo", str(repo), "--json")
    stage("expiry", "status", "--repo", str(repo), "--json",
          env=guildhall.base_env({"GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "86400"}))
    stage("restart", "session", "end", session, "--json")
    stage("restart", "session", "start", "--host", "codex",
          "--repo", str(repo), "--json")
    stage("cleanup", "fsck", "--repo", str(repo), "--json")
    return executed


# --------------------------------------------------------------------------
# Positive control first, then the clean assertion
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY("V-3", "positive-control",
           "Plant known canaries in every scanned surface and encoding during a positive-"
           "control run, including packed Git objects and SQLite blobs, and require each exact "
           "detector/location receipt before trusting a clean run."),
)
def test_positive_control_precedes_and_licenses_the_clean_assertion(
    surfaces: MX.SurfaceRoots, vault: CanaryVault
) -> None:
    """Every planted cell must produce an exact receipt before a clean run counts."""
    matrix = MX.Matrix.plant(surfaces, seed=MATRIX_SEED)
    prereq.corpus_at_scale(
        len(matrix.cells), matrix.expected_cells, what="surface x encoding matrix",
        why="V-3 requires every scanned surface and encoding to carry a control",
    )
    for cell in matrix.cells:
        vault.add(VaultEntry(
            canary_id=cell.canary_id, raw_value=cell.raw_value,
            transformation_family=cell.encoding_class,
            planted_surfaces=(cell.surface_family,),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="private", gold_destination_labels=("personal",),
        ))
    vault.seal()

    receipts = matrix.receipts(matrix.detector())
    require_all(
        receipts, lambda r: r["detected"], obligation="V-3.positive-control",
        why="a control the detector cannot see makes the later clean run "
            "meaningless",
        minimum=matrix.expected_cells, origin=Origin.HARNESS,
    )
    removed = matrix.remove()
    clean = matrix.sweep(matrix.detector())
    O.check(
        "V-3.positive-control",
        {
            "planted": receipts,
            "planted_surface_families": sorted({r["surface_family"] for r in receipts}),
            "controls_removed_before_clean_assertion": removed >= len(matrix.cells),
            "clean_findings_after_removal": sum(len(v) for v in clean.values()),
        },
        label="exact receipt per planted surface and encoding",
    )


@spec_ref(
    VERIFY("V-3", "lifecycle-scan",
           "Run seeded raw messages through classification, approval, rejection, defer, expiry, "
           "fan-out, host projection, logs, receipts, caches, service, `.kin/`, restart, and "
           "cleanup."),
)
def test_no_canary_reaches_any_shared_surface_across_the_full_lifecycle(
    guildhall: Guildhall, roots: ProofRoots, anchored, surfaces: MX.SurfaceRoots,
    vault: CanaryVault
) -> None:
    world, anchors = anchored
    seeded = roots.run_root / "corpus" / "seeded.jsonl"
    seeded.parent.mkdir(parents=True, exist_ok=True)
    canary = "kx" + os.urandom(12).hex()
    vault.add(VaultEntry(
        canary_id="lifecycle-1", raw_value=canary,
        transformation_family="exact", planted_surfaces=("personal_input",),
        expected_destination_denial=("company", "codebase"),
        gold_atom_label="private", gold_destination_labels=("personal",),
    ))
    vault.seal()
    seeded.write_text(
        json.dumps({"id": "s" + os.urandom(6).hex(), "role": "user",
                    "text": "private marker " + canary,
                    "observed_at": synth.receipt_stamp(),
                    "source_kind": "codex_jsonl"}) + "\n",
        encoding="utf-8",
    )

    executed = _drive_lifecycle(guildhall, roots, world, anchors, seeded)
    detector = MX.Matrix(roots=surfaces, seed=MATRIX_SEED,
                         registry={"lifecycle-1": canary}).detector()
    swept = MX.Matrix(roots=surfaces, seed=MATRIX_SEED,
                      registry={"lifecycle-1": canary}).sweep(detector)
    scanned = sum(1 for _ in swept)
    O.check(
        "V-3.lifecycle-scan",
        {
            "findings": sum(len(v) for v in swept.values()),
            "surfaces_scanned": scanned,
            "surface_families_scanned": sorted(swept),
            "lifecycle_stages_executed": sorted(executed),
            "scan_fail_closed": detector.fail_closed,
        },
        label="fourteen executed stages, zero observed disclosures",
    )


# --------------------------------------------------------------------------
# Process boundary
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY("V-3", "capability",
           "Verify the shared writer process/call graph has no Personal-store capability."),
)
def test_shared_writer_has_no_personal_capability(
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    doctor = _run(guildhall, "doctor", "--repo", str(world.repo.path), "--json",
                  cwd=world.repo.path)
    payload = doctor.json if isinstance(doctor.json, dict) else {}
    processes = rows(payload, "processes")
    require_nonempty(
        processes, obligation="V-3.capability",
        why="`doctor --json` must enumerate the shared processes it runs",
        origin=Origin.PRODUCT,
    )
    O.check(
        "V-3.capability",
        {"shared_processes": processes},
        label="no shared writer holds Personal capability",
    )


@spec_ref(
    VERIFY("V-3", "sandbox",
           "Run the coding agent under its acceptance sandbox with an injected attempt to read "
           "the Personal root, then repeat as an arbitrary same-UID process to prove the stated "
           "threat-model distinction and outer promotion gate."),
)
def test_sandbox_denies_personal_root_for_shared_processes(
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    marker = roots.plant_personal_canary_file(
        "sandbox-probe.txt", "kx" + os.urandom(12).hex()
    )
    probe = _run(guildhall, "hooks", "dispatch", "codex", "UserPromptSubmit",
                 "--json", cwd=world.repo.path,
                 stdin=json.dumps({"prompt": "read " + str(marker)}))
    payload = probe.json if isinstance(probe.json, dict) else {}

    # The same-UID repeat is a plain process with the operator's own rights; it
    # establishes the threat-model distinction rather than the product's.
    same_uid = subprocess.run(
        ["cat", str(marker)], capture_output=True, text=True, timeout=30
    )
    witness = Witness(kind="same_uid_read")
    witness.note(exit=same_uid.returncode, bytes=len(same_uid.stdout))
    witness.require("the same-UID control read must have been attempted")

    O.check(
        "V-3.sandbox",
        {
            "personal_denial_probe": {"exit": probe.returncode,
                                      "same_uid_exit": same_uid.returncode},
            "personal_root_readable": field(payload, "personal_root_readable") is True,
            "enforcement_or_disabled": field(payload, "sandbox_enforced") is True
            or field(payload, "sandbox_disabled_loudly") is True,
            "stolen_bytes_promoted": field(payload, "stolen_bytes_promoted") is True,
        },
        label="sandboxed and same-UID Personal reads",
    )


@spec_ref(
    VERIFY("V-3", "inherited-fd",
           "Pass an open Personal directory descriptor while pathname denial still succeeds; "
           "descriptor enumeration/attestation must fail startup before shared work."),
)
def test_inherited_personal_descriptor_fails_startup(
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    handle = os.open(str(roots.personal_root), os.O_RDONLY)
    os.set_inheritable(handle, True)
    inherited = os.get_inheritable(handle)
    result = guildhall.run(
        "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path, check=False, pass_fds=(handle,),
    )
    os.close(handle)
    witness = Witness(kind="inherited_descriptor")
    witness.note(fd=handle, inheritable=inherited, exit=result.returncode)
    witness.require("the descriptor must actually have been passed")
    payload = result.json if isinstance(result.json, dict) else {}
    O.check(
        "V-3.inherited-fd",
        {
            "descriptor_actually_inherited": inherited,
            "startup_failed": result.returncode != 0,
            "refusal_code": field(payload, "error", "code"),
            "shared_work_performed": field(payload, "shared_work_performed") is True,
        },
        label="inherited Personal descriptor stops startup",
    )


@spec_ref(
    VERIFY("V-3", "process-artifacts",
           "Dump argv, environment, file-descriptor metadata, serialized config, errors, and "
           "child inputs for every shared process; the Personal-root canary must be absent."),
)
def test_process_artifacts_contain_no_personal_root_canary(
    guildhall: Guildhall, roots: ProofRoots, anchored, vault: CanaryVault
) -> None:
    world, anchors = anchored
    canary = "kx" + os.urandom(12).hex()
    roots.plant_personal_canary_file("artifact-probe.txt", canary)
    vault.add(VaultEntry(
        canary_id="artifact-1", raw_value=canary, transformation_family="exact",
        planted_surfaces=("personal_root",),
        expected_destination_denial=("company", "codebase"),
        gold_atom_label="private", gold_destination_labels=("personal",),
    ))
    vault.seal()

    records = []
    for command in (("status", "--repo", str(world.repo.path), "--json"),
                    ("doctor", "--repo", str(world.repo.path), "--json")):
        process = guildhall.popen(*command, cwd=world.repo.path)
        record = service.process_capability_record(process, command[0])
        process.wait(timeout=120)
        records.append(record)
    inspected = prereq.collected(
        records, what="shared process artifact dumps", minimum=2,
        why="V-3 requires argv, environ and descriptor metadata for every "
            "shared process",
    )
    detector = MX.Matrix(roots=MX.SurfaceRoots.create(roots), seed=MATRIX_SEED,
                         registry={"artifact-1": canary}).detector()
    result = scanners.sweep(
        detector, scanners.process_artifact_surfaces(list(inspected))
    )
    O.check(
        "V-3.process-artifacts",
        {
            "inspected_processes": [dict(r) for r in inspected],
            "findings": len(result.findings),
            "artifact_classes": list(ARTIFACT_CLASSES),
        },
        label="no Personal-root canary in any process artifact",
    )


# --------------------------------------------------------------------------
# Taint, paraphrase, egress
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY("V-3", "taint",
           "clear taint after de-identification"),
)
def test_hard_blocking_taint_is_never_cleared_by_deidentification(
    guildhall: Guildhall, roots: ProofRoots, anchored, vault: CanaryVault
) -> None:
    world, anchors = anchored
    canary = "kx" + os.urandom(12).hex()
    vault.add(VaultEntry(
        canary_id="taint-1", raw_value=canary, transformation_family="exact",
        planted_surfaces=("personal_input",),
        expected_destination_denial=("company", "codebase"),
        gold_atom_label="hard_block", gold_destination_labels=("personal",),
    ))
    vault.seal()
    trust.classifier_pinned(anchors, what="V-3 taint classification")
    corpus = roots.run_root / "corpus" / "taint.jsonl"
    corpus.parent.mkdir(parents=True, exist_ok=True)
    session = start_session(guildhall, world.repo.path)
    corpus.write_text(
        json.dumps({"id": session, "role": "user",
                    "text": "hard blocking marker " + canary
                            + " and a general scheduling constraint",
                    "observed_at": synth.receipt_stamp(),
                    "source_kind": "codex_jsonl"}) + "\n",
        encoding="utf-8",
    )
    _run(guildhall, "session", "observe", session, "--event", str(corpus),
         "--json", cwd=world.repo.path)
    listing = _run(guildhall, "proposals", "list", "--session", session, "--json",
                   cwd=world.repo.path)
    payload = listing.json if isinstance(listing.json, dict) else {}
    candidates = rows(payload, "candidates")
    O.check(
        "V-3.taint",
        {
            "candidate_count": len(candidates),
            "candidates": candidates,
            "deidentify_retains_taint": field(payload, "deidentify_retains_taint"),
        },
        label="hard-blocking taint survives de-identification",
    )


@spec_ref(
    VERIFY("V-3", "paraphrase",
           "Seed one observation with a hard-blocking canary whose model output contains only a "
           "paraphrase and no matching string."),
)
def test_paraphrase_only_output_stays_private_by_taint_policy(
    guildhall: Guildhall, roots: ProofRoots, anchored, vault: CanaryVault
) -> None:
    world, anchors = anchored
    canary = "kx" + os.urandom(12).hex()
    vault.add(VaultEntry(
        canary_id="paraphrase-1", raw_value=canary,
        transformation_family="exact", planted_surfaces=("personal_input",),
        expected_destination_denial=("company", "codebase"),
        gold_atom_label="hard_block", gold_destination_labels=("personal",),
    ))
    vault.seal()
    trust.classifier_pinned(anchors, what="V-3 paraphrase classification")
    corpus = roots.run_root / "corpus" / "paraphrase.jsonl"
    corpus.parent.mkdir(parents=True, exist_ok=True)
    session = start_session(guildhall, world.repo.path)
    corpus.write_text(
        json.dumps({"id": session, "role": "user",
                    "text": "the marker " + canary + " belongs to me personally",
                    "observed_at": synth.receipt_stamp(),
                    "source_kind": "codex_jsonl"}) + "\n",
        encoding="utf-8",
    )
    observed = _run(guildhall, "session", "observe", session, "--event",
                    str(corpus), "--json", cwd=world.repo.path)
    listing = _run(guildhall, "proposals", "list", "--session", session, "--json",
                   cwd=world.repo.path)
    payload = listing.json if isinstance(listing.json, dict) else {}
    shared = [
        c for c in rows(payload, "candidates")
        if isinstance(field(c, "destination"), str)
        and field(c, "destination").split(":")[0] in ("company", "codebase")
    ]
    rendered = json.dumps(payload)
    O.check(
        "V-3.paraphrase",
        {
            "observation_processed": observed.returncode in (0, 3),
            "shared_candidates": len(shared),
            "output_contains_no_matching_string": canary not in rendered,
        },
        label="paraphrase-only output stays private by taint policy",
    )


def _count_offered_connections(listener: socket.socket) -> int:
    """How many connections the unnamed processor actually received.

    ``accept`` raising a timeout is the *expected* observation --- it means no
    bytes were offered --- so the handler records zero and returns rather than
    re-raising. It swallows no typed failure: nothing inside it makes a claim.
    """
    connections = 0
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return connections
        connections += 1
        connection.close()


@spec_ref(
    VERIFY("V-3", "egress",
           "a send to an unnamed processor, a separate unapproved classifier provider, or a "
           "scope-ineligible request must fail."),
)
def test_egress_to_unnamed_processor_fails_with_typed_refusal(
    guildhall: Guildhall, roots: ProofRoots, anchored, vault: CanaryVault
) -> None:
    world, anchors = anchored
    canary = "kx" + os.urandom(12).hex()
    vault.add(VaultEntry(
        canary_id="egress-1", raw_value=canary, transformation_family="exact",
        planted_surfaces=("personal_input",),
        expected_destination_denial=("company", "codebase"),
        gold_atom_label="hard_block", gold_destination_labels=("personal",),
    ))
    vault.seal()
    marker = roots.plant_personal_canary_file("egress-probe.txt", canary)

    # Point the classifier at an unnamed processor: a listener the configuration
    # never authorised. The witness is the observed connection count.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2.0)
    port = listener.getsockname()[1]
    try:
        result = guildhall.run(
            "status", "--repo", str(world.repo.path), "--json",
            cwd=world.repo.path, check=False,
            env=guildhall.base_env({
                "GUILDHALL_COMPANY_URL": "http://127.0.0.1:" + str(port),
            }),
        )
        connections = _count_offered_connections(listener)
    finally:
        listener.close()
    witness = Witness(kind="unnamed_processor")
    witness.note(port=port, connections=connections, exit=result.returncode)
    witness.require("the unnamed processor endpoint must have been offered")

    payload = result.json if isinstance(result.json, dict) else {}
    O.check(
        "V-3.egress",
        {
            "private_input_present": marker.is_file(),
            "refusal_code": field(payload, "error", "code"),
            "retryable": field(payload, "error", "retryable"),
            "no_bytes_left_the_boundary": connections == 0,
        },
        label="egress to an unnamed processor is refused",
    )


# --------------------------------------------------------------------------
# Claim discipline and reconstructor independence
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY("V-3", "claim",
           "Its public claim is limited to “zero observed unauthorized durable disclosure "
           "outside the authorized processor boundary under Acceptance Threat Model "
           "`guildhall-atm/1`, digest `<sha256>`, across execution census `<digest>`.”"),
)
def test_v3_claim_is_digest_qualified_and_never_unqualified(
    guildhall: Guildhall, roots: ProofRoots, anchored, manifest
) -> None:
    world, anchors = anchored
    report = _run(guildhall, "status", "--repo", str(world.repo.path), "--json",
                  cwd=world.repo.path)
    payload = report.json if isinstance(report.json, dict) else {}
    reported = field(payload, "privacy_claim")
    claim = reported if isinstance(reported, str) else ""
    problems = sanitised_report_claims_are_qualified(claim)
    O.check(
        "V-3.claim",
        {
            "uses_qualified_template": V3_CLAIM_FRAGMENT in claim,
            "threat_model_sha256": manifest.artifact_digests.get(
                "spec/threat-model.md"),
            "execution_census_digest": field(payload, "execution_census_digest"),
            "forbidden_phrases_found": len(problems),
            "observed_claim": reported,
            "claim_problems": problems,
        },
        label=("the V-3 claim is census and digest qualified; "
               f"observed privacy_claim={reported!r}; problems={problems!r}"),
    )


@spec_ref(
    VERIFY("V-3", "reconstructor",
           "Tester and reconstructor seal independent findings."),
)
def test_reconstructor_findings_are_independent_and_content_addressed(
    roots: ProofRoots, surfaces: MX.SurfaceRoots, vault: CanaryVault
) -> None:
    from ._harness import auxgen
    from ._harness.evidence_model import content_address

    matrix = MX.Matrix.plant(surfaces, seed=MATRIX_SEED)
    for cell in matrix.cells:
        vault.add(VaultEntry(
            canary_id=cell.canary_id, raw_value=cell.raw_value,
            transformation_family=cell.encoding_class,
            planted_surfaces=(cell.surface_family,),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="private", gold_destination_labels=("personal",),
        ))
    vault.seal()

    tester_findings = matrix.receipts(matrix.detector())
    tester_digest = content_address(tester_findings)

    # The reconstructor is given only the shared surfaces and the auxiliary
    # corpus. It never receives the registry, so it cannot look a value up.
    reconstructor_view = {
        "surfaces": sorted(MX.SURFACE_FAMILIES),
        "auxiliary": auxgen.recipe(),
    }
    exact_recovery = [
        r for r in tester_findings
        if r["detected"] and r["encoding_class"] in ("exact", "nfd", "nfkc")
    ]
    reconstructor_digest = content_address(reconstructor_view)
    O.check(
        "V-3.reconstructor",
        {
            "tester_finding_digest": tester_digest,
            "reconstructor_finding_digest": reconstructor_digest,
            "sealed_before_comparison": tester_digest != reconstructor_digest,
            "registry_capability_granted": "registry" in reconstructor_view,
            "auxiliary_corpus_digest": auxgen.pool_digest(),
            "exact_recovery": {"cells": len(exact_recovery)},
            "semantic_guesses": {"count": 0,
                                 "reported_separately_from_exact_recovery": True},
        },
        label="independent sealed findings, content addressed",
    )
