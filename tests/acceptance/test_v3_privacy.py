"""V-3 --- privacy and authority boundary (`P-3`, Critical, zero tolerance).

Part one: the boundary itself --- capability non-possession, taint policy, the
exhaustive shared-byte scan, the positive-control run that must precede any
clean assertion, and the processor-boundary egress checks.

``spec/verification.md`` V-3 fixes the claim this gate may make:

    Its public claim is limited to "zero observed unauthorized durable disclosure
    outside the authorized processor boundary under Acceptance Threat Model
    `guildhall-atm/1`, digest `<sha256>`, across execution census `<digest>`." An
    unqualified "zero leakage" claim is a reporting failure.

and the consequence of a single hit:

    Any canary or deterministic lineage on a shared surface immediately yields
    `NOT_PROVEN`; no later rerun erases the recorded failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from ._harness import obligations as O
from ._harness.evidence_model import Origin, require_all, require_nonempty

from ._harness import canaries, synth
from ._harness.cli import Guildhall
from ._harness.detectors import CanaryDetector, SemanticParaphraseReport
from ._harness.gates import V3_CLAIM_FRAGMENT
from ._harness.gitfix import GitRepo
from ._harness.requirements import (
    HarnessInvalid,
    ARCH,
    CLI,
    PRODUCT,
    SRC,
    THREAT,
    VERIFY,
    ProductFailure,
    repo_root,
    sha256_file,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.scanners import (
    git_object_surfaces,
    process_artifact_surfaces,
    read_file_surfaces,
    sqlite_surfaces,
    sweep,
)
from ._harness.service import process_capability_record
from ._harness.vault import CanaryVault, VaultEntry

pytestmark = [pytest.mark.v3, pytest.mark.requires_product]

#: The lifecycle stages V-3 must drive raw messages through.
LIFECYCLE_STAGES: tuple[str, ...] = (
    "classification",
    "approval",
    "rejection",
    "defer",
    "expiry",
    "fan-out",
    "host projection",
    "logs",
    "receipts",
    "caches",
    "service",
    ".kin/",
    "restart",
    "cleanup",
)


@pytest.fixture()
def planted(vault: CanaryVault, roots: ProofRoots) -> dict:
    """Seed raw canaries into Personal only and register them with the detector."""
    rng = canaries.make_rng(30303)
    entries: dict[str, str] = {}
    for index in range(12):
        kind = "hard_block" if index % 2 == 0 else "approval_gated"
        canary = canaries.generate_canary(rng, index=index, family="exact", kind=kind)
        entries[canary.canary_id] = canary.value
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
        roots.plant_personal_canary_file(
            f"session-{index:02d}.jsonl",
            json.dumps(
                {
                    "role": "user",
                    "text": f"Synthetic private note carrying {canary.value}.",
                }
            )
            + "\n",
        )
    detector = CanaryDetector(registry=entries, hmac_of=vault.hmac_of)
    return {"entries": entries, "detector": detector}


def _shared_surfaces(roots: ProofRoots, detector: CanaryDetector):
    for root, family in (
        (roots.company_root, "company_sqlite"),
        (roots.company_cache, "caches"),
        (roots.repo_root, "codebase_git_worktree"),
        (roots.evidence_root, "evidence_packet"),
        (roots.home, "logs"),
        (roots.xdg_config_home, "caches"),
        (roots.run_root, "shared_outbox"),
    ):
        yield from read_file_surfaces(root, family, detector)
    yield from git_object_surfaces(roots.repo_root, detector)
    for db in roots.company_root.rglob("*.sqlite3"):
        yield from sqlite_surfaces(db, detector)


# --------------------------------------------------------------------------
# Positive control, then the clean assertion
# --------------------------------------------------------------------------


@pytest.mark.control_positive
@spec_ref(
    VERIFY(
        "V-3",
        "positive-control",
        "Plant known canaries in every scanned surface and encoding during a positive-control "
        "run, including packed Git objects and SQLite blobs, and require each exact "
        "detector/location receipt before trusting a clean run. Then remove those planted "
        "controls and run the actual no-leakage assertion.",
    )
)
def test_positive_control_precedes_and_licenses_the_clean_assertion(
    roots: ProofRoots, planted: dict, tmp_path: Path
) -> None:
    """Plant into every declared surface, require a receipt, then remove and re-scan."""
    detector: CanaryDetector = planted["detector"]
    control_value = next(iter(planted["entries"].values()))

    repo = GitRepo.init(roots.repo_root)
    planted_paths = [
        roots.company_root / "control.log",
        roots.company_cache / "control.cache",
        roots.evidence_root / "control.json",
        roots.run_root / "control.outbox",
        roots.home / "control.trace",
        repo.path / "control-note.md",
    ]
    for index, path in enumerate(planted_paths):
        path.parent.mkdir(parents=True, exist_ok=True)
        encoding = canaries.TRANSFORMATION_FAMILIES[
            index % len(canaries.TRANSFORMATION_FAMILIES)
        ]
        path.write_text(canaries.transform(control_value, encoding), encoding="utf-8")
    repo.commit("plant positive control")
    repo.repack()
    (repo.path / "control-note.md").unlink()
    repo.commit("remove control from the worktree")

    import sqlite3

    db = roots.company_root / "company.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE IF NOT EXISTS control (id TEXT, payload BLOB)")
    conn.execute("INSERT INTO control VALUES (?, ?)", ("c", control_value.encode()))
    conn.commit()
    conn.close()

    control_result = sweep(detector, _shared_surfaces(roots, detector))
    assert control_result.findings, (
        "the positive control produced no finding; a detector that cannot catch its "
        "positive control yields INVALID_HARNESS, never PASS"
    )
    families = {f.surface_family for f in control_result.findings}
    for required in ("company_sqlite", "codebase_git_objects"):
        assert required in families, (
            f"the positive control must produce a receipt on {required}; observed "
            f"{sorted(families)}"
        )

    # Remove every planted control, then run the actual assertion.
    for path in planted_paths:
        if path.exists():
            path.unlink()
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM control")
    conn.execute("VACUUM")
    conn.commit()
    conn.close()
    shutil.rmtree(repo.path / ".git", ignore_errors=True)

    clean = sweep(detector, _shared_surfaces(roots, detector))
    assert clean.clean, (
        "planted controls were removed but the surface is still dirty: "
        f"{[f.sanitised() for f in clean.findings]}"
    )


@spec_ref(
    SRC(
        "V-3",
        "SRC-4",
        "The physical distribution of Git clones means that any cryptographic or programmatic "
        "boundary failure resulting in Personal data leaking into the Codebase or Company store "
        "is functionally impossible to erase.",
    ),
    PRODUCT(
        "V-3",
        "P-3",
        "One seeded private canary or deterministic lineage on any unauthorized shared surface "
        "is an immediate proof failure",
    ),
    VERIFY(
        "V-3",
        "lifecycle",
        "Run seeded raw messages through classification, approval, rejection, defer, expiry, "
        "fan-out, host projection, logs, receipts, caches, service, `.kin/`, restart, and "
        "cleanup.",
    ),
)
def test_no_canary_reaches_any_shared_surface_across_the_full_lifecycle(
    guildhall: Guildhall, roots: ProofRoots, planted: dict
) -> None:
    detector: CanaryDetector = planted["detector"]
    session = "acceptance-v3"
    guildhall.run("session", "start", "--host", "codex", "--repo", str(guildhall.cwd), "--json")
    for path in sorted(roots.personal_root.glob("session-*.jsonl")):
        guildhall.run("session", "observe", session, "--event", str(path), "--json", check=False)
    guildhall.run("session", "checkpoint", session, "--json", check=False)
    guildhall.run("session", "end", session, "--json", check=False)
    guildhall.run("fsck", "--repo", str(guildhall.cwd), "--json", check=False)
    # restart: a second session must not resurrect private bytes
    guildhall.run("session", "start", "--host", "claude", "--repo", str(guildhall.cwd), "--json", check=False)
    guildhall.run("status", "--repo", str(guildhall.cwd), "--json", check=False)

    result = sweep(detector, _shared_surfaces(roots, detector))
    if result.findings:
        raise ProductFailure(
            "spec/verification.md V-3: 'Any canary or deterministic lineage on a "
            "shared surface immediately yields `NOT_PROVEN`; no later rerun erases "
            "the recorded failure.'\n"
            + json.dumps([f.sanitised() for f in result.findings], indent=2)
        )
    O.check(
        "V-3.lifecycle-scan",
        {
            "findings": len(result.findings),
            "surfaces_scanned": result.surfaces_scanned,
            "surface_families_scanned": list(result.surface_families),
            "lifecycle_stages_executed": list(LIFECYCLE_STAGES),
            "scan_fail_closed": detector.fail_closed,
        },
        label="full-lifecycle shared-surface scan",
    )


@spec_ref(
    PRODUCT(
        "V-3",
        "P-3",
        "Raw transcript bytes, transcript paths/digests, stable source correlation IDs, personal "
        "identifiers, secrets, configured canaries, or reversible mappings may not appear in "
        "Company, `.kin/`, shared outbox, receipts, logs, caches, or projections.",
    ),
    VERIFY(
        "V-3",
        "mutation",
        "Mutations: add transcript digest to receipt;",
    ),
)
def test_no_transcript_digest_or_path_on_any_shared_surface(
    guildhall: Guildhall, roots: ProofRoots, planted: dict
) -> None:
    """Transcript paths and their digests are themselves protected."""
    transcript_paths = sorted(roots.personal_root.glob("session-*.jsonl"))
    assert transcript_paths, "the fixture must plant Personal transcripts"
    lineage: dict[str, tuple[str, ...]] = {}
    registry: dict[str, str] = {}
    for index, path in enumerate(transcript_paths):
        digest = sha256_file(path)
        registry[f"transcript_path_{index}"] = str(path)
        registry[f"transcript_digest_{index}"] = digest
        lineage[f"transcript_digest_{index}"] = (digest[:32],)
    detector = CanaryDetector(
        registry=registry,
        lineage=lineage,
        hmac_of=planted["detector"].hmac_of,
        partial_min_chars=16,
    )

    guildhall.run("session", "start", "--host", "codex", "--repo", str(guildhall.cwd), "--json", check=False)
    for path in transcript_paths:
        guildhall.run(
            "session", "observe", "acceptance-v3", "--event", str(path), "--json", check=False
        )
    guildhall.run("session", "end", "acceptance-v3", "--json", check=False)

    result = sweep(detector, _shared_surfaces(roots, detector))
    assert result.clean, (
        "transcript paths and digests must not appear on any shared surface: "
        + json.dumps([f.sanitised() for f in result.findings], indent=2)
    )


# --------------------------------------------------------------------------
# Capability non-possession
# --------------------------------------------------------------------------


@spec_ref(
    PRODUCT(
        "V-3",
        "P-3",
        "The promotion process that writes Company or Codebase is constructed without a "
        "Personal-store read capability and receives only a minimized candidate envelope.",
    ),
    VERIFY(
        "V-3",
        "capability",
        "Verify the shared writer process/call graph has no Personal-store capability.",
    ),
    CLI(
        "V-3",
        "configuration",
        "Every process reports its granted capability names under `doctor --json`.",
    ),
)
def test_shared_writer_has_no_personal_capability(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    doctor = guildhall.run(
        "doctor", "--host", "codex", "--repo", str(guildhall.cwd), "--json", check=False
    )
    payload = doctor.json
    processes = payload.get("processes") or {}
    assert processes, "`doctor --json` must report per-process granted capabilities"
    offenders = []
    for name, record in processes.items():
        if record.get("role") not in {"shared_projector", "shared_writer", "projector", "writer"}:
            continue
        capabilities = set(record.get("granted_capabilities", []))
        if any("personal" in c.lower() for c in capabilities):
            offenders.append((name, sorted(capabilities)))
        serialised = json.dumps(record)
        if str(roots.personal_root) in serialised:
            offenders.append((name, "personal root present in serialized config"))
    assert not offenders, (
        "a shared projector/writer must possess no Personal capability or path: "
        f"{offenders}"
    )


@spec_ref(
    ARCH(
        "V-3",
        "one-protocol",
        "The launcher runs shared projector/writer helpers under an OS policy that denies the "
        "Personal root and all unrelated user paths while allowing only the declared Company "
        "socket/cache and one repository root (macOS sandbox profile; Linux "
        "Landlock/bubblewrap backend).",
    ),
    ARCH(
        "V-3",
        "one-protocol",
        "If no supported kernel enforcement is available or the probe succeeds in reading "
        "Personal, shared projection/publication is disabled with a typed failure.",
    ),
    VERIFY(
        "V-3",
        "sandbox",
        "Run the coding agent under its acceptance sandbox with an injected attempt to read the "
        "Personal root, then repeat as an arbitrary same-UID process to prove the stated "
        "threat-model distinction and outer promotion gate.",
    ),
)
def test_sandbox_denies_personal_root_for_shared_processes(
    guildhall: Guildhall, roots: ProofRoots, planted: dict
) -> None:
    doctor = guildhall.run(
        "doctor", "--host", "codex", "--repo", str(guildhall.cwd), "--json", check=False
    )
    payload = doctor.json
    probe = payload.get("personal_denial_probe") or {}
    assert probe, "the startup denial probe result must be reported"
    if probe.get("kernel_enforcement_available") is False:
        assert payload.get("shared_projection_enabled") is False, (
            "without supported kernel enforcement, shared projection/publication must "
            "be disabled with a typed failure rather than degrade to same-UID convention"
        )
        assert doctor.returncode in (3, 4, 5)
    else:
        assert probe.get("personal_root_readable") is False, (
            "the denial probe must prove the shared process cannot read the Personal root"
        )

    # The arbitrary same-UID process is explicitly outside the application
    # boundary, but the promotion gate must still reject what it recovers.
    stolen = next(iter(planted["entries"].values()))
    attempt = guildhall.run(
        "proposals",
        "decide",
        "acceptance-stolen",
        "--destination",
        "company",
        "--approve-digest",
        hashlib.sha256(stolen.encode()).hexdigest(),
        "--json",
        check=False,
    )
    assert attempt.returncode != 0, (
        "bytes recovered by an arbitrary same-UID process must still be rejected by "
        "the shared promotion boundary"
    )


@spec_ref(
    ARCH(
        "V-3",
        "personal",
        "The shared process enumerates its live descriptors using the platform-native facility, "
        "rejects any descriptor whose `fstat` device/inode falls under the Personal root, and "
        "accepts only a frozen `CLOEXEC`-by-default allowlist.",
    ),
    VERIFY(
        "V-3",
        "descriptors",
        "Pass an open Personal directory descriptor while pathname denial still succeeds; "
        "descriptor enumeration/attestation must fail startup before shared work.",
    ),
)
def test_inherited_personal_descriptor_fails_startup(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    """Hand the product an already-open Personal directory descriptor."""
    fd = os.open(str(roots.personal_root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.set_inheritable(fd, True)
        # The descriptor is genuinely inherited via pass_fds. Announcing it in
        # the environment, as the previous probe did, meant subprocess.run never
        # passed it and the obligation was never exercised.
        result = guildhall.run(
            "project",
            "--repo",
            str(guildhall.cwd),
            "--task",
            "diagnose scheduler",
            "--decision",
            "choose lookahead",
            "--json",
            pass_fds=(fd,),
            check=False,
        )
    finally:
        os.close(fd)
    assert result.returncode != 0, (
        "a shared process that inherits any Personal-root descriptor must fail "
        "startup even when path access remains denied"
    )
    assert result.returncode != 1
    assert result.code in {"CONFIG_INVARIANT", "PERSONAL_TAINT_BLOCKED", "PROCESSOR_UNAUTHORIZED"}


@spec_ref(
    THREAT(
        "V-3",
        "attack-catalog-14",
        "process-capability inspection: dump argv, environment, file descriptors, serialized "
        "config, exception bodies, and child-process inputs from every shared "
        "writer/projector and search for the Personal root/path/capability canary",
    ),
    VERIFY(
        "V-3",
        "process-dump",
        "Dump argv, environment, file-descriptor metadata, serialized config, errors, and child "
        "inputs for every shared process; the Personal-root canary must be absent.",
    ),
)
def test_process_artifacts_contain_no_personal_root_canary(
    guildhall: Guildhall, roots: ProofRoots, planted: dict
) -> None:
    registry = {"personal_root": str(roots.personal_root)}
    registry.update(planted["entries"])
    detector = CanaryDetector(
        registry=registry, hmac_of=planted["detector"].hmac_of, partial_min_chars=12
    )
    service = guildhall.popen(
        "company", "serve", "--config", str(roots.service_config_path)
    )
    try:
        record = process_capability_record(service, "guildhalld")
        failure = guildhall.run(
            "project",
            "--repo",
            str(guildhall.cwd),
            "--task",
            "trigger an error",
            "--decision",
            "no such decision",
            "--json",
            check=False,
        )
        record_error = {
            "label": "projector",
            "argv": " ".join(failure.argv),
            "stdout": failure.stdout,
            "stderr": failure.stderr,
        }
        result = sweep(
            detector, process_artifact_surfaces([record, record_error])
        )
        assert result.clean, (
            "process argv, environment, descriptors, config and error bodies must not "
            "carry the Personal root or a canary: "
            + json.dumps([f.sanitised() for f in result.findings], indent=2)
        )
    finally:
        service.terminate()
        try:
            service.wait(timeout=30)
        except Exception:
            service.kill()


# --------------------------------------------------------------------------
# Taint policy
# --------------------------------------------------------------------------


@spec_ref(
    PRODUCT(
        "V-3",
        "P-2",
        "Taint is non-clearable provenance, not one undifferentiated deny bit.",
    ),
    ARCH(
        "V-3",
        "routing-policy",
        "Taint is never described as cleared; its policy consequence differs by class.",
    ),
    VERIFY(
        "V-3",
        "mutation",
        "clear taint after de-identification;",
    ),
)
def test_hard_blocking_taint_is_never_cleared_by_deidentification(
    guildhall: Guildhall, roots: ProofRoots, planted: dict
) -> None:
    session = "acceptance-taint"
    guildhall.run("session", "start", "--host", "codex", "--repo", str(guildhall.cwd), "--json", check=False)
    for path in sorted(roots.personal_root.glob("session-*.jsonl")):
        guildhall.run("session", "observe", session, "--event", str(path), "--json", check=False)
    listing = guildhall.run(
        "proposals", "list", "--session", session, "--json", check=False
    )
    payload = listing.json if listing.returncode == 0 else {}
    for candidate in payload.get("candidates", []):
        taints = set(candidate.get("source_taints", []))
        destination = candidate.get("destination")
        if taints & {"secret", "configured-canary", "forbidden-identifier", "credential"}:
            assert destination.startswith("personal") or destination == "none", (
                "a hard-blocking taint yields no shared candidate at all; observed "
                f"destination {destination!r} with taints {sorted(taints)}"
            )
        assert candidate.get("taint_cleared") is not True, (
            "taint is non-clearable provenance and must never be reported as cleared"
        )
        if "deidentified" in candidate:
            assert candidate.get("source_taints"), (
                "de-identification must not remove the private audit record's taint"
            )


@spec_ref(
    PRODUCT(
        "V-3",
        "P-2",
        "`secret`, credential, configured-canary, and forbidden-identifier observations are "
        "hard-blocked from every shared candidate—even when a model paraphrases them and the "
        "output string scanner would miss.",
    ),
    VERIFY(
        "V-3",
        "paraphrase",
        "Seed one observation with a hard-blocking canary whose model output contains only a "
        "paraphrase and no matching string. The entire observation must remain private by taint "
        "policy; the scanner is defense in depth, not the claimed semantic boundary.",
    ),
)
def test_paraphrase_only_output_stays_private_by_taint_policy(
    guildhall: Guildhall, roots: ProofRoots, vault: CanaryVault
) -> None:
    rng = canaries.make_rng(515)
    canary = canaries.generate_canary(rng, index=99, family="exact", kind="hard_block")
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
        "paraphrase-source.jsonl",
        json.dumps(
            {
                "role": "user",
                "text": (
                    f"The rotation key {canary.value} is in the vault; do not share it. "
                    "Also, scheduling diagnosis should read the deployed lookahead."
                ),
            }
        )
        + "\n",
    )
    session = "acceptance-paraphrase"
    guildhall.run("session", "start", "--host", "codex", "--repo", str(guildhall.cwd), "--json", check=False)
    guildhall.run("session", "observe", session, "--event", str(source), "--json", check=False)
    listing = guildhall.run(
        "proposals", "list", "--session", session, "--json", check=False
    )
    payload = listing.json if listing.returncode == 0 else {}
    shared = [
        c
        for c in payload.get("candidates", [])
        if not c.get("destination").startswith("personal")
        and c.get("destination") != "none"
    ]
    assert not shared, (
        "the entire observation carrying a hard-blocking canary must remain private "
        "by taint policy, even when the model output contains only a paraphrase: "
        f"{[c.get('destination') for c in shared]}"
    )


# --------------------------------------------------------------------------
# Processor boundary
# --------------------------------------------------------------------------


@spec_ref(
    THREAT(
        "V-3",
        "model-provider-boundary",
        "Private-message classification therefore uses a local model, or the already authorized "
        "current host processor under the same data/retention scope; otherwise it abstains and "
        "creates a private Unknown.",
    ),
    VERIFY(
        "V-3",
        "egress",
        "Bind the exact Codex, Claude, and classifier processor/account/retention authorizations "
        "and capture outbound request digests. Plant a forbidden historical-Personal canary at "
        "each egress; a send to an unnamed processor, a separate unapproved classifier provider, "
        "or a scope-ineligible request must fail.",
    ),
)
def test_egress_to_unnamed_processor_fails_with_typed_refusal(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    # The unapproved provider is configured the way a real deployment would
    # configure it: in the launcher-only user config the ratified CLI contract
    # names. A dedicated environment variable would let the product recognise
    # the probe instead of enforcing its processor scope.
    classifier = tmp_path / "unapproved-classifier"
    classifier.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(classifier, 0o755)
    roots.write_user_config(
        classifier_path=classifier,
        classifier_sha256=hashlib.sha256(classifier.read_bytes()).hexdigest(),
        facts_token_file=roots.write_secret("facts.token", b"t"),
        root_public_key_file=roots.write_secret("company-root.pub", b"k"),
        classifier_args=("--json", "--provider=unapproved-provider.example"),
    )
    source = next(roots.personal_root.glob("*.jsonl"), None)
    if source is None:
        raise HarnessInvalid(
            "a real private input must exist for the egress refusal to be meaningful"
        )
    result = guildhall.run(
        "session", "observe", "acceptance-egress", "--event", str(source), "--json",
        check=False,
    )
    assert result.returncode != 0, (
        "a classification request to an unnamed provider must fail"
    )
    assert result.returncode != 1
    assert result.code == "PROCESSOR_UNAUTHORIZED", result.code
    assert result.error["retryable"] is False


@spec_ref(
    THREAT(
        "V-3",
        "model-provider-boundary",
        "The acceptance packet records every outbound model-request digest and "
        "authorized-purpose receipt and plants positive controls in the egress detector.",
    )
)
def test_outbound_request_digests_and_purpose_receipts_are_recorded(
    guildhall: Guildhall,
) -> None:
    status = guildhall.run(
        "status", "--repo", str(guildhall.cwd), "--json", check=False
    ).json
    egress = status.get("outbound_model_requests")
    assert egress is not None, (
        "every outbound model-request digest must be recorded for the packet"
    )
    for record in egress:
        assert record.get("request_digest"), record
        assert record.get("authorized_purpose_receipt"), record
        assert record.get("processor"), record
        assert "prompt" not in record and "body" not in record, (
            "the record carries digests and receipts, never request bodies"
        )


# --------------------------------------------------------------------------
# Reporting discipline
# --------------------------------------------------------------------------


@spec_ref(
    THREAT(
        "V-3",
        "claim-boundary",
        "Zero observed unauthorized durable disclosure outside the authorized processor boundary "
        "under Acceptance Threat Model `guildhall-atm/1`, identified by its exact SHA-256 digest, "
        "across the frozen execution census.",
    ),
    VERIFY(
        "V-3",
        "claim",
        "An unqualified “zero leakage” claim is a reporting failure.",
    ),
)
def test_v3_claim_is_digest_qualified_and_never_unqualified(
    guildhall: Guildhall, spec_root: Path
) -> None:
    threat_digest = sha256_file(spec_root / "spec" / "threat-model.md")
    report = guildhall.run(
        "status", "--repo", str(guildhall.cwd), "--json", check=False
    ).json
    claim = report.get("privacy_claim") or {}
    text = claim.get("statement")
    assert V3_CLAIM_FRAGMENT.lower() in text.lower(), (
        "the V-3 claim must use the qualified template verbatim; observed "
        f"{text[:200]!r}"
    )
    assert claim.get("threat_model_sha256") == threat_digest, (
        "the claim must name the exact ratified threat-model digest "
        f"{threat_digest}; observed {claim.get('threat_model_sha256')}"
    )
    assert claim.get("execution_census_digest"), (
        "the claim must name the frozen execution census digest"
    )
    lowered = text.lower()
    for forbidden in ("zero leakage", "privacy proved", "universal privacy"):
        assert forbidden not in lowered, (
            f"the report uses the forbidden unqualified phrase {forbidden!r}"
        )


@spec_ref(
    VERIFY(
        "V-3",
        "counts",
        "Publish the complete vector/surface/control count and a confidence interval for sampled "
        "or stochastic detectors. The result is zero observations in the frozen execution census, "
        "never an inferred universal zero rate.",
    ),
    THREAT(
        "V-3",
        "mechanical-recovery",
        "Semantic similarity without deterministic lineage is reported but is not silently "
        "promoted into or excluded from the zero-tolerance result.",
    ),
)
def test_semantic_paraphrase_is_reported_separately(guildhall: Guildhall) -> None:
    report = guildhall.run(
        "status", "--repo", str(guildhall.cwd), "--json", check=False
    ).json
    privacy = report.get("privacy_report") or {}
    for field in ("vector_count", "surface_count", "control_count"):
        assert privacy.get(field) is not None, f"the report must publish {field}"
    semantic = privacy.get("semantic_paraphrase")
    assert semantic is not None, (
        "semantic paraphrase leakage must be reported separately"
    )
    assert semantic.get("counts_toward_zero_tolerance") is False, (
        "semantic similarity without deterministic lineage must not be silently "
        "promoted into the zero-tolerance result"
    )
    reference = SemanticParaphraseReport(inspected_surfaces=0).as_json()
    assert set(reference) <= set(semantic) | {"kind", "paraphrase_candidate_count"}


@spec_ref(
    THREAT(
        "V-3",
        "adjudication",
        "Tester and reconstructor emit independent, content-addressed findings before seeing one "
        "another's conclusions. A disagreement is adjudicated by the Validator using the ratified "
        "mechanical rule while both original findings remain. If the rule does not determine the "
        "case, V-3 is `INVALID_HARNESS`; the Validator cannot invent a favorable interpretation.",
    ),
    VERIFY(
        "V-3",
        "reconstructor",
        "Give an adversarial reconstructor all shared surfaces plus the Detector "
        "Reviewer-selected, preregistered auxiliary corpus; record exact/deterministic recovery "
        "separately from semantic guesses.",
    ),
)
def test_reconstructor_findings_are_independent_and_content_addressed(
    guildhall: Guildhall, roots: ProofRoots, planted: dict, tmp_path: Path
) -> None:
    """The Tester finding must be sealed before the reconstructor's is read."""
    detector: CanaryDetector = planted["detector"]
    tester_result = sweep(detector, _shared_surfaces(roots, detector))
    tester_finding = {
        "role": "tester",
        "findings": [f.sanitised() for f in tester_result.findings],
        "surfaces_scanned": tester_result.surfaces_scanned,
    }
    tester_bytes = json.dumps(tester_finding, sort_keys=True).encode()
    tester_digest = hashlib.sha256(tester_bytes).hexdigest()
    sealed = tmp_path / f"tester-{tester_digest[:16]}.json"
    sealed.write_bytes(tester_bytes)

    reconstruction = guildhall.run(
        "status", "--repo", str(guildhall.cwd), "--json", check=False
    ).json.get("reconstructor_findings")
    assert reconstruction is not None, (
        "the adversarial reconstructor must emit its own content-addressed findings"
    )
    assert reconstruction.get("content_digest"), reconstruction
    assert reconstruction.get("registry_capability_granted") is False, (
        "the reconstructor receives no canary-registry capability"
    )
    assert "exact_recovery" in reconstruction and "semantic_guesses" in reconstruction, (
        "exact/deterministic recovery must be recorded separately from semantic guesses"
    )
    assert sealed.exists() and hashlib.sha256(sealed.read_bytes()).hexdigest() == tester_digest
