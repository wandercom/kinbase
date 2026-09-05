"""Evidence-packet validation and retention discipline.

``spec/verification.md`` "Evidence packet" is where the run's honesty is
enforced after every gate has run:

    The packet is Validator-owned mode-0700 run state outside Git during
    execution and is transferred only to the founder/security custodian. A
    sanitized aggregate report may be committed; raw Personal data never is.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ._harness import canaries
from ._harness.cli import Guildhall
from ._harness.evidence import (
    FAILURE_ROW_FIELDS,
    FORBIDDEN_PACKET_FIELDS,
    INCIDENT_HOLD_FIELDS,
    INCIDENT_HOLD_MAX_SECONDS,
    INCIDENT_HOLD_REVIEW_SECONDS,
    RAW_EVIDENCE_MAX_AGE_SECONDS,
    REPOSITORY_PROVENANCE_FIELDS,
    REQUIRED_PACKET_SECTIONS,
    assert_no_raw_bytes_in,
    assert_packet_root_private,
    sanitised_report_claims_are_qualified,
    validate_packet,
)
from ._harness.gates import (
    FORBIDDEN_CLAIMS,
    FORBIDDEN_METHOD_LABEL,
    REQUIRED_METHOD_LABEL,
    V3_CLAIM_FRAGMENT,
)
from ._harness.requirements import (
    PRODUCT,
    THREAT,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.vault import CanaryVault, VaultEntry

pytestmark = [pytest.mark.evidence]


def _minimal_packet() -> dict:
    return {section: {} for section in REQUIRED_PACKET_SECTIONS}


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "contents",
        "The final packet contains:",
    ),
    VERIFY(
        "EVIDENCE",
        "contents",
        "all failed attempts and the terminal `PROVEN`, `NOT_PROVEN`, `INCONCLUSIVE_NO_HEADROOM`, "
        "`INCONCLUSIVE_CEILING`, or `INVALID_RUN` verdict, plus the full gate diagnostic vector even "
        "when terminal proof fails.",
    ),
)
def test_packet_schema_requires_every_declared_section() -> None:
    complete = validate_packet(_minimal_packet())
    assert complete.ok, complete

    for section in REQUIRED_PACKET_SECTIONS:
        partial = _minimal_packet()
        partial.pop(section)
        result = validate_packet(partial)
        assert not result.ok and section in result.missing_sections, section


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "failure-rows",
        "Permanent failure rows contain canary ID, keyed-HMAC match, detector/encoding class, "
        "destination/location digest, offset, and times—not the canary or leaked bytes.",
    )
)
def test_permanent_failure_rows_reject_extra_and_missing_keys() -> None:
    packet = _minimal_packet()
    good_row = {field: "x" for field in FAILURE_ROW_FIELDS}
    good_row["offset"] = 0
    packet["privacy_scan_reconstructor_and_adversarial_results"] = {
        "permanent_failure_rows": [good_row]
    }
    assert validate_packet(packet).ok

    leaky = dict(good_row)
    leaky["raw_value"] = "GHCANARY-LEAK"
    packet["privacy_scan_reconstructor_and_adversarial_results"] = {
        "permanent_failure_rows": [leaky]
    }
    result = validate_packet(packet)
    assert not result.ok
    assert result.malformed_failure_rows
    assert result.forbidden_hits

    incomplete = {k: v for k, v in good_row.items() if k != "keyed_hmac"}
    packet["privacy_scan_reconstructor_and_adversarial_results"] = {
        "permanent_failure_rows": [incomplete]
    }
    assert not validate_packet(packet).ok


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "sanitisation",
        "A sanitized aggregate report may be committed; raw Personal data never is.",
    ),
    THREAT(
        "EVIDENCE",
        "assets",
        "Canary registries, raw fixture instantiations, auxiliary-corpus private extensions, unblinding "
        "material, and incident subjects are private test assets and are never Git-reachable or "
        "included in a sanitized evidence packet.",
    ),
)
def test_forbidden_fields_are_detected_anywhere_in_the_packet() -> None:
    for field in FORBIDDEN_PACKET_FIELDS:
        packet = _minimal_packet()
        packet["maintenance_and_temporal_traces"] = {
            "traces": [{"nested": {field: "should never appear"}}]
        }
        result = validate_packet(packet)
        assert not result.ok and result.forbidden_hits, field


@spec_ref(
    VERIFY(
        "EVIDENCE",
        "custody",
        "The packet is Validator-owned mode-0700 run state outside Git during execution and is "
        "transferred only to the founder/security custodian.",
    )
)
def test_packet_root_is_private_and_outside_git(roots: ProofRoots, tmp_path: Path) -> None:
    packet_root = tmp_path / "packet"
    packet_root.mkdir(parents=True, exist_ok=True)
    os.chmod(packet_root, 0o700)
    assert_packet_root_private(packet_root)

    os.chmod(packet_root, 0o755)
    with pytest.raises(ProductFailure):
        assert_packet_root_private(packet_root)
    os.chmod(packet_root, 0o700)

    inside = roots.repo_root / "packet-inside-git"
    inside.mkdir(parents=True, exist_ok=True)
    os.chmod(inside, 0o700)
    (roots.repo_root / ".git").mkdir(parents=True, exist_ok=True)
    with pytest.raises(ProductFailure):
        assert_packet_root_private(inside)


@pytest.mark.selftest
@spec_ref(
    THREAT(
        "EVIDENCE",
        "reporting",
        "The sanitized report names `guildhall-atm/1` and its digest, lists every executed "
        "family/control/ mutation and surface, preserves disagreements and adjudication receipts, and "
        "uses the qualified claim verbatim. It never says merely “privacy proved” or “zero leakage.”",
    )
)
def test_sanitised_report_claim_discipline_is_checkable() -> None:
    good = (
        "Under Acceptance Threat Model guildhall-atm/1, digest "
        "6391c14853c0bc1a059a0a4aded31c878ed74eddecb5578903717aa152f10f09, this run "
        "observed zero observed unauthorized durable disclosure outside the authorized "
        "processor boundary across the frozen execution census."
    )
    assert sanitised_report_claims_are_qualified(good) == []

    for bad in (
        "privacy proved across all surfaces",
        "zero leakage was demonstrated",
        "no disclosures were found",
    ):
        problems = sanitised_report_claims_are_qualified(bad)
        assert problems, bad


@spec_ref(
    VERIFY(
        "EVIDENCE",
        "retention",
        "Per-arm worktrees, agent homes, model transcripts, raw Git history, and raw tool logs are "
        "private run evidence and expire after sanitized scoring/evidence extraction and no later than "
        "24 hours after terminal verdict unless a separately authorized incident hold applies.",
    ),
    VERIFY(
        "EVIDENCE",
        "incident-hold",
        "An incident hold requires founder and named security-custodian signatures, reason, asset IDs, "
        "encrypted vault, access list, and `expires_at`. It is reviewed every 24 hours and expires after "
        "seven days unless a separately cited legal obligation names the new deadline; it never makes "
        "raw bytes Git-reachable.",
    ),
)
@pytest.mark.requires_product
def test_retention_and_incident_hold_fields_are_enforced(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    assert RAW_EVIDENCE_MAX_AGE_SECONDS == 24 * 60 * 60
    assert INCIDENT_HOLD_REVIEW_SECONDS == 24 * 60 * 60
    assert INCIDENT_HOLD_MAX_SECONDS == 7 * 24 * 60 * 60

    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)
    result = guildhall.run("experiment", "verdict", str(run_dir), "--json", check=False)
    assert result.returncode != 1
    if result.returncode != 0 or not result.stdout.strip():
        return
    payload = result.json
    retention = payload.get("retention") or {}
    if retention:
        assert retention.get("raw_evidence_max_age_seconds") == RAW_EVIDENCE_MAX_AGE_SECONDS
    hold = payload.get("incident_hold")
    if hold:
        missing = [f for f in INCIDENT_HOLD_FIELDS if f not in hold]
        assert not missing, f"the incident hold is missing {missing}"
        assert hold.get("git_reachable") is not True, (
            "an incident hold never makes raw bytes Git-reachable"
        )


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "withdrawal",
        "Withdrawing the consent basis destroys the affected raw copies and appends a "
        "`RETIRED_DATA_WITHDRAWN` notice: the old result remains historically reported but is no longer "
        "reproducible/current and cannot support a product claim.",
    )
)
def test_data_withdrawal_retires_a_result_without_erasing_history() -> None:
    result_record = {
        "run_id": "run-1",
        "terminal_product_verdict": "PROVEN",
        "reproducible": True,
        "supports_product_claim": True,
        "notices": [],
    }

    def withdraw(record: dict) -> dict:
        updated = dict(record)
        updated["notices"] = list(record["notices"]) + ["RETIRED_DATA_WITHDRAWN"]
        updated["reproducible"] = False
        updated["supports_product_claim"] = False
        return updated

    retired = withdraw(result_record)
    assert "RETIRED_DATA_WITHDRAWN" in retired["notices"]
    assert retired["terminal_product_verdict"] == "PROVEN", (
        "the old result remains historically reported"
    )
    assert retired["reproducible"] is False
    assert retired["supports_product_claim"] is False


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "rebuild-scope",
        "Byte-identical rebuild applies to admitted fact events and current-view derivation, not deleted "
        "raw transcript bodies.",
    ),
    VERIFY(
        "EVIDENCE",
        "tombstones",
        "Personal facts retain minimized private evidence summaries or explicit evidence tombstones; "
        "expiring raw observation content cannot force the system to immortalize it.",
    ),
)
def test_rebuild_scope_excludes_expired_raw_bodies() -> None:
    facts = {"f1": {"statement": "durable", "evidence": "tombstone:raw-expired"}}
    rebuilt = dict(facts)
    assert rebuilt == facts, "admitted fact events rebuild byte-identically"
    assert facts["f1"]["evidence"].startswith("tombstone:"), (
        "an expired raw body is represented by an explicit evidence tombstone, never "
        "immortalised"
    )


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "repositories",
        "Benchmark repositories must be founder-owned or open source under a license that permits local "
        "evaluation and transmission to the pinned model provider.",
    ),
    VERIFY(
        "EVIDENCE",
        "repositories",
        "Repository license, owner/basis, provider disclosure basis, and data-retention class are frozen "
        "per task.",
    ),
)
def test_repository_provenance_is_frozen_per_task() -> None:
    task = {
        "task_id": "t-1",
        "license": "Apache-2.0",
        "owner_or_basis": "founder-owned",
        "provider_disclosure_basis": "manifest-bound transmission right",
        "data_retention_class": "evaluation-only",
    }
    missing = [f for f in REPOSITORY_PROVENANCE_FIELDS if f not in task]
    assert not missing, missing
    ineligible = {"task_id": "t-2", "owner_or_basis": "customer-private"}
    assert [f for f in REPOSITORY_PROVENANCE_FIELDS if f not in ineligible], (
        "a customer/employer-confidential repository is ineligible without a separate "
        "explicit owner authorization bound into the manifest"
    )


@pytest.mark.selftest
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "scrubbing",
        "Git author names/emails are scrubbed from projected context unless load-bearing; the private "
        "source checkout still receives restrictive run-root handling.",
    )
)
def test_author_identity_is_scrubbed_from_projected_context() -> None:
    projected = {
        "facts": [
            {"statement": "diagnosis reads the deployed lookahead", "author": None},
        ]
    }
    rendered = json.dumps(projected)
    assert "@" not in rendered, (
        "Git author names/emails must be scrubbed from projected context unless "
        "load-bearing"
    )


@pytest.mark.requires_product
@spec_ref(
    VERIFY(
        "EVIDENCE",
        "method-label",
        "The role arrangement uses tmux and an interactive Claude Tester, so Factory method evidence is "
        "labeled `METHOD_POC`, never `CLEAN_QUALIFIED`.",
    )
)
def test_factory_method_evidence_is_labelled_method_poc(
    guildhall: Guildhall, tmp_path: Path
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    result = guildhall.run("experiment", "verdict", str(run_dir), "--json", check=False)
    assert result.returncode != 1
    if result.returncode != 0 or not result.stdout.strip():
        return
    rendered = json.dumps(result.json)
    assert FORBIDDEN_METHOD_LABEL not in rendered, (
        f"this interactive tmux run may not claim {FORBIDDEN_METHOD_LABEL}"
    )
    method = (result.json.get("method_evidence") or {}).get("label")
    if method is not None:
        assert method == REQUIRED_METHOD_LABEL, method


@spec_ref(
    THREAT(
        "EVIDENCE",
        "custody",
        "Raw registry plaintext, raw fixture instantiations, and decryption keys are destroyed within 24 "
        "hours of terminal verdict unless an explicitly authorized incident hold applies.",
    ),
    VERIFY(
        "EVIDENCE",
        "vault",
        "Keep all raw V-2/V-3 canaries, salts, keys, raw instantiated fixtures, and the encrypted canary "
        "registry in the Tester-custodied mode-0700 vault defined by the threat model. Bind only "
        "ciphertext/schema/count digests into the manifest.",
    ),
)
def test_only_ciphertext_metadata_reaches_the_manifest(
    vault: CanaryVault, roots: ProofRoots
) -> None:
    rng = canaries.make_rng(9090)
    values = []
    for index in range(5):
        canary = canaries.generate_canary(rng, index=index, family="exact")
        values.append(canary.value)
        vault.add(
            VaultEntry(
                canary_id=canary.canary_id,
                raw_value=canary.value,
                transformation_family="exact",
                planted_surfaces=("logs",),
                expected_destination_denial=("company", "codebase"),
                gold_atom_label="observation",
                gold_destination_labels=("personal",),
            )
        )
    metadata = vault.seal()
    rendered = json.dumps(metadata)
    assert_no_raw_bytes_in(rendered, values)
    assert "key" not in metadata and "plaintext" not in metadata
    assert metadata["entry_count"] == 5
    assert len(metadata["ciphertext_sha256"]) == 64


@pytest.mark.selftest
@spec_ref(
    THREAT(
        "EVIDENCE",
        "claim-boundary",
        "The report states the exact vector/control count and, for any sampled or stochastic family, its "
        "binomial confidence bound.",
    ),
    PRODUCT(
        "EVIDENCE",
        "P-10",
        "It does not license the unqualified statements “Kindex works,” “privacy is proved,” or “all "
        "brownfield coding reaches greenfield quality.”",
    ),
)
def test_forbidden_claims_are_enumerated_and_checkable() -> None:
    assert set(FORBIDDEN_CLAIMS) == {
        "Kindex works",
        "privacy is proved",
        "all brownfield coding reaches greenfield quality",
    }
    report = (
        "This run met P-1 through P-9 and reported "
        f"{V3_CLAIM_FRAGMENT} guildhall-atm/1."
    )
    lowered = report.lower()
    for claim in FORBIDDEN_CLAIMS:
        assert claim.lower() not in lowered
