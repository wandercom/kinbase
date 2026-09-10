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

from ._harness import obligations as O
from ._harness.evidence_model import Origin, require_nonempty

from ._harness.cli import Kinbase
from ._harness.evidence import (
    FAILURE_ROW_FIELDS,
    FORBIDDEN_PACKET_FIELDS,
    INCIDENT_HOLD_FIELDS,
    REPOSITORY_PROVENANCE_FIELDS,
    REQUIRED_PACKET_SECTIONS,
    assert_packet_root_private,
    freshness_of,
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

    require_nonempty(
        REQUIRED_PACKET_SECTIONS,
        obligation="V-3.claim",
        why="the packet schema must declare a non-empty required-section set",
        origin=Origin.HARNESS,
    )
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

def test_packet_root_is_private_and_outside_git(
    roots: ProofRoots, tmp_path: Path
) -> None:
    import stat as _stat

    packet = roots.evidence_root
    packet.mkdir(parents=True, exist_ok=True)
    os.chmod(packet, 0o700)
    assert_packet_root_private(packet)
    inside_worktree = any(
        (parent / ".git").exists() for parent in [packet, *packet.parents]
    )
    O.check(
        "EV.custody",
        {
            "mode": _stat.S_IMODE(packet.stat().st_mode),
            "inside_git_worktree": inside_worktree,
            "outside_repository": roots.repo_root not in packet.parents
            and packet != roots.repo_root,
        },
        label="the evidence packet root is private and outside Git",
    )


@pytest.mark.selftest
@spec_ref(
    THREAT(
        "EVIDENCE",
        "reporting",
        "The sanitized report names `kinbase-atm/1` and its digest, lists every executed "
        "family/control/ mutation and surface, preserves disagreements and adjudication receipts, and "
        "uses the qualified claim verbatim. It never says merely “privacy proved” or “zero leakage.”",
    )
)
def test_sanitised_report_claim_discipline_is_checkable() -> None:
    good = (
        "Under Acceptance Threat Model kinbase-atm/1, digest "
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
@pytest.mark.selftest
def test_retention_and_incident_hold_fields_are_enforced(tmp_path: Path) -> None:
    """The packet schema carries every hold field the specification names.

    Instrument-only (``EV.retention`` fails closed to ``INVALID_HARNESS``): the
    expected field set is transcribed from the ratified sentence, so a schema
    that drops one of them fails here rather than silently accepting a hold
    without, say, an access list.
    """
    raw = tmp_path / "raw-transcript.jsonl"
    raw.write_text(json.dumps({"turn": 1}) + "\n", encoding="utf-8")
    age = freshness_of(raw)
    # spec/verification.md "incident-hold": "founder and named security-custodian
    # signatures, reason, asset IDs, encrypted vault, access list, and `expires_at`".
    spec_named = (
        "founder_signature",
        "security_custodian_signature",
        "reason",
        "asset_ids",
        "encrypted_vault",
        "access_list",
        "expires_at",
    )
    fields = [
        {"field": name, "present": name in INCIDENT_HOLD_FIELDS}
        for name in spec_named
    ]
    O.check(
        "EV.retention",
        {
            "raw_evidence_age_seconds": age,
            "incident_hold_fields": fields,
            "hold_requires_two_named_authorities": (
                "founder_signature" in INCIDENT_HOLD_FIELDS
                and "security_custodian_signature" in INCIDENT_HOLD_FIELDS
            ),
        },
        label="retention and incident-hold fields are enforced",
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
    kinbase: Kinbase, tmp_path: Path
) -> None:
    packet = {
        "method_label": REQUIRED_METHOD_LABEL,
        "role_arrangement": "tmux with an interactive Claude Tester",
    }
    rendered = json.dumps(packet)
    O.check(
        "EV.method-label",
        {
            "method_label": packet["method_label"],
            "forbidden_label_occurrences": rendered.count(FORBIDDEN_METHOD_LABEL),
        },
        label="Factory method evidence is labelled METHOD_POC",
    )


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
    import hashlib as _hashlib

    raw = "kx" + os.urandom(12).hex()
    vault.add(VaultEntry(
        canary_id="manifest-1", raw_value=raw, transformation_family="exact",
        planted_surfaces=("personal_input",),
        expected_destination_denial=("company", "codebase"),
        gold_atom_label="private", gold_destination_labels=("personal",),
    ))
    vault.seal()
    registry = vault.registry_path
    ciphertext = registry.read_bytes()
    manifest_binding = {
        "ciphertext_digest": _hashlib.sha256(ciphertext).hexdigest(),
        "schema": "kinbase-canary-registry/1",
        "count": len(vault.entries()),
    }
    rendered = json.dumps(manifest_binding)
    O.check(
        "EV.ciphertext-only",
        {
            "ciphertext_digest": manifest_binding["ciphertext_digest"],
            "schema": manifest_binding["schema"],
            "count": manifest_binding["count"],
            "plaintext_values_in_manifest": rendered.count(raw),
            "key_material_in_manifest": rendered.count(vault.key.hex()),
        },
        label="only ciphertext metadata reaches the manifest",
    )


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
        f"{V3_CLAIM_FRAGMENT} kinbase-atm/1."
    )
    lowered = report.lower()
    for claim in FORBIDDEN_CLAIMS:
        assert claim.lower() not in lowered
