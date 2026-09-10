"""Evidence-packet schema and validation.

``spec/verification.md`` "Evidence packet" enumerates the final packet contents
and the sanitisation rules. This module encodes both as a checkable schema so
the acceptance suite can validate a produced packet rather than eyeball it.

The two rules that carry the most weight, and that this validator enforces
mechanically:

    Permanent failure rows contain canary ID, keyed-HMAC match, detector/encoding
    class, destination/location digest, offset, and times---not the canary or
    leaked bytes.

    The packet is Validator-owned mode-0700 run state outside Git during
    execution and is transferred only to the founder/security custodian. A
    sanitized aggregate report may be committed; raw Personal data never is.
"""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .requirements import ProductFailure

#: ``spec/verification.md`` "Evidence packet": "The final packet contains:".
REQUIRED_PACKET_SECTIONS: tuple[str, ...] = (
    "ratified_specs_and_digests",
    "source_corpus_manifests_and_adapter_receipts",
    "classifier_corpus_gold_labels_raw_predictions_and_metrics",
    "privacy_scan_reconstructor_and_adversarial_results",
    "threat_model_attack_catalog_auxiliary_corpus_digests_and_coverage",
    "leak_runbook_tabletop_private_soak_and_tripwire_results",
    "maintenance_and_temporal_traces",
    "authority_question_and_signed_answer_receipts",
    "host_setup_and_hook_invocation_receipts",
    "benchmark_manifest_candidates_tests_scores_traces_costs_and_analysis",
    "role_identities_and_method_limitations",
    "failed_attempts_and_terminal_verdict_with_gate_vector",
)

#: Permitted keys in a permanent failure row. Anything else risks carrying bytes.
FAILURE_ROW_FIELDS: tuple[str, ...] = (
    "canary_id",
    "keyed_hmac",
    "detector_class",
    "encoding_class",
    "location_digest",
    "surface_family",
    "offset",
    "observed_at",
)

#: Fields that must never appear anywhere in a sanitised packet.
FORBIDDEN_PACKET_FIELDS: tuple[str, ...] = (
    "raw_value",
    "canary_value",
    "leaked_bytes",
    "plaintext",
    "transcript_body",
    "transcript_path",
    "registry_key",
    "decryption_key",
    "denied_prose",
    "personal_path",
)

#: ``spec/verification.md``: raw per-arm evidence "expire after sanitized scoring
#: and evidence extraction and no later than 24 hours after terminal verdict".
RAW_EVIDENCE_MAX_AGE_SECONDS = 24 * 60 * 60

#: ``spec/verification.md``: an incident hold "is reviewed every 24 hours and
#: expires after seven days unless a separately cited legal obligation names the
#: new deadline".
INCIDENT_HOLD_REVIEW_SECONDS = 24 * 60 * 60
INCIDENT_HOLD_MAX_SECONDS = 7 * 24 * 60 * 60

#: Required incident-hold fields.
INCIDENT_HOLD_FIELDS: tuple[str, ...] = (
    "founder_signature",
    "security_custodian_signature",
    "reason",
    "asset_ids",
    "encrypted_vault",
    "access_list",
    "expires_at",
)

#: ``spec/verification.md``: benchmark repository provenance frozen per task.
REPOSITORY_PROVENANCE_FIELDS: tuple[str, ...] = (
    "license",
    "owner_or_basis",
    "provider_disclosure_basis",
    "data_retention_class",
)


@dataclass
class PacketValidation:
    missing_sections: tuple[str, ...]
    forbidden_hits: tuple[str, ...]
    malformed_failure_rows: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not (
            self.missing_sections or self.forbidden_hits or self.malformed_failure_rows
        )

    def raise_if_bad(self) -> None:
        if self.ok:
            return
        parts: list[str] = []
        if self.missing_sections:
            parts.append(
                "missing required packet sections: " + ", ".join(self.missing_sections)
            )
        if self.forbidden_hits:
            parts.append(
                "sanitised packet contains forbidden fields: "
                + ", ".join(self.forbidden_hits)
            )
        if self.malformed_failure_rows:
            parts.append(
                "permanent failure rows carry disallowed keys: "
                + ", ".join(self.malformed_failure_rows)
            )
        raise ProductFailure("; ".join(parts))


def _walk_keys(node: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(node, Mapping):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path, value
            yield from _walk_keys(value, path)
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            path = f"{prefix}[{index}]"
            yield from _walk_keys(value, path)


def validate_packet(packet: Mapping[str, Any]) -> PacketValidation:
    missing = tuple(s for s in REQUIRED_PACKET_SECTIONS if s not in packet)

    forbidden: list[str] = []
    for path, value in _walk_keys(packet):
        leaf = path.split(".")[-1].split("[")[0]
        if leaf in FORBIDDEN_PACKET_FIELDS:
            forbidden.append(path)

    malformed: list[str] = []
    rows = packet.get("privacy_scan_reconstructor_and_adversarial_results", {})
    if isinstance(rows, Mapping):
        for row in rows.get("permanent_failure_rows", []) or []:
            if not isinstance(row, Mapping):
                malformed.append(repr(row)[:80])
                continue
            extra = sorted(set(row) - set(FAILURE_ROW_FIELDS))
            if extra:
                malformed.append(f"{row.get('canary_id', '?')}: {extra}")
            missing_row = sorted(set(FAILURE_ROW_FIELDS) - set(row))
            if missing_row:
                malformed.append(f"{row.get('canary_id', '?')} missing {missing_row}")

    return PacketValidation(
        missing_sections=missing,
        forbidden_hits=tuple(sorted(set(forbidden))),
        malformed_failure_rows=tuple(malformed),
    )


def assert_packet_root_private(path: Path) -> None:
    """The run-state packet root must be mode 0700 and outside Git."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o700:
        raise ProductFailure(
            "spec/verification.md: the evidence packet is 'Validator-owned "
            f"mode-0700 run state outside Git'; {path} is mode {mode:04o}"
        )
    marker = path
    while marker != marker.parent:
        if (marker / ".git").exists():
            raise ProductFailure(
                f"the evidence packet root {path} is inside a Git worktree at {marker}"
            )
        marker = marker.parent


def assert_no_raw_bytes_in(text: str, forbidden_values: Sequence[str]) -> None:
    """No raw canary or Personal value may appear in a sanitised artifact."""
    hits = [v for v in forbidden_values if v and v in text]
    if hits:
        raise ProductFailure(
            f"{len(hits)} raw protected value(s) present in a sanitised artifact"
        )


def sanitised_report_claims_are_qualified(report: str) -> list[str]:
    """Check the report against the frozen claim discipline.

    ``spec/threat-model.md`` "Retention and reporting": the sanitised report
    "names ``kinbase-atm/1`` and its digest, lists every executed
    family/control/mutation and surface, preserves disagreements and adjudication
    receipts, and uses the qualified claim verbatim. It never says merely
    'privacy proved' or 'zero leakage'."
    """
    problems: list[str] = []
    lowered = report.lower()
    if "kinbase-atm/1" not in report:
        problems.append("report does not name kinbase-atm/1")
    for banned in ("privacy proved", "zero leakage"):
        if banned in lowered:
            problems.append(f"report uses the forbidden phrase {banned!r}")
    if "zero observed unauthorized durable disclosure" not in lowered:
        problems.append("report omits the qualified V-3 claim")
    return problems


def freshness_of(path: Path, now: float | None = None) -> float:
    """Age of ``path`` in seconds, measured from its last modification.

    The ``EV.retention`` clause compares this against
    ``RAW_EVIDENCE_MAX_AGE_SECONDS``; an absolute ``st_mtime`` would exceed
    any sane age bound and could never satisfy it.
    """
    reference = time.time() if now is None else now
    return max(0.0, reference - os.stat(path).st_mtime)
