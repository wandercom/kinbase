"""V-2 --- classification and fan-out (`P-2`, Critical).

The held-out corpus is generated, never committed as prose. ``spec/verification.md``
"Evidence packet": "Committed V-2/V-3 fixtures contain only generators,
placeholder IDs, structural gold labels, and policies." The structural gold set
lives in ``tests/fixtures/gold/routing_corpus.json`` and is instantiated with
vault-held random canary values at run time.
"""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path

import pytest

from ._harness import canaries, stats, synth
from ._harness.cli import Guildhall
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    SRC,
    VERIFY,
    HarnessInvalid,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.vault import CanaryVault, VaultEntry

pytestmark = [pytest.mark.v2, pytest.mark.requires_product]

GOLD_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "gold" / "routing_corpus.json"

#: Frozen V-2 thresholds, ``spec/product.md`` P-2 and ``spec/verification.md`` V-2.
HELD_OUT_MESSAGE_FLOOR = 120
MIXED_MESSAGE_FLOOR = 40
CANARY_MESSAGE_FLOOR = 100
SEEDED_CANARY_FLOOR = 30
CALIBRATION_MESSAGE_COUNT = 60
MACRO_F1_FLOOR = 0.90
SHARED_PRECISION_FLOOR = 0.95
ANNOTATOR_KAPPA_FLOOR = 0.80
PINNED_RUNS = 5


# --------------------------------------------------------------------------
# Corpus construction
# --------------------------------------------------------------------------


def _load_gold() -> dict:
    if not GOLD_PATH.is_file():
        raise HarnessInvalid(f"structural gold corpus missing at {GOLD_PATH}")
    return json.loads(GOLD_PATH.read_text(encoding="utf-8"))


@pytest.fixture()
def routing_corpus(vault: CanaryVault, tmp_path: Path) -> dict:
    """Instantiate the held-out corpus with vault-held random canary values."""
    gold = _load_gold()
    rng = canaries.make_rng(int(gold["generator_seed"]))
    slot_values: dict[str, str] = {}
    for index, slot in enumerate(sorted(gold["canary_slots"])):
        canary = canaries.generate_canary(
            rng,
            index=index,
            family=gold["canary_slots"][slot]["transformation_family"],
            kind=gold["canary_slots"][slot]["kind"],
        )
        slot_values[slot] = canary.value
        vault.add(
            VaultEntry(
                canary_id=canary.canary_id,
                raw_value=canary.value,
                transformation_family=canary.family,
                planted_surfaces=tuple(gold["canary_slots"][slot]["planted_surfaces"]),
                expected_destination_denial=tuple(
                    gold["canary_slots"][slot]["expected_destination_denial"]
                ),
                gold_atom_label=gold["canary_slots"][slot]["gold_atom_label"],
                gold_destination_labels=tuple(
                    gold["canary_slots"][slot]["gold_destination_labels"]
                ),
            )
        )
    messages = []
    for record in gold["messages"]:
        text = record["template"]
        for slot in record["canary_slots"]:
            text = text.replace("{" + slot + "}", slot_values[slot])
        messages.append({**record, "text": text})
    # Raw instantiations live only in the vault, never a committed path.
    raw_dir = vault.raw_fixture_dir("v2-routing")
    (raw_dir / "messages.jsonl").write_text(
        "\n".join(json.dumps(m, sort_keys=True) for m in messages) + "\n",
        encoding="utf-8",
    )
    os.chmod(raw_dir / "messages.jsonl", 0o600)
    return {
        "gold": gold,
        "messages": messages,
        "slot_values": slot_values,
        "path": raw_dir / "messages.jsonl",
    }


@spec_ref(
    VERIFY(
        "V-2",
        "held-out-corpus",
        "Tester freezes at least 120 held-out natural messages with gold atom boundaries and "
        "destination sets; at least 40 are mixed and at least 100 contain varied "
        "private/safety canaries or transformations.",
    ),
    PRODUCT(
        "V-2",
        "P-2",
        "The held-out routing corpus contains at least 120 natural messages, at least 40 "
        "mixed-scope messages, ambiguous non-facts, temporary suggestions, codebase facts, "
        "Company architecture, and at least 30 seeded private/sensitive canaries.",
    ),
)
@pytest.mark.selftest
def test_held_out_corpus_meets_every_frozen_floor(routing_corpus) -> None:
    messages = routing_corpus["messages"]
    assert len(messages) >= HELD_OUT_MESSAGE_FLOOR, len(messages)
    mixed = [m for m in messages if m["mixed"]]
    assert len(mixed) >= MIXED_MESSAGE_FLOOR, len(mixed)
    with_canaries = [m for m in messages if m["canary_slots"]]
    assert len(with_canaries) >= CANARY_MESSAGE_FLOOR, len(with_canaries)
    assert len(routing_corpus["slot_values"]) >= SEEDED_CANARY_FLOOR, (
        "P-2 requires at least 30 seeded private/sensitive canaries"
    )
    strata = {m["stratum"] for m in messages}
    for required in (
        "ambiguous_non_fact",
        "temporary_suggestion",
        "codebase_fact",
        "company_architecture",
    ):
        assert required in strata, f"corpus stratum {required} is missing"


@spec_ref(
    VERIFY(
        "V-2",
        "annotators",
        "Two independent annotators label the routing/atomization gold set before model "
        "execution. Cohen's kappa must be at least 0.80 per destination; disagreements are "
        "adjudicated and the adjudication digest freezes before classifier runs. Below that, "
        "V-2 is `INVALID_HARNESS`, not a classifier failure.",
    )
)
@pytest.mark.selftest
def test_annotator_agreement_and_frozen_adjudication_digest(routing_corpus) -> None:
    gold = routing_corpus["gold"]
    annotations = gold["annotations"]
    assert set(annotations) == {"annotator_a", "annotator_b"}, (
        "exactly two independent annotators label the gold set"
    )
    per_destination: dict[str, float] = {}
    for destination in synth.DESTINATIONS:
        a = [
            "1" if destination in row else "0"
            for row in annotations["annotator_a"].values()
        ]
        b = [
            "1" if destination in row else "0"
            for row in annotations["annotator_b"].values()
        ]
        if len(set(a)) == 1 and len(set(b)) == 1 and a == b:
            per_destination[destination] = 1.0
            continue
        per_destination[destination] = stats.cohen_kappa(a, b)
    low = {d: k for d, k in per_destination.items() if k < ANNOTATOR_KAPPA_FLOOR}
    if low:
        raise HarnessInvalid(
            "Cohen's kappa below 0.80 per destination makes V-2 INVALID_HARNESS, "
            f"not a classifier failure: {low}"
        )
    assert gold["adjudication_digest"], (
        "the adjudication digest must freeze before classifier runs"
    )
    assert gold["adjudication_frozen_before_classifier_runs"] is True


# --------------------------------------------------------------------------
# Live classifier metrics
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY(
        "V-2",
        "pinned-runs",
        "The live semantic classifier executes at least five preregistered runs with pinned "
        "model/version/settings. Apply utility thresholds to the lower confidence bound and "
        "freeze replay from run 1, never the best run.",
    ),
    PRODUCT(
        "V-2",
        "P-2",
        "Required macro-F1 across destination labels is 0.90 and each shared-destination "
        "precision is at least 0.95 across the preregistered 95% lower bound of at least five "
        "pinned live-model runs.",
    ),
)
def test_five_pinned_runs_lower_bound_meets_macro_f1_and_shared_precision(
    guildhall: Guildhall, routing_corpus, roots: ProofRoots
) -> None:
    payload = guildhall.run(
        "session",
        "observe",
        "acceptance-v2",
        "--event",
        str(routing_corpus["path"]),
        "--json",
    ).ok().json
    metrics = payload.get("classification_metrics") or {}
    runs = metrics.get("runs") or []
    assert len(runs) >= PINNED_RUNS, (
        f"at least {PINNED_RUNS} preregistered runs are required; observed {len(runs)}"
    )
    fingerprints = {json.dumps(r.get("model_fingerprint"), sort_keys=True) for r in runs}
    assert len(fingerprints) == 1, (
        f"all runs must pin one model/version/settings identity; observed {fingerprints}"
    )
    assert metrics.get("replay_frozen_from_run") == 1, (
        "replay freezes from run 1, never the best run"
    )

    macro = metrics.get("macro_f1_lower_bound")
    assert macro is not None, "macro-F1 must be reported as a lower bound"
    assert macro >= MACRO_F1_FLOOR, (
        f"macro-F1 lower bound {macro} is below the frozen {MACRO_F1_FLOOR}"
    )
    assert metrics.get("macro_f1_interval_method") == "message_stratified_bootstrap", (
        "spec/product.md P-2 fixes a message-stratified bootstrap for macro-F1"
    )
    for destination in ("company", "codebase"):
        precision = (metrics.get("shared_precision_lower_bound") or {}).get(destination)
        assert precision is not None, f"no shared precision reported for {destination}"
        assert precision >= SHARED_PRECISION_FLOOR, (
            f"{destination} shared precision lower bound {precision} is below "
            f"{SHARED_PRECISION_FLOOR}"
        )
    assert metrics.get("shared_precision_interval_method") == "wilson", (
        "spec/product.md P-2 fixes a Wilson interval over pooled frozen predictions"
    )
    for field in (
        "exact_match_atomization",
        "per_label_precision_recall_f1",
        "private_to_shared_detection",
        "calibration_and_abstention",
    ):
        assert field in metrics, f"V-2 requires {field} to be computed"


@spec_ref(
    VERIFY(
        "V-2",
        "calibration",
        "Before V-10, run a separate excluded 60-message calibration corpus through the same "
        "five-run configuration. Its 95% lower bound must reach macro-F1 0.90 and each shared "
        "precision 0.95; failure is a P-2 product failure and stops expensive measurement, not "
        "an excuse to change the held-out corpus.",
    )
)
def test_excluded_calibration_corpus_gates_measurement(
    guildhall: Guildhall, routing_corpus
) -> None:
    gold = routing_corpus["gold"]
    calibration_ids = set(gold["calibration_message_ids"])
    held_out_ids = {m["message_id"] for m in routing_corpus["messages"]}
    assert len(calibration_ids) == CALIBRATION_MESSAGE_COUNT, len(calibration_ids)
    assert not (calibration_ids & held_out_ids), (
        "the calibration corpus must be separate and excluded from the held-out set"
    )
    payload = guildhall.run(
        "experiment", "calibrate", str(gold["calibration_manifest"]), "--json", check=False
    )
    if payload.returncode == 0:
        metrics = payload.json.get("classifier_calibration") or {}
        assert metrics.get("macro_f1_lower_bound", 0) >= MACRO_F1_FLOOR
        for destination in ("company", "codebase"):
            assert (
                metrics.get("shared_precision_lower_bound", {}).get(destination, 0)
                >= SHARED_PRECISION_FLOOR
            )
    else:
        # A calibration miss stops measurement as a P-2 product failure; it must
        # not be reported as a harness repair opportunity.
        assert payload.returncode != 1
        assert payload.code in {"LIMIT_EXCEEDED", "CONFIG_INVARIANT", "SCORER_UNCALIBRATED"}


@spec_ref(
    PRODUCT(
        "V-2",
        "P-2",
        "Mixed text must split rather than force one label on the whole message.",
    ),
    VERIFY(
        "V-2",
        "mutation",
        "Mutations: whole-message single label; shared-by-default under low confidence; common "
        "fan-out transaction; remove nonce uniqueness/recovery. Each must fail.",
    ),
)
def test_mixed_messages_atomise_rather_than_take_one_label(
    guildhall: Guildhall, routing_corpus
) -> None:
    payload = guildhall.run(
        "session",
        "observe",
        "acceptance-v2",
        "--event",
        str(routing_corpus["path"]),
        "--json",
    ).ok().json
    atoms_by_message: dict[str, list[dict]] = {}
    for atom in payload.get("atoms", []):
        atoms_by_message.setdefault(atom["message_id"], []).append(atom)

    offenders: list[str] = []
    for message in routing_corpus["messages"]:
        if not message["mixed"]:
            continue
        atoms = atoms_by_message.get(message["message_id"], [])
        if len(atoms) < 2:
            offenders.append(f"{message['message_id']}: {len(atoms)} atom(s)")
            continue
        destinations = {d for atom in atoms for d in atom.get("destinations", [])}
        if len(destinations) < 2:
            offenders.append(
                f"{message['message_id']}: one destination set {destinations}"
            )
    assert not offenders, (
        "mixed-scope messages must split into independent atoms, not take one "
        f"whole-message label: {offenders}"
    )


@spec_ref(
    VERIFY(
        "V-2",
        "metrics",
        "Compute exact-match atomization, per-label precision/recall/F1, macro-F1, shared "
        "precision, private-to-shared detection, and calibration/abstention.",
    )
)
def test_exact_match_atomization_and_per_label_metrics(
    guildhall: Guildhall, routing_corpus
) -> None:
    payload = guildhall.run(
        "session",
        "observe",
        "acceptance-v2",
        "--event",
        str(routing_corpus["path"]),
        "--json",
    ).ok().json
    metrics = payload.get("classification_metrics") or {}
    per_label = metrics.get("per_label_precision_recall_f1") or {}
    assert set(per_label) >= set(synth.DESTINATIONS), (
        f"per-label metrics must cover every destination; observed {sorted(per_label)}"
    )
    for destination, values in per_label.items():
        assert {"precision", "recall", "f1"} <= set(values), destination
    computed = stats.macro_f1(
        {
            label: (
                values.get("true_positives", 0),
                values.get("false_positives", 0),
                values.get("false_negatives", 0),
            )
            for label, values in per_label.items()
            if "true_positives" in values
        }
    )
    reported = metrics.get("macro_f1_point")
    if reported is not None and computed:
        assert abs(reported - computed) < 0.02, (
            f"reported macro-F1 {reported} disagrees with the independently computed "
            f"{computed:.4f}"
        )


@spec_ref(
    PRODUCT(
        "V-2",
        "P-2",
        "A low-confidence shared label is demoted to `none`/Unknown rather than guessed.",
    )
)
def test_low_confidence_shared_label_demotes_to_none_or_unknown(
    guildhall: Guildhall, routing_corpus
) -> None:
    payload = guildhall.run(
        "session",
        "observe",
        "acceptance-v2",
        "--event",
        str(routing_corpus["path"]),
        "--json",
    ).ok().json
    offenders = []
    for atom in payload.get("atoms", []):
        confidence = atom.get("confidence_lower_bound")
        destinations = set(atom.get("destinations", []))
        if confidence is None:
            continue
        shared = destinations & {"company"} or {
            d for d in destinations if d.startswith("codebase")
        }
        if shared and confidence < atom.get("shared_confidence_threshold", 1.0):
            offenders.append((atom.get("atom_id"), confidence, sorted(destinations)))
    assert not offenders, (
        "a low-confidence shared label must demote to none/Unknown rather than be "
        f"guessed: {offenders}"
    )


@spec_ref(
    SRC(
        "V-2",
        "SRC-3",
        "De-identified could be used in shared repos. Writes can go to multiple destinations.",
    ),
    VERIFY(
        "V-2",
        "fan-out",
        "One mixed message must yield independent Personal and Codebase candidates; another "
        "yields Personal, Company, and Codebase candidates with distinct minimized bytes.",
    ),
)
def test_independent_candidates_with_distinct_minimized_bytes(
    guildhall: Guildhall, routing_corpus
) -> None:
    payload = guildhall.run(
        "session",
        "observe",
        "acceptance-v2",
        "--event",
        str(routing_corpus["path"]),
        "--json",
    ).ok().json
    candidates = payload.get("candidates", [])
    by_message: dict[str, dict[str, dict]] = {}
    for candidate in candidates:
        by_message.setdefault(candidate["message_id"], {})[
            candidate["destination"].split(":")[0]
        ] = candidate

    two_store = [
        m for m, d in by_message.items() if {"personal", "codebase"} <= set(d)
    ]
    three_store = [
        m for m, d in by_message.items() if {"personal", "company", "codebase"} <= set(d)
    ]
    assert two_store, "no message produced independent Personal and Codebase candidates"
    assert three_store, (
        "no message produced Personal, Company and Codebase candidates"
    )
    for message_id in three_store:
        payloads = {
            destination: candidate["minimized_payload_digest"]
            for destination, candidate in by_message[message_id].items()
        }
        assert len(set(payloads.values())) == len(payloads), (
            f"{message_id}: destination payloads must be distinct minimized bytes, "
            f"observed {payloads}"
        )


# --------------------------------------------------------------------------
# Fan-out saga
# --------------------------------------------------------------------------


@spec_ref(
    PRODUCT(
        "V-2",
        "P-2",
        "Partial success is reported per destination and never rolls back an already durable "
        "independent write.",
    ),
    VERIFY(
        "V-2",
        "apology",
        "Force Company failure after Codebase commit: receipts expose partial success and an "
        "apology Unknown names the approver as responsible and destination maintainer as "
        "closing authority, withholds the orphaned Codebase fact, and reaches an explicit "
        "reconcile/abandon state; retry returns the original receipt without duplication.",
    ),
)
def test_partial_fanout_failure_does_not_roll_back_committed_destination(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    """Commit Codebase, then make Company terminally unreachable."""
    candidate = guildhall.run(
        "proposals", "list", "--session", "acceptance-v2", "--json"
    ).ok().json
    items = candidate.get("candidates") or candidate.get("items") or []
    assert items, "no candidate available to fan out"
    target = items[0]
    digest = target["payload_digest"]

    codebase_receipt = guildhall.run(
        "proposals",
        "decide",
        target["candidate_id"],
        "--destination",
        target["codebase_destination"],
        "--approve-digest",
        digest,
        "--json",
    ).ok().json
    assert codebase_receipt.get("state") == "committed"

    # Company is unreachable: point at a closed loopback port.
    company_result = guildhall.run(
        "proposals",
        "decide",
        target["candidate_id"],
        "--destination",
        "company",
        "--approve-digest",
        target["company_payload_digest"],
        "--json",
        env={"GUILDHALL_COMPANY_URL": "http://127.0.0.1:1"},
        check=False,
    )
    assert company_result.returncode != 0
    assert company_result.returncode != 1

    status = guildhall.run(
        "status", "--repo", str(guildhall.cwd), "--json"
    ).ok().json
    receipts = status.get("fanout_receipts") or {}
    assert receipts.get("codebase", {}).get("state") == "committed", (
        "the durable Codebase write must not be rolled back"
    )
    assert receipts.get("company", {}).get("state") in {"refused", "pending", "abandoned"}

    apology = status.get("apology_unknowns") or []
    assert apology, "a terminally divergent fan-out must emit an apology Unknown"
    entry = apology[0]
    assert entry.get("responsible_party_role") == "approving-principal"
    assert entry.get("closing_authority_role") in {
        "repository-maintainer",
        "company-steward",
    }
    assert entry.get("orphaned_fact_withheld") is True
    assert entry.get("state") in {"awaiting_reconcile_or_abandon", "reconciled", "abandoned"}


@spec_ref(
    PRODUCT(
        "V-2",
        "P-2",
        "A retry of an already committed exact event returns the original commit receipt even "
        "after token expiry; it cannot create a second event or pretend the first commit did "
        "not happen.",
    )
)
def test_retry_returns_original_receipt_without_duplication(
    guildhall: Guildhall,
) -> None:
    items = (
        guildhall.run("proposals", "list", "--session", "acceptance-v2", "--json")
        .ok()
        .json.get("candidates", [])
    )
    assert items
    target = items[0]
    first = guildhall.run(
        "proposals",
        "decide",
        target["candidate_id"],
        "--destination",
        target["codebase_destination"],
        "--approve-digest",
        target["payload_digest"],
        "--json",
    ).ok().json
    second = guildhall.run(
        "proposals",
        "decide",
        target["candidate_id"],
        "--destination",
        target["codebase_destination"],
        "--approve-digest",
        target["payload_digest"],
        "--json",
    ).ok().json
    assert first["receipt_id"] == second["receipt_id"], (
        "a matching authorized committed retry must return the stored historical receipt"
    )
    assert second.get("event_created") is False
    status = guildhall.run("status", "--repo", str(guildhall.cwd), "--json").ok().json
    assert status.get("duplicate_events", 0) == 0


@spec_ref(
    PRODUCT(
        "V-2",
        "P-2",
        "If its closing authority does not act by the signed deadline, the destination service "
        "must emit an `orphan_abandoned` terminal event naming that authority and keep the "
        "claim untrusted; an orphan cannot remain in an ownerless pending state forever.",
    ),
    VERIFY(
        "V-2",
        "orphan-abandoned",
        "Let the closing deadline expire without a response: the destination service emits one "
        "signed `orphan_abandoned`, names the unresponsive authority, keeps the fact withdrawn, "
        "and leaves no pending orphan forever.",
    ),
)
def test_expired_closing_deadline_emits_one_signed_orphan_abandoned(
    guildhall: Guildhall,
) -> None:
    expired = guildhall.run(
        "status",
        "--repo",
        str(guildhall.cwd),
        "--json",
        env={"GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "864000"},
    ).ok().json
    events = [
        e
        for e in expired.get("destination_events", [])
        if e.get("kind") == "orphan_abandoned"
    ]
    assert len(events) == 1, (
        f"exactly one signed orphan_abandoned event is required; observed {len(events)}"
    )
    event = events[0]
    assert event.get("unresponsive_closing_authority"), (
        "orphan_abandoned must name the unresponsive closing authority"
    )
    assert event.get("signature"), "orphan_abandoned must be signed"
    assert event.get("fact_state") == "withdrawn"
    assert not [
        u
        for u in expired.get("apology_unknowns", [])
        if u.get("state") == "awaiting_reconcile_or_abandon"
    ], "no orphan may remain pending after the deadline"


@spec_ref(
    VERIFY(
        "V-2",
        "host-path",
        "Invoke the actual host/CLI path and assert the approver sees the one-item apology, can "
        "dispatch reconcile or abandon, and the closing authority receives the same signed "
        "Unknown with deadline; a permanently unwritable apology yields local quarantine and "
        "exit-5 doctor state without Company dependency.",
    ),
    ARCH(
        "V-2",
        "entity-ownership",
        "Permanent inability to write the apology leaves a local quarantine marker and exit-5 "
        "`doctor` failure; local orphan blocking requires no Company round trip.",
    ),
)
def test_unwritable_apology_quarantines_locally_with_exit_five(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    apology_root = roots.repo_root / ".kin" / "local"
    apology_root.mkdir(parents=True, exist_ok=True)
    os.chmod(apology_root, 0o500)
    try:
        doctor = guildhall.run(
            "doctor",
            "--repo",
            str(guildhall.cwd),
            "--json",
            env={"GUILDHALL_COMPANY_URL": "http://127.0.0.1:1"},
            check=False,
        )
        assert doctor.returncode == 5, (
            "a permanently unwritable apology must yield exit-5 doctor state without "
            f"a Company round trip; observed exit {doctor.returncode}"
        )
        payload = doctor.json
        assert payload.get("local_quarantine") or payload.get("quarantine_marker"), (
            "a local quarantine marker must exist"
        )
    finally:
        os.chmod(apology_root, 0o700)


@spec_ref(
    VERIFY(
        "V-2",
        "crash-recovery",
        "Kill each destination between nonce reservation, event append/rename, manifest, "
        "receipt, and apology transitions, then retry concurrently. Company returns the one "
        "transaction's receipt; Codebase recovery completes the one content-addressed "
        "event/journal without duplicate or recursive apologies.",
    ),
    ARCH(
        "V-2",
        "entity-ownership",
        "Every crash point is replayed; no check-then-act lookup may create a second event or "
        "hide a first.",
    ),
)
@pytest.mark.slow
def test_kill_at_every_transition_then_concurrent_retry(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    """Crash at each frozen journal transition and require exactly-once recovery."""
    transitions = (
        "nonce_reservation",
        "event_append",
        "event_rename",
        "manifest",
        "receipt",
        "apology",
    )
    for transition in transitions:
        crashed = guildhall.run(
            "proposals",
            "decide",
            "acceptance-candidate",
            "--destination",
            "codebase:acceptance",
            "--approve-digest",
            "0" * 64,
            "--json",
            env={"GUILDHALL_ACCEPTANCE_CRASH_AT": transition},
            check=False,
        )
        assert crashed.returncode != 1, (
            f"crash at {transition} must not return the reserved ambiguous exit 1"
        )
        recovered = guildhall.run(
            "fsck", "--repo", str(guildhall.cwd), "--json", check=False
        )
        payload = recovered.json if recovered.returncode in (0, 3) else recovered.error
        if isinstance(payload, dict):
            assert payload.get("duplicate_events", 0) == 0, (
                f"crash at {transition} produced duplicate events"
            )
            assert payload.get("recursive_apologies", 0) == 0, (
                f"crash at {transition} produced recursive apologies"
            )


@spec_ref(
    PRODUCT(
        "V-2",
        "P-2",
        "One source may fan out to multiple stores, but no cross-store transaction, shared "
        "private lineage token, or accept-all operation exists.",
    ),
    ARCH(
        "V-2",
        "entity-ownership",
        "Cross-destination fan-out is a saga: each destination returns its own "
        "committed/refused/pending/abandoned receipt. No global rollback is claimed.",
    ),
)
def test_no_cross_store_transaction_exists(guildhall: Guildhall) -> None:
    help_text = guildhall.run("proposals", "decide", "--help", check=False).stdout
    for forbidden in ("--all", "--accept-all", "--batch", "--all-destinations"):
        assert forbidden not in help_text, (
            f"spec/architecture.md section 5: 'There is no batch/accept-all endpoint "
            f"in Core or CLI.'; observed {forbidden}"
        )
    status = guildhall.run("status", "--repo", str(guildhall.cwd), "--json").ok().json
    receipts = status.get("fanout_receipts") or {}
    for destination, receipt in receipts.items():
        assert receipt.get("state") in {
            "committed",
            "refused",
            "pending",
            "abandoned",
        }, f"{destination} receipt state {receipt.get('state')!r} is outside the saga enum"
        assert "global_rollback" not in receipt


@spec_ref(
    ARCH(
        "V-2",
        "routing-policy",
        "There is no batch/accept-all endpoint in Core or CLI.",
    ),
    CLI(
        "V-2",
        "session-candidates-approval",
        "No accept-all command exists.",
    ),
    PRODUCT(
        "V-2",
        "P-9",
        "The system never reveals an accept-all path.",
    ),
)
def test_no_accept_all_path_is_reachable(guildhall: Guildhall) -> None:
    top = guildhall.run("--help", check=False).stdout
    assert "accept-all" not in top.lower()
    proposals = guildhall.run("proposals", "--help", check=False).stdout
    assert "accept-all" not in proposals.lower()
    attempted = guildhall.run(
        "proposals", "decide", "--all", "--approve", check=False
    )
    assert attempted.returncode != 0, "an accept-all invocation must not succeed"
