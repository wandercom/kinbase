"""V-1 --- real heterogeneous corpus (`P-1`, Critical).

Detector Reviewer finding 11: the ratified adapter lifecycle table sums to
**64** cells, the catalog required 61, transitions were generic JSON written
outside each adapter's native source, and all cells shared one receipt mutation.
Finding 14: the fixtures carried no external trust anchor, so a conforming
product should have refused every positive control the gate offered.

This module fixes both at the root. Every fixture first establishes the four
ratified trust anchors --- a live Company, an external root outside the work
tree, a steward-signed repository certificate, a published ``AuthorityRegistry``
--- and only then plants state. The lifecycle matrix executes all 64 cells in
each adapter's own native format through
:mod:`acceptance._harness.lifecycle`, digests the raw source tree before and
after every transition, and carries a distinct negative mutation per cell.

Every claim here is typed: obligations go through the frozen catalog checker and
instrument-owned prerequisites go through :mod:`acceptance._harness.prereq`, so
a missing fixture can never be reported as a product failure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ._harness import lifecycle as L
from ._harness import lifecycle_observations as LO
from ._harness import obligations as O
from ._harness import prereq, synth, trust
from ._harness.cli import Guildhall
from ._harness.evidence_model import (
    Origin,
    field,
    require_all,
    require_nonempty,
    require_total_coverage,
    rows,
)
from ._harness.requirements import (
    ARCH,
    SRC,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.worldbuilder import SignedWorld, start_session, temporal_extra_authorities, DEPLOY_OWNER, OpaqueIds

pytestmark = [pytest.mark.v1, pytest.mark.requires_product]

#: The ten ratified adapters, frozen in the harness so the loop domains below
#: are fixed by committed bytes rather than by product output.
ADAPTERS: tuple[str, ...] = synth.ADAPTERS

#: The three cursors V-1 requires out-of-order and skew handling across.
CURSORS: tuple[str, ...] = ("personal", "company", "codebase")

#: Native source directory names, one per adapter family, inside the repository.
SOURCE_ROOTS: dict[str, str] = {
    "codex_jsonl": "codex",
    "claude_jsonl": "claude",
    "repo_code": "src",
    "repo_tests": "tests",
    "git_history": ".git",
    "docs_adr": "adr",
    "github_export": "github",
    "runtime_evidence": "runtime",
    "kindex": "kindex",
    "authority_answer": "answers",
}


#: The approval principals V-1 misextraction / never_true range over.
APPROVERS: tuple[synth.Signer, ...] = (
    synth.make_signer("approver-local-1", "approver:local", seed_byte=23),
    synth.make_signer("approver-local-2", "approver:local", seed_byte=29),
)


# --------------------------------------------------------------------------
# Fixtures: trust anchors first, then raw state, then the product
# --------------------------------------------------------------------------


@pytest.fixture()
def anchored(roots: ProofRoots, guildhall: Guildhall):
    """A world whose external trust prerequisites are genuinely in place."""
    world = SignedWorld.create(roots.repo_root)
    # The two approvers are registered principals (approval scope) so their
    # misextraction notice is admissible; neither is a steward/maintainer, so
    # the never_true withdrawal from either must still be refused.
    anchors = trust.establish(
        guildhall, roots, world,
        extra_authorities=tuple((a, "approver:local") for a in APPROVERS) + temporal_extra_authorities(),
    )
    sources = roots.repo_root / "sources"
    sources.mkdir(parents=True, exist_ok=True)
    ctx = L.LifecycleContext(world=world, sources=sources,
                             external=roots.company_root / "native")
    ctx.external.mkdir(parents=True, exist_ok=True)
    return world, anchors, ctx


@pytest.fixture()
def matrix(anchored, guildhall: Guildhall):
    """All 64 ratified cells, executed natively, with per-cell witnesses."""
    world, anchors, ctx = anchored
    trust.classifier_pinned(anchors, what="V-1 native source extraction")
    cells = L.execution_cells()
    witnesses: dict[str, dict] = {}
    for cell in cells:
        before = _status(guildhall, world.repo.path)
        witness = cell.run(ctx)
        revoked_entry = None
        if witness.get("registry_revoke"):
            authority_id = witness["registry_revoke"]
            revoked_entry = anchors.registry.entry_for(authority_id)
            signer = world.maintainer if authority_id == world.maintainer.authority_id else world.architect
            witness["registry_publication"] = anchors.revoke(
                signer, cursor=str(int(anchors.registry.cursor) + 1))
        target_repo = Path(witness.get("clone", world.repo.path))
        source = ctx.sources / SOURCE_ROOTS[cell.adapter]
        if cell.adapter == "repo_code":
            source = target_repo / "src"
        elif cell.adapter == "git_history":
            source = target_repo
        elif target_repo != world.repo.path:
            source = target_repo / source.relative_to(world.repo.path)
        _ingest(guildhall, target_repo, cell.adapter, source)
        after = _status(guildhall, target_repo)
        if witness.get("repeat_ingest"):
            _ingest(guildhall, target_repo, cell.adapter, source)
            witness["replay_status"] = _status(guildhall, target_repo)
        witness["derived"] = LO.derive(cell, witness, before, after)
        witnesses[cell.key] = witness
        if revoked_entry is not None:
            # Subsequent independent cells use a newly published authority epoch.
            anchors.registry.entries.append(revoked_entry)
            anchors.republish_registry(cursor=str(int(anchors.registry.cursor) + 1))
    prereq.corpus_at_scale(
        len(witnesses), L.CELL_COUNT, what="adapter lifecycle matrix",
        why="spec/verification.md V-1 freezes a table that sums to 64 cells",
    )
    world.repo.run("add", "-A")
    world.repo.commit("record native adapter sources")
    return world, anchors, ctx, witnesses


def _ingest(guildhall: Guildhall, repo: Path, adapter: str, source: Path) -> dict:
    """Drive one adapter through the ratified ingest surface."""
    result = guildhall.run(
        "ingest", adapter, str(source), "--repo", str(repo), "--json",
        cwd=repo, check=False,
    )
    if result.returncode == 1:
        raise ProductFailure(
            f"`ingest {adapter}` returned the reserved ambiguous exit 1"
        )
    payload = result.json
    if not isinstance(payload, dict):
        raise ProductFailure(
            f"`ingest {adapter} --json` did not return an object; observed "
            f"exit {result.returncode}"
        )
    return payload


def _ingest_all(guildhall: Guildhall, world, ctx) -> dict[str, dict]:
    receipts: dict[str, dict] = {}
    for adapter in ADAPTERS:
        source = ctx.sources / SOURCE_ROOTS[adapter]
        if adapter == "git_history":
            source = world.repo.path
        elif adapter == "repo_code":
            source = world.repo.path / "src"
        receipts[adapter] = _ingest(guildhall, world.repo.path, adapter, source)
    return receipts


def _rebuild(guildhall: Guildhall, repo: Path, store: str = "codebase") -> dict:
    result = guildhall.run(
        "corpus", "rebuild", "--store", store, "--repo", str(repo), "--json",
        cwd=repo, check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`corpus rebuild` returned the reserved exit 1")
    payload = result.json
    if not isinstance(payload, dict):
        raise ProductFailure("`corpus rebuild --json` did not return an object")
    return payload


def _status(guildhall: Guildhall, repo: Path) -> dict:
    result = guildhall.run("status", "--repo", str(repo), "--json",
                           cwd=repo, check=False)
    if result.returncode == 1:
        raise ProductFailure("`status` returned the reserved ambiguous exit 1")
    payload = result.json
    if not isinstance(payload, dict):
        raise ProductFailure("`status --json` did not return an object")
    return payload


# --------------------------------------------------------------------------
# Obligations
# --------------------------------------------------------------------------


@spec_ref(
    SRC("V-1", "SRC-1",
        "IF folks (or agents) are doing conversational things, capture it in the SQLite graph "
        "by all means."),
    VERIFY("V-1", "acceptance-map",
           "Run all ten adapters against native-format sources in isolated fixtures; at least "
           "seven participate in the recorded end-to-end build."),
)
def test_all_ten_adapters_run_against_native_sources(guildhall: Guildhall, matrix) -> None:
    world, anchors, ctx, witnesses = matrix
    receipts = _ingest_all(guildhall, world, ctx)
    require_nonempty(receipts, obligation="V-1.adapters-native",
                     why="every ratified adapter must produce a receipt",
                     origin=Origin.PRODUCT)
    require_total_coverage(
        receipts, ADAPTERS, obligation="V-1.adapters-native",
        why="all ten ratified adapters must execute against native sources",
        origin=Origin.PRODUCT,
    )
    receipt_rows = []
    participating = 0
    for adapter in ADAPTERS:
        payload = receipts[adapter]
        observations = payload.get("observations")
        receipt_rows.append({
            "adapter": field(payload, "adapter"),
            "source_identity": field(payload, "source_identity"),
            "observations": observations if isinstance(observations, list) else [],
        })
        if isinstance(observations, list) and observations:
            participating += 1
    O.check(
        "V-1.adapters-native",
        {
            "adapters_executed": sorted(receipts),
            "participating_count": participating,
            "receipts": receipt_rows,
        },
        label="ten adapters against native-format sources",
    )


@spec_ref(
    ARCH("V-1", "source-adapter-contract",
         "A source-class count alone does not pass P-1: the evidence report lists native "
         "observations and derived facts."),
)
def test_adapter_receipt_reports_observations_not_counts(
    guildhall: Guildhall, matrix
) -> None:
    world, anchors, ctx, witnesses = matrix
    receipts = _ingest_all(guildhall, world, ctx)
    require_nonempty(receipts, obligation="V-1.receipt-not-count",
                     why="no adapter produced a receipt to inspect",
                     origin=Origin.PRODUCT)
    observations: list[dict] = []
    derived: list = []
    counted_only = {}
    for adapter in ADAPTERS:
        payload = receipts[adapter]
        listed = payload.get("observations")
        if isinstance(listed, list):
            observations.extend(o for o in listed if isinstance(o, dict))
        facts = payload.get("derived_facts")
        if isinstance(facts, list):
            derived.extend(facts)
        if "observations_count_only" in payload:
            counted_only[adapter] = payload["observations_count_only"]
    evidence = {"observations": observations, "derived_facts": derived}
    if counted_only:
        evidence["observations_count_only"] = counted_only
    O.check("V-1.receipt-not-count", evidence,
            label="receipts list observations and derived facts")


@spec_ref(
    VERIFY("V-1", "build-manifest",
           "Build manifest binds observation IDs, source revisions, digests, checkpoints, "
           "and fact derivations."),
)
def test_end_to_end_build_uses_at_least_seven_source_classes(
    guildhall: Guildhall, matrix
) -> None:
    world, anchors, ctx, witnesses = matrix
    _ingest_all(guildhall, world, ctx)
    build = _rebuild(guildhall, world.repo.path)
    manifest = build.get("build_manifest")
    if not isinstance(manifest, dict):
        raise ProductFailure(
            "`corpus rebuild --json` emitted no build_manifest object; V-1 "
            "requires the manifest to bind provenance"
        )
    O.check("V-1.build-manifest", {"build_manifest": manifest},
            label="build manifest binds provenance")


@spec_ref(
    VERIFY("V-1", "idempotence",
           "Re-run unchanged ingestion: no duplicate observations/facts and byte-identical "
           "current views."),
)
def test_reingest_unchanged_is_idempotent_and_byte_identical(
    guildhall: Guildhall, matrix
) -> None:
    world, anchors, ctx, witnesses = matrix
    _ingest_all(guildhall, world, ctx)
    first = _rebuild(guildhall, world.repo.path)
    _ingest_all(guildhall, world, ctx)
    second = _rebuild(guildhall, world.repo.path)

    first_digest = first.get("current_view_digest")
    second_digest = second.get("current_view_digest")
    if not isinstance(first_digest, str) or not first_digest:
        raise ProductFailure(
            "the first rebuild reported no current_view_digest, so byte "
            "identity cannot be established"
        )
    O.check(
        "V-1.idempotence",
        {
            "current_view_digest": first_digest,
            "current_view_byte_identical": first_digest == second_digest,
            "duplicate_observations": second.get("duplicate_observations"),
            "duplicate_facts": second.get("duplicate_facts"),
            "observation_count": second.get("observation_count"),
        },
        label="unchanged re-ingest is idempotent",
    )


@spec_ref(
    VERIFY("V-1", "disposition-change",
           "Change, delete, reject/revert, and re-run representative sources: history remains, "
           "current disposition changes explicitly."),
)
def test_change_delete_reject_revert_preserve_history_and_change_disposition(
    guildhall: Guildhall, matrix
) -> None:
    world, anchors, ctx, witnesses = matrix
    before = _ingest_all(guildhall, world, ctx)
    require_nonempty(before, obligation="V-1.disposition-change",
                     why="the pre-change ingest produced no receipt",
                     origin=Origin.PRODUCT)

    # The change/delete/reject/revert transitions are the ratified cells that
    # perform exactly those four operations, already executed by the matrix
    # fixture in native form. Re-ingesting reads their result.
    _ingest_all(guildhall, world, ctx)
    status = _status(guildhall, world.repo.path)
    changed = status.get("changed_dispositions")
    O.check(
        "V-1.disposition-change",
        {
            "history_retained": status.get("history_retained"),
            "changed_dispositions": changed if isinstance(changed, list) else [],
        },
        label="history retained while disposition changes explicitly",
    )


@spec_ref(
    VERIFY("V-1", "lifecycle-matrix",
           "Every declared cell has an expected observation/current-fact/Unknown state and "
           "at least one negative mutation."),
)
def test_lifecycle_matrix_executes_every_declared_cell(
    guildhall: Guildhall, matrix
) -> None:
    """All 64 ratified cells, natively executed, each with its own mutation."""
    world, anchors, ctx, witnesses = matrix
    declared = L.verify_table()
    require_all(
        declared, lambda c: c.key in witnesses,
        obligation="V-1.lifecycle-matrix",
        why="every declared cell must have executed its native transition",
        minimum=L.CELL_COUNT, origin=Origin.HARNESS,
    )
    derived_rows = [witnesses[cell.key]["derived"] for cell in declared]
    O.check(
        "V-1.lifecycle-matrix",
        {
            "declared_cell_count": len(declared),
            "adapters_covered": sorted({c.adapter for c in declared}),
            "cells": derived_rows,
        },
        label="64 ratified lifecycle cells executed natively",
    )


@spec_ref(
    VERIFY("V-1", "support-retirement",
           "the first recomputes provenance while retaining the fact, the second withdraws "
           "the fact and reopens every dependent decision"),
)
def test_retiring_supports_one_at_a_time_recomputes_then_withdraws(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors, ctx = anchored
    key = "architecture/scheduler/retry-ceiling"
    first = world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the retry ceiling is four attempts per hour",
        evidence_refs=("adr-0011",),
    )
    second = world.plant_event(
        world.maintainer, store_kind="codebase", logical_key=key,
        statement="the retry ceiling is four attempts per hour",
        evidence_refs=("src/scheduler/retry.py",),
    )
    world.plant_event(
        world.architect, store_kind="company",
        logical_key="architecture/scheduler/backoff",
        statement="backoff derives from the retry ceiling",
        parents=(first["event_id"],),
    )
    world.verify_planted()
    supports = prereq.collected(
        [first, second], what="multiply supported fact", minimum=2,
        why="the retirement sequence needs at least two independent supports",
    )
    _ingest(guildhall, world.repo.path, "kindex", world.repo.path / ".kin")

    world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the retry ceiling is four attempts per hour",
        disposition="retracted", supersedes=(first["event_id"],),
    )
    after_first = _status(guildhall, world.repo.path)

    world.plant_event(
        world.maintainer, store_kind="codebase", logical_key=key,
        statement="the retry ceiling is four attempts per hour",
        disposition="retracted", supersedes=(second["event_id"],),
    )
    after_final = _status(guildhall, world.repo.path)

    reopened = after_final.get("reopened_decisions")
    O.check(
        "V-1.support-retirement",
        {
            "initial_support_count": len(supports),
            "after_first_retirement": {
                "state": _fact_state(after_first, key),
                "provenance_recomputed": _fact_field(
                    after_first, key, "provenance_recomputed"
                ),
            },
            "after_final_retirement": {
                "state": _fact_state(after_final, key),
                "reopened_decisions": reopened if isinstance(reopened, list) else [],
            },
        },
        label="one support retired, then the last",
    )


def _facts(status: dict) -> list[dict]:
    facts = status.get("facts")
    return [f for f in facts if isinstance(f, dict)] if isinstance(facts, list) else []


def _fact_state(status: dict, logical_key: str):
    for fact in _facts(status):
        if fact.get("logical_key") == logical_key:
            return fact.get("state")
    return None


def _fact_field(status: dict, logical_key: str, field: str):
    for fact in _facts(status):
        if fact.get("logical_key") == logical_key:
            return fact.get(field)
    return None


@spec_ref(
    VERIFY("V-1", "clock-skew",
           "Out-of-order delivery and positive/negative clock skew run across Personal, "
           "Company, and Codebase cursors."),
)
def test_out_of_order_and_clock_skew_quarantine_across_all_three_cursors(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors, ctx = anchored
    # R-14: mutate receipt times, never historical validity dates. Personal
    # uses native observations, Codebase uses runtime observation envelopes,
    # Company uses signed request expiry (C7 forbids Personal FactEvents).
    import json

    def codes(payload):
        if isinstance(payload, dict):
            return {v for k, v in payload.items()
                    if k in ("code", "disposition", "state") and isinstance(v, str)} | set().union(
                        *(codes(v) for v in payload.values()))
        if isinstance(payload, list):
            return set().union(*(codes(v) for v in payload))
        return set()

    detail = []
    identities = OpaqueIds()
    all_codes = set()
    for cursor in CURSORS:
        outcomes = {}
        # Both in-bound arrivals are delivered newest first. Two out-of-bound
        # claims exercise both polarities without depending on exact boundaries.
        session = start_session(guildhall, world.repo.path) if cursor == "personal" else None
        for label, offset in (("newer", 0), ("older", -60), ("positive", 600), ("negative", -600)):
            token = identities.token(cursor + "/" + label)
            if cursor == "company":
                response = anchors.client.get("/facts", expires_in=60 if abs(offset) < 300 else offset)
                payload = response.json
                success = response.status == 200
                if abs(offset) < 300:
                    event = world.plant_event(
                        world.architect, store_kind="company",
                        logical_key="architecture/scheduler/" + identities.token("company-history"),
                        statement="the scheduler window is " + ("568" if label == "newer" else "300"),
                        asserted_at=synth._stamp(day=2 if label == "newer" else 1),
                    )
                    success = success and bool(event.get("document"))
            elif cursor == "personal":
                path = ctx.external / (token + ".jsonl")
                path.write_text(json.dumps({
                    "id": token, "role": "user", "text": "I prefer quiet notifications " + token,
                    "source_kind": "codex_jsonl", "observed_at": synth.receipt_stamp(offset),
                }) + "\n", encoding="utf-8")
                result = guildhall.run("session", "observe", session, "--event", str(path),
                                      "--json", cwd=world.repo.path, check=False)
                payload, success = result.json, result.returncode == 0
            else:
                path = ctx.sources / "runtime" / (token + ".json")
                synth.command_result_envelope(
                    path, command=["printf", token], exit_code=0, stdout=token,
                    observed_at=synth.receipt_stamp(offset),
                    environment_id="prod-eu", owner=DEPLOY_OWNER.authority_id,
                )
                result = guildhall.run("ingest", "runtime_evidence", str(path),
                                      "--repo", str(world.repo.path), "--json",
                                      cwd=world.repo.path, check=False)
                payload, success = result.json, result.returncode == 0
            observed_codes = codes(payload)
            all_codes.update(observed_codes)
            outcomes[label] = "CLOCK_SKEW" in observed_codes if abs(offset) > 300 else (
                success and "CLOCK_SKEW" not in observed_codes)
        # Preserve the existing ordering obligation as well as witnessing both
        # valid deliveries; successful command exits alone do not prove ordering.
        cursor_report = next((row for row in rows(_status(guildhall, world.repo.path), "cursor_skew")
                              if field(row, "cursor") == cursor), {})
        detail.append({"cursor": cursor,
                       "positive_skew_quarantined": outcomes["positive"],
                       "negative_skew_quarantined": outcomes["negative"],
                       "out_of_order_handled": outcomes["newer"] and outcomes["older"]
                       and field(cursor_report, "out_of_order_handled") is True})
    O.check("V-1.clock-skew", {
        "skew_dispositions": sorted(all_codes),
        "cursors_exercised": [row["cursor"] for row in detail],
        "cursors_exercised_detail": detail,
    }, label="receipt-time skew on all three cursors (R-14)")


@spec_ref(
    VERIFY("V-1", "misextraction",
           "it asserts only evidence/byte mismatch, withholds the fact, and reopens a "
           "subject-matter-authority Unknown"),
)
def test_misextraction_notice_is_approver_owned_and_withholds_only(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors, ctx = anchored
    key = "architecture/scheduler/lookahead-owner"
    planted = world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the lookahead owner is the scheduling steward",
    )
    approver = APPROVERS[0]
    # Validator ruling C13: misextraction is a FactEvent disposition whose
    # parents name the misread event.
    world.plant_event(
        approver, store_kind="company", logical_key=key,
        statement="the extracted bytes do not match the cited evidence",
        atom_kind="claim", disposition="misextraction",
        parents=(planted["event_id"],),
    )
    world.verify_planted()
    _ingest(guildhall, world.repo.path, "kindex", world.repo.path / ".kin")
    status = _status(guildhall, world.repo.path)

    notices = status.get("misextraction_notices")
    notice = {}
    if isinstance(notices, list):
        for entry in notices:
            if isinstance(entry, dict) and entry.get("logical_key") == key:
                notice = entry
                break
    unknowns = status.get("unknowns")
    reopened = {}
    if isinstance(unknowns, list):
        for entry in unknowns:
            if isinstance(entry, dict) and entry.get("logical_key") == key:
                reopened = entry
                break
    O.check(
        "V-1.misextraction",
        {
            "notice_admitted": notice.get("admitted"),
            "asserted_claim": notice.get("asserted_claim"),
            "fact_withheld": _fact_state(status, key) in ("withheld", "withdrawn"),
            "semantic_withdrawal": notice.get("semantic_withdrawal"),
            "reopened_unknown": {"owner_identity": reopened.get("owner_identity")},
        },
        label="approver-signed misextraction notice",
    )


@spec_ref(
    VERIFY("V-1", "never-true-authority",
           "A distinct steward/maintainer `never_true` event performs semantic withdrawal; "
           "mutation that lets the approver mint it must fail."),
)
def test_never_true_requires_subject_matter_authority(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors, ctx = anchored
    key = "architecture/scheduler/retry-window"
    claim = world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the retry window is five minutes",
    )
    approver = APPROVERS[1]
    # Validator ruling C13: never_true is a FactEvent disposition naming the
    # withdrawn event. The approver's attempt is expected to be refused.
    world.plant_event(
        approver, store_kind="company", logical_key=key,
        statement="the retry window claim was never true",
        atom_kind="claim", disposition="never_true",
        parents=(claim["event_id"],), supersedes=(claim["event_id"],),
        may_refuse=True,
    )
    world.plant_event(
        world.steward, store_kind="company", logical_key=key,
        statement="the retry window claim was never true",
        atom_kind="claim", disposition="never_true",
        parents=(claim["event_id"],), supersedes=(claim["event_id"],),
    )
    world.verify_planted()
    _ingest(guildhall, world.repo.path, "kindex", world.repo.path / ".kin")
    status = _status(guildhall, world.repo.path)

    admissions = status.get("never_true_admissions")
    by_authority = {}
    if isinstance(admissions, list):
        for entry in admissions:
            if isinstance(entry, dict) and "authority_id" in entry:
                by_authority[entry["authority_id"]] = entry
    approver_record = field(by_authority, "approver-local-2")
    steward_record = field(by_authority, world.steward.authority_id)
    O.check(
        "V-1.never-true-authority",
        {
            "approver_minted_accepted": field(approver_record, "accepted"),
            "refusal_code": field(approver_record, "refusal_code"),
            "steward_minted_accepted": field(steward_record, "accepted"),
        },
        label="only subject-matter authority may mint never_true",
    )


@spec_ref(
    VERIFY("V-1", "origin-trust",
           "Change, delete, reject/revert, and re-run representative sources: history remains, "
           "current disposition changes explicitly."),
)
def test_origin_trust_class_is_derived_and_bounds_trusted_direction(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors, ctx = anchored
    repo = world.repo
    repo.write("docs/adr/0021-merged.md", "# 21. merged decision\n\nStatus: Accepted\n")
    repo.commit("record a merged decision")
    merged_head = repo.head()
    repo.branch("proposal/0022")
    repo.checkout("proposal/0022")
    repo.write("docs/adr/0022-branch.md", "# 22. branch decision\n\nStatus: Accepted\n")
    repo.commit("record a branch decision")
    repo.checkout(repo.default_branch)

    _ingest(guildhall, repo.path, "docs_adr", repo.path / "docs" / "adr")
    _ingest(guildhall, repo.path, "git_history", repo.path)
    status = _status(guildhall, repo.path)

    listed = rows(status, "observations")
    promoted = any(
        isinstance(field(fact, "logical_key"), str)
        and field(fact, "logical_key").endswith("0022-branch")
        and field(fact, "state") == "current"
        for fact in _facts(status)
    )
    O.check(
        "V-1.origin-trust",
        {
            "observed_classes": sorted(
                {o.get("origin_trust_class") for o in listed
                 if isinstance(o.get("origin_trust_class"), str)}
            ),
            "observations": listed,
            "branch_adr_promoted": promoted,
            "merged_head": merged_head,
        },
        label="origin trust class derived from repository topology",
    )
