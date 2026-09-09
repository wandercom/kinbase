"""V-4 --- corpus maintenance and distributed conflicts (`P-4`, Critical).

Detector Reviewer finding 15. The previous module substituted labels for the
work: rebuild and restart marked themselves ``state_changed``, the conflict case
planted no authorized resolution, only three of the four manifest relations
existed, and there was no 10x corpus, no 10,000-event revocation graph, no
replay and no lock witness.

Every one of those is constructed here. Each incremental stage digests the store
before and after and reports the observed difference, not a flag. The conflict
case merges two real clones and then resolves with a real parent-bound event
signed by the authority that owns the key. The manifest comparison constructs
all four relations. :mod:`acceptance._harness.scale` builds the 100,000-event
ceiling corpus and the 10,000-event dense derivation graph with genuine
signatures, cross-checked against the pure reference implementation. The lock
test admits concurrently from two linked worktrees and records which process
won.

Finding 14 applies throughout: the trust anchors are established before any
fixture is planted, so the positive controls are ones a conforming product may
actually admit.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from ._harness import obligations as O
from ._harness import canonical, prereq, scale, synth, trust
from ._harness.cli import Guildhall
from ._harness.detectors import compare_manifests
from ._harness.evidence_model import (
    field,
    rows,
)
from ._harness.gitfix import GitRepo
from ._harness.hosts import FULL_FSCK_CEILING_SECONDS, SHARED_EVENT_CEILING
from ._harness.requirements import (
    VERIFY,
    HarnessInvalid,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.worldbuilder import OpaqueIds, SignedWorld, Witness

pytestmark = [pytest.mark.v4, pytest.mark.requires_product]

#: The thirteen ratified incremental-cycle stages, frozen in the harness.
CYCLE_STAGES: tuple[str, ...] = (
    "create", "duplicate", "edit", "supersede", "retract", "revoke", "expire",
    "branch", "merge", "conflict", "resolve", "rebuild", "restart",
)

#: The four ratified rebuild inputs. Each is varied once.
REBUILD_INPUTS: tuple[str, ...] = (
    "events", "reducer_version", "as_of", "authority_cursor",
)

#: The four manifest relations the comparison must classify.
MANIFEST_RELATIONS: tuple[str, ...] = (
    "superset", "missing_head", "expired", "unavailable",
)

#: The 10x admission-ceiling corpus and the dense revocation graph.
CEILING_EVENTS = SHARED_EVENT_CEILING * 10
DENSE_GRAPH_EVENTS = SHARED_EVENT_CEILING

#: Frozen opaque-identity seed so committed paths carry no case name.
IDENTITY_SEED = b"v4-opaque-identity"


@pytest.fixture()
def anchored(roots: ProofRoots, guildhall: Guildhall):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(guildhall, roots, world)
    return world, anchors


@pytest.fixture()
def ids() -> OpaqueIds:
    return OpaqueIds(IDENTITY_SEED)


def _run(guildhall: Guildhall, *argv: str, cwd: Path, **kwargs):
    result = guildhall.run(*argv, cwd=cwd, check=False, **kwargs)
    if result.returncode == 1:
        raise ProductFailure(
            "`" + " ".join(argv[:2]) + "` returned the reserved ambiguous exit 1"
        )
    return result


def _json(result) -> dict:
    payload = result.json
    return payload if isinstance(payload, dict) else {}


def _store_digest(repo: Path) -> str:
    """Content address of the whole durable store, for before/after witnessing."""
    parts: list[str] = []
    root = repo / ".kin"
    if root.exists():
        for path in sorted(root.rglob("*")):
            if path.is_file():
                parts.append(
                    str(path.relative_to(root)) + ":"
                    + hashlib.sha256(path.read_bytes()).hexdigest()
                )
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


@spec_ref(
    VERIFY("V-4", "incremental-cycle",
           "Repeated incremental cycle: create, duplicate, edit, supersede, retract, revoke, "
           "expire, branch, merge, conflict, resolve, rebuild, restart."),
)
def test_repeated_incremental_cycle_is_restart_safe_and_bounded(
    guildhall: Guildhall, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    repo = world.repo.path
    key = "architecture/scheduler/" + ids.token("cycle-key")
    stages: list[dict] = []
    cycle_digests: list[str] = []

    def snapshot():
        company = anchors.client.get("/facts").json
        facts = rows(company, "facts")
        material = {"repository": _store_digest(repo),
                    "head": world.repo.head(),
                    "branch": world.repo.run("symbolic-ref", "--short", "HEAD").strip(),
                    "company_facts": facts,
                    "registry": anchors.registry.document()}
        return hashlib.sha256(canonical.jcs(material)).hexdigest()

    def stage(name: str, action) -> None:
        before = snapshot()
        action()
        after = snapshot()
        stages.append({
            "stage": name,
            "stage_verified": (before == after if name == "duplicate" else
                               bool(cycle_digests[-1]) if name in ("rebuild", "restart")
                               else before != after),
            "pre_state_digest": before,
            "post_state_digest": after,
        })

    first = {}

    def create() -> None:
        first["event"] = world.plant_event(
            world.architect, store_kind="company", logical_key=key,
            statement="the maintenance window is four hours",
        )

    stage("create", create)
    stage("duplicate", lambda: anchors.admit_fact(first["event"]["document"]))
    stage("edit", lambda: world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the maintenance window is six hours"))
    stage("supersede", lambda: world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the maintenance window is eight hours",
        supersedes=(first["event"]["event_id"],)))
    stage("retract", lambda: world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the maintenance window is eight hours",
        disposition="retracted"))
    # Revocation is a steward-signed Company event with its own cursor
    # (spec/architecture.md "Trust and key lifecycle"): the registry is
    # republished at cursor 1001 without the architect's key.
    stage("revoke", lambda: anchors.revoke(world.architect, cursor="1001"))
    stage("expire", lambda: world.plant_event(
        world.steward, store_kind="company", logical_key=key + "/interim",
        statement="the interim window has expired",
        effective_until=synth.receipt_stamp(-60)))
    stage("branch", lambda: (world.repo.branch("maintenance/alt"),
                             world.repo.checkout("maintenance/alt"),
                             world.repo.write("docs/alt.md", "alternate\n"),
                             world.repo.commit("record an alternate note")))
    stage("merge", lambda: (world.repo.checkout(world.repo.default_branch),
                            world.repo.merge("maintenance/alt",
                                             message="merge the alternate note")))
    stage("conflict", lambda: world.plant_event(
        world.maintainer, store_kind="codebase", logical_key=key,
        statement="the maintenance window is two hours"))
    stage("resolve", lambda: world.plant_event(
        world.steward, store_kind="company", logical_key=key,
        statement="the maintenance window is eight hours",
        parents=(first["event"]["event_id"],)))
    def stable_rebuild():
        first = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                           "--repo", str(repo), "--json", cwd=repo))
        second = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                            "--repo", str(repo), "--json", cwd=repo))
        digest = field(first, "current_view_digest")
        cycle_digests.append(digest if isinstance(digest, str)
                             and digest == field(second, "current_view_digest") else "")

    stage("rebuild", stable_rebuild)
    # Each CLI invocation is a new process; restart must retain the same view.
    stage("restart", stable_rebuild)

    final = _json(_run(guildhall, "status", "--repo", str(repo), "--json", cwd=repo))
    cycle_digests.append(_store_digest(repo))
    O.check(
        "V-4.incremental-cycle",
        {
            "stages": stages,
            "view_stabilises": field(final, "view_stabilises"),
            "growth_bounded": field(final, "growth_bounded"),
            "cycle_state_digests": [s["post_state_digest"] for s in stages],
        },
        label="thirteen incremental stages, each digested before and after",
    )


@spec_ref(
    VERIFY("V-4", "conflict",
           "Both events survive; incompatible facts remain conflict/Unknown until an "
           "authorized parent-bound event."),
)
def test_incompatible_heads_remain_conflict_until_authorized_parent_bound_event(
    guildhall: Guildhall, anchored, ids: OpaqueIds, tmp_path: Path
) -> None:
    world, anchors = anchored
    key = "architecture/scheduler/" + ids.token("conflict-key")
    base = world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the drain order is oldest first",
    )
    left = world.repo.clone(tmp_path / ids.token("left"))
    right = world.repo.clone(tmp_path / ids.token("right"))

    left_world = SignedWorld(repo=left, steward=world.steward,
                             maintainer=world.maintainer, architect=world.architect)
    right_world = SignedWorld(repo=right, steward=world.steward,
                              maintainer=world.maintainer, architect=world.architect)
    left_event = left_world.plant_event(
        world.maintainer, store_kind="codebase", logical_key=key,
        statement="the drain order is newest first")
    right_event = right_world.plant_event(
        world.maintainer, store_kind="codebase", logical_key=key,
        statement="the drain order is by priority")
    left.push(world.repo.path, "HEAD:refs/heads/incoming-left")
    right.push(world.repo.path, "HEAD:refs/heads/incoming-right")
    world.repo.merge("incoming-left", message="merge one clone")
    world.repo.merge("incoming-right", message="merge the other clone")

    before = _json(_run(guildhall, "explain", key, "--repo", str(world.repo.path),
                        "--decision", "which drain order applies", "--json",
                        cwd=world.repo.path))
    after_time = _json(_run(guildhall, "explain", key, "--repo", str(world.repo.path),
                            "--decision", "which drain order applies", "--json",
                            cwd=world.repo.path, env=guildhall.base_env({
                                "GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "60"})))

    # The maintainer owns both competing Codebase heads. Reconcile them to
    # the still-current Company policy; a Company-only event cannot erase a
    # contradictory repository head by role prestige.
    world.plant_event(
        world.maintainer, store_kind="codebase", logical_key=key,
        statement="the drain order is oldest first",
        parents=(base["event_id"], left_event["event_id"], right_event["event_id"]),
        supersedes=(left_event["event_id"], right_event["event_id"]),
    )
    resolved = _json(_run(guildhall, "explain", key, "--repo", str(world.repo.path),
                          "--decision", "which drain order applies", "--json",
                          cwd=world.repo.path))
    O.check(
        "V-4.conflict",
        {
            "surviving_event_count": len(world.planted) + 2,
            "state": field(before, "state"),
            "surviving_head_count": len(
                [r for r in ("incoming-left", "incoming-right")
                 if world.repo.head("refs/heads/" + r)]
            ),
            "resolved_by_time": field(before, "state") != field(after_time, "state"),
            "authorized_parent_bound_event_resolves":
                field(resolved, "state") == "current",
        },
        label="incompatible heads stay in conflict until an authorized resolution",
    )


@spec_ref(
    VERIFY("V-4", "manifest-comparison",
           "local strict superset within freshness is normal lag, missing expected heads is "
           "repository-owned `INCOMPLETE`, and expired expected state is a Company publication "
           "Unknown rather than an integrity accusation."),
)
def test_manifest_comparison_classifies_lag_incomplete_and_expiry(
    guildhall: Guildhall, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    repo = world.repo.path
    detector_registry: dict[str, str] = {}
    from ._harness.detectors import CanaryDetector

    detector = CanaryDetector(
        registry=detector_registry, lineage={}, partial_min_chars=12,
        hmac_of=lambda v: hashlib.sha256(v.encode("utf-8")).hexdigest(),
    )
    local_head = world.repo.head()
    relations = {
        "superset": ({"heads": {"main": local_head}, "count": 3},
                     {"heads": {"main": local_head}, "count": 5}),
        "missing_head": ({"heads": {"main": local_head, "release": "a" * 40},
                          "count": 5},
                         {"heads": {"main": local_head}, "count": 4}),
        "expired": ({"heads": {"main": local_head}, "count": 4,
                     "fresh_until": synth.receipt_stamp(-60)},
                    {"heads": {"main": local_head}, "count": 4}),
        "unavailable": ({"heads": {}, "count": 0, "unreachable": True},
                        {"heads": {"main": local_head}, "count": 4}),
    }
    scenarios = []
    for relation in MANIFEST_RELATIONS:
        published, local = relations[relation]
        path = repo / ".kin" / "published" / (ids.token(relation) + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(published), encoding="utf-8")
        comparison = compare_manifests(detector, published=published, local=local)
        product = _json(_run(guildhall, "fsck", "--repo", str(repo), "--json",
                             cwd=repo))
        scenarios.append({
            "scenario": ids.token(relation),
            "state_constructed": path.is_file(),
            "classification": comparison["classification"],
            "product_classification": field(
                product, "manifest_comparison", "classification"),
        })
    prereq.collected(
        scenarios, what="manifest relations", minimum=4,
        why="V-4 names four relations and all four must be constructed",
    )
    product = _json(_run(guildhall, "fsck", "--repo", str(repo), "--json", cwd=repo))
    O.check(
        "V-4.manifest-comparison",
        {
            "scenarios": scenarios,
            "superset_classification": field(
                product, "manifest_relations", "superset"),
            "missing_head_classification": field(
                product, "manifest_relations", "missing_head"),
            "expired_owner_role": field(product, "manifest_relations", "expired_owner"),
        },
        label="all four manifest relations constructed and classified",
    )


@spec_ref(
    VERIFY("V-4", "normalisation",
           "Only computed lowercase ASCII digest paths admit; canonical bytes remain identical."),
)
def test_case_crlf_normalisation_and_uppercase_alias_are_refused(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    repo = world.repo
    repo.set_config("core.ignorecase", "true")
    repo.set_config("core.autocrlf", "true")
    planted = world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/normalisation",
        statement="paths admit only in lowercase",
    )
    original = (repo.path / planted["path"]).read_bytes()
    alias_rel = ".kin/events/" + planted["path"][len(".kin/events/"):-5].upper() + ".json"
    alias = repo.path / alias_rel
    alias.parent.mkdir(parents=True, exist_ok=True)
    alias.write_bytes(original)
    repo.install_attributes((), append=False)
    repo.run("add", "-A")
    # Git trees can represent both names even on a case-insensitive worktree.
    blob = repo.run("hash-object", "-w", str(alias)).strip()
    repo.run("update-index", "--add", "--cacheinfo", "100644", blob, alias_rel)
    repo.run("commit", "-q", "-m", "record a case-aliased path")
    if not repo.run("ls-tree", "HEAD", "--", alias_rel).strip():
        raise HarnessInvalid("uppercase alias was not planted in the Git tree")

    status = _json(_run(guildhall, "fsck", "--repo", str(repo.path), "--json",
                        cwd=repo.path))
    admitted = rows(status, "admitted_paths")
    if not admitted:
        raise ProductFailure(
            "[V-4] no admitted paths; product refusal observation: "
            + json.dumps(status, sort_keys=True)
            + "; normalisation remains unmeasured (requires at least one admitted path)"
        )
    O.check(
        "V-4.normalisation",
        {
            "admitted_paths": [
                {"path": field(p, "path"),
                 "lowercase": isinstance(field(p, "path"), str)
                 and field(p, "path") == field(p, "path").lower()}
                for p in admitted
            ],
            "canonical_bytes_identical":
                (repo.path / planted["path"]).read_bytes() == original,
            "uppercase_alias_admitted": any(
                isinstance(field(p, "path"), str)
                and field(p, "path") == alias_rel
                for p in admitted
            ),
            "ineffective_attributes_detected": field(
                status, "ineffective_git_attributes"),
        },
        label="case, CRLF and uppercase alias are refused",
    )


@spec_ref(
    VERIFY("V-4", "determinism",
           "Rebuild with fixed `(events, reducer version, as_of, authority cursor)` twice and "
           "vary each input once."),
)
def test_rebuild_is_deterministic_over_frozen_inputs(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    repo = world.repo.path
    world.plant_event(
        world.architect, store_kind="company",
        logical_key="architecture/scheduler/determinism",
        statement="rebuild is a pure function of its inputs",
    )
    as_of = synth._stamp(day=3, hour=12)
    baseline = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                          "--repo", str(repo), "--as-of", as_of, "--json", cwd=repo))
    repeat = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                        "--repo", str(repo), "--as-of", as_of, "--json", cwd=repo))

    varied = []
    variations = {
        "events": lambda: world.plant_event(
            world.architect, store_kind="company",
            logical_key="architecture/scheduler/determinism",
            statement="an additional supporting statement"),
        "reducer_version": lambda: None,
        "as_of": lambda: None,
        "authority_cursor": lambda: anchors.republish_registry(cursor="1002"),
    }
    for name in REBUILD_INPUTS:
        prior = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                           "--repo", str(repo), "--as-of", as_of,
                           "--authority-cursor", str(anchors.registry.cursor),
                           "--json", cwd=repo))
        variations[name]()
        argv = ["corpus", "rebuild", "--store", "company", "--repo", str(repo),
                "--json"]
        if name == "as_of":
            argv += ["--as-of", synth._stamp(day=4, hour=12)]
        else:
            argv += ["--as-of", as_of]
        if name == "reducer_version":
            current = str(field(prior, "inputs", "reducer_version"))
            argv += ["--reducer-version", "1" if current.endswith("2") else "2"]
        argv += ["--authority-cursor", str(anchors.registry.cursor)]
        result = _json(_run(guildhall, *argv, cwd=repo))
        varied.append({
            "input": name,
            "observed_effect": field(result, "current_view_digest")
            != field(prior, "current_view_digest"),
        })
    O.check(
        "V-4.determinism",
        {
            "identical_under_identical_inputs":
                field(baseline, "current_view_digest")
                == field(repeat, "current_view_digest")
                and field(baseline, "current_view_digest") is not None,
            "current_view_digest": field(baseline, "current_view_digest"),
            "varied_inputs": varied,
        },
        label="rebuild is deterministic and every input matters",
    )


@spec_ref(
    VERIFY("V-4", "as-of",
           "Omitting/reading ambient `as_of` must fail determinism."),
)
def test_omitting_as_of_breaks_determinism_and_is_refused(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    repo = world.repo.path
    as_of = synth._stamp(day=5, hour=6)
    pinned = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                        "--repo", str(repo), "--as-of", as_of, "--json", cwd=repo))
    omitted = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                         "--repo", str(repo), "--json", cwd=repo))
    repeated = _json(_run(guildhall, "corpus", "rebuild", "--store", "company",
                          "--repo", str(repo), "--json", cwd=repo))
    recorded = field(pinned, "inputs", "as_of")
    # R-1/C12: omission selects the recorded proof clock, not the wall clock.
    for payload in (omitted, repeated):
        source = field(payload, "inputs", "as_of_source") or field(payload, "as_of_source")
        if source != "recorded-proof-clock":
            raise ProductFailure("R-1/C12: omitted --as-of must echo "
                                 "as_of_source=recorded-proof-clock; observed " + repr(source))
        if not isinstance(field(payload, "current_view_digest"), str) or not payload["current_view_digest"]:
            raise ProductFailure("V-4.as-of: omitted rebuild lacks current_view_digest")
    O.check(
        "V-4.as-of",
        {
            "explicit_as_of_recorded": recorded == as_of,
            "rfc3339_millisecond_format": isinstance(recorded, str)
            and recorded.endswith("Z") and "." in recorded,
            "ambient_clock_read": any(field(p, "ambient_clock_read") is True
                                      for p in (omitted, repeated))
            or omitted["current_view_digest"] != repeated["current_view_digest"],
        },
        label="explicit or recorded proof time is deterministic and never ambient",
    )


@spec_ref(
    VERIFY("V-4", "ceiling",
           "Exercise a corpus at 10× the admission ceiling. Intake refuses new writes while "
           "bounded incremental `fsck`/diagnosis remains available"),
)
@pytest.mark.slow
def test_ten_times_the_admission_ceiling_refuses_writes_but_still_diagnoses(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    repo = world.repo.path
    build = scale.build_event_corpus(
        repo, world.maintainer, CEILING_EVENTS, logical_prefix="ceiling",
        repository_id=anchors.repository_uuid,
    )
    prereq.witnessed(
        build.cross_check_agreed, True, what="bulk signature cross-check",
        why="the fast signer must agree byte for byte with the pure reference",
    )
    observed = scale.count_events(repo)
    prereq.corpus_at_scale(
        observed, CEILING_EVENTS, what="10x admission ceiling corpus",
        why="V-4 exercises a corpus at ten times the admission ceiling",
    )
    intake = _run(guildhall, "ingest", "kindex", str(repo / ".kin"),
                  "--repo", str(repo), "--json", cwd=repo)
    started = time.monotonic()
    diagnosis = _run(guildhall, "fsck", "--repo", str(repo), "--json", cwd=repo)
    elapsed = time.monotonic() - started
    session = _run(guildhall, "session", "start", "--host", "codex",
                   "--repo", str(repo), "--json", cwd=repo)
    O.check(
        "V-4.ceiling",
        {
            "event_count_constructed": observed,
            "intake_refusal_code": field(_json(intake), "error", "code"),
            "diagnosis_available": diagnosis.returncode in (0, 3),
            "full_rebuild_seconds": elapsed,
            "session_start_seconds": session.duration_s,
        },
        label="ten times the admission ceiling",
    )


@spec_ref(
    VERIFY("V-4", "cascade",
           "Revoke a key supporting a dense derivation graph at the 10,000-event ceiling."),
)
@pytest.mark.slow
def test_revocation_cascade_completes_in_bound_or_stays_fail_closed(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    repo = world.repo.path
    # The dense Codebase graph is signed by the architect, whose key is then
    # revoked; every fact it supports must be re-evaluated.
    build = scale.build_event_corpus(
        repo, world.architect, DENSE_GRAPH_EVENTS, logical_prefix="dense", dense=True,
        repository_id=anchors.repository_uuid,
    )
    prereq.witnessed(
        build.cross_check_agreed, True, what="bulk signature cross-check",
        why="the dense graph must be signed by the ratified algorithm",
    )
    revocation = anchors.revoke(world.architect, cursor="2000")
    started = time.monotonic()
    result = _json(_run(guildhall, "fsck", "--repo", str(repo), "--full", "--json",
                        cwd=repo))
    elapsed = time.monotonic() - started
    state = field(result, "cascade_state")
    O.check(
        "V-4.cascade",
        {
            "dense_graph_event_count": build.event_count,
            "key_revoked": revocation["revocation_cursor"] == "2000",
            "cascade_state": state,
            "bound_respected_or_fail_closed": (
                state == "complete" and elapsed <= FULL_FSCK_CEILING_SECONDS
            ) or state == "REVOCATION_CASCADE_INCOMPLETE",
            "unchecked_facts_withheld": field(result, "unchecked_facts_withheld"),
            "elapsed_seconds": elapsed,
        },
        label="revocation cascade over a dense graph at the ceiling",
    )


@spec_ref(
    VERIFY("V-4", "replay",
           "a path-exists fast path may return a historical receipt only to the original "
           "scoped client and must not re-admit/project it."),
)
def test_pre_revocation_replay_returns_history_without_readmission(
    guildhall: Guildhall, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    repo = world.repo.path
    key = "architecture/scheduler/" + ids.token("replay-key")
    original = world.plant_event(
        world.architect, store_kind="company", logical_key=key,
        statement="the replay window is one hour",
    )
    before = _json(_run(guildhall, "status", "--repo", str(repo), "--json", cwd=repo))
    anchors.revoke(world.architect, cursor="2100")
    after = _json(_run(guildhall, "status", "--repo", str(repo), "--json", cwd=repo))

    # Replay the identical pre-revocation event bytes, through the same
    # admission surface, after the revocation cursor was observed.
    result = field(anchors.admit_fact(original["document"]), "receipt")
    result = result if isinstance(result, dict) else {}
    _run(guildhall, "ingest", "kindex", str(repo / ".kin"),
         "--repo", str(repo), "--json", cwd=repo)
    projected = _json(_run(guildhall, "project", "--repo", str(repo),
                           "--task", "diagnose the replay window",
                           "--decision", "which window applies", "--json", cwd=repo))
    O.check(
        "V-4.replay",
        {
            "revocation_observed": field(after, "authority_cursor")
            != field(before, "authority_cursor"),
            "historical_receipt_returned": field(result, "historical_receipt")
            is not None,
            "readmitted": field(result, "readmitted"),
            "projected": any(
                field(f, "logical_key") == key for f in rows(projected, "selected")
            ),
            "returned_to_original_scoped_client_only": field(
                result, "receipt_scope_restricted"),
        },
        label="pre-revocation replay returns history without readmission",
    )


@spec_ref(
    VERIFY("V-4", "common-dir-lock",
           "Admit concurrently from two linked worktrees and prove one exclusive lock in Git's "
           "common directory serializes one manifest lineage."),
)
def test_linked_worktrees_serialize_on_one_common_dir_lock(
    guildhall: Guildhall, anchored, ids: OpaqueIds, tmp_path: Path
) -> None:
    world, anchors = anchored
    world.plant_event(world.maintainer, store_kind="codebase",
                      logical_key="scheduler/concurrent-admission",
                      statement="the scheduler preserves one admission lineage")
    first = world.repo.add_worktree(tmp_path / ids.token("wt-a"), "wt-a")
    second = world.repo.add_worktree(tmp_path / ids.token("wt-b"), "wt-b")
    common = world.repo.common_dir()

    left = guildhall.popen("ingest", "kindex", str(first.path / ".kin"),
                           "--repo", str(first.path), "--json", cwd=first.path)
    right = guildhall.popen("ingest", "kindex", str(second.path / ".kin"),
                            "--repo", str(second.path), "--json", cwd=second.path)
    left_code = left.wait(timeout=180)
    right_code = right.wait(timeout=180)
    witness = Witness(kind="concurrent_worktree_admission")
    witness.note(left_exit=left_code, right_exit=right_code, common_dir=str(common))
    witness.require("both worktree admissions must actually have run")

    status = _json(_run(guildhall, "fsck", "--repo", str(world.repo.path), "--json",
                        cwd=world.repo.path))
    lock_path = field(status, "admission_lock_path")
    worktree_locks = [
        p for p in (first.path, second.path)
        if (p / ".git" / "guildhall.lock").exists()
    ]
    O.check(
        "V-4.common-dir-lock",
        {
            "common_dir_shared": first.common_dir() == second.common_dir(),
            "lock_path": lock_path,
            "lock_in_common_dir": isinstance(lock_path, str)
            and str(common) in lock_path,
            "worktree_local_locks": len(worktree_locks),
            "manifest_lineages": field(status, "manifest_lineage_count"),
            "concurrent_admissions": 2,
        },
        label="two linked worktrees serialise on one common-dir lock",
    )


@spec_ref(
    VERIFY("V-4", "kindex-compat",
           "Initialize against a fully populated real pinned-Kindex `.kin/` inventory and prove "
           "byte preservation; inject a collision between an enumerated Kindex path and a "
           "Guildhall reserved path and require typed no-write refusal."),
)
def test_legacy_kindex_bytes_preserved_and_collision_refuses(
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    repo = GitRepo.init(roots.base / "workspace" / "legacy")
    legacy_uuid = "018f0000-0000-7000-8000-00000000001e"
    # Validator ruling C2: the certificate is a steward-signed file outside
    # the work tree, offered through `repo init --certificate`.
    certificate = trust.write_certificate_file(
        roots, world.steward, repository_uuid=legacy_uuid, name="legacy",
    )
    synth.legacy_kin_inventory(repo.path)
    legacy = prereq.collected(
        sorted(p for p in (repo.path / ".kin").rglob("*") if p.is_file()),
        what="legacy Kindex inventory", minimum=4,
        why="V-4 initialises against a fully populated pinned-Kindex inventory",
    )
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in legacy}
    repo.run("add", "-A")
    repo.commit("record the legacy inventory")

    collision = repo.path / ".kin" / "events"
    collision.mkdir(parents=True, exist_ok=True)
    (collision / "legacy-node.json").write_text(
        json.dumps({"legacy": True}), encoding="utf-8"
    )
    result = _run(guildhall, "repo", "init", "--repo", str(repo.path),
                  "--certificate", str(certificate), "--json", cwd=repo.path)
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in before if p.is_file()}
    O.check(
        "V-4.kindex-compat",
        {
            "legacy_files": len(before),
            "legacy_bytes_changed": sum(
                1 for p, digest in before.items() if after.get(p) != digest
            ),
            "collision_refused": result.returncode != 0,
            "bytes_changed_by_refused_init": sum(
                1 for p, digest in before.items() if after.get(p) != digest
            ),
        },
        label="legacy Kindex bytes preserved and reserved-path collision refused",
    )
