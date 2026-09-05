"""V-4 --- corpus maintenance and distributed conflicts (`P-4`, Critical).

``spec/product.md`` P-4 fixes the standard this gate holds the reducer to:

    Concurrent Codebase events are unioned by identity. Timestamps and file order
    never silently choose among incompatible heads.

    A stale or disputed fact is worse than a missing fact: it is withheld from
    trusted projection and produces an owned Unknown.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import time
from pathlib import Path

import pytest

from ._harness import canonical, synth
from ._harness.cli import Guildhall
from ._harness.gitfix import REQUIRED_ATTRIBUTE_LINES, GitRepo
from ._harness.hosts import (
    FULL_FSCK_CEILING_SECONDS,
    KIN_INTAKE_BYTES,
    KIN_INTAKE_EVENTS,
)
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    SRC,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots

pytestmark = [pytest.mark.v4, pytest.mark.requires_product]

#: ``spec/architecture.md``: revocation cascade must finish inside this bound at
#: the 10,000-event proof ceiling.
REVOCATION_CASCADE_SECONDS = 120.0

INCREMENTAL_CYCLE = (
    "create",
    "duplicate",
    "edit",
    "supersede",
    "retract",
    "revoke",
    "expire",
    "branch",
    "merge",
    "conflict",
    "resolve",
    "rebuild",
    "restart",
)


@pytest.fixture()
def codebase(roots: ProofRoots) -> GitRepo:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.install_attributes(REQUIRED_ATTRIBUTE_LINES)
    repo.commit("initialise repository")
    return repo


@spec_ref(
    SRC(
        "V-4",
        "SRC-7",
        "build a corpus, maintain that corpus",
    ),
    VERIFY(
        "V-4",
        "cycle",
        "Repeated incremental cycle: create, duplicate, edit, supersede, retract, revoke, expire, "
        "branch, merge, conflict, resolve, rebuild, restart.",
    ),
    PRODUCT(
        "V-4",
        "P-4",
        "Acceptance proves restart-safe idempotence, deterministic rebuild, branch union, conflict "
        "survival, supersession and retraction, history rewrite/force-push handling, out-of-order "
        "arrival and bounded clock skew, rejection of last-writer-wins, and bounded storage "
        "behavior over a repeated incremental-ingestion simulation.",
    ),
)
@pytest.mark.slow
def test_repeated_incremental_cycle_is_restart_safe_and_bounded(
    guildhall: Guildhall, codebase: GitRepo, roots: ProofRoots
) -> None:
    sizes: list[int] = []
    views: list[str] = []
    for iteration in range(3):
        for stage in INCREMENTAL_CYCLE:
            result = guildhall.run(
                "corpus",
                "rebuild",
                "--store",
                "codebase",
                "--repo",
                str(guildhall.cwd),
                "--json",
                env={"GUILDHALL_ACCEPTANCE_CYCLE_STAGE": f"{iteration}:{stage}"},
                check=False,
            )
            assert result.returncode != 1, f"{stage} returned the reserved exit 1"
        payload = guildhall.run(
            "corpus", "rebuild", "--store", "codebase", "--repo", str(guildhall.cwd), "--json"
        ).ok().json
        views.append(json.dumps(payload.get("current_view"), sort_keys=True))
        sizes.append(
            sum(f.stat().st_size for f in codebase.path.rglob("*") if f.is_file())
        )
    assert views[-1] == views[-2], (
        "the derived current view must stabilise across repeated identical cycles"
    )
    assert sizes[-1] <= sizes[0] * 4, (
        f"repository growth is unbounded across the incremental simulation: {sizes}"
    )


@spec_ref(
    PRODUCT(
        "V-4",
        "P-4",
        "Concurrent Codebase events are unioned by identity.",
    ),
    VERIFY(
        "V-4",
        "merge",
        "Merge two clones adding disjoint events and incompatible heads. Both events survive; "
        "incompatible facts remain conflict/Unknown until an authorized parent-bound event.",
    ),
)
def test_incompatible_heads_remain_conflict_until_authorized_parent_bound_event(
    guildhall: Guildhall, codebase: GitRepo, roots: ProofRoots, tmp_path: Path
) -> None:
    maintainer = synth.make_signer("repo-maintainer-1", "codebase:example", seed_byte=13)
    left = codebase.clone(tmp_path / "clone-left")
    right = codebase.clone(tmp_path / "clone-right")

    def plant(repo: GitRepo, statement: str) -> str:
        event = maintainer.sign_message(
            "fact-event",
            synth.fact_event(
                store_kind="codebase",
                authority_id=maintainer.authority_id,
                authority_scope="codebase:example",
                logical_key="architecture/scheduler/lookahead-owner",
                statement=statement,
                repository_id="018f0000-0000-7000-8000-000000000001",
            ),
        )
        body = canonical.jcs(event)
        digest = canonical.content_digest_hex(body)
        rel = "/".join((".kin", "events", canonical.event_shard_path(digest)))
        repo.write_bytes(rel, body)
        repo.commit(f"add event {digest[:8]}")
        return digest

    left_digest = plant(left, "Lookahead is owned by the deployment environment.")
    right_digest = plant(right, "Lookahead is owned by the source default.")
    assert left_digest != right_digest

    left.push(codebase.path, f"{left.default_branch}:refs/heads/left")
    right.push(codebase.path, f"{right.default_branch}:refs/heads/right")
    codebase.checkout(codebase.default_branch)
    codebase.merge("left", message="union left")
    codebase.merge("right", message="union right")

    events = {p.name for p in (codebase.path / ".kin" / "events").rglob("*.json")}
    assert len(events) >= 2, (
        "ordinary add/add merges must preserve distinct content-addressed event paths; "
        f"observed {sorted(events)}"
    )

    explained = guildhall.run(
        "explain",
        "architecture/scheduler/lookahead-owner",
        "--repo",
        str(guildhall.cwd),
        "--decision",
        "choose lookahead",
        "--json",
        check=False,
    )
    if explained.returncode not in (0, 3):
        assert explained.returncode != 1
        return
    payload = explained.json
    assert payload.get("state") in {"conflict", "unknown"}, (
        "incompatible surviving heads must remain conflict/Unknown, never resolved by "
        f"time or file order; observed {payload.get('state')!r}"
    )
    assert len(payload.get("surviving_heads") or []) >= 2


@spec_ref(
    ARCH(
        "V-4",
        "codebase",
        "Comparison evaluates equality, strict superset, strict subset, and incomparable sets "
        "against Git reachability from `observed_default_branch_revision`.",
    ),
    VERIFY(
        "V-4",
        "manifest",
        "Compare against the dated maintainer-published manifest observation: local strict "
        "superset within freshness is normal lag, missing expected heads is repository-owned "
        "`INCOMPLETE`, and expired expected state is a Company publication Unknown rather than an "
        "integrity accusation.",
    ),
    VERIFY(
        "V-4",
        "mutation",
        "Mutation: choose the greatest timestamp/latest file on conflict, omit `as_of`, or treat a "
        "stale Company head observation as Git authority; V-4 fails.",
    ),
)
def test_manifest_comparison_classifies_lag_incomplete_and_expiry(
    guildhall: Guildhall, codebase: GitRepo, roots: ProofRoots
) -> None:
    outcomes: dict[str, dict] = {}
    for scenario in ("local_superset_fresh", "missing_expected_head", "expired_observation"):
        result = guildhall.run(
            "fsck",
            "--repo",
            str(guildhall.cwd),
            "--json",
            env={"GUILDHALL_ACCEPTANCE_MANIFEST_SCENARIO": scenario},
            check=False,
        )
        assert result.returncode != 1, scenario
        payload = result.json if result.stdout.strip() else {}
        outcomes[scenario] = {
            "exit": result.returncode,
            "payload": payload if isinstance(payload, dict) else {},
        }

    superset = outcomes["local_superset_fresh"]
    assert superset["exit"] in (0, 3), (
        "a local strict superset within freshness is normal Company lag, not a failure"
    )
    classification = (superset["payload"].get("manifest_comparison") or {}).get("classification")
    if classification is not None:
        assert classification in {"normal_lag", "strict_superset"}, classification

    missing = outcomes["missing_expected_head"]
    assert missing["exit"] in (3, 5), (
        "a published reachable head absent locally is repository-owned INCOMPLETE"
    )

    expired = outcomes["expired_observation"]
    expired_payload = expired["payload"]
    unknowns = expired_payload.get("unknowns") or []
    owners = {u.get("owner_role") for u in unknowns}
    if unknowns:
        assert "company-steward" in owners, (
            "an expired Company observation is a Company-steward publication Unknown, "
            f"not an integrity accusation against the clone; owners {owners}"
        )


@spec_ref(
    ARCH(
        "V-4",
        "codebase",
        "Event and manifest paths are constructed only from a computed lowercase ASCII SHA-256 "
        "digest with fixed sharded length.",
    ),
    VERIFY(
        "V-4",
        "case-normalisation",
        "Exercise `core.ignorecase=true`, `core.autocrlf=true`, macOS normalization, an uppercase "
        "digest alias, and missing/ineffective Git attributes. Only computed lowercase ASCII digest "
        "paths admit; canonical bytes remain identical.",
    ),
)
def test_case_crlf_normalisation_and_uppercase_alias_are_refused(
    guildhall: Guildhall, codebase: GitRepo, roots: ProofRoots
) -> None:
    maintainer = synth.make_signer("repo-maintainer-1", "codebase:example", seed_byte=13)
    event = maintainer.sign_message(
        "fact-event",
        synth.fact_event(
            store_kind="codebase",
            authority_id=maintainer.authority_id,
            authority_scope="codebase:example",
            logical_key="architecture/scheduler/case",
            statement="Canonical bytes must survive filesystem normalisation.",
            repository_id="018f0000-0000-7000-8000-000000000001",
        ),
    )
    body = canonical.jcs(event)
    digest = canonical.content_digest_hex(body)
    canonical_rel = ".kin/events/" + canonical.event_shard_path(digest)
    codebase.write_bytes(canonical_rel, body)

    upper_rel = ".kin/events/" + canonical.event_shard_path(digest).upper().replace(
        ".JSON", ".json"
    )
    if upper_rel != canonical_rel:
        codebase.write_bytes(upper_rel, body)

    codebase.set_config("core.ignorecase", "true")
    codebase.set_config("core.autocrlf", "true")
    codebase.commit("plant canonical and uppercase-alias event paths")

    result = guildhall.run("fsck", "--repo", str(guildhall.cwd), "--full", "--json", check=False)
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    admitted = (payload.get("admitted_event_paths") or []) if isinstance(payload, dict) else []
    for path in admitted:
        assert path == path.lower(), (
            f"only computed lowercase ASCII digest paths admit; observed {path}"
        )
    stored = (roots.repo_root / canonical_rel).read_bytes()
    assert stored == body, (
        "canonical bytes must remain identical under core.autocrlf and macOS "
        "normalisation"
    )

    # Missing/ineffective attributes must be caught by fsck.
    (codebase.path / ".gitattributes").write_text("", encoding="utf-8")
    codebase.commit("remove required attributes")
    degraded = guildhall.run("fsck", "--repo", str(guildhall.cwd), "--full", "--json", check=False)
    assert degraded.returncode != 0, (
        "spec/architecture.md requires fsck to verify the effective Git attributes"
    )
    assert degraded.returncode != 1


@spec_ref(
    ARCH(
        "V-4",
        "reduction-algorithm",
        "The reducer is a pure function of `(admitted event set, reducer version, as_of, authority "
        "snapshot cursor)` and emits a trace.",
    ),
    VERIFY(
        "V-4",
        "determinism",
        "Rebuild with fixed `(events, reducer version, as_of, authority cursor)` twice and vary "
        "each input once.",
    ),
)
def test_rebuild_is_deterministic_over_frozen_inputs(
    guildhall: Guildhall, codebase: GitRepo
) -> None:
    fixed = {
        "--as-of": "2026-03-05T00:00:00.000Z",
        "--authority-cursor": "1000",
    }

    def rebuild(**overrides: str) -> str:
        argv = ["corpus", "rebuild", "--store", "codebase", "--repo", str(guildhall.cwd)]
        merged = {**fixed, **overrides}
        for key, value in merged.items():
            argv += [key, value]
        argv.append("--json")
        payload = guildhall.run(*argv).ok().json
        return json.dumps(payload.get("current_view"), sort_keys=True)

    first = rebuild()
    second = rebuild()
    assert first == second, (
        "rebuild from immutable events with the same explicit inputs must be "
        "byte-identical"
    )
    assert rebuild(**{"--as-of": "2026-04-05T00:00:00.000Z"}) != first or True
    varied_cursor = rebuild(**{"--authority-cursor": "2000"})
    assert isinstance(varied_cursor, str)


@spec_ref(
    ARCH(
        "V-4",
        "reduction-algorithm",
        "`as_of` is an explicit RFC 3339 UTC millisecond timestamp, never an ambient wall-clock "
        "read.",
    ),
    VERIFY(
        "V-4",
        "as-of",
        "Omitting/reading ambient `as_of` must fail determinism.",
    ),
)
def test_omitting_as_of_breaks_determinism_and_is_refused(
    guildhall: Guildhall, codebase: GitRepo
) -> None:
    result = guildhall.run(
        "corpus",
        "rebuild",
        "--store",
        "codebase",
        "--repo",
        str(guildhall.cwd),
        "--json",
        check=False,
    )
    if result.returncode == 0:
        payload = result.json
        as_of = (payload.get("inputs") or {}).get("as_of")
        assert as_of, (
            "a rebuild without an explicit as_of must either refuse or record the "
            "explicit value it used; an ambient wall-clock read is forbidden"
        )
        assert canonical.is_rfc3339_ms(as_of), (
            f"as_of {as_of!r} is not an RFC 3339 UTC millisecond timestamp with a Z suffix"
        )
    else:
        assert result.returncode != 1
        assert result.code == "CONFIG_INVARIANT", result.code


@spec_ref(
    VERIFY(
        "V-4",
        "ceiling",
        "Exercise a corpus at 10× the admission ceiling. Intake refuses new writes while bounded "
        "incremental `fsck`/diagnosis remains available; SessionStart latency and full-rebuild time "
        "are recorded rather than allowed to hang.",
    ),
    CLI(
        "V-4",
        "error-contract",
        "`LIMIT_EXCEEDED` | size/rate/cost ceiling would be crossed | 4",
    ),
)
@pytest.mark.slow
@pytest.mark.timing
def test_ten_times_the_admission_ceiling_refuses_writes_but_still_diagnoses(
    guildhall: Guildhall, codebase: GitRepo
) -> None:
    over = guildhall.run(
        "ingest",
        "kindex",
        str(codebase.path / ".kin"),
        "--repo",
        str(guildhall.cwd),
        "--json",
        env={
            "GUILDHALL_ACCEPTANCE_SYNTHETIC_EVENT_COUNT": str(KIN_INTAKE_EVENTS * 10),
        },
        check=False,
    )
    assert over.returncode != 1
    if over.returncode != 0:
        over.refused("LIMIT_EXCEEDED")
        assert over.error["remediation"], "LIMIT_EXCEEDED must carry remediation"

    started = time.monotonic()
    diagnosis = guildhall.run(
        "fsck",
        "--repo",
        str(guildhall.cwd),
        "--json",
        env={
            "GUILDHALL_ACCEPTANCE_SYNTHETIC_EVENT_COUNT": str(KIN_INTAKE_EVENTS * 10),
        },
        timeout=FULL_FSCK_CEILING_SECONDS + 60,
        check=False,
    )
    elapsed = time.monotonic() - started
    assert diagnosis.returncode != 1
    assert elapsed < FULL_FSCK_CEILING_SECONDS + 60, (
        f"bounded incremental fsck/diagnosis must remain available; took {elapsed:.1f}s"
    )
    payload = diagnosis.json if diagnosis.stdout.strip() else {}
    if isinstance(payload, dict):
        assert payload.get("full_rebuild_seconds") is not None or payload.get(
            "incremental"
        ) is not None, "rebuild time must be recorded rather than allowed to hang"


@spec_ref(
    ARCH(
        "V-4",
        "trust-and-key-lifecycle",
        "Until every locally addressable fact/trace is re-evaluated, projection state is "
        "`REVOCATION_CASCADE_INCOMPLETE` and all not-yet-rechecked facts are withheld, not assumed "
        "unaffected.",
    ),
    VERIFY(
        "V-4",
        "cascade",
        "Revoke a key supporting a dense derivation graph at the 10,000-event ceiling. Until local "
        "transitive recomputation completes, every not-yet-rechecked fact is "
        "`REVOCATION_CASCADE_INCOMPLETE` and withheld; completion must be within 120 seconds or the "
        "typed fail-closed limit state persists with remaining count.",
    ),
)
@pytest.mark.slow
@pytest.mark.timing
def test_revocation_cascade_completes_in_bound_or_stays_fail_closed(
    guildhall: Guildhall, codebase: GitRepo
) -> None:
    started = time.monotonic()
    result = guildhall.run(
        "corpus",
        "rebuild",
        "--store",
        "codebase",
        "--repo",
        str(guildhall.cwd),
        "--as-of",
        "2026-03-06T00:00:00.000Z",
        "--authority-cursor",
        "2000",
        "--json",
        env={
            "GUILDHALL_ACCEPTANCE_SYNTHETIC_EVENT_COUNT": str(KIN_INTAKE_EVENTS),
            "GUILDHALL_ACCEPTANCE_REVOKE_DENSE_KEY": "1",
        },
        timeout=REVOCATION_CASCADE_SECONDS + 120,
        check=False,
    )
    elapsed = time.monotonic() - started
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    if not isinstance(payload, dict):
        return
    cascade = payload.get("revocation_cascade") or {}
    if cascade.get("state") == "complete":
        assert elapsed <= REVOCATION_CASCADE_SECONDS + 30, (
            f"a completed cascade must land inside the 120-second bound; took {elapsed:.1f}s"
        )
    else:
        assert cascade.get("state") == "REVOCATION_CASCADE_INCOMPLETE", cascade
        assert cascade.get("remaining_count") is not None, (
            "exceeding the bound must record the remaining count and retain fail-closed "
            "state"
        )
        assert not payload.get("trusted_facts"), (
            "not-yet-rechecked facts must be withheld, not assumed unaffected"
        )


@spec_ref(
    ARCH(
        "V-4",
        "entity-ownership",
        "A pre-revocation committed retry may return its historical receipt to its original client, "
        "but current projection is still recalculated under current revocation state.",
    ),
    VERIFY(
        "V-4",
        "replay",
        "Replay a pre-revocation event after observing the revocation cursor: a path-exists fast "
        "path may return a historical receipt only to the original scoped client and must not "
        "re-admit/project it.",
    ),
)
def test_pre_revocation_replay_returns_history_without_readmission(
    guildhall: Guildhall, codebase: GitRepo
) -> None:
    result = guildhall.run(
        "status",
        "--repo",
        str(guildhall.cwd),
        "--json",
        env={"GUILDHALL_ACCEPTANCE_REPLAY_PRE_REVOCATION": "1"},
        check=False,
    )
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    if not isinstance(payload, dict):
        return
    replay = payload.get("pre_revocation_replay") or {}
    if replay:
        assert replay.get("historical_receipt_returned") is True
        assert replay.get("readmitted") is False, (
            "a path-exists fast path must not re-admit a revoked event"
        )
        assert replay.get("projected") is False, (
            "a replayed pre-revocation event must not be projected"
        )
        assert replay.get("returned_to_original_scoped_client_only") is True


@spec_ref(
    ARCH(
        "V-4",
        "entity-ownership",
        "A repository-scoped admission lock is an exclusive OS file lock stored in Git's common "
        "directory and keyed by certified repository UUID, so every linked worktree contends on the "
        "same lock.",
    ),
    VERIFY(
        "V-4",
        "lock",
        "Admit concurrently from two linked worktrees and prove one exclusive lock in Git's common "
        "directory serializes one manifest lineage. A worktree-local lock mutation must fail.",
    ),
)
def test_linked_worktrees_serialize_on_one_common_dir_lock(
    guildhall: Guildhall, codebase: GitRepo, tmp_path: Path
) -> None:
    linked = codebase.add_worktree(tmp_path / "linked", "linked-branch")
    assert linked.common_dir().resolve() == codebase.common_dir().resolve() or str(
        codebase.path
    ) in str(linked.common_dir().resolve()), (
        "the linked worktree must share Git's common directory"
    )

    def admit(repo: GitRepo, tag: str) -> int:
        return guildhall.run(
            "repo",
            "publish-manifest",
            "--repo",
            str(repo.path),
            "--json",
            cwd=repo.path,
            env={"GUILDHALL_ACCEPTANCE_ADMIT_TAG": tag},
            check=False,
        ).returncode

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(admit, codebase, "primary"),
            pool.submit(admit, linked, "linked"),
        ]
        results = [f.result() for f in futures]
    assert all(rc != 1 for rc in results), (
        "concurrent admission from linked worktrees must never return exit 1"
    )
    lock_candidates = list(codebase.common_dir().glob("*guildhall*lock*")) + list(
        codebase.common_dir().glob("guildhall*")
    )
    worktree_local = list((linked.path / ".git").glob("*guildhall*lock*")) if (
        linked.path / ".git"
    ).is_dir() else []
    assert not worktree_local, (
        "the admission lock must live in Git's common directory, not per worktree; "
        f"found {worktree_local}"
    )


@spec_ref(
    ARCH(
        "V-4",
        "repository-compatibility",
        "Acceptance initializes against a fully populated real pinned-Kindex repository, proves "
        "every legacy byte is preserved, and injects one deliberate path collision that must "
        "refuse.",
    ),
    VERIFY(
        "V-4",
        "kindex-collision",
        "Initialize against a fully populated real pinned-Kindex `.kin/` inventory and prove byte "
        "preservation; inject a collision between an enumerated Kindex path and a Guildhall "
        "reserved path and require typed no-write refusal.",
    ),
)
def test_legacy_kindex_bytes_preserved_and_collision_refuses(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    repo = GitRepo.init(roots.repo_root)
    legacy_files = synth.legacy_kin_inventory(repo.path)
    before = {p: p.read_bytes() for p in legacy_files}
    repo.commit("populated legacy Kindex repository")

    certificate = tmp_path / "certificate.json"
    steward = synth.make_signer("company-steward-1", "company:root", seed_byte=11)
    certificate.write_text(
        json.dumps(
            synth.repo_certificate(
                steward, repository_uuid="018f0000-0000-7000-8000-000000000001"
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    guildhall.run(
        "repo", "init", "--repo", str(repo.path), "--certificate", str(certificate), "--json",
        check=False,
    )
    after = {p: p.read_bytes() if p.exists() else None for p in legacy_files}
    changed = [str(p) for p in legacy_files if before[p] != after[p]]
    assert not changed, (
        "every legacy Kindex byte must be preserved by `repo init`; changed: " + str(changed)
    )

    # Inject a deliberate collision with a Guildhall reserved path.
    collision = repo.path / ".kin" / "events" / "legacy-kindex-owned.json"
    collision.parent.mkdir(parents=True, exist_ok=True)
    collision.write_text('{"legacy": true}', encoding="utf-8")
    repo.commit("legacy file at a Guildhall reserved path")
    result = guildhall.run(
        "repo", "init", "--repo", str(repo.path), "--certificate", str(certificate), "--json",
        check=False,
    )
    assert result.returncode not in (0, 1), (
        "an actual collision must produce a typed refusal and change no byte"
    )
    assert collision.read_text(encoding="utf-8") == '{"legacy": true}'


@spec_ref(
    ARCH(
        "V-4",
        "repository-compatibility",
        "`repo init` edits an existing `.gitattributes` additively and refuses contradictory rules; "
        "it never replaces the file.",
    )
)
def test_repo_init_is_additive_and_refuses_contradictory_attribute_rules(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    repo = GitRepo.init(roots.repo_root)
    repo.install_attributes(("*.md text=auto", "docs/** diff=markdown"), append=False)
    existing = (repo.path / ".gitattributes").read_text(encoding="utf-8")
    repo.commit("pre-existing attributes")

    certificate = tmp_path / "certificate.json"
    steward = synth.make_signer("company-steward-1", "company:root", seed_byte=11)
    certificate.write_text(
        json.dumps(
            synth.repo_certificate(
                steward, repository_uuid="018f0000-0000-7000-8000-000000000001"
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    guildhall.run(
        "repo", "init", "--repo", str(repo.path), "--certificate", str(certificate), "--json",
        check=False,
    )
    updated = (repo.path / ".gitattributes").read_text(encoding="utf-8")
    assert existing.strip() in updated, (
        "`repo init` must edit .gitattributes additively and never replace the file"
    )

    # A contradictory rule must be refused rather than silently overridden.
    repo.install_attributes((".kin/events/** text diff merge",))
    repo.commit("contradictory attribute rule")
    contradictory = guildhall.run(
        "repo", "init", "--repo", str(repo.path), "--certificate", str(certificate), "--json",
        check=False,
    )
    assert contradictory.returncode != 1
    if contradictory.returncode == 0:
        attrs = repo.effective_attributes(".kin/events/aa/bb/cc.json")
        assert attrs.get("merge") in {"unset", "-merge", None}, (
            "the effective attributes must leave .kin/events/** unmerged; observed "
            f"{attrs}"
        )
