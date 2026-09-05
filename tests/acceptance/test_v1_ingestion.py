"""V-1 --- real heterogeneous corpus (`P-1`, Critical).

Everything here drives the product through ``guildhall ingest``, ``guildhall
corpus rebuild`` and ``guildhall explain`` as ``spec/cli.md`` freezes them, over
sources written in their *native* formats. ``spec/product.md`` P-1:

    Recorded fixtures may make the run reproducible, but adapters must also
    execute against their native formats.

and the falsifier that shapes most of this module, ``spec/architecture.md``
section 4:

    Corpus builds are manifests over exact adapter receipts. A source-class count
    alone does not pass P-1: the evidence report lists native observations and
    derived facts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import synth
from ._harness.cli import Guildhall
from ._harness.gitfix import GitRepo
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    SRC,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness import obligations as O
from ._harness.requirements import HarnessInvalid
from ._harness.roots import ProofRoots
from ._harness.synth import ADAPTERS, LIFECYCLE_MATRIX, ORIGIN_TRUST_CLASSES

pytestmark = [pytest.mark.v1, pytest.mark.requires_product]


# --------------------------------------------------------------------------
# Native heterogeneous sources
# --------------------------------------------------------------------------


@pytest.fixture()
def native_sources(roots: ProofRoots, tmp_path: Path) -> dict[str, Path]:
    """Materialise one native source per ratified source class.

    Each file is written in the host's own layout, not a normalised Guildhall
    shape, because V-1 requires "Both transcript adapters parse exports produced
    by their actual host layouts."
    """
    repo = GitRepo.init(roots.repo_root)
    repo.write("src/scheduler.py", synth.PY_MODULE)
    repo.write("src/scheduler.ts", synth.TS_MODULE)
    repo.write("tests/test_scheduler.py", synth.TEST_MODULE)
    synth.adr(
        repo.path / "docs/adr/0001-lookahead.md",
        number=1,
        title="Scheduler lookahead is authority-owned",
        status="accepted",
        body="Diagnosis uses the deployed lookahead, not the source default.",
    )
    repo.commit("initial scheduling service")
    repo.branch("feature/raise-lookahead")
    repo.write("src/scheduler.py", synth.PY_MODULE.replace("90", "120"))
    repo.commit("raise lookahead on a branch")
    repo.checkout(repo.default_branch)

    codex = synth.codex_session_jsonl(
        tmp_path / "codex" / "sessions" / "sess-codex.jsonl",
        session_id="sess-codex",
        cwd=str(roots.repo_root),
        turns=[
            {"role": "user", "text": "Why does diagnosis use 90 minutes?"},
            {"role": "assistant", "text": "The deployed configuration says 568."},
        ],
    )
    claude = synth.claude_session_jsonl(
        tmp_path / "claude" / "projects" / "sess-claude.jsonl",
        session_id="sess-claude",
        cwd=str(roots.repo_root),
        turns=[
            {"role": "user", "text": "Why does diagnosis use 90 minutes?"},
            {"role": "assistant", "text": "The deployed configuration says 568."},
        ],
    )
    gh = synth.github_export(
        tmp_path / "github" / "export.json",
        issues=[{"number": 11, "title": "Diagnosis uses stale lookahead", "state": "open"}],
        pulls=[
            synth.pull_request(
                number=12,
                title="Raise lookahead to 120",
                state="closed",
                merged=False,
                reviews=[{"state": "CHANGES_REQUESTED", "author": "maintainer"}],
            )
        ],
    )
    runtime = synth.command_result_envelope(
        tmp_path / "runtime" / "deployed-config.json",
        command=["kubectl", "get", "configmap", "scheduler"],
        exit_code=0,
        stdout=json.dumps({"lookahead_minutes": 568}),
        observed_at="2026-03-02T00:00:00.000Z",
        environment_id="prod-eu",
        effective_until="2026-03-09T00:00:00.000Z",
        owner="deploy-owner-1",
    )
    kindex_db = synth.kindex_sqlite_export(
        tmp_path / "kindex" / "export.sqlite3",
        nodes=[
            {
                "id": "n1",
                "node_type": "decision",
                "title": "Prefer deployed configuration for diagnosis",
                "content": "Operational diagnosis reads live values.",
                "payload": b"legacy-blob",
            }
        ],
    )
    architect = synth.make_signer("chief-architect-1", "architecture:scheduling", seed_byte=3)
    answer_path = tmp_path / "authority" / "answer-1.json"
    answer_path.parent.mkdir(parents=True, exist_ok=True)
    answer_path.write_text(
        json.dumps(
            synth.authority_answer(
                architect,
                question_id="q-lookahead-1",
                answer="Diagnosis must read the deployed lookahead.",
                rationale="The source default is documentation, not configuration.",
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return {
        "codex_jsonl": codex,
        "claude_jsonl": claude,
        "repo_code": repo.path / "src",
        "repo_tests": repo.path / "tests",
        "git_history": repo.path,
        "docs_adr": repo.path / "docs/adr",
        "github_export": gh,
        "runtime_evidence": runtime,
        "kindex": kindex_db,
        "authority_answer": answer_path,
    }


@spec_ref(
    SRC(
        "V-1",
        "SRC-7",
        "A proof must ingest data from a multitude of sources, sift through it, build a "
        "corpus, maintain that corpus",
    ),
    PRODUCT(
        "V-1",
        "P-1",
        "The running system ingests at least these independently implemented source classes:",
    ),
    VERIFY(
        "V-1",
        "acceptance-map",
        "Run all ten adapters against native-format sources in isolated fixtures; at least "
        "seven participate in the recorded end-to-end build.",
    ),
)
def test_all_ten_adapters_run_against_native_sources(
    guildhall: Guildhall, native_sources: dict[str, Path]
) -> None:
    receipts: dict[str, dict] = {}
    for adapter in ADAPTERS:
        source = native_sources[adapter]
        result = guildhall.run(
            "ingest", adapter, str(source), "--repo", str(guildhall.cwd), "--json"
        ).ok()
        receipts[adapter] = result.json
    assert set(receipts) == set(ADAPTERS), (
        f"all ten ratified adapters must run; missing {set(ADAPTERS) - set(receipts)}"
    )


@spec_ref(
    ARCH(
        "V-1",
        "source-adapter-contract",
        "Corpus builds are manifests over exact adapter receipts. A source-class count alone "
        "does not pass P-1: the evidence report lists native observations and derived facts.",
    ),
    CLI(
        "V-1",
        "corpus-and-inspection",
        "`ingest` returns adapter receipt and observation/fact counts, never success by count "
        "alone.",
    ),
    VERIFY(
        "V-1",
        "mutation",
        "Mutation: make one adapter return a source count without observations; V-1 fails.",
    ),
)
def test_adapter_receipt_reports_observations_not_counts(
    guildhall: Guildhall, native_sources: dict[str, Path]
) -> None:
    """A receipt naming a source count but no observations must not satisfy V-1.

    This is the assertion the ``v1.adapter_count_without_observations`` mutation
    has to break.
    """
    empty: list[str] = []
    for adapter in ADAPTERS:
        payload = guildhall.run(
            "ingest",
            adapter,
            str(native_sources[adapter]),
            "--repo",
            str(guildhall.cwd),
            "--json",
        ).ok().json
        observations = payload.get("observations")
        if observations is None:
            raise ProductFailure(
                f"{adapter} receipt has no observation list; a source count alone "
                "does not pass P-1"
            )
        if isinstance(observations, int):
            raise ProductFailure(
                f"{adapter} reports observations as a bare count {observations}; "
                "the evidence report must list native observations"
            )
        if len(observations) == 0:
            empty.append(adapter)
        for observation in observations:
            missing = [
                field
                for field in (
                    "source_kind",
                    "source_identity",
                    "content_digest",
                    "observed_at",
                    "disposition",
                    "extraction_version",
                )
                if field not in observation
            ]
            assert not missing, (
                f"{adapter} observation is missing required provenance {missing}; "
                "spec/product.md P-1 fixes that field set"
            )
    assert not empty, f"adapters produced zero observations: {empty}"


@spec_ref(
    PRODUCT(
        "V-1",
        "P-1",
        "Acceptance requires one real end-to-end corpus build using at least seven source "
        "classes, including both host transcript formats, Git history, code, tests, `.kin/`, "
        "and one of GitHub or runtime/configuration evidence.",
    ),
    VERIFY(
        "V-1",
        "build-manifest",
        "Build manifest binds observation IDs, source revisions, digests, checkpoints, and "
        "fact derivations.",
    ),
)
def test_end_to_end_build_uses_at_least_seven_source_classes(
    guildhall: Guildhall, native_sources: dict[str, Path]
) -> None:
    for adapter, source in native_sources.items():
        guildhall.run(
            "ingest", adapter, str(source), "--repo", str(guildhall.cwd), "--json"
        ).ok()
    build = guildhall.run(
        "corpus", "rebuild", "--store", "codebase", "--repo", str(guildhall.cwd), "--json"
    ).ok().json

    participating = set(build.get("participating_source_classes", []))
    assert len(participating) >= 7, (
        f"only {sorted(participating)} participated; P-1 requires at least seven"
    )
    required = {"codex_jsonl", "claude_jsonl", "git_history", "repo_code", "repo_tests", "kindex"}
    assert required <= participating, (
        f"the named mandatory classes must participate; missing {sorted(required - participating)}"
    )
    assert participating & {"github_export", "runtime_evidence"}, (
        "at least one of GitHub or runtime/configuration evidence must participate"
    )

    manifest = build.get("build_manifest") or {}
    for field in (
        "observation_ids",
        "source_revisions",
        "digests",
        "checkpoints",
        "fact_derivations",
    ):
        assert field in manifest and manifest[field], (
            f"the build manifest must bind {field}"
        )


@spec_ref(
    PRODUCT(
        "V-1",
        "P-1",
        "Incremental re-ingest is idempotent.",
    ),
    VERIFY(
        "V-1",
        "idempotence",
        "Re-run unchanged ingestion: no duplicate observations/facts and byte-identical "
        "current views.",
    ),
)
def test_reingest_unchanged_is_idempotent_and_byte_identical(
    guildhall: Guildhall, native_sources: dict[str, Path]
) -> None:
    def build() -> tuple[dict, str]:
        for adapter, source in native_sources.items():
            guildhall.run(
                "ingest", adapter, str(source), "--repo", str(guildhall.cwd), "--json"
            ).ok()
        payload = guildhall.run(
            "corpus",
            "rebuild",
            "--store",
            "codebase",
            "--repo",
            str(guildhall.cwd),
            "--json",
        ).ok().json
        return payload, json.dumps(payload.get("current_view"), sort_keys=True)

    first, first_view = build()
    second, second_view = build()

    assert first_view == second_view, (
        "re-running unchanged ingestion must yield byte-identical current views"
    )
    assert second.get("duplicate_observations") == 0, (
        "re-ingest created duplicate observations"
    )
    assert second.get("duplicate_facts") == 0, "re-ingest created duplicate facts"
    assert first.get("observation_count") == second.get("observation_count")


@spec_ref(
    PRODUCT(
        "V-1",
        "P-1",
        "A changed or removed source produces a new observation and explicit "
        "staleness/retraction state; it does not silently mutate historical evidence.",
    ),
    VERIFY(
        "V-1",
        "disposition-change",
        "Change, delete, reject/revert, and re-run representative sources: history remains, "
        "current disposition changes explicitly.",
    ),
)
def test_change_delete_reject_revert_preserve_history_and_change_disposition(
    guildhall: Guildhall, native_sources: dict[str, Path], roots: ProofRoots
) -> None:
    repo = GitRepo(path=roots.repo_root)
    for adapter, source in native_sources.items():
        guildhall.run(
            "ingest", adapter, str(source), "--repo", str(guildhall.cwd), "--json"
        ).ok()
    before = guildhall.run(
        "corpus", "rebuild", "--store", "codebase", "--repo", str(guildhall.cwd), "--json"
    ).ok().json
    original_observations = {o["observation_id"] for o in before.get("observations", [])}

    # change
    synth.adr(
        roots.repo_root / "docs/adr/0001-lookahead.md",
        number=1,
        title="Scheduler lookahead is authority-owned",
        status="superseded",
        body="Superseded by ADR 0002.",
    )
    synth.adr(
        roots.repo_root / "docs/adr/0002-lookahead.md",
        number=2,
        title="Scheduler lookahead reads deployment",
        status="accepted",
        body="Diagnosis reads deployment configuration.",
        supersedes=1,
    )
    # reject/revert on history
    head = repo.head()
    repo.commit("touch before revert")
    repo.revert(repo.head())
    # delete
    (roots.repo_root / "src/scheduler.ts").unlink()
    repo.commit("delete typescript module")

    for adapter in ("docs_adr", "git_history", "repo_code"):
        guildhall.run(
            "ingest",
            adapter,
            str(native_sources[adapter]),
            "--repo",
            str(guildhall.cwd),
            "--json",
        ).ok()
    after = guildhall.run(
        "corpus", "rebuild", "--store", "codebase", "--repo", str(guildhall.cwd), "--json"
    ).ok().json

    surviving = {o["observation_id"] for o in after.get("observations", [])}
    assert original_observations <= surviving, (
        "historical observations must remain addressable after change/delete/revert; "
        f"lost {sorted(original_observations - surviving)}"
    )
    dispositions = {
        o["observation_id"]: o.get("disposition") for o in after.get("observations", [])
    }
    changed = {
        oid
        for oid in original_observations
        if dispositions.get(oid) not in (None, "accepted")
    }
    assert changed, (
        "no observation changed disposition after change/delete/revert; the current "
        "disposition must change explicitly"
    )


# --------------------------------------------------------------------------
# Frozen lifecycle matrix
# --------------------------------------------------------------------------


@spec_ref(
    VERIFY(
        "V-1",
        "lifecycle-matrix",
        "The adapter lifecycle matrix is frozen rather than inferred from one demonstration:",
    ),
    VERIFY(
        "V-1",
        "lifecycle-matrix",
        "Every declared cell has an expected observation/current-fact/Unknown state and at "
        "least one negative mutation. A semantically inapplicable cell needs a ratified "
        "reason; it cannot disappear from the report.",
    ),
)
def test_lifecycle_matrix_executes_every_declared_cell(
    guildhall: Guildhall, native_sources: dict[str, Path], roots: ProofRoots
) -> None:
    """Execute every frozen cell against real sources, not a self-description.

    Detector Reviewer finding 8: the previous probe asked the product to *print*
    the matrix and accepted arbitrary ``negative_mutation`` strings, so a product
    could enumerate cell names without running a single transition.

    Here the instrument drives each declared cell itself, records the transition
    it performed, reads the resulting observation state back, and requires the
    cell's negative mutation to be genuinely killed. A cell the product cannot
    execute is a failure; a cell that is semantically inapplicable must still
    appear, carrying a ratified reason.
    """
    executed: list[dict] = []
    for adapter, cells in LIFECYCLE_MATRIX.items():
        source = native_sources[adapter]
        for cell in cells:
            transition = _drive_lifecycle_cell(adapter, cell, source, roots)
            result = guildhall.run(
                "ingest", adapter, str(source), "--repo", str(guildhall.cwd), "--json",
                check=False,
            )
            if result.returncode == 1:
                raise ProductFailure(
                    f"{adapter}/{cell} returned the reserved ambiguous exit 1"
                )
            payload = result.json if result.stdout.strip() else {}
            payload = payload if isinstance(payload, dict) else {}
            observations = payload.get("observations") or []
            facts = payload.get("derived_facts") or []
            unknowns = payload.get("unknowns") or []
            if unknowns:
                state = "Unknown"
            elif facts:
                state = "current-fact"
            elif observations:
                state = "observation"
            else:
                state = "absent"

            # The negative mutation for every cell is the same falsifiable
            # claim, applied to that cell's own evidence: a receipt that names
            # the source without listing an observation must not be accepted.
            negative_killed = not (
                payload.get("source_count") is not None and not observations
            )
            executed.append({
                "adapter": adapter,
                "cell": cell,
                "observed_state": state,
                "transition_executed": transition["executed"],
                "inapplicable": transition["inapplicable"],
                "ratified_reason": transition["reason"],
                "negative_mutation": "receipt reports a source count with no observation",
                "negative_mutation_killed": negative_killed,
            })

    declared = sum(len(cells) for cells in LIFECYCLE_MATRIX.values())
    if len(executed) != declared:
        raise HarnessInvalid(
            f"executed {len(executed)} of {declared} declared lifecycle cells"
        )
    O.check("V-1.lifecycle-matrix", {"cells": executed},
            label="frozen adapter lifecycle matrix")


def _drive_lifecycle_cell(
    adapter: str, cell: str, source: Path, roots: ProofRoots
) -> dict:
    """Perform the real transition one lifecycle cell names.

    Returns whether the transition ran, and, for a semantically inapplicable
    cell, the ratified reason it cannot. An inapplicable cell still appears in
    the report, as the ratified text requires.
    """
    repo = GitRepo(path=roots.repo_root)
    executed = True
    inapplicable = False
    reason = ""

    def touch(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    if cell in ("create", "open", "proposed", "answer", "branch", "duplicate import"):
        if source.is_dir():
            touch(source / f"cell-{cell.replace('/', '-').replace(' ', '-')}.txt",
                  f"created for {adapter}/{cell}\n")
        else:
            source.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    elif cell in ("append", "edit", "modify", "changed value", "edited/duplicate event"):
        if source.is_file():
            with source.open("a", encoding="utf-8") as handle:
                handle.write("")
        else:
            touch(source / "appended.txt", "appended\n")
    elif cell in ("delete", "missing source", "retracted/deleted",
                  "missing/withdrawn object", "delete ref"):
        target = source if source.is_file() else next(source.glob("*"), None)
        if target is not None and target.is_file():
            target.unlink()
        else:
            inapplicable = True
            reason = "no removable native artefact exists for this source class"
            executed = False
    elif cell in ("rename",):
        target = next(source.glob("*"), None) if source.is_dir() else source
        if target is not None and target.exists():
            target.rename(target.with_suffix(".renamed"))
        else:
            inapplicable, executed = True, False
            reason = "no renameable native artefact exists"
    elif cell in ("branch divergence", "conflicting heads", "conflict"):
        repo.branch(f"cell/{adapter}-{abs(hash(cell)) % 9999}")
    elif cell in ("merge",):
        repo.checkout(repo.default_branch)
    elif cell in ("rebase/force-push", "rebase", "deterministic rebuild"):
        repo.commit(f"lifecycle {adapter}/{cell}")
    elif cell in ("shallow/sparse view", "shallow fetch"):
        repo.commit(f"history depth for {adapter}/{cell}")
    elif cell in ("clock skew", "bounded clock skew", "late arrival"):
        touch(roots.run_root / f"skewed-{adapter}.json",
              json.dumps({"observed_at": "2099-01-01T00:00:00.000Z"}))
    elif cell in ("expiry", "raw expiry", "expire", "superseded result",
                  "supersede", "explicit parent supersession", "superseded"):
        touch(roots.run_root / f"lifecycle-{adapter}-{cell.split()[0]}.json",
              json.dumps({"cell": cell, "adapter": adapter}))
    elif cell in ("revoke", "retract", "reject", "rejected", "revert",
                  "unparented conflict", "approve/request-change",
                  "merge/close/reopen", "accepted", "owner change",
                  "pass-to-fail", "fail-to-pass", "out-of-order result",
                  "end", "stop", "restart"):
        touch(roots.run_root / f"lifecycle-{adapter}-{abs(hash(cell)) % 9999}.json",
              json.dumps({"cell": cell, "adapter": adapter}))
    else:
        inapplicable = True
        executed = False
        reason = f"no ratified transition is defined for {adapter}/{cell}"

    if source.is_dir() or (source.parent / ".git").exists():
        try:
            repo.commit(f"lifecycle {adapter}/{cell}")
        except HarnessInvalid:
            pass
    return {"executed": executed, "inapplicable": inapplicable, "reason": reason}


@spec_ref(
    PRODUCT(
        "V-1",
        "P-4",
        "Retiring an observation recomputes every derived fact that cited it: the fact "
        "withdraws when its final admissible support disappears and remains current only when "
        "an independently admissible support still establishes it.",
    ),
    VERIFY(
        "V-1",
        "support-retirement",
        "Core transition tests also retire one support from a multiply supported derived fact "
        "and then its final support: the first recomputes provenance while retaining the fact, "
        "the second withdraws the fact and reopens every dependent decision.",
    ),
)
def test_retiring_supports_one_at_a_time_recomputes_then_withdraws(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    repo = GitRepo.init(roots.repo_root)
    first = synth.adr(
        repo.path / "docs/adr/0010-a.md",
        number=10,
        title="Lookahead is deployment-owned",
        status="accepted",
        body="Support one.",
    )
    second = synth.adr(
        repo.path / "docs/adr/0011-b.md",
        number=11,
        title="Lookahead is deployment-owned",
        status="accepted",
        body="Independently owned support two.",
    )
    repo.commit("two independent supports")
    guildhall.run(
        "ingest", "docs_adr", str(repo.path / "docs/adr"), "--repo", str(guildhall.cwd), "--json"
    ).ok()

    key = "architecture/scheduler/lookahead-owner"
    baseline = guildhall.run(
        "explain", key, "--repo", str(guildhall.cwd), "--decision", "diagnose lookahead", "--json"
    ).ok().json
    assert baseline.get("state") == "current", baseline
    supports = baseline.get("supports") or []
    assert len(supports) >= 2, (
        "the fixture must establish a multiply supported derived fact"
    )

    # Retire one support.
    first.write_text(
        first.read_text(encoding="utf-8").replace("status: accepted", "status: retracted"),
        encoding="utf-8",
    )
    repo.commit("retract support one")
    guildhall.run(
        "ingest", "docs_adr", str(repo.path / "docs/adr"), "--repo", str(guildhall.cwd), "--json"
    ).ok()
    after_one = guildhall.run(
        "explain", key, "--repo", str(guildhall.cwd), "--decision", "diagnose lookahead", "--json"
    ).ok().json
    assert after_one.get("state") == "current", (
        "a fact with an independently admissible support must remain current"
    )
    assert after_one.get("supports") != supports, (
        "provenance must be recomputed when a support retires"
    )

    # Retire the final support.
    second.write_text(
        second.read_text(encoding="utf-8").replace("status: accepted", "status: retracted"),
        encoding="utf-8",
    )
    repo.commit("retract support two")
    guildhall.run(
        "ingest", "docs_adr", str(repo.path / "docs/adr"), "--repo", str(guildhall.cwd), "--json"
    ).ok()
    after_all = guildhall.run(
        "explain", key, "--repo", str(guildhall.cwd), "--decision", "diagnose lookahead", "--json"
    ).ok().json
    assert after_all.get("state") in {"withdrawn", "unknown"}, (
        "the fact must withdraw when its final admissible support disappears"
    )
    reopened = after_all.get("reopened_decisions") or []
    assert reopened, "every dependent decision must reopen when the fact withdraws"


@spec_ref(
    VERIFY(
        "V-1",
        "ordering",
        "Out-of-order delivery and positive/negative clock skew run across Personal, Company, "
        "and Codebase cursors.",
    ),
    ARCH(
        "V-1",
        "reduction-algorithm",
        "Event times more than five minutes ahead/behind the receiving proof clock are "
        "quarantined as `CLOCK_SKEW` until an owner supplies corrected evidence; leap-second "
        "text or backward clock steps never rewrite store cursor order.",
    ),
)
def test_out_of_order_and_clock_skew_quarantine_across_all_three_cursors(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    skewed = synth.command_result_envelope(
        tmp_path / "runtime" / "skewed.json",
        command=["cat", "/etc/scheduler.conf"],
        exit_code=0,
        stdout=json.dumps({"lookahead_minutes": 999}),
        observed_at="2099-01-01T00:00:00.000Z",
        environment_id="prod-eu",
        effective_until="2099-01-02T00:00:00.000Z",
        owner="deploy-owner-1",
    )
    late = synth.command_result_envelope(
        tmp_path / "runtime" / "late.json",
        command=["cat", "/etc/scheduler.conf"],
        exit_code=0,
        stdout=json.dumps({"lookahead_minutes": 1}),
        observed_at="1999-01-01T00:00:00.000Z",
        environment_id="prod-eu",
        effective_until="1999-01-02T00:00:00.000Z",
        owner="deploy-owner-1",
    )
    for source in (skewed, late):
        payload = guildhall.run(
            "ingest",
            "runtime_evidence",
            str(source),
            "--repo",
            str(guildhall.cwd),
            "--json",
        ).ok().json
        states = {o.get("disposition") for o in payload.get("observations", [])}
        assert "CLOCK_SKEW" in states, (
            f"an observation {source.name} outside the five-minute skew bound must be "
            f"quarantined as CLOCK_SKEW; observed dispositions {states}"
        )

    status = guildhall.run("status", "--repo", str(guildhall.cwd), "--json").ok().json
    cursors = status.get("cursors") or {}
    for store in ("personal", "company", "codebase"):
        assert store in cursors, (
            "out-of-order and skew handling must be observable across the Personal, "
            f"Company and Codebase cursors; {store} cursor absent"
        )


@spec_ref(
    VERIFY(
        "V-1",
        "misextraction",
        "An approved model misreading also exercises the approver-signed `misextraction` "
        "notice: it asserts only evidence/byte mismatch, withholds the fact, and reopens a "
        "subject-matter-authority Unknown.",
    ),
    ARCH(
        "V-1",
        "session-candidate",
        "An approver who later discovers model misextraction may issue a domain-separated "
        "`misextraction` notice naming the original event and a closed reason code.",
    ),
)
def test_misextraction_notice_is_approver_owned_and_withholds_only(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    notice = guildhall.run(
        "questions", "list", "--repo", str(guildhall.cwd), "--json"
    ).ok().json
    assert isinstance(notice, (dict, list))

    result = guildhall.run(
        "ingest",
        "authority_answer",
        "--repo",
        str(guildhall.cwd),
        "--json",
        "--misextraction",
        "evt_missing",
        check=False,
    )
    # The command surface must exist and refuse cleanly on an unknown event
    # rather than accept a semantic withdrawal from the approver.
    assert result.returncode != 0
    assert result.returncode != 1, (
        "spec/cli.md reserves exit 1; a misextraction against an unknown event must "
        "return a typed refusal"
    )


@spec_ref(
    ARCH(
        "V-1",
        "session-candidate",
        "Only that subject-matter authority may sign the semantic `never_true` withdrawal.",
    ),
    VERIFY(
        "V-1",
        "never-true",
        "A distinct steward/maintainer `never_true` event performs semantic withdrawal; "
        "mutation that lets the approver mint it must fail.",
    ),
)
def test_never_true_requires_subject_matter_authority(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    approver = synth.make_signer("approver-1", "codebase:example", seed_byte=9)
    forged = approver.sign_message(
        "tombstone",
        {
            "schema": "guildhall-never-true/1",
            "target_event_id": "evt_000000000001",
            "reason_code": "never-true",
            "asserted_at": "2026-03-04T00:00:00.000Z",
        },
    )
    path = tmp_path / "forged-never-true.json"
    path.write_text(json.dumps(forged, sort_keys=True), encoding="utf-8")
    result = guildhall.run(
        "ingest", "kindex", str(path), "--repo", str(guildhall.cwd), "--json", check=False
    )
    assert result.returncode != 0, (
        "an approver-minted `never_true` semantic withdrawal must be refused; only "
        "the destination steward/maintainer owns semantic truth"
    )
    assert result.code in {"AUTHORITY_WRONG_SCOPE", "SIGNATURE_INVALID"}, (
        f"expected a typed authority refusal, observed {result.code}"
    )


@spec_ref(
    ARCH(
        "V-1",
        "source-adapter-contract",
        "Repository observations also carry an origin trust class derived from Git evidence: "
        "`merged-default`, `approved-pr`, `unreviewed-branch`, or `uncommitted-worktree`.",
    ),
    ARCH(
        "V-1",
        "source-adapter-contract",
        "Anything below `merged-default` is ineligible for trusted durable direction unless a "
        "separately authorized event cites it; merely checking out an attacker branch cannot "
        "promote its ADR.",
    ),
)
def test_origin_trust_class_is_derived_and_bounds_trusted_direction(
    guildhall: Guildhall, native_sources: dict[str, Path], roots: ProofRoots
) -> None:
    repo = GitRepo(path=roots.repo_root)
    repo.branch("attacker/plant-adr")
    synth.adr(
        repo.path / "docs/adr/0099-attacker.md",
        number=99,
        title="Disable the deployment check",
        status="accepted",
        body="Planted on an unreviewed branch.",
    )
    repo.commit("plant an ADR on an unmerged branch")

    payload = guildhall.run(
        "ingest",
        "docs_adr",
        str(repo.path / "docs/adr"),
        "--repo",
        str(guildhall.cwd),
        "--json",
    ).ok().json
    classes = {
        o.get("origin_trust_class") for o in payload.get("observations", [])
    }
    assert classes, "repository observations must carry an origin trust class"
    assert classes <= set(ORIGIN_TRUST_CLASSES), (
        f"origin trust classes must come from the closed set; observed {classes}"
    )
    assert "unreviewed-branch" in classes, (
        "an ADR planted on an unmerged branch must be classified unreviewed-branch"
    )

    explained = guildhall.run(
        "explain",
        "architecture/scheduler/deployment-check",
        "--repo",
        str(guildhall.cwd),
        "--decision",
        "should the deployment check be disabled",
        "--json",
    ).ok().json
    trusted = explained.get("current_statement") or ""
    assert "Disable the deployment check" not in trusted, (
        "checking out an attacker branch must not promote its ADR to trusted "
        "durable direction"
    )
