"""The exact 64 ratified adapter lifecycle cells, each natively executed.

Detector Reviewer finding 11. ``spec/verification.md`` V-1 freezes a table whose
rows sum to **64** cells; the previous catalog required 61 and asserted them by
writing generic JSON into a shared directory, so nine adapters never saw their
native format and every cell shared one receipt mutation.

    Every declared cell has an expected observation/current-fact/Unknown state
    and at least one negative mutation. A semantically inapplicable cell needs a
    ratified reason; it cannot disappear from the report.

This module is that report. Each :class:`Cell` carries

* the adapter and the exact ratified cell name, taken from
  ``synth.LIFECYCLE_MATRIX`` so the table cannot drift;
* the three expected states, from closed vocabularies;
* a **native** transition that performs the cell in the adapter's own source
  format --- a JSONL append, a Git branch divergence, an ADR status change, a
  GitHub export edit, a runtime-evidence envelope, a Kindex SQLite row, a signed
  authority answer --- and returns a before/after witness the harness digests;
* a cell-specific negative mutation, so no two cells are killed by one defect.

Nothing here reads product output. The applier changes raw state and reports
what it changed; the gate then drives the shipping surface and compares.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import canonical, planters, prereq, synth
from .requirements import HarnessInvalid

# -- closed vocabularies ---------------------------------------------------

OBSERVATION_STATES: tuple[str, ...] = (
    "appended", "amended_new_observation", "terminal", "expired_raw_withheld",
    "absent_source_recorded", "resumed", "superseded_observation",
    "retracted_observation", "revoked_observation", "conflicting_observations",
    "late_arrival_ordered", "skew_bounded", "removed_observation",
    "narrowed_view", "rewritten_lineage",
)

FACT_STATES: tuple[str, ...] = (
    "current", "unchanged", "withdrawn", "historical_only", "conflict",
    "absent", "recomputed",
)

UNKNOWN_STATES: tuple[str, ...] = (
    "none", "opened", "reopened", "closed", "owner_scoped",
)


@dataclass
class LifecycleContext:
    """Raw state the cells act on. No product output enters here."""

    world: Any                      # SignedWorld
    sources: Path                   # native source tree, inside the repo
    external: Path                  # native sources outside the work tree
    last_transcript: dict[str, str] = dataclass_field(default_factory=dict)
    clock_day: int = 1
    _counter: int = 0

    def stamp(self, *, hour: int = 0, minute: int = 0) -> str:
        return synth._stamp(day=self.clock_day, hour=hour, minute=minute)

    def next_index(self) -> int:
        self._counter += 1
        return self._counter

    @property
    def repo(self):
        return self.world.repo


def _digest_tree(root: Path) -> str:
    """Content address of a native source tree, for before/after witnessing."""
    if not root.exists():
        return "absent"
    parts: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            parts.append(
                f"{path.relative_to(root)}:"
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}"
            )
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Cell:
    """One ratified lifecycle cell with its own transition and mutation."""

    adapter: str
    cell: str
    native_format: str
    observation: str
    fact: str
    unknown: str
    mutation_id: str
    mutation_effect: str
    transition: Callable[[LifecycleContext], dict]
    inapplicable_reason: str = ""

    def __post_init__(self) -> None:
        if self.observation not in OBSERVATION_STATES:
            raise HarnessInvalid(f"{self.key}: unknown observation state")
        if self.fact not in FACT_STATES:
            raise HarnessInvalid(f"{self.key}: unknown fact state")
        if self.unknown not in UNKNOWN_STATES:
            raise HarnessInvalid(f"{self.key}: unknown Unknown state")

    @property
    def key(self) -> str:
        return f"{self.adapter}::{self.cell}"

    def run(self, ctx: LifecycleContext) -> dict:
        """Perform the native transition and return an independent witness."""
        before = _digest_tree(ctx.repo.path)
        detail = self.transition(ctx)
        native = detail.get("native_path")
        if native and Path(native).is_file():
            raw = Path(native).read_bytes()
            mutated = planters.mutate(
                "native.source", raw, cell=self.key, adapter=self.adapter
            )
            if mutated is not raw:
                Path(native).write_bytes(mutated)
                planters.witness_path(Path(native))
        after = _digest_tree(ctx.repo.path)
        if before == after and not detail.get("tree_unchanged_is_the_point"):
            raise prereq.missing(
                "fixture", self.key,
                "the native transition changed no source byte, so the cell was "
                "never actually performed",
            )
        return {
            "cell": self.key,
            "adapter": self.adapter,
            "native_format": self.native_format,
            "source_tree_before": before,
            "source_tree_after": after,
            **detail,
        }

    def as_json(self) -> dict:
        return {
            "adapter": self.adapter,
            "cell": self.cell,
            "native_format": self.native_format,
            "observation_state": self.observation,
            "current_fact_state": self.fact,
            "unknown_state": self.unknown,
            "mutation_id": self.mutation_id,
            "mutation_effect": self.mutation_effect,
            "inapplicable_reason": self.inapplicable_reason,
        }


# ==========================================================================
# codex_jsonl / claude_jsonl -- real host export layouts
# ==========================================================================


def _transcript_dir(ctx: LifecycleContext, host: str) -> Path:
    root = ctx.sources / host
    root.mkdir(parents=True, exist_ok=True)
    return root


def _turns(*texts: str) -> list[dict]:
    return [{"role": "assistant" if i % 2 else "user", "text": t}
            for i, t in enumerate(texts)]


def _session_path(ctx: LifecycleContext, host: str, session: str) -> Path:
    return _transcript_dir(ctx, host) / f"{session}.jsonl"


def _transcript_create(host: str):
    def run(ctx: LifecycleContext) -> dict:
        session = f"s{ctx.next_index():04d}"
        path = _session_path(ctx, host, session)
        writer = synth.codex_session_jsonl if host == "codex" else synth.claude_session_jsonl
        writer(path, session_id=session, cwd=str(ctx.repo.path),
               turns=_turns("the retry ceiling is four attempts per hour",
                            "recorded"))
        return {"session": session, "native_path": str(path),
                "lines": len(path.read_text(encoding="utf-8").splitlines())}
    return run


def _transcript_append(host: str):
    def run(ctx: LifecycleContext) -> dict:
        path = _latest(ctx, host)
        before = len(path.read_text(encoding="utf-8").splitlines())
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "type": "message", "role": "user", "ts": ctx.stamp(hour=2),
                "content": [{"type": "text",
                             "text": "the ceiling also applies to retries after a restart"}],
            }) + "\n")
        after = len(path.read_text(encoding="utf-8").splitlines())
        return {"native_path": str(path), "lines_before": before, "lines_after": after}
    return run


def _transcript_edit_duplicate(host: str):
    def run(ctx: LifecycleContext) -> dict:
        path = _latest(ctx, host)
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) < 2:
            raise prereq.missing("fixture", str(path), "no line to amend")
        amended = json.loads(lines[1])
        amended["edited"] = True
        amended["ts"] = ctx.stamp(hour=3)
        lines.append(json.dumps(amended))
        lines.append(lines[1])          # a genuine duplicate of the original line
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"native_path": str(path), "duplicate_of_line": 2,
                "amended_line_index": len(lines) - 2}
    return run


def _transcript_terminal(host: str, marker: str):
    def run(ctx: LifecycleContext) -> dict:
        path = _latest(ctx, host)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "type": marker, "ts": ctx.stamp(hour=4),
                "session_id": path.stem,
            }) + "\n")
        return {"native_path": str(path), "terminal_marker": marker}
    return run


def _transcript_raw_expiry(host: str):
    def run(ctx: LifecycleContext) -> dict:
        path = _latest(ctx, host)
        import os
        import time

        stale = time.time() - (synth_retention_seconds() + 60)
        os.utime(path, (stale, stale))
        marker = path.with_suffix(".jsonl.retention")
        marker.write_text(
            json.dumps({"private_retention_seconds": synth_retention_seconds(),
                        "raw_mtime": stale}),
            encoding="utf-8",
        )
        return {"native_path": str(path), "raw_mtime": stale,
                "retention_marker": str(marker)}
    return run


def synth_retention_seconds() -> int:
    from .hosts import PRIVATE_RAW_RETENTION_SECONDS

    return int(PRIVATE_RAW_RETENTION_SECONDS)


def _transcript_missing_source(host: str):
    def run(ctx: LifecycleContext) -> dict:
        path = _latest(ctx, host)
        ctx.last_transcript[host] = path.stem
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        path.unlink()
        return {"removed_native_path": str(path), "removed_digest": digest}
    return run


def _transcript_restart(host: str):
    def run(ctx: LifecycleContext) -> dict:
        previous = _latest_name(ctx, host)
        session = f"{previous}-r{ctx.next_index():02d}"
        path = _session_path(ctx, host, session)
        writer = synth.codex_session_jsonl if host == "codex" else synth.claude_session_jsonl
        writer(path, session_id=session, cwd=str(ctx.repo.path),
               turns=_turns("resuming after restart; the ceiling is unchanged"))
        return {"native_path": str(path), "resumed_from": previous}
    return run


def _latest(ctx: LifecycleContext, host: str) -> Path:
    root = _transcript_dir(ctx, host)
    files = sorted(p for p in root.glob("*.jsonl"))
    if not files:
        raise prereq.missing(
            "fixture", f"{host} transcript",
            "no native transcript exists yet; the create cell must run first",
        )
    return files[-1]


def _latest_name(ctx: LifecycleContext, host: str) -> str:
    if host in ctx.last_transcript:
        return ctx.last_transcript[host]
    files = sorted(_transcript_dir(ctx, host).glob("*.jsonl"))
    if files:
        return files[-1].stem
    markers = sorted(_transcript_dir(ctx, host).glob("*.jsonl.retention"))
    if markers:
        return markers[-1].name.removesuffix(".jsonl.retention")
    raise prereq.missing("fixture", host + " restart", "no prior session identity")


# ==========================================================================
# repo_code -- real files, real Git topology
# ==========================================================================


def _code_create(ctx: LifecycleContext) -> dict:
    ctx.repo.write("src/scheduler/window.py", synth.PY_MODULE)
    ctx.repo.write("src/scheduler/window.ts", synth.TS_MODULE)
    ctx.repo.commit("add scheduler window module")
    return {"paths": ["src/scheduler/window.py", "src/scheduler/window.ts"],
            "head": ctx.repo.head()}


def _code_modify(ctx: LifecycleContext) -> dict:
    before = ctx.repo.head()
    ctx.repo.write(
        "src/scheduler/window.py",
        synth.PY_MODULE + "\n\nLOOKAHEAD_SECONDS = 568\n",
    )
    ctx.repo.commit("widen the lookahead window")
    return {"head_before": before, "head_after": ctx.repo.head()}


def _code_delete(ctx: LifecycleContext) -> dict:
    target = ctx.repo.path / "src/scheduler/window.ts"
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.unlink()
    ctx.repo.run("add", "-A")
    ctx.repo.commit("drop the duplicate implementation")
    return {"removed": "src/scheduler/window.ts", "removed_digest": digest,
            "head": ctx.repo.head()}


def _code_rename(ctx: LifecycleContext) -> dict:
    ctx.repo.run("mv", "src/scheduler/window.py", "src/scheduler/lookahead.py")
    ctx.repo.commit("rename the module")
    return {"from": "src/scheduler/window.py", "to": "src/scheduler/lookahead.py",
            "head": ctx.repo.head()}


def _code_branch_divergence(ctx: LifecycleContext) -> dict:
    base = ctx.repo.head()
    ctx.repo.branch("feature/lookahead", start=base)
    ctx.repo.checkout("feature/lookahead")
    ctx.repo.write("src/scheduler/lookahead.py",
                   synth.PY_MODULE + "\n\nLOOKAHEAD_SECONDS = 90\n")
    ctx.repo.commit("narrow the lookahead on the branch")
    diverged = ctx.repo.head()
    ctx.repo.checkout(ctx.repo.default_branch)
    return {"base": base, "branch_head": diverged,
            "reachable": ctx.repo.reachable_from(ctx.repo.default_branch, diverged)}


def _code_rebase_force_push(ctx: LifecycleContext) -> dict:
    remote = ctx.repo.path.parent / "origin.git"
    if not remote.exists():
        from .gitfix import GitRepo

        GitRepo.init(remote, bare=True)
    ctx.repo.push(remote, f"{ctx.repo.default_branch}:{ctx.repo.default_branch}")
    ctx.repo.write("docs/rebase-base.txt", f"base {ctx.next_index()}\n")
    ctx.repo.commit("advance main before rebase")
    ctx.repo.checkout("feature/lookahead")
    before = ctx.repo.head()
    ctx.repo.rebase(ctx.repo.default_branch)
    after = ctx.repo.head()
    ctx.repo.push(remote, "feature/lookahead:feature/lookahead", force=True)
    ctx.repo.checkout(ctx.repo.default_branch)
    return {"pre_rebase": before, "post_rebase": after, "remote": str(remote),
            "rewritten": before != after}


def _code_shallow_sparse(ctx: LifecycleContext) -> dict:
    dest = ctx.repo.path.parent / f"shallow-{ctx.next_index()}"
    clone = ctx.repo.clone(dest, depth=1, sparse=["src/scheduler"])
    return {"clone": str(dest), "depth": 1, "sparse": ["src/scheduler"],
            "clone_head": clone.head(), "tree_unchanged_is_the_point": True}


# ==========================================================================
# repo_tests -- real command-result envelopes
# ==========================================================================


def _test_envelope(ctx: LifecycleContext, *, exit_code: int, stdout: str,
                   hour: int, name: str) -> Path:
    path = ctx.sources / "tests" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    synth.command_result_envelope(
        path, command=["pytest", "-q", "tests/test_window.py"],
        exit_code=exit_code, stdout=stdout, observed_at=synth.receipt_stamp(),
    )
    return path


def _tests_create(ctx: LifecycleContext) -> dict:
    ctx.repo.write("tests/test_window.py", synth.TEST_MODULE)
    ctx.repo.commit("add the window test")
    path = _test_envelope(ctx, exit_code=0, stdout="1 passed", hour=1, name="run-1")
    return {"native_path": str(path), "outcome": "passed"}


def _tests_pass_to_fail(ctx: LifecycleContext) -> dict:
    path = _test_envelope(ctx, exit_code=1, stdout="1 failed", hour=2, name="run-2")
    return {"native_path": str(path), "outcome": "failed"}


def _tests_fail_to_pass(ctx: LifecycleContext) -> dict:
    path = _test_envelope(ctx, exit_code=0, stdout="1 passed", hour=3, name="run-3")
    return {"native_path": str(path), "outcome": "passed"}


def _tests_superseded(ctx: LifecycleContext) -> dict:
    path = _test_envelope(ctx, exit_code=0, stdout="1 passed, rerun", hour=4,
                          name="run-4")
    return {"native_path": str(path), "supersedes": "run-3"}


def _tests_delete(ctx: LifecycleContext) -> dict:
    target = ctx.sources / "tests" / "run-1.json"
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.unlink()
    return {"removed": str(target), "removed_digest": digest}


def _tests_out_of_order(ctx: LifecycleContext) -> dict:
    """A result observed later but *asserted* earlier than the current one."""
    path = _test_envelope(ctx, exit_code=1, stdout="1 failed", hour=2,
                          name="run-5-late")
    return {"native_path": str(path), "asserted_hour": 2, "arrived_after": "run-4"}


# ==========================================================================
# git_history
# ==========================================================================


def _history_branch(ctx: LifecycleContext) -> dict:
    ctx.repo.branch("release/1.x")
    ctx.repo.checkout("release/1.x")
    ctx.repo.write("CHANGELOG.md", "# 1.x\n\n- scheduler window\n")
    ctx.repo.commit("open the release branch")
    head = ctx.repo.head()
    ctx.repo.checkout(ctx.repo.default_branch)
    return {"branch": "release/1.x", "head": head}


def _history_merge(ctx: LifecycleContext) -> dict:
    before = ctx.repo.head()
    ctx.repo.merge("release/1.x", message="merge the release branch")
    return {"before": before, "after": ctx.repo.head(),
            "merged": ctx.repo.reachable_from("HEAD", before)}


def _history_reject(ctx: LifecycleContext) -> dict:
    path = ctx.sources / "github" / "rejected.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    synth.github_export(path, pulls=[synth.pull_request(
        number=41, title="halve the lookahead", state="closed", merged=False,
        reviews=[{"state": "CHANGES_REQUESTED", "author": "repo-maintainer-1"}],
        body="rejected: the window is load bearing",
    )])
    return {"native_path": str(path), "pull": 41, "merged": False}


def _history_revert(ctx: LifecycleContext) -> dict:
    target = ctx.repo.head()
    ctx.repo.run("revert", "--no-edit", "-n", "-m", "1", target)
    ctx.repo.commit("revert the merged release")
    return {"reverted": target, "head": ctx.repo.head()}


def _history_delete_ref(ctx: LifecycleContext) -> dict:
    head = ctx.repo.head("refs/heads/release/1.x")
    ctx.repo.delete_ref("refs/heads/release/1.x")
    return {"deleted_ref": "refs/heads/release/1.x", "was": head,
            "tree_unchanged_is_the_point": True}


def _history_rebase_force_push(ctx: LifecycleContext) -> dict:
    return _code_rebase_force_push(ctx)


def _history_shallow_fetch(ctx: LifecycleContext) -> dict:
    dest = ctx.repo.path.parent / f"shallow-fetch-{ctx.next_index()}"
    clone = ctx.repo.clone(dest, depth=1)
    return {"clone": str(dest), "depth": 1, "clone_head": clone.head(),
            "tree_unchanged_is_the_point": True}


def _history_clock_skew(ctx: LifecycleContext) -> dict:
    """A commit whose author date precedes its parent by a bounded amount."""
    skewed = ctx.stamp(hour=0, minute=0)
    ctx.repo.write("docs/notes.md", "the window applies from the previous cycle\n")
    ctx.repo.run("add", "-A")
    ctx.repo.run(
        "-c", f"user.name={ctx.repo.default_branch}", "commit", "-m",
        "record a back-dated note",
        env={"GIT_AUTHOR_DATE": skewed, "GIT_COMMITTER_DATE": skewed},
    )
    return {"head": ctx.repo.head(), "author_date": skewed, "bounded": True}


# ==========================================================================
# docs_adr
# ==========================================================================


def _adr(ctx: LifecycleContext, *, number: int, status: str, body: str,
         supersedes: int | None = None) -> Path:
    path = ctx.sources / "adr" / f"{number:04d}-lookahead.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    synth.adr(path, number=number, title="scheduler lookahead window",
              status=status, body=body, supersedes=supersedes)
    return path


def _adr_proposed(ctx: LifecycleContext) -> dict:
    path = _adr(ctx, number=11, status="Proposed",
                body="widen the lookahead window to 568 seconds")
    return {"native_path": str(path), "status": "Proposed"}


def _adr_accepted(ctx: LifecycleContext) -> dict:
    path = _adr(ctx, number=11, status="Accepted",
                body="widen the lookahead window to 568 seconds")
    return {"native_path": str(path), "status": "Accepted"}


def _adr_rejected(ctx: LifecycleContext) -> dict:
    path = _adr(ctx, number=12, status="Rejected",
                body="halve the lookahead window to 90 seconds")
    return {"native_path": str(path), "status": "Rejected"}


def _adr_superseded(ctx: LifecycleContext) -> dict:
    path = _adr(ctx, number=13, status="Accepted",
                body="lookahead becomes adaptive within a 568 second ceiling",
                supersedes=11)
    older = _adr(ctx, number=11, status="Superseded",
                 body="widen the lookahead window to 568 seconds")
    return {"native_path": str(path), "supersedes": 11, "older": str(older)}


def _adr_retracted(ctx: LifecycleContext) -> dict:
    target = ctx.sources / "adr" / "0012-lookahead.md"
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.unlink()
    return {"removed": str(target), "removed_digest": digest}


def _adr_conflicting_heads(ctx: LifecycleContext) -> dict:
    """Two accepted ADRs for one logical key, on two heads that both exist."""
    base = ctx.repo.head()
    ctx.repo.branch("adr/alternate", start=base)
    ctx.repo.checkout("adr/alternate")
    alternate = _adr(ctx, number=13, status="Accepted",
                     body="lookahead is fixed at 90 seconds")
    ctx.repo.run("add", "-A")
    ctx.repo.commit("record the alternate decision")
    alternate_head = ctx.repo.head()
    ctx.repo.checkout(ctx.repo.default_branch)
    _adr(ctx, number=13, status="Accepted",
         body="lookahead becomes adaptive within a 568 second ceiling",
         supersedes=11)
    ctx.repo.run("add", "-A")
    ctx.repo.commit("record the primary decision")
    return {"heads": [ctx.repo.head(), alternate_head],
            "native_path": str(alternate), "logical_key": "adr-0013"}


# ==========================================================================
# github_export
# ==========================================================================


def _gh(ctx: LifecycleContext, name: str, **kwargs) -> Path:
    path = ctx.sources / "github" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    synth.github_export(path, **kwargs)
    return path


def _gh_open(ctx: LifecycleContext) -> dict:
    path = _gh(ctx, "export-1", issues=[{
        "number": 7, "title": "lookahead window is too narrow", "state": "open",
        "body": "the 90 second window drops late arrivals",
    }])
    return {"native_path": str(path), "state": "open"}


def _gh_edit(ctx: LifecycleContext) -> dict:
    path = _gh(ctx, "export-2", issues=[{
        "number": 7, "title": "lookahead window is too narrow", "state": "open",
        "body": "the 90 second window drops late arrivals; measured at 568",
        "edited": True,
    }])
    return {"native_path": str(path), "edited": True}


def _gh_review(ctx: LifecycleContext) -> dict:
    path = _gh(ctx, "export-3", pulls=[synth.pull_request(
        number=42, title="widen the lookahead", state="open", merged=False,
        reviews=[{"state": "APPROVED", "author": "chief-architect-1"},
                 {"state": "CHANGES_REQUESTED", "author": "repo-maintainer-1"}],
    )])
    return {"native_path": str(path), "reviews": 2}


def _gh_merge_close_reopen(ctx: LifecycleContext) -> dict:
    path = _gh(ctx, "export-4",
               issues=[{"number": 7, "title": "lookahead window is too narrow",
                        "state": "open", "reopened": True,
                        "body": "reopened after the merge regressed"}],
               pulls=[synth.pull_request(
                   number=42, title="widen the lookahead", state="closed",
                   merged=True)])
    return {"native_path": str(path), "merged": 42, "reopened": 7}


def _gh_missing_object(ctx: LifecycleContext) -> dict:
    """A later export in which a previously exported object is simply gone."""
    path = _gh(ctx, "export-5", issues=[{
        "number": 8, "title": "retry ceiling", "state": "open",
        "body": "unrelated",
    }])
    return {"native_path": str(path), "withdrawn_object": 7}


# ==========================================================================
# runtime_evidence
# ==========================================================================


def _runtime(ctx: LifecycleContext, name: str, *, stdout: str, hour: int,
             environment_id: str = "env-prod-1", owner: str = "sre-owner-1",
             effective_until: str | None = None) -> Path:
    path = ctx.sources / "runtime" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    synth.command_result_envelope(
        path, command=["kubectl", "get", "cm", "scheduler", "-o", "json"],
        exit_code=0, stdout=stdout, observed_at=synth.receipt_stamp(
            -240 if name == "obs-6-skew" else -60 if "late" in name else 0),
        environment_id=environment_id, owner=owner,
        effective_until=effective_until,
    )
    return path


def _runtime_create(ctx: LifecycleContext) -> dict:
    path = _runtime(ctx, "obs-1", stdout='{"lookahead_seconds": 568}', hour=1,
                    effective_until=synth._stamp(day=ctx.clock_day + 7))
    return {"native_path": str(path), "value": 568}


def _runtime_changed_value(ctx: LifecycleContext) -> dict:
    path = _runtime(ctx, "obs-2", stdout='{"lookahead_seconds": 300}', hour=2,
                    effective_until=synth._stamp(day=ctx.clock_day + 7))
    return {"native_path": str(path), "value": 300}


def _runtime_owner_change(ctx: LifecycleContext) -> dict:
    path = _runtime(ctx, "obs-3", stdout='{"lookahead_seconds": 300}', hour=3,
                    owner="sre-owner-2",
                    effective_until=synth._stamp(day=ctx.clock_day + 7))
    return {"native_path": str(path), "owner": "sre-owner-2"}


def _runtime_expiry(ctx: LifecycleContext) -> dict:
    path = _runtime(ctx, "obs-4", stdout='{"lookahead_seconds": 300}', hour=4,
                    effective_until=synth._stamp(day=ctx.clock_day))
    return {"native_path": str(path),
            "effective_until": synth._stamp(day=ctx.clock_day)}


def _runtime_late_arrival(ctx: LifecycleContext) -> dict:
    path = _runtime(ctx, "obs-5-late", stdout='{"lookahead_seconds": 240}', hour=2,
                    effective_until=synth._stamp(day=ctx.clock_day + 7))
    return {"native_path": str(path), "observed_hour": 2, "arrived_after": "obs-4"}


def _runtime_bounded_skew(ctx: LifecycleContext) -> dict:
    path = _runtime(ctx, "obs-6-skew", stdout='{"lookahead_seconds": 240}', hour=0,
                    effective_until=synth._stamp(day=ctx.clock_day + 7))
    return {"native_path": str(path), "skew_minutes": 4, "bounded": True}


def _runtime_unregistered_environment(ctx: LifecycleContext) -> dict:
    path = _runtime(ctx, "obs-7-unreg", stdout='{"lookahead_seconds": 999}',
                    hour=5, environment_id="env-not-registered")
    return {"native_path": str(path), "environment_id": "env-not-registered"}


# ==========================================================================
# kindex -- a real SQLite export
# ==========================================================================


def _kindex_path(ctx: LifecycleContext) -> Path:
    path = ctx.sources / "kindex" / "kindex.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _kindex_write(ctx: LifecycleContext, nodes: Sequence[Mapping[str, Any]]) -> Path:
    path = _kindex_path(ctx)
    synth.kindex_sqlite_export(path, nodes)
    return path


def _kindex_node(identifier: str, content: str, *, disposition: str = "accepted",
                 **metadata) -> dict:
    # C21: lifecycle metadata belongs in the native export's payload column.
    return {"id": identifier, "node_type": "decision", "title": "Lookahead",
            "content": content,
            "payload": canonical.jcs({"disposition": disposition, **metadata}),
            "created_at": synth._stamp()}


def _kindex_duplicate_import(ctx: LifecycleContext) -> dict:
    node = _kindex_node("kx-1", "lookahead ceiling is 568 seconds")
    path = _kindex_write(ctx, [node])
    # A native PK cannot contain two rows with one id. Re-import the export
    # through the adapter twice (the gate consumes repeat_ingest), C21.
    return {"native_path": str(path), "rows": 1, "distinct_node_ids": 1,
            "repeat_ingest": True}


def _kindex_supersede(ctx: LifecycleContext) -> dict:
    path = _kindex_write(ctx, [
        _kindex_node("kx-1", "lookahead ceiling is 568 seconds",
                     disposition="superseded"),
        _kindex_node("kx-2", "lookahead ceiling is adaptive", supersedes=["kx-1"]),
    ])
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO edges VALUES (?,?,?,?)",
                     ("kx-2", "kx-1", "supersedes", "explicit replacement"))
    return {"native_path": str(path), "supersedes": "kx-1"}


def _kindex_retract(ctx: LifecycleContext) -> dict:
    path = _kindex_path(ctx)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE nodes SET payload = ? WHERE id = ?",
                     (canonical.jcs({"disposition": "retracted"}), "kx-2"))
    return {"native_path": str(path), "retracted": "kx-2"}


def _kindex_revoke(ctx: LifecycleContext) -> dict:
    # R-10: the fixture runner republishes the authority registry. A native
    # support_withdrawn row would not exercise an authority revocation.
    return {"native_path": str(_kindex_path(ctx)),
            "registry_revoke": ctx.world.maintainer.authority_id,
            "tree_unchanged_is_the_point": "revocation occurs in the external registry"}


def _kindex_expire(ctx: LifecycleContext) -> dict:
    path = _kindex_write(ctx, [_kindex_node(
        "kx-expired", "expired at the publication horizon",
        disposition="manifest_observation_expired", effective_until=ctx.stamp(),
    )])
    return {"native_path": str(path), "expired": "kx-expired"}


def _kindex_conflict(ctx: LifecycleContext) -> dict:
    path = _kindex_write(ctx, [
        _kindex_node("kx-conflict-a", "lookahead ceiling is 568 seconds"),
        _kindex_node("kx-conflict-b", "lookahead ceiling is 90 seconds"),
    ])
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO edges VALUES (?,?,?,?)",
                     ("kx-conflict-a", "kx-conflict-b", "contradicts", "same scope"))
    return {"native_path": str(path),
            "conflicting_ids": ["kx-conflict-a", "kx-conflict-b"]}


def _kindex_deterministic_rebuild(ctx: LifecycleContext) -> dict:
    path = _kindex_path(ctx)
    first = hashlib.sha256(path.read_bytes()).hexdigest()
    copy = path.with_name("kindex-rebuild.sqlite3")
    with sqlite3.connect(path) as src, sqlite3.connect(copy) as dst:
        src.backup(dst)
    second = hashlib.sha256(copy.read_bytes()).hexdigest()
    return {"native_path": str(copy), "source_digest": first,
            "rebuild_digest": second}


# ==========================================================================
# authority_answer -- genuinely signed
# ==========================================================================


def _answer_path(ctx: LifecycleContext, name: str) -> Path:
    path = ctx.sources / "answers" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _answer(ctx: LifecycleContext) -> dict:
    payload = synth.authority_answer(
        ctx.world.architect, question_id="q-lookahead-1",
        answer="the ceiling is 568 seconds",
        rationale="the deployed configuration is authoritative for diagnosis",
    )
    path = _answer_path(ctx, "answer-1")
    path.write_bytes(canonical.jcs(payload))
    return {"native_path": str(path), "question_id": "q-lookahead-1"}


def _answer_parent_supersession(ctx: LifecycleContext) -> dict:
    payload = synth.authority_answer(
        ctx.world.architect, question_id="q-lookahead-1",
        answer="the ceiling is adaptive with a 568 second cap",
        rationale="supersedes the earlier answer under the same scope",
    )
    previous = json.loads(_answer_path(ctx, "answer-1").read_text())
    parent = canonical.content_digest_hex(canonical.jcs(previous))
    payload["parents"] = [parent]
    payload = ctx.world.architect.sign_message("answer", payload)
    path = _answer_path(ctx, "answer-2")
    path.write_bytes(canonical.jcs(payload))
    return {"native_path": str(path), "parents": [parent]}


def _answer_unparented_conflict(ctx: LifecycleContext) -> dict:
    payload = synth.authority_answer(
        ctx.world.architect, question_id="q-lookahead-1",
        answer="the ceiling is 90 seconds",
        rationale="asserted without naming the answer it replaces",
    )
    path = _answer_path(ctx, "answer-3")
    path.write_bytes(canonical.jcs(payload))
    return {"native_path": str(path), "parents": []}


def _answer_revoke(ctx: LifecycleContext) -> dict:
    # Re-read the previously admitted answer after actual registry republication.
    return {"native_path": str(_answer_path(ctx, "answer-3")),
            "registry_revoke": ctx.world.architect.authority_id,
            "tree_unchanged_is_the_point": "revocation occurs in the external registry"}


def _answer_late_arrival(ctx: LifecycleContext) -> dict:
    payload = synth.authority_answer(
        ctx.world.architect, question_id="q-lookahead-0",
        answer="the previous cycle used 300 seconds",
        rationale="answering a question raised before the current cursor",
    )
    payload["asserted_at"] = ctx.stamp(hour=0)
    payload = ctx.world.architect.sign_message("answer", payload)
    path = _answer_path(ctx, "answer-5-late")
    path.write_bytes(canonical.jcs(payload))
    return {"native_path": str(path), "asserted_hour": 0,
            "arrived_after": "registry revocation"}


# ==========================================================================
# The frozen 64
# ==========================================================================


def _c(adapter, cell, native, obs, fact, unknown, mutation, effect, fn) -> Cell:
    return Cell(adapter, cell, native, obs, fact, unknown,
                f"v1.cell.{mutation}", effect, fn)


CELLS: tuple[Cell, ...] = (
    # -- codex_jsonl (7) --------------------------------------------------
    _c("codex_jsonl", "create", "codex session jsonl", "appended", "current",
       "none", "codex_create", "drop the first turn so no observation is created",
       _transcript_create("codex")),
    _c("codex_jsonl", "append", "codex session jsonl", "appended", "current",
       "none", "codex_append", "ignore lines after the first read offset",
       _transcript_append("codex")),
    _c("codex_jsonl", "edited/duplicate event", "codex session jsonl",
       "amended_new_observation", "recomputed", "none", "codex_edit_duplicate",
       "treat the duplicated line as a second observation",
       _transcript_edit_duplicate("codex")),
    _c("codex_jsonl", "end", "codex session jsonl", "terminal", "current",
       "closed", "codex_end", "ignore the terminal marker and keep the session open",
       _transcript_terminal("codex", "session_end")),
    _c("codex_jsonl", "raw expiry", "codex session jsonl", "expired_raw_withheld",
       "current", "none", "codex_raw_expiry",
       "retain the raw transcript past the private retention bound",
       _transcript_raw_expiry("codex")),
    _c("codex_jsonl", "missing source", "codex session jsonl",
       "absent_source_recorded", "historical_only", "opened", "codex_missing",
       "silently forget the observation instead of recording the absent source",
       _transcript_missing_source("codex")),
    _c("codex_jsonl", "restart", "codex session jsonl", "resumed", "current",
       "none", "codex_restart",
       "start a new lineage rather than resuming the prior session",
       _transcript_restart("codex")),
    # -- claude_jsonl (7) -------------------------------------------------
    _c("claude_jsonl", "create", "claude session jsonl", "appended", "current",
       "none", "claude_create", "drop the first turn so no observation is created",
       _transcript_create("claude")),
    _c("claude_jsonl", "append", "claude session jsonl", "appended", "current",
       "none", "claude_append", "ignore lines after the first read offset",
       _transcript_append("claude")),
    _c("claude_jsonl", "edited/duplicate event", "claude session jsonl",
       "amended_new_observation", "recomputed", "none", "claude_edit_duplicate",
       "treat the duplicated line as a second observation",
       _transcript_edit_duplicate("claude")),
    _c("claude_jsonl", "stop", "claude session jsonl", "terminal", "current",
       "closed", "claude_stop", "ignore the stop marker and keep the session open",
       _transcript_terminal("claude", "stop")),
    _c("claude_jsonl", "raw expiry", "claude session jsonl",
       "expired_raw_withheld", "current", "none", "claude_raw_expiry",
       "retain the raw transcript past the private retention bound",
       _transcript_raw_expiry("claude")),
    _c("claude_jsonl", "missing source", "claude session jsonl",
       "absent_source_recorded", "historical_only", "opened", "claude_missing",
       "silently forget the observation instead of recording the absent source",
       _transcript_missing_source("claude")),
    _c("claude_jsonl", "restart", "claude session jsonl", "resumed", "current",
       "none", "claude_restart",
       "start a new lineage rather than resuming the prior session",
       _transcript_restart("claude")),
    # -- repo_code (7) ----------------------------------------------------
    _c("repo_code", "create", "python and typescript modules", "appended",
       "current", "none", "code_create", "skip newly added files",
       _code_create),
    _c("repo_code", "modify", "python module", "amended_new_observation",
       "recomputed", "none", "code_modify",
       "reuse the prior content digest after the edit", _code_modify),
    _c("repo_code", "delete", "typescript module", "removed_observation",
       "withdrawn", "opened", "code_delete",
       "keep the deleted file's fact current", _code_delete),
    _c("repo_code", "rename", "python module", "amended_new_observation",
       "current", "none", "code_rename",
       "treat the rename as a delete plus an unrelated create", _code_rename),
    _c("repo_code", "branch divergence", "git branch", "conflicting_observations",
       "conflict", "opened", "code_branch_divergence",
       "trust the unmerged branch as current", _code_branch_divergence),
    _c("repo_code", "rebase/force-push", "git ref rewrite", "rewritten_lineage",
       "recomputed", "none", "code_rebase",
       "keep the pre-rebase commit as the current source revision",
       _code_rebase_force_push),
    _c("repo_code", "shallow/sparse view", "shallow sparse clone",
       "narrowed_view", "unchanged", "opened", "code_shallow_sparse",
       "report the narrowed view as a complete corpus", _code_shallow_sparse),
    # -- repo_tests (6) ---------------------------------------------------
    _c("repo_tests", "create", "command result envelope", "appended", "current",
       "none", "tests_create", "skip the first result envelope", _tests_create),
    _c("repo_tests", "pass-to-fail", "command result envelope", "appended",
       "current", "opened", "tests_pass_to_fail",
       "keep the passing result current after a failure", _tests_pass_to_fail),
    _c("repo_tests", "fail-to-pass", "command result envelope", "appended",
       "current", "closed", "tests_fail_to_pass",
       "leave the failure Unknown open after a passing run", _tests_fail_to_pass),
    _c("repo_tests", "superseded result", "command result envelope",
       "superseded_observation", "current", "none", "tests_superseded",
       "keep both results current instead of superseding", _tests_superseded),
    _c("repo_tests", "delete", "command result envelope", "removed_observation",
       "historical_only", "none", "tests_delete",
       "destroy the historical result rather than retaining it", _tests_delete),
    _c("repo_tests", "out-of-order result", "command result envelope",
       "late_arrival_ordered", "unchanged", "none", "tests_out_of_order",
       "let the late-arriving older result overwrite the current one",
       _tests_out_of_order),
    # -- git_history (8) --------------------------------------------------
    _c("git_history", "branch", "git ref", "appended", "unchanged", "none",
       "history_branch", "treat the branch tip as the current decision",
       _history_branch),
    _c("git_history", "merge", "git merge commit", "appended", "current",
       "none", "history_merge", "drop the merged branch's observations",
       _history_merge),
    _c("git_history", "reject", "github export", "appended", "unchanged",
       "none", "history_reject",
       "treat the rejected change as evidence for its own claim",
       _history_reject),
    _c("git_history", "revert", "git revert commit", "amended_new_observation",
       "withdrawn", "reopened", "history_revert",
       "keep the reverted fact current", _history_revert),
    _c("git_history", "delete ref", "git ref deletion", "removed_observation",
       "historical_only", "none", "history_delete_ref",
       "destroy the events reachable only from the deleted ref",
       _history_delete_ref),
    _c("git_history", "rebase/force-push", "git ref rewrite", "rewritten_lineage",
       "recomputed", "none", "history_rebase",
       "keep the pre-rewrite lineage as authoritative",
       _history_rebase_force_push),
    _c("git_history", "shallow fetch", "shallow clone", "narrowed_view",
       "unchanged", "opened", "history_shallow_fetch",
       "report the shallow view as complete history", _history_shallow_fetch),
    _c("git_history", "clock skew", "back-dated commit", "skew_bounded",
       "unchanged", "none", "history_clock_skew",
       "order by author date without bounding the skew", _history_clock_skew),
    # -- docs_adr (6) -----------------------------------------------------
    _c("docs_adr", "proposed", "markdown adr", "appended", "unchanged", "none",
       "adr_proposed", "treat a proposed ADR as current", _adr_proposed),
    _c("docs_adr", "accepted", "markdown adr", "appended", "current", "none",
       "adr_accepted", "ignore the status transition to Accepted", _adr_accepted),
    _c("docs_adr", "rejected", "markdown adr", "appended", "unchanged", "none",
       "adr_rejected", "treat a rejected ADR as current", _adr_rejected),
    _c("docs_adr", "superseded", "markdown adr", "superseded_observation",
       "current", "none", "adr_superseded",
       "keep the superseded ADR current alongside its successor",
       _adr_superseded),
    _c("docs_adr", "retracted/deleted", "markdown adr", "removed_observation",
       "historical_only", "none", "adr_retracted",
       "destroy the retracted ADR's history", _adr_retracted),
    _c("docs_adr", "conflicting heads", "markdown adr on two heads",
       "conflicting_observations", "conflict", "opened", "adr_conflicting_heads",
       "pick the greatest timestamp instead of reporting the conflict",
       _adr_conflicting_heads),
    # -- github_export (5) ------------------------------------------------
    _c("github_export", "open", "github export json", "appended", "unchanged",
       "none", "gh_open", "treat an open issue as a decision", _gh_open),
    _c("github_export", "edit", "github export json",
       "amended_new_observation", "unchanged", "none", "gh_edit",
       "overwrite the original body instead of amending", _gh_edit),
    _c("github_export", "approve/request-change", "github export json",
       "appended", "conflict", "opened", "gh_review",
       "count approvals as votes and pick the majority", _gh_review),
    _c("github_export", "merge/close/reopen", "github export json", "appended",
       "current", "reopened", "gh_merge_close_reopen",
       "close the Unknown on merge and ignore the reopen", _gh_merge_close_reopen),
    _c("github_export", "missing/withdrawn object", "github export json",
       "absent_source_recorded", "historical_only", "opened", "gh_missing",
       "silently drop the withdrawn object", _gh_missing_object),
    # -- runtime_evidence (6) ---------------------------------------------
    _c("runtime_evidence", "create", "command result envelope", "appended",
       "current", "none", "runtime_create",
       "admit the observation without its environment registration",
       _runtime_create),
    _c("runtime_evidence", "changed value", "command result envelope",
       "amended_new_observation", "current", "none", "runtime_changed_value",
       "keep the previous value current", _runtime_changed_value),
    _c("runtime_evidence", "owner change", "command result envelope",
       "amended_new_observation", "current", "owner_scoped",
       "runtime_owner_change",
       "keep the previous owner on the derived Unknown", _runtime_owner_change),
    _c("runtime_evidence", "expiry", "command result envelope",
       "expired_raw_withheld", "withdrawn", "owner_scoped", "runtime_expiry",
       "keep the expired operational fact trusted", _runtime_expiry),
    _c("runtime_evidence", "late arrival", "command result envelope",
       "late_arrival_ordered", "unchanged", "none", "runtime_late_arrival",
       "let the late older observation overwrite the current value",
       _runtime_late_arrival),
    _c("runtime_evidence", "bounded clock skew", "command result envelope",
       "skew_bounded", "unchanged", "none", "runtime_bounded_skew",
       "accept unbounded skew as ordinary ordering", _runtime_bounded_skew),
    # -- kindex (7) -------------------------------------------------------
    _c("kindex", "duplicate import", "kindex sqlite export", "appended",
       "current", "none", "kindex_duplicate",
       "admit the duplicate row as a second observation",
       _kindex_duplicate_import),
    _c("kindex", "supersede", "kindex sqlite export", "superseded_observation",
       "current", "none", "kindex_supersede",
       "keep the superseded version current", _kindex_supersede),
    _c("kindex", "retract", "kindex sqlite export", "retracted_observation",
       "withdrawn", "reopened", "kindex_retract",
       "keep the retracted node's fact current", _kindex_retract),
    _c("kindex", "revoke", "kindex sqlite export", "revoked_observation",
       "withdrawn", "reopened", "kindex_revoke",
       "admit facts signed by the revoked key", _kindex_revoke),
    _c("kindex", "expire", "kindex sqlite export", "expired_raw_withheld",
       "historical_only", "owner_scoped", "kindex_expire",
       "keep the expired node projectable", _kindex_expire),
    _c("kindex", "conflict", "kindex sqlite export", "conflicting_observations",
       "conflict", "opened", "kindex_conflict",
       "resolve the conflict by greatest version number", _kindex_conflict),
    _c("kindex", "deterministic rebuild", "kindex sqlite export", "appended",
       "recomputed", "none", "kindex_rebuild",
       "let the rebuild depend on ambient wall-clock time",
       _kindex_deterministic_rebuild),
    # -- authority_answer (5) ---------------------------------------------
    _c("authority_answer", "answer", "signed authority answer", "appended",
       "current", "closed", "answer_answer",
       "admit an answer whose signer is not the asked authority", _answer),
    _c("authority_answer", "explicit parent supersession",
       "signed authority answer", "superseded_observation", "current", "closed",
       "answer_supersession",
       "keep the superseded answer current alongside its successor",
       _answer_parent_supersession),
    _c("authority_answer", "unparented conflict", "signed authority answer",
       "conflicting_observations", "conflict", "opened", "answer_conflict",
       "silently take the newest unparented answer",
       _answer_unparented_conflict),
    _c("authority_answer", "revoke", "signed authority answer",
       "revoked_observation", "withdrawn", "reopened", "answer_revoke",
       "keep facts admitted under the revoked answering key",
       _answer_revoke),
    _c("authority_answer", "late arrival", "signed authority answer",
       "late_arrival_ordered", "unchanged", "none", "answer_late_arrival",
       "let the late older answer close the current Unknown",
       _answer_late_arrival),
)


def verify_table() -> tuple[Cell, ...]:
    """The declared cells must be exactly the ratified table, with no gaps."""
    declared: dict[str, list[str]] = {}
    for cell in CELLS:
        declared.setdefault(cell.adapter, []).append(cell.cell)
    ratified = synth.LIFECYCLE_MATRIX
    if set(declared) != set(ratified):
        raise HarnessInvalid(
            f"adapter set differs from the ratified table: "
            f"{sorted(set(declared) ^ set(ratified))}"
        )
    for adapter, cells in ratified.items():
        if tuple(declared[adapter]) != tuple(cells):
            raise HarnessInvalid(
                f"{adapter}: declared cells {declared[adapter]} are not the "
                f"ratified cells {list(cells)}"
            )
    total = sum(len(v) for v in ratified.values())
    if len(CELLS) != total:
        raise HarnessInvalid(
            f"{len(CELLS)} cells declared, the ratified table sums to {total}"
        )
    ids = [c.mutation_id for c in CELLS]
    if len(set(ids)) != len(ids):
        raise HarnessInvalid(
            "two cells share one negative mutation; V-1 requires at least one "
            "mutation per cell so no two cells are killed by one defect"
        )
    return CELLS


CELL_COUNT = sum(len(v) for v in synth.LIFECYCLE_MATRIX.values())


def execution_cells(cells: Sequence[Cell] | None = None) -> tuple[Cell, ...]:
    """Dispatch 008: deterministic dependencies, with destructive expiry last.

    The ratified declaration stays intact. Missing-source runs before expiry
    can remove the raw file; restart follows missing-source and precedes expiry.
    Input enumeration (including pytest collection) cannot change this order.
    """
    declared = verify_table()
    selected = tuple(declared if cells is None else cells)
    if {c.key for c in selected} != {c.key for c in declared} or len(selected) != len(declared):
        raise HarnessInvalid("lifecycle execution requires all 64 declared cells")
    order = {c.key: i for i, c in enumerate(declared)}
    for adapter in ("codex_jsonl", "claude_jsonl"):
        names = ("create", "append", "edited/duplicate event",
                 "end" if adapter == "codex_jsonl" else "stop",
                 "missing source", "restart", "raw expiry")
        first = order[adapter + "::create"]
        order.update({adapter + "::" + name: first + i for i, name in enumerate(names)})
    return tuple(sorted(selected, key=lambda c: order[c.key]))


def by_adapter() -> dict[str, tuple[Cell, ...]]:
    out: dict[str, list[Cell]] = {}
    for cell in CELLS:
        out.setdefault(cell.adapter, []).append(cell)
    return {k: tuple(v) for k, v in out.items()}


def as_json() -> dict:
    return {
        "schema": "guildhall-v1-lifecycle-matrix/1",
        "declared_cells": len(CELLS),
        "ratified_cells": CELL_COUNT,
        "cells": [c.as_json() for c in CELLS],
    }


def digest() -> str:
    return hashlib.sha256(
        json.dumps(as_json(), sort_keys=True).encode("utf-8")
    ).hexdigest()
