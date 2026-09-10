"""V-9 --- approval fatigue, reissue atomicity and the operator exercise.

Detector Reviewer finding 19. The blinded operator file was never driven: the
absence of a result passed, and adequacy sent the same file five times and then
trusted the product's own reported slot count.

Both are repaired. The operator exercise is a *human* run on the proof machine,
so the instrument requires its recorded responses as a typed prerequisite and
scores every one of the twenty decisions against Tester-held gold itself,
timing each from the recorded timestamps. Absence is ``INVALID_HARNESS`` naming
the exact protocol, never a pass.

Adequacy now sends **distinct per-window arrivals** built from the frozen
maintenance workload, and computes decision slots, admitted-correct counts and
per-window prompt totals in the harness from the receipts, joining opaque
identifiers to gold that never reaches the product.
"""

from __future__ import annotations

import json
import statistics
import subprocess
import time
from pathlib import Path

import pytest

from ._harness import corpora, hosts, operator_exercise
from ._harness import obligations as O
from ._harness import prereq, synth, trust
from ._harness.cli import Kinbase
from ._harness.evidence_model import Origin, field, require_nonempty, rows
from ._harness.requirements import (
    HarnessInvalid,
    CLI,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.worldbuilder import OpaqueIds, SignedWorld, start_session, Witness

pytestmark = [pytest.mark.v9, pytest.mark.requires_product]

#: Where a completed blinded operator run records its decisions. Harness-only:
#: it never reaches the product.
OPERATOR_RESPONSES_ENV = "KINBASE_OPERATOR_RESPONSES"

#: The frozen fatigue ceilings.
PROMPTS_PER_HOUR = hosts.PROMPTS_PER_SLIDING_HOUR
MAX_CONSECUTIVE = hosts.MAX_CONSECUTIVE_PROMPTS
WINDOWS = hosts.MAINTENANCE_WINDOWS

IDENTITY_SEED = b"v9-fatigue-identity"


@pytest.fixture()
def ids() -> OpaqueIds:
    return OpaqueIds(IDENTITY_SEED)


@pytest.fixture()
def anchored(roots: ProofRoots, kinbase: Kinbase):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(kinbase, roots, world)
    trust.classifier_pinned(anchors, what="V-9 candidate extraction")
    return world, anchors


def _run(kinbase: Kinbase, *argv: str, cwd: Path, **kwargs):
    result = kinbase.run(*argv, cwd=cwd, check=False, **kwargs)
    if result.returncode == 1:
        raise ProductFailure(
            "`" + " ".join(argv[:2]) + "` returned the reserved ambiguous exit 1"
        )
    return result


def _json(result) -> dict:
    payload = result.json
    return payload if isinstance(payload, dict) else {}


def _eligible_candidates(kinbase: Kinbase, world, ids: OpaqueIds,
                         count: int) -> tuple[str, list[dict]]:
    """Plant ``count`` genuinely distinct eligible candidates and list them."""
    session = start_session(kinbase, world.repo.path)
    corpus_id = ids.token("fatigue-corpus")
    corpus = world.repo.path.parent / (corpus_id + ".jsonl")
    corpus.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for index in range(count):
        lines.append(json.dumps({
            "id": ids.token("candidate-" + str(index)),
            "role": "user",
            "text": "the retry ceiling for shard " + str(index)
                    + " is four attempts per hour",
            "observed_at": synth.receipt_stamp(),
            "source_kind": "codex_jsonl",
        }))
    corpus.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _run(kinbase, "session", "observe", session, "--event", str(corpus),
         "--json", cwd=world.repo.path)
    listing = _json(_run(kinbase, "proposals", "list", "--session", session,
                         "--json", cwd=world.repo.path))
    return session, rows(listing, "candidates")


@spec_ref(
    VERIFY("V-9", "prompt-budget",
           "Run the four-total-per-hour/three-consecutive approval flood across destinations and "
           "concurrent Codex/Claude sessions sharing one host instance."),
)
def test_four_total_per_hour_shared_across_destinations(
    kinbase: Kinbase, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    session, candidates = _eligible_candidates(kinbase, world, ids, 8)
    require_nonempty(
        candidates, obligation="V-9.prompt-budget",
        why="the flood needs real eligible candidates to render",
        origin=Origin.PRODUCT,
    )
    rendered = [c for c in candidates if field(c, "rendered") is True]
    suppressed = [c for c in candidates if field(c, "suppressed") is True]
    status = _json(_run(kinbase, "doctor", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    O.check(
        "V-9.prompt-budget",
        {
            "eligible_candidates": len(candidates),
            "rendered": len(rendered),
            "suppressed": len(suppressed),
            "shard": {
                "shard_id": field(status, "budget_shard", "shard_id"),
                "signed": field(status, "budget_shard", "signed"),
            },
            "unknown_global_total_warning": field(
                status, "unknown_global_total_warning"),
        },
        label="four total prompts per hour shared across destinations",
    )


@spec_ref(
    CLI("V-9", "reset",
        "`reset` only clears the three-consecutive counter after a real new primary-task event, "
        "is limited to once per hour, and records its closed reason code."),
)
def test_reset_clears_only_the_consecutive_counter_once_per_hour(
    kinbase: Kinbase, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    session, candidates = _eligible_candidates(kinbase, world, ids, 6)
    primary = {"event_id": ids.token("primary")}
    event = world.repo.path.parent / (ids.token("primary-transcript") + ".jsonl")
    event.write_text(json.dumps({"id": primary["event_id"], "role": "user",
                                "text": "Start a new primary task: inspect scheduler compatibility.",
                                "source_kind": "codex_jsonl",
                                "observed_at": synth.receipt_stamp()}) + "\n")
    _run(kinbase, "session", "observe", session, "--event", str(event),
         "--json", cwd=world.repo.path)
    first = _run(kinbase, "proposals", "reset",
                 "--after-primary-event", primary["event_id"],
                 "--reason-code", "new-primary-task", "--json",
                 cwd=world.repo.path)
    second = _run(kinbase, "proposals", "reset",
                  "--after-primary-event", primary["event_id"],
                  "--reason-code", "new-primary-task", "--json",
                  cwd=world.repo.path)
    free_text = _run(kinbase, "proposals", "reset",
                     "--after-primary-event", primary["event_id"],
                     "--reason-code", "the operator felt like it", "--json",
                     cwd=world.repo.path)
    status = _json(_run(kinbase, "doctor", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    O.check(
        "V-9.reset",
        {
            "first_reset_accepted": first.returncode == 0,
            "second_reset_refusal_code": field(_json(second), "error", "code"),
            "hourly_ceiling_preserved":
                field(status, "hourly_prompts_consumed") is not None,
            "consecutive_after_reset": field(status, "consecutive_prompts"),
            "free_text_reason_accepted": free_text.returncode == 0,
        },
        label="reset clears only the consecutive counter, once per hour",
    )


@spec_ref(
    VERIFY("V-9", "reissue-atomicity",
           "Reissue eligibility, unique digest lock, total slot reservation, and consecutive "
           "count must commit in one `BEGIN IMMEDIATE`"),
)
def test_reissue_and_reservation_commit_in_one_immediate_transaction(
    kinbase: Kinbase, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    session, candidates = _eligible_candidates(kinbase, world, ids, 4)
    require_nonempty(
        candidates, obligation="V-9.reissue-atomicity",
        why="reissue needs a real candidate whose bytes can change",
        origin=Origin.PRODUCT,
    )
    identifier = str(field(candidates[0], "candidate_id"))
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/reissue",
        statement="the rendered bytes changed materially",
    )
    first = _decide_reissue(kinbase, world, identifier)
    second = _decide_reissue(kinbase, world, identifier)

    # Untrusted churn: a branch nobody merged must not make bytes "change".
    world.repo.branch("churn/" + ids.token("churn"))
    world.repo.checkout("churn/" + ids.token("churn"))
    world.repo.write("docs/churn.md", "unmerged churn\n")
    world.repo.commit("record unmerged churn")
    world.repo.checkout(world.repo.default_branch)
    churned = _decide_reissue(kinbase, world, identifier)
    status = _json(_run(kinbase, "doctor", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    issued = [r for r in (first, second) if r["issued"]]
    O.check(
        "V-9.reissue-atomicity",
        {
            "eligible_candidates": len(candidates),
            "issued": len(issued),
            "candidate_ids_distinct": len({r["candidate_id"] for r in issued})
            == len(issued),
            "digests_distinct": len({r["digest"] for r in issued}) == len(issued),
            "hourly_consumed": field(status, "hourly_prompts_consumed"),
            "untrusted_churn_triggered_reissue": churned["issued"]
            and churned["candidate_id"] not in {r["candidate_id"] for r in issued},
        },
        label="reissue and reservation commit in one immediate transaction",
    )


def _decide_reissue(kinbase: Kinbase, world, identifier: str) -> dict:
    result = _run(kinbase, "proposals", "reissue", identifier, "--json",
                  cwd=world.repo.path)
    payload = _json(result)
    return {
        "issued": result.returncode == 0,
        "candidate_id": field(payload, "candidate_id"),
        "digest": field(payload, "payload_digest"),
    }


@spec_ref(
    VERIFY("V-9", "interleave",
           "Force Codex and Claude sessions on one host instance to interleave exactly between "
           "slot check and render."),
)
def test_interleaved_sessions_never_exceed_four_prompts_per_window(
    kinbase: Kinbase, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    session, candidates = _eligible_candidates(kinbase, world, ids, 8)
    require_nonempty(
        candidates, obligation="V-9.interleave",
        why="interleaving needs real candidates to contend for slots",
        origin=Origin.PRODUCT,
    )
    processes = []
    for name in hosts.HOSTS:
        envelope = hosts.envelope_for(
            name, "UserPromptSubmit", session_id=ids.token("interleave-" + name),
            cwd=str(world.repo.path),
        )
        process = kinbase.popen("hooks", "dispatch", name, "UserPromptSubmit",
                                  "--json", cwd=world.repo.path,
                                  stdin=subprocess.PIPE)
        processes.append((name, process, envelope))
    started = time.monotonic()
    outcomes = []
    for name, process, envelope in processes:
        try:
            process.stdin.write(json.dumps(envelope).encode())
            process.stdin.close()
            process.stdin = None
        except BrokenPipeError as exc:
            raise ProductFailure(f"[V-9.interleave] {name} closed its input before the envelope") from exc
    for name, process, envelope in processes:
        process.communicate(timeout=180)
        outcomes.append({"host": name, "exit": process.returncode})
    overlap = time.monotonic() - started

    crashed = kinbase.popen("proposals", "reissue",
                              str(field(candidates[0], "candidate_id")), "--json",
                              cwd=world.repo.path)
    time.sleep(0.05)
    crashed.kill()
    crashed.wait(timeout=30)
    witness = Witness(kind="interleaved_sessions")
    witness.note(hosts=[o["host"] for o in outcomes], overlap_seconds=overlap,
                 crashed_exit=crashed.returncode)
    witness.require("both host sessions must actually have run concurrently")

    status = _json(_run(kinbase, "doctor", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    listing = _json(_run(kinbase, "proposals", "list", "--session", session,
                         "--json", cwd=world.repo.path))
    rendered = [c for c in rows(listing, "candidates")
                if field(c, "rendered") is True]
    O.check(
        "V-9.interleave",
        {
            "eligible_candidates": len(candidates),
            "rendered": len(rendered),
            "interleaving_witnessed": len(outcomes) == len(hosts.HOSTS),
            "crash_after_reservation_counted":
                field(status, "reservations_held_after_crash") is not None,
            "delivery_loss_rate": field(status, "delivery_loss_rate"),
        },
        label="interleaved sessions never exceed four prompts per window",
    )


# --------------------------------------------------------------------------
# The blinded operator exercise
# --------------------------------------------------------------------------


def _operator_responses() -> list[dict]:
    """Load the recorded decisions of a real blinded operator run.

    ``spec/verification.md`` V-9 requires a twenty-item blinded exercise with
    recorded accuracy and decision time. That is a human run on the proof
    machine; the instrument cannot synthesise it and must not pass without it.
    """
    configured = prereq.env_var(
        OPERATOR_RESPONSES_ENV, what="blinded operator responses",
        why="V-9 conducts a 20-item blinded operator exercise and records "
            "accuracy and decision time. Run the exercise on the proof machine "
            "and point this variable at the recorded JSONL: one object per item "
            "with item_id, decision and decided_at, in presentation order, with "
            "no gold field",
    )
    path = Path(configured)
    raw = prereq.fixture_file(
        path, why="the recorded blinded operator decisions", minimum_bytes=32
    )
    out: list[dict] = []
    for line in raw.decode("utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


@spec_ref(
    VERIFY("V-9", "operator",
           "Conduct the 20-item blinded operator exercise; record accuracy and decision time."),
)
def test_blinded_operator_exercise_accuracy_and_median_time(
    roots: ProofRoots
) -> None:
    """Scored by the harness against gold the operator never saw."""
    exercise = corpora.load_gold("operator_exercise.json")
    operator_exercise.validate(exercise)
    items = prereq.gold_records(
        exercise["items"], name="operator exercise", minimum=20,
        why="V-9 freezes a twenty-item blinded exercise",
    )
    presented = corpora.bind_operator_exercise(
        exercise, roots.run_root / "operator" / "exercise.jsonl"
    )
    responses = _operator_responses()
    prereq.collected(
        responses, what="recorded operator decisions", minimum=len(items),
        why="every presented item must carry a recorded decision; a missing "
            "decision is not an implicit approval",
    )
    gold = {presented.ids.token(i["item_id"]): i["gold_decision"] for i in items}
    response_ids = [str(r["item_id"]) for r in responses]
    if response_ids != list(gold):
        raise HarnessInvalid("operator responses must contain each presented ID exactly once, in presentation order")
    for response in responses:
        if response.get("decision") not in ("approve", "reject"):
            raise HarnessInvalid("operator decision must be approve or reject")
        if "also_belongs_in" in response:
            additional = response["also_belongs_in"]
            if not isinstance(additional, list) or any(
                store not in ("personal", "company", "codebase") for store in additional
            ):
                raise HarnessInvalid("also_belongs_in must list personal, company or codebase")
    answered = {str(r["item_id"]): r for r in responses}
    joined = prereq.gold_join(answered, gold, name="operator exercise")

    correct = 0
    seconds: list[float] = []
    previous = None
    # gold_join sorts opaque keys; timing must follow the recorded presentation.
    for token in response_ids:
        response = answered[token]
        if response.get("decision") == gold[token]:
            correct += 1
        stamp = _epoch(str(response["decided_at"]))
        if previous is not None:
            if stamp < previous:
                raise HarnessInvalid("operator decision timestamps must be monotonic")
            seconds.append(stamp - previous)
        previous = stamp
    rendered_input = presented.path.read_text(encoding="utf-8")
    O.check(
        "V-9.operator",
        {
            "item_count": len(items),
            "blinded": bool(exercise["blinded"]),
            "decisions_recorded": len(joined),
            "accuracy": correct / len(joined) if joined else 0.0,
            "median_decision_seconds": statistics.median(seconds) if seconds else 0.0,
            "gold_withheld_from_operator_input":
                "gold_decision" not in rendered_input
                and "gold_reason" not in rendered_input,
        },
        label="blinded operator accuracy and median decision time",
    )


def _epoch(stamp: str) -> float:
    from datetime import datetime

    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()


@spec_ref(
    VERIFY("V-9", "adequacy",
           "Run the frozen 100-observation/20-durable-fact maintenance workload through five "
           "simulated sliding-hour windows."),
)
@pytest.mark.slow
def test_corpus_growth_adequacy_under_the_fatigue_ceiling(
    kinbase: Kinbase, roots: ProofRoots, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    workload = corpora.load_gold("maintenance_workload.json")
    observations = prereq.gold_records(
        workload["observations"], name="maintenance workload", minimum=100,
        why="V-9 freezes a 100-observation workload",
    )
    bound = corpora.bind_maintenance_workload(
        workload, roots.run_root / "workload" / "all.jsonl"
    )
    per_window = max(1, len(observations) // WINDOWS)
    window_reports: list[dict] = []
    slots: set[str] = set()
    admitted_correct = 0
    gold = {
        bound.ids.token(o["observation_id"]): o for o in observations
    }
    for window in range(WINDOWS):
        # Distinct arrivals per window: the slice this window actually receives,
        # never the whole file five times.
        slice_path = roots.run_root / "workload" / ("w" + str(window) + ".jsonl")
        lines = bound.path.read_text(encoding="utf-8").splitlines()
        chunk = lines[window * per_window:(window + 1) * per_window]
        slice_path.write_text("\n".join(chunk) + "\n", encoding="utf-8")
        session = start_session(kinbase, world.repo.path)
        _run(kinbase, "session", "observe", session, "--event", str(slice_path),
             "--json", cwd=world.repo.path,
             env=kinbase.base_env({
                 "KINBASE_PROOF_CLOCK_OFFSET_SECONDS": str(window * 3600),
             }))
        listing = _json(_run(kinbase, "proposals", "list", "--session", session,
                             "--json", cwd=world.repo.path))
        candidates = rows(listing, "candidates")
        prompts = [c for c in candidates if field(c, "rendered") is True]
        for candidate in prompts:
            token = str(field(candidate, "message_id"))
            slots.add(token)
            record = gold.get(token)
            if record is not None and record.get("durable_shared_fact"):
                admitted_correct += 1
        window_reports.append({
            "window": window,
            "arrivals": len(chunk),
            "prompts": len(prompts),
        })
    ordering = _json(_run(kinbase, "doctor", "--repo", str(world.repo.path),
                          "--json", cwd=world.repo.path))
    O.check(
        "V-9.adequacy",
        {
            "observations_ingested": len(observations),
            "durable_facts": int(workload["durable_shared_fact_count"]),
            "decision_slots": len(slots),
            "admitted_correct": admitted_correct,
            "windows": window_reports,
            "low_authority_churn_displaced_high_distortion": field(
                ordering, "low_authority_displaced_high_distortion"),
            "gold_withheld_from_product":
                "durable_shared_fact" not in bound.path.read_text(encoding="utf-8"),
        },
        label="corpus growth adequacy under the fatigue ceiling",
    )
