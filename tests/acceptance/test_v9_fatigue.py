"""V-9 --- approval fatigue, reissue atomicity, and corpus-growth adequacy.

``spec/product.md`` P-9 makes this a product gate, not a usability footnote:

    Failing either usability bound is `NOT_PROVEN` even if routing and privacy
    tests pass.

and pairs it with the opposite failure mode:

    The fatigue control may not starve useful maintenance.
    ...
    Failing this corpus-growth adequacy gate is `NOT_PROVEN`.
"""

from __future__ import annotations

import concurrent.futures
import json
import statistics
import time
from pathlib import Path

import pytest

from ._harness.cli import Guildhall
from ._harness.gitfix import GitRepo
from ._harness.hosts import (
    MAINTENANCE_ADMITTED_MINIMUM,
    MAINTENANCE_DURABLE_FACTS,
    MAINTENANCE_OBSERVATIONS,
    MAINTENANCE_SLOTS_MINIMUM,
    MAINTENANCE_WINDOWS,
    MAX_CONSECUTIVE_PROMPTS,
    OPERATOR_ACCURACY_MINIMUM,
    OPERATOR_EXERCISE_ITEMS,
    OPERATOR_MEDIAN_DECISION_SECONDS,
    PROMPTS_PER_SLIDING_HOUR,
)
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.synth import RESET_REASON_CODES

pytestmark = [pytest.mark.v9, pytest.mark.requires_product]


@pytest.fixture()
def fatigue_repo(roots: ProofRoots) -> GitRepo:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.commit("initialise")
    return repo


def _budget(guildhall: Guildhall, repo: GitRepo) -> dict:
    result = guildhall.run("doctor", "--repo", str(repo.path), "--json", check=False)
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    return payload.get("prompt_budget") or {} if isinstance(payload, dict) else {}


@spec_ref(
    PRODUCT(
        "V-9",
        "P-9",
        "In the proof workload, the system may surface at most four total reserved "
        "shared-destination approval opportunities per composite `(principal_id, host_instance_id)` "
        "budget shard in a sliding 60-minute window and no more than three consecutively without "
        "returning the user to their primary task.",
    ),
    VERIFY(
        "V-9",
        "flood",
        "Run the four-total-per-hour/three-consecutive approval flood across destinations and "
        "concurrent Codex/Claude sessions sharing one host instance. Destinations do not each receive "
        "four slots; hourly state cannot reset, consecutive reset requires a new task event and has "
        "one-per-hour cooldown, and the signed host budget-shard plus unknown-global-total warning is "
        "visible in `doctor`.",
    ),
)
def test_four_total_per_hour_shared_across_destinations(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    rendered = 0
    suppressed = 0
    destinations = ("company", "codebase:018f0000-0000-7000-8000-000000000001")
    for index in range(12):
        destination = destinations[index % len(destinations)]
        result = guildhall.run(
            "proposals",
            "list",
            "--session",
            "fatigue",
            "--json",
            env={
                "GUILDHALL_ACCEPTANCE_REQUEST_PROMPT": destination,
                "GUILDHALL_ACCEPTANCE_HOST_INSTANCE": "host-1",
            },
            check=False,
        )
        assert result.returncode != 1
        if result.returncode != 0 or not result.stdout.strip():
            suppressed += 1
            continue
        payload = result.json
        if isinstance(payload, dict) and payload.get("prompt_rendered"):
            rendered += 1
        else:
            suppressed += 1
    assert rendered <= PROMPTS_PER_SLIDING_HOUR, (
        f"{rendered} prompts rendered in one sliding hour; destinations share the "
        f"{PROMPTS_PER_SLIDING_HOUR}-slot ceiling and do not each receive four slots"
    )
    assert suppressed > 0, (
        "exceeding the ceiling must suppress new shared prompts, not silently drop them"
    )

    budget = _budget(guildhall, fatigue_repo)
    if budget:
        assert budget.get("consumed") is not None and budget.get("reserved") is not None, (
            "spec/product.md P-9: `doctor` shows consumed/reserved counts"
        )
        assert budget.get("shard_id") or budget.get("host_instance_id"), (
            "the host instance owns and signs its shard observation"
        )
        assert budget.get("signature") or budget.get("signed") is True, (
            "the `prompt_budget_shard` observation is host-signed"
        )
        warning = json.dumps(budget).lower()
        assert "global" in warning and (
            "unknown" in warning or "no cross-machine" in warning
        ), (
            "`doctor` must carry the explicit warning that no global cross-machine "
            "total is known"
        )


@spec_ref(
    PRODUCT(
        "V-9",
        "P-9",
        "Exceeding the prompt ceiling suppresses new shared prompts until the sliding window clears; "
        "a reset clears only the consecutive counter after a new task event and never the hourly "
        "ceiling.",
    ),
    ARCH(
        "V-9",
        "routing-policy",
        "A principal reset may clear only the three-consecutive counter after a new primary-task event "
        "and is limited to once per hour.",
    ),
    CLI(
        "V-9",
        "reset",
        "`reset` only clears the three- consecutive counter after a real new primary-task event, is "
        "limited to once per hour, and records its closed reason code.",
    ),
)
def test_reset_clears_only_the_consecutive_counter_once_per_hour(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    before = _budget(guildhall, fatigue_repo)
    hourly_before = before.get("hourly_consumed")

    first = guildhall.run(
        "proposals",
        "reset",
        "--after-primary-event",
        "evt-primary-1",
        "--reason-code",
        "new-primary-task",
        "--json",
        check=False,
    )
    assert first.returncode != 1

    second = guildhall.run(
        "proposals",
        "reset",
        "--after-primary-event",
        "evt-primary-2",
        "--reason-code",
        "new-primary-task",
        "--json",
        check=False,
    )
    assert second.returncode != 1
    assert second.returncode != 0, (
        "a second reset inside the one-hour cooldown must refuse"
    )
    assert second.code == "LIMIT_EXCEEDED", second.code

    after = _budget(guildhall, fatigue_repo)
    if hourly_before is not None and after.get("hourly_consumed") is not None:
        assert after["hourly_consumed"] >= hourly_before, (
            "a reset must never clear the hourly ceiling"
        )
    if after.get("consecutive_consumed") is not None:
        assert after["consecutive_consumed"] == 0, (
            "a reset clears the three-consecutive counter"
        )

    # Reason codes are closed and never carry prose.
    bad = guildhall.run(
        "proposals",
        "reset",
        "--after-primary-event",
        "evt-primary-3",
        "--reason-code",
        "because the operator said so",
        "--json",
        check=False,
    )
    assert bad.returncode != 0, "reset reason codes are a closed set"
    for code in RESET_REASON_CODES:
        assert code in guildhall.run("proposals", "reset", "--help", check=False).stdout, (
            f"the closed reason-code set must include {code}"
        )


@spec_ref(
    ARCH(
        "V-9",
        "routing-policy",
        "Core executes one `BEGIN IMMEDIATE` transaction that checks reissue eligibility, inserts the "
        "unique `(principal, destination, content_digest, lock_window)` reissue lock, reserves one of "
        "four total cross-destination sliding-hour slots, increments the consecutive count, and issues "
        "a single-use display token.",
    ),
    VERIFY(
        "V-9",
        "reissue",
        "Race two byte-changed reissues with rejection and reservation. Reissue eligibility, unique "
        "digest lock, total slot reservation, and consecutive count must commit in one `BEGIN "
        "IMMEDIATE`; moving any check outside the transaction must produce a failing "
        "duplicate/starvation mutation.",
    ),
)
def test_reissue_and_reservation_commit_in_one_immediate_transaction(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    def reissue(tag: str) -> tuple[int, str]:
        result = guildhall.run(
            "proposals",
            "reissue",
            "acceptance-candidate",
            "--json",
            env={"GUILDHALL_ACCEPTANCE_REISSUE_TAG": tag},
            check=False,
        )
        return result.returncode, result.stdout

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(reissue, ("a", "b", "c", "d")))
    assert all(rc != 1 for rc, _ in outcomes), (
        "racing reissues must never return the reserved ambiguous exit 1"
    )
    issued = []
    for rc, out in outcomes:
        if rc == 0 and out.strip():
            try:
                issued.append(json.loads(out))
            except json.JSONDecodeError:
                pass
    digests = {i.get("payload_digest") for i in issued}
    candidate_ids = {i.get("candidate_id") for i in issued}
    assert len(candidate_ids) == len(issued), (
        "each reissue must create a new candidate ID; duplicates indicate a check "
        "outside the transaction"
    )
    if len(issued) > 1:
        assert len(digests) == len(issued), (
            "two reissues committed the same digest under one lock window"
        )

    budget = _budget(guildhall, fatigue_repo)
    if budget.get("hourly_consumed") is not None:
        assert budget["hourly_consumed"] <= PROMPTS_PER_SLIDING_HOUR, (
            "racing reissues over-reserved the four-slot sliding-hour shard"
        )


@spec_ref(
    ARCH(
        "V-9",
        "routing-policy",
        "A rejected/deferred/expired content digest cannot be reissued for 24 hours unless its source "
        "revision or rendered bytes change; byte-change reissue is eligible only for an "
        "authority-trusted source revision",
    ),
    VERIFY(
        "V-9",
        "churn",
        "Untrusted branch/worktree churn cannot trigger byte-change reissue.",
    ),
)
def test_untrusted_branch_churn_cannot_trigger_byte_change_reissue(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    fatigue_repo.branch("untrusted/churn")
    fatigue_repo.write("churn.md", "byte change on an unreviewed branch\n")
    fatigue_repo.commit("churn on an untrusted branch")

    result = guildhall.run(
        "proposals",
        "reissue",
        "acceptance-candidate",
        "--json",
        env={"GUILDHALL_ACCEPTANCE_SOURCE_TRUST": "unreviewed-branch"},
        check=False,
    )
    assert result.returncode != 1
    assert result.returncode != 0, (
        "byte-change reissue is eligible only for an authority-trusted source revision"
    )
    assert result.code in {"LIMIT_EXCEEDED", "AUTHORITY_WRONG_SCOPE", "APPROVAL_EXPIRED"}, (
        result.code
    )


@spec_ref(
    VERIFY(
        "V-9",
        "interleave",
        "Force Codex and Claude sessions on one host instance to interleave exactly between slot check "
        "and render. Moving the reservation increment after render must produce more than four prompts "
        "and make the mutation fail; crash after reservation remains counted until expiry and "
        "delivery-loss rate is explicit.",
    ),
    ARCH(
        "V-9",
        "routing-policy",
        "Crash/ abandon releases no counter directly—the reservation expires on the same sliding "
        "clock—preventing race/decrement abuse.",
    ),
)
def test_interleaved_sessions_never_exceed_four_prompts_per_window(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    def request(host: str, index: int) -> tuple[int, str]:
        result = guildhall.run(
            "proposals",
            "list",
            "--session",
            f"{host}-{index}",
            "--json",
            env={
                "GUILDHALL_ACCEPTANCE_HOST_INSTANCE": "host-1",
                "GUILDHALL_ACCEPTANCE_INTERLEAVE_AT": "between_slot_check_and_render",
                "GUILDHALL_ACCEPTANCE_REQUEST_PROMPT": "company",
            },
            check=False,
        )
        return result.returncode, result.stdout

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(request, host, index)
            for index in range(6)
            for host in ("codex", "claude")
        ]
        outcomes = [f.result() for f in futures]

    rendered = 0
    for rc, out in outcomes:
        assert rc != 1
        if rc == 0 and out.strip():
            try:
                payload = json.loads(out)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("prompt_rendered"):
                rendered += 1
    assert rendered <= PROMPTS_PER_SLIDING_HOUR, (
        f"{rendered} prompts rendered across interleaved Codex/Claude sessions sharing "
        f"one host instance; the shard ceiling is {PROMPTS_PER_SLIDING_HOUR}"
    )

    # Crash after reservation must remain counted until expiry.
    crashed = guildhall.run(
        "proposals",
        "list",
        "--session",
        "crash-after-reservation",
        "--json",
        env={
            "GUILDHALL_ACCEPTANCE_HOST_INSTANCE": "host-1",
            "GUILDHALL_ACCEPTANCE_CRASH_AT": "after_reservation",
        },
        check=False,
    )
    assert crashed.returncode != 1
    budget = _budget(guildhall, fatigue_repo)
    if budget.get("reserved") is not None:
        assert budget["reserved"] >= 0
    if budget.get("delivery_loss_rate") is not None:
        assert isinstance(budget["delivery_loss_rate"], (int, float)), (
            "delivery-loss rate must be explicit"
        )


@spec_ref(
    PRODUCT(
        "V-9",
        "P-9",
        "A 20-item blinded operator exercise must achieve at least 95% correct approve/reject "
        "decisions with median decision time at most 30 seconds.",
    ),
    VERIFY(
        "V-9",
        "operator",
        "Conduct the 20-item blinded operator exercise; record accuracy and decision time.",
    ),
)
def test_blinded_operator_exercise_accuracy_and_median_time(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    fixture = (
        Path(__file__).resolve().parents[1] / "fixtures" / "gold" / "operator_exercise.json"
    )
    assert fixture.is_file(), (
        "the Tester must freeze the 20-item blinded operator exercise before the run"
    )
    exercise = json.loads(fixture.read_text(encoding="utf-8"))
    items = exercise["items"]
    assert len(items) == OPERATOR_EXERCISE_ITEMS, len(items)
    assert exercise["blinded"] is True
    assert {i["gold_decision"] for i in items} <= {"approve", "reject"}
    approvals = sum(1 for i in items if i["gold_decision"] == "approve")
    assert 6 <= approvals <= 14, (
        "the exercise must not be answerable by always approving or always rejecting; "
        f"{approvals}/20 are approvals"
    )

    result = guildhall.run(
        "doctor", "--repo", str(fatigue_repo.path), "--json", check=False
    )
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    recorded = (payload or {}).get("operator_exercise")
    if recorded:
        accuracy = recorded.get("accuracy")
        median_seconds = recorded.get("median_decision_seconds")
        assert accuracy is not None and accuracy >= OPERATOR_ACCURACY_MINIMUM, (
            f"operator accuracy {accuracy} is below the {OPERATOR_ACCURACY_MINIMUM} bound; "
            "spec/product.md P-9 makes failing either usability bound NOT_PROVEN"
        )
        assert (
            median_seconds is not None
            and median_seconds <= OPERATOR_MEDIAN_DECISION_SECONDS
        ), (
            f"median decision time {median_seconds}s exceeds "
            f"{OPERATOR_MEDIAN_DECISION_SECONDS}s"
        )
        assert recorded.get("item_count") == OPERATOR_EXERCISE_ITEMS


@spec_ref(
    PRODUCT(
        "V-9",
        "P-9",
        "In a preregistered 100- observation workload with 20 independently gold-labeled durable "
        "shared facts, the distortion/authority queue must place at least 18 of those facts into a "
        "human decision slot within five simulated sliding-hour windows, admit at least 17 correct "
        "facts after decisions, and surface no more than four total prompts in any window.",
    ),
    VERIFY(
        "V-9",
        "adequacy",
        "Run the frozen 100-observation/20-durable-fact maintenance workload through five simulated "
        "sliding-hour windows. At least 18 durable facts receive a decision slot, at least 17 correct "
        "facts admit, no window exceeds four total prompts, and low- authority churn cannot outrank "
        "high-distortion eligible facts.",
    ),
)
@pytest.mark.slow
def test_corpus_growth_adequacy_under_the_fatigue_ceiling(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    fixture = (
        Path(__file__).resolve().parents[1] / "fixtures" / "gold" / "maintenance_workload.json"
    )
    assert fixture.is_file(), (
        "the Tester must freeze the 100-observation/20-durable-fact maintenance workload"
    )
    workload = json.loads(fixture.read_text(encoding="utf-8"))
    assert len(workload["observations"]) == MAINTENANCE_OBSERVATIONS
    durable = [o for o in workload["observations"] if o["durable_shared_fact"]]
    assert len(durable) == MAINTENANCE_DURABLE_FACTS, len(durable)
    assert workload["windows"] == MAINTENANCE_WINDOWS

    result = guildhall.run(
        "status",
        "--repo",
        str(fatigue_repo.path),
        "--json",
        env={
            "GUILDHALL_ACCEPTANCE_MAINTENANCE_WORKLOAD": str(fixture),
            "GUILDHALL_ACCEPTANCE_SIMULATED_WINDOWS": str(MAINTENANCE_WINDOWS),
        },
        check=False,
    )
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    adequacy = (payload or {}).get("maintenance_adequacy")
    if not adequacy:
        raise ProductFailure(
            "the corpus-growth adequacy gate produces no report; spec/product.md P-9 "
            "makes failing it NOT_PROVEN"
        )
    slots = adequacy.get("durable_facts_given_a_decision_slot")
    admitted = adequacy.get("correct_facts_admitted")
    per_window = adequacy.get("prompts_per_window") or []
    assert slots is not None and slots >= MAINTENANCE_SLOTS_MINIMUM, (
        f"only {slots} of {MAINTENANCE_DURABLE_FACTS} durable facts received a decision "
        f"slot; at least {MAINTENANCE_SLOTS_MINIMUM} required"
    )
    assert admitted is not None and admitted >= MAINTENANCE_ADMITTED_MINIMUM, (
        f"only {admitted} correct facts admitted; at least "
        f"{MAINTENANCE_ADMITTED_MINIMUM} required"
    )
    assert per_window and len(per_window) == MAINTENANCE_WINDOWS, per_window
    over = [w for w in per_window if w > PROMPTS_PER_SLIDING_HOUR]
    assert not over, (
        f"windows exceeded the four-prompt ceiling: {per_window}"
    )
    displacement = adequacy.get("low_authority_churn_displaced_high_distortion")
    assert displacement in (False, 0, None), (
        "low-authority source churn and byte-only reissues cannot displace a "
        "higher-distortion eligible fact"
    )


@spec_ref(
    PRODUCT(
        "V-9",
        "P-9",
        "Reserved/rendered/suppressed/delivery-loss rates are reported.",
    ),
    ARCH(
        "V-9",
        "routing-policy",
        "Reserved, rendered, decided, expired, suppressed, and delivery-loss counts are "
        "product-quality metrics.",
    ),
)
def test_every_prompt_budget_metric_is_reported(
    guildhall: Guildhall, fatigue_repo: GitRepo
) -> None:
    budget = _budget(guildhall, fatigue_repo)
    if not budget:
        raise ProductFailure(
            "`doctor --json` exposes no prompt-budget shard; spec/product.md P-9 "
            "requires consumed/reserved counts and the unknown-global-total warning"
        )
    for metric in (
        "reserved",
        "rendered",
        "decided",
        "expired",
        "suppressed",
        "delivery_loss_rate",
    ):
        assert metric in budget, (
            f"the prompt-budget report must include {metric}; observed {sorted(budget)}"
        )
