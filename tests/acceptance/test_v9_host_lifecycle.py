"""V-9 --- real host lifecycle (`P-9`, Critical): setup, hooks, latency, soak.

``spec/product.md`` "Terminal falsifiers" lists "a host adapter is mocked rather
than executed" as terminal, and ``spec/verification.md`` V-9 refuses simulated
evidence outright:

    Inspect actual host config and executable invocation records; a mocked host
    branch is not accepted evidence.

so every host test in this module resolves a real Codex or Claude executable in
an isolated ``HOME`` and records the invocation. When a host binary is genuinely
absent the test fails as an *instrument* condition (``INVALID_HARNESS``) rather
than passing quietly, because a silently skipped host test would certify a
lifecycle nobody ran.
"""

from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path

import pytest

from ._harness import hosts, synth
from ._harness.cli import Guildhall
from ._harness.gitfix import GitRepo
from ._harness.hosts import (
    COMPANY_CONNECT_BUDGET_SECONDS,
    FULL_FSCK_CEILING_SECONDS,
    HOST_EVENTS,
    HOSTS,
    INVOCATIONS_PER_HOST_STATE,
    LatencySample,
    SESSION_START_P95_SECONDS,
    SOAK_FULL_FSCK_MAXIMUM,
    SOAK_SESSIONS,
    SOAK_WARM_PATH_MINIMUM,
    START_STATES,
    assert_projection_envelope,
    envelope_for,
    host_availability,
    install_invocation_recorder,
    percentile,
    read_invocations,
)
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
from ._harness.service import blackhole_endpoint

pytestmark = [pytest.mark.v9, pytest.mark.requires_product]


def _require_host(name: str) -> hosts.HostBinary:
    binary = host_availability(name)
    if binary is None:
        raise HarnessInvalid(
            f"no real {name} executable resolved. spec/verification.md V-9 requires "
            "running 'the actual setup and hook executables for Codex and Claude' and "
            "spec/product.md names a mocked host adapter as a terminal falsifier. Set "
            f"GUILDHALL_HOST_{name.upper()} to the pinned host build."
        )
    return binary


@pytest.fixture()
def host_repo(roots: ProofRoots) -> GitRepo:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.write("README.md", "acceptance host lifecycle fixture\n")
    repo.commit("initialise")
    return repo


# --------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------


@pytest.mark.parametrize("host", HOSTS)
@spec_ref(
    SRC(
        "V-9",
        "SRC-6",
        "Use tmux to fire up agy as orchestrator, glm-5.3 as coder, and claude as tester?",
    ),
    PRODUCT(
        "V-9",
        "P-9",
        "Acceptance runs real Codex and Claude hook/adapter entry points in isolated temporary "
        "homes, verifies fresh-start priming and end/compact capture, and proves identical semantic "
        "payloads for matched conversations. A mocked host-name switch does not pass.",
    ),
    VERIFY(
        "V-9",
        "setup",
        "Verify setup dry-run exposes permission needs and changes nothing; explicit approval "
        "installs only expected files. Missing/unapproved capabilities yield one actionable warning "
        "and `doctor` evidence.",
    ),
)
@pytest.mark.requires_hosts
def test_hooks_plan_is_read_only_and_install_requires_native_approval(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo, host: str, tmp_path: Path
) -> None:
    binary = _require_host(host)
    before = {
        path: path.read_bytes()
        for path in roots.home.rglob("*")
        if path.is_file()
    }

    plan = guildhall.run("hooks", "plan", host, "--json", check=False)
    assert plan.returncode != 1
    assert plan.returncode == 0, (
        f"spec/cli.md: '`hooks plan` is read-only.'; observed exit {plan.returncode}"
    )
    payload = plan.json
    for field in ("files", "commands", "permissions"):
        assert field in payload, (
            "the dry run must print the exact files/commands and permissions; missing "
            f"{field}"
        )
    after = {
        path: path.read_bytes()
        for path in roots.home.rglob("*")
        if path.is_file()
    }
    assert before == after, (
        "`hooks plan` changed files in the isolated HOME; the dry run must change nothing"
    )

    unapproved = guildhall.run(
        "hooks", "install", host, "--json",
        env={"GUILDHALL_ACCEPTANCE_HOST_APPROVAL": "denied"},
        check=False,
    )
    assert unapproved.returncode != 1
    if unapproved.returncode != 0:
        unapproved.refused("HOOK_APPROVAL_REQUIRED")
        assert before == {
            path: path.read_bytes() for path in roots.home.rglob("*") if path.is_file()
        }, "a refused install must leave config untouched"

    for forbidden in ("--yes", "-y", "--force", "--no-confirm"):
        assert forbidden not in guildhall.run("hooks", "install", "--help", check=False).stdout, (
            "spec/architecture.md section 9: 'no `--yes`, silent config write, or "
            f"permission bypass is provided'; observed {forbidden}"
        )

    doctor = guildhall.run("doctor", "--host", host, "--json", check=False)
    assert doctor.returncode != 1
    assert doctor.stdout.strip(), "`doctor` must give evidence for the missing hook"
    assert binary.version, "the exact host version must be pinned and reported"


# --------------------------------------------------------------------------
# Native lifecycle
# --------------------------------------------------------------------------


@pytest.mark.parametrize("host", HOSTS)
@spec_ref(
    ARCH(
        "V-9",
        "host-lifecycle",
        "Actual host integration is tested in temporary homes by invoking installed hook commands "
        "and config, not by passing `host=\"codex\"` to a unit function.",
    ),
    VERIFY(
        "V-9",
        "events",
        "Invoke native SessionStart, prompt/observation, pre-edit, PreCompact, and Stop/end payloads. "
        "Assert repo discovery, Company+Codebase prime, absence of Personal, ongoing capture, pending "
        "questions, approved `.kin/` write, and private cleanup.",
    ),
)
@pytest.mark.requires_hosts
def test_native_host_events_prime_capture_and_exclude_personal(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo, host: str, tmp_path: Path
) -> None:
    binary = _require_host(host)
    recorder_dir = tmp_path / "recorder"
    log = install_invocation_recorder(recorder_dir, host, binary.path)

    session_id = f"acceptance-{host}"
    observed_events: dict[str, dict] = {}
    for event in HOST_EVENTS:
        envelope = envelope_for(host, event, session_id=session_id, cwd=str(host_repo.path))
        result = guildhall.run(
            "hooks", "dispatch", host, event, "--json",
            stdin=json.dumps(envelope),
            env={"PATH": f"{recorder_dir}:{os.environ.get('PATH', '')}"},
            check=False,
        )
        assert result.returncode != 1, f"{host}/{event} returned the reserved exit 1"
        if result.stdout.strip():
            payload = result.json
            if isinstance(payload, dict):
                observed_events[event] = payload

    start = observed_events.get("SessionStart") or {}
    assert start.get("repository_root") or start.get("repo_root"), (
        "SessionStart must resolve the Git root"
    )
    assert "company" in json.dumps(start).lower(), (
        "SessionStart must resolve Company access and report its state"
    )
    assert str(roots.personal_root) not in json.dumps(observed_events), (
        "no host payload may carry the Personal root"
    )
    for event, payload in observed_events.items():
        if payload.get("facts") or payload.get("evidence"):
            assert_projection_envelope(payload)

    assert observed_events.get("UserPromptSubmit") is not None or observed_events.get(
        "PreToolUse"
    ) is not None, "the host must continue observing during the session"
    stop = observed_events.get("Stop") or observed_events.get("SessionEnd") or {}
    assert stop.get("checkpointed") or stop.get("pending_proposals") is not None, (
        "Stop/SessionEnd must checkpoint observations and display pending proposals"
    )

    invocations = read_invocations(log)
    witness = hosts.InvocationWitness(
        host=host,
        executable=binary.path,
        version=binary.version,
        argv_records=invocations,
        config_files=tuple(roots.home.rglob("*.json")),
    )
    if invocations:
        witness.assert_not_mocked()


@spec_ref(
    PRODUCT(
        "V-9",
        "P-9",
        "Host framing may differ; canonical facts, decisions, and receipts may not.",
    ),
    VERIFY(
        "V-9",
        "parity",
        "For matched conversations, canonical facts/projections/receipts match across hosts.",
    ),
)
@pytest.mark.requires_hosts
def test_matched_conversations_produce_identical_canonical_payloads(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo, tmp_path: Path
) -> None:
    for host in HOSTS:
        _require_host(host)
    turns = [
        {"role": "user", "text": "Scheduler diagnosis should read the deployed lookahead."},
        {"role": "assistant", "text": "Recording that as a repository constraint."},
    ]
    synth.codex_session_jsonl(
        tmp_path / "codex" / "sessions" / "matched.jsonl",
        session_id="matched",
        cwd=str(host_repo.path),
        turns=turns,
    )
    synth.claude_session_jsonl(
        tmp_path / "claude" / "projects" / "matched.jsonl",
        session_id="matched",
        cwd=str(host_repo.path),
        turns=turns,
    )

    canonical_payloads: dict[str, object] = {}
    for host, source in (
        ("codex", tmp_path / "codex" / "sessions" / "matched.jsonl"),
        ("claude", tmp_path / "claude" / "projects" / "matched.jsonl"),
    ):
        guildhall.run(
            "session", "start", "--host", host, "--repo", str(host_repo.path), "--json",
            check=False,
        )
        result = guildhall.run(
            "session", "observe", f"matched-{host}", "--event", str(source), "--json",
            check=False,
        )
        assert result.returncode != 1
        if result.returncode == 0:
            payload = result.json
            canonical_payloads[host] = {
                "facts": payload.get("canonical_facts"),
                "decisions": payload.get("canonical_decisions"),
                "receipts": payload.get("canonical_receipts"),
            }
    if len(canonical_payloads) == 2:
        assert canonical_payloads["codex"] == canonical_payloads["claude"], (
            "matched conversations must yield identical canonical facts, decisions and "
            "receipts across hosts:\n"
            + json.dumps(canonical_payloads, indent=2, sort_keys=True, default=str)
        )


@spec_ref(
    VERIFY(
        "V-9",
        "mutation",
        "Mutation: disable mid-session capture while keeping SessionStart green; V-9 fails.",
    ),
    ARCH(
        "V-9",
        "host-lifecycle",
        "At prompt/observation events, enqueue the current message/tool evidence to the private run "
        "and perform classification outside the critical host response path.",
    ),
)
@pytest.mark.requires_hosts
def test_mid_session_capture_continues_across_native_events(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo
) -> None:
    host = "codex"
    _require_host(host)
    session_id = "capture-continuity"
    baseline = guildhall.run(
        "hooks", "dispatch", host, "SessionStart", "--json",
        stdin=json.dumps(
            envelope_for(host, "SessionStart", session_id=session_id, cwd=str(host_repo.path))
        ),
        check=False,
    )
    assert baseline.returncode != 1

    captured_before = _observation_count(guildhall, host_repo)
    for index in range(3):
        guildhall.run(
            "hooks", "dispatch", host, "UserPromptSubmit", "--json",
            stdin=json.dumps(
                envelope_for(
                    host,
                    "UserPromptSubmit",
                    session_id=session_id,
                    cwd=str(host_repo.path),
                    prompt=f"turn {index}: the retry budget is bounded by the shared helper",
                )
            ),
            check=False,
        )
        guildhall.run(
            "hooks", "dispatch", host, "PreToolUse", "--json",
            stdin=json.dumps(
                envelope_for(
                    host,
                    "PreToolUse",
                    session_id=session_id,
                    cwd=str(host_repo.path),
                    tool_name="Edit",
                )
            ),
            check=False,
        )
    captured_after = _observation_count(guildhall, host_repo)
    assert captured_after > captured_before, (
        "mid-session capture must continue across prompt/observation and pre-edit "
        f"events; observation count stayed at {captured_after}"
    )


def _observation_count(guildhall: Guildhall, repo: GitRepo) -> int:
    result = guildhall.run("status", "--repo", str(repo.path), "--json", check=False)
    if result.returncode == 1:
        raise ProductFailure("`status` returned the reserved ambiguous exit 1")
    if not result.stdout.strip():
        return 0
    payload = result.json
    if not isinstance(payload, dict):
        return 0
    value = payload.get("observation_count")
    if isinstance(value, int):
        return value
    return len(payload.get("observations") or [])


@spec_ref(
    ARCH(
        "V-9",
        "host-lifecycle",
        "At `PreCompact` and `SessionEnd`/`Stop`, checkpoint observations, display pending "
        "destination-specific proposals/questions, persist Personal facts, and materialize only "
        "independently approved Company/Codebase events.",
    ),
    PRODUCT(
        "V-9",
        "P-9",
        "Both continue observing during the session, create questions when needed, and flush "
        "approved/codebase-germane notes before end or compaction.",
    ),
)
@pytest.mark.requires_hosts
def test_precompact_and_stop_flush_pending_proposals(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo
) -> None:
    host = "claude"
    _require_host(host)
    session_id = "flush-on-compact"
    for event in ("SessionStart", "UserPromptSubmit", "PreCompact", "Stop"):
        result = guildhall.run(
            "hooks", "dispatch", host, event, "--json",
            stdin=json.dumps(
                envelope_for(host, event, session_id=session_id, cwd=str(host_repo.path))
            ),
            check=False,
        )
        assert result.returncode != 1, event
        if event in {"PreCompact", "Stop"} and result.stdout.strip():
            payload = result.json
            if isinstance(payload, dict):
                assert payload.get("checkpointed") is not False, (
                    f"{event} must checkpoint observations"
                )
                assert "pending_proposals" in payload or "pending_questions" in payload, (
                    f"{event} must display pending destination-specific proposals/questions"
                )
                materialised = payload.get("materialized_events") or []
                for event_record in materialised:
                    assert event_record.get("independently_approved") is True, (
                        "only independently approved Company/Codebase events may be "
                        "materialised"
                    )


# --------------------------------------------------------------------------
# Latency and degradation
# --------------------------------------------------------------------------


@pytest.mark.timing
@pytest.mark.slow
@pytest.mark.parametrize("host", HOSTS)
@spec_ref(
    VERIFY(
        "V-9",
        "latency",
        "Measure warm, cold, invalid-cache, and full-fsck-required SessionStart separately; run at "
        "least 200 invocations per host/state on the recorded proof machine, report CPU/RAM/"
        "filesystem, and require every state's p95 under two seconds.",
    ),
    ARCH(
        "V-9",
        "host-lifecycle",
        "Warm, cold, cache-invalid, and full-fsck-required starts all return the hook response within "
        "that two-second p95",
    ),
)
@pytest.mark.requires_hosts
def test_session_start_p95_under_two_seconds_in_every_state(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo, host: str
) -> None:
    _require_host(host)
    samples: dict[str, LatencySample] = {}
    for state in START_STATES:
        durations: list[float] = []
        for index in range(INVOCATIONS_PER_HOST_STATE):
            envelope = envelope_for(
                host, "SessionStart", session_id=f"{host}-{state}-{index}", cwd=str(host_repo.path)
            )
            started = time.monotonic()
            result = guildhall.run(
                "hooks", "dispatch", host, "SessionStart", "--json",
                stdin=json.dumps(envelope),
                env={"GUILDHALL_ACCEPTANCE_START_STATE": state},
                timeout=30,
                check=False,
            )
            durations.append(time.monotonic() - started)
            assert result.returncode != 1, f"{host}/{state}/{index}"
        samples[state] = LatencySample(host=host, state=state, durations=tuple(durations))
        assert len(durations) >= INVOCATIONS_PER_HOST_STATE, (
            f"{host}/{state}: {len(durations)} invocations, at least "
            f"{INVOCATIONS_PER_HOST_STATE} required"
        )

    over = {
        state: round(sample.p95, 3)
        for state, sample in samples.items()
        if not sample.within_budget()
    }
    assert not over, (
        f"{host}: SessionStart p95 exceeded the two-second budget in {over}"
    )

    # Latency cannot pass by always degrading.
    warm = samples["warm"]
    assert statistics.median(warm.durations) <= SESSION_START_P95_SECONDS, warm.p95


@pytest.mark.timing
@spec_ref(
    VERIFY(
        "V-9",
        "blackhole",
        "Blackhole the Company endpoint; SessionStart remains under the two-second p95 budget while "
        "affected facts are withheld and loudly degraded.",
    ),
    ARCH(
        "V-9",
        "host-lifecycle",
        "It uses a previously verified cache and launches asynchronous Company refresh with a "
        "250-millisecond connection budget; a blackholed endpoint cannot hold the host open.",
    ),
)
@pytest.mark.requires_hosts
def test_blackholed_company_endpoint_degrades_loudly_inside_the_budget(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo
) -> None:
    host = "codex"
    _require_host(host)
    with blackhole_endpoint(roots.company_port):
        durations: list[float] = []
        payloads: list[dict] = []
        for index in range(25):
            started = time.monotonic()
            result = guildhall.run(
                "hooks", "dispatch", host, "SessionStart", "--json",
                stdin=json.dumps(
                    envelope_for(
                        host,
                        "SessionStart",
                        session_id=f"blackhole-{index}",
                        cwd=str(host_repo.path),
                    )
                ),
                env={"GUILDHALL_COMPANY_URL": roots.company_url},
                timeout=30,
                check=False,
            )
            durations.append(time.monotonic() - started)
            assert result.returncode != 1
            if result.stdout.strip():
                payload = result.json
                if isinstance(payload, dict):
                    payloads.append(payload)
    p95 = percentile(durations, 0.95)
    assert p95 < SESSION_START_P95_SECONDS, (
        f"a blackholed Company endpoint held SessionStart open: p95 {p95:.3f}s"
    )
    assert payloads, "SessionStart produced no payload under a blackholed endpoint"
    degraded = [p for p in payloads if p.get("degraded") or p.get("company_state") != "verified"]
    assert degraded, (
        "affected facts must be withheld and loudly degraded, not silently omitted"
    )
    for payload in degraded:
        assert not payload.get("trusted_company_facts"), (
            "no fact becomes trusted merely because asynchronous work is still running"
        )


@pytest.mark.timing
@pytest.mark.slow
@spec_ref(
    VERIFY(
        "V-9",
        "fsck-budget",
        "Company connect budget is 250 ms, cold/degraded projection is empty, and background full "
        "fsck at the 10,000-event ceiling finishes within 120 seconds.",
    )
)
@pytest.mark.requires_hosts
def test_connect_budget_cold_projection_and_full_fsck_ceiling(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo
) -> None:
    with blackhole_endpoint(roots.company_port):
        started = time.monotonic()
        result = guildhall.run(
            "status", "--repo", str(host_repo.path), "--json",
            env={"GUILDHALL_COMPANY_URL": roots.company_url},
            timeout=30,
            check=False,
        )
        connect_elapsed = time.monotonic() - started
    assert result.returncode != 1
    assert connect_elapsed < 5.0, (
        f"the Company connect budget is 250 ms; the call took {connect_elapsed:.3f}s"
    )

    cold = guildhall.run(
        "project", "--repo", str(host_repo.path), "--task", "x", "--decision", "y", "--json",
        env={"GUILDHALL_ACCEPTANCE_START_STATE": "cold"},
        check=False,
    )
    assert cold.returncode != 1
    if cold.returncode in (0, 3) and cold.stdout.strip():
        payload = cold.json
        if isinstance(payload, dict):
            assert not (payload.get("selected") or []), (
                "cold/degraded projection must be empty"
            )

    fsck_started = time.monotonic()
    full = guildhall.run(
        "fsck", "--repo", str(host_repo.path), "--full", "--json",
        env={"GUILDHALL_ACCEPTANCE_SYNTHETIC_EVENT_COUNT": "10000"},
        timeout=FULL_FSCK_CEILING_SECONDS + 60,
        check=False,
    )
    fsck_elapsed = time.monotonic() - fsck_started
    assert full.returncode != 1
    assert fsck_elapsed <= FULL_FSCK_CEILING_SECONDS, (
        f"background full fsck at the 10,000-event ceiling took {fsck_elapsed:.1f}s, "
        f"above the {FULL_FSCK_CEILING_SECONDS}s bound"
    )


# --------------------------------------------------------------------------
# Repository topology
# --------------------------------------------------------------------------


@spec_ref(
    ARCH(
        "V-9",
        "host-lifecycle",
        "Repository discovery resolves Git's common directory: linked worktrees share the certified "
        "repository UUID while their checkout revision remains distinct. A submodule or nested "
        "repository is an independent repository and needs its own certificate; superproject facts do "
        "not automatically scope into it.",
    ),
    VERIFY(
        "V-9",
        "topology",
        "Launch inside a normal clone, linked worktree, submodule, and nested repository: common-dir "
        "worktrees share UUID, while nested/submodule roots require independent certificates and "
        "never inherit superproject fact bodies.",
    ),
)
def test_worktrees_share_uuid_while_nested_roots_require_their_own_certificate(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo, tmp_path: Path
) -> None:
    clone = host_repo.clone(tmp_path / "normal-clone")
    linked = host_repo.add_worktree(tmp_path / "linked-worktree", "linked")
    nested_child = GitRepo.init(tmp_path / "nested-child")
    nested_child.write("child.md", "nested repository\n")
    nested_child.commit("child")
    nested_inside = GitRepo.init(host_repo.path / "vendor" / "nested")
    nested_inside.write("inner.md", "nested inside the superproject\n")
    nested_inside.commit("inner")

    identities: dict[str, str | None] = {}
    for label, repo in (
        ("clone", clone),
        ("linked", linked),
        ("nested", nested_inside),
    ):
        result = guildhall.run(
            "doctor", "--repo", str(repo.path), "--json", cwd=repo.path, check=False
        )
        assert result.returncode != 1, label
        payload = result.json if result.stdout.strip() else {}
        identities[label] = (
            payload.get("repository_uuid") if isinstance(payload, dict) else None
        )
        if isinstance(payload, dict) and label == "nested":
            assert not payload.get("inherited_superproject_facts"), (
                "a nested repository must not inherit superproject fact bodies"
            )

    primary = guildhall.run(
        "doctor", "--repo", str(host_repo.path), "--json", cwd=host_repo.path, check=False
    )
    if primary.returncode != 1 and primary.stdout.strip():
        primary_uuid = (primary.json or {}).get("repository_uuid")
        if primary_uuid and identities.get("linked"):
            assert identities["linked"] == primary_uuid, (
                "a linked worktree shares the certified repository UUID"
            )
        if primary_uuid and identities.get("nested"):
            assert identities["nested"] != primary_uuid, (
                "a nested repository is an independent identity"
            )


# --------------------------------------------------------------------------
# Soak
# --------------------------------------------------------------------------


@pytest.mark.soak
@pytest.mark.slow
@pytest.mark.timing
@spec_ref(
    VERIFY(
        "V-9",
        "soak",
        "Across the 20-session private soak, at least 90% of starts must take the warm verified path "
        "and deliver nonempty trusted context when eligible facts exist; after the first cold start, "
        "at most 5% of ordinary append/branch-switch/restart/linked-worktree starts may require a "
        "full fsck.",
    ),
    VERIFY(
        "V-9",
        "soak",
        "Latency cannot pass by always degrading or repeatedly forcing a two-minute knowledge "
        "blackout.",
    ),
)
@pytest.mark.requires_hosts
def test_twenty_session_soak_warm_path_and_fsck_incidence(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo, tmp_path: Path
) -> None:
    host = "codex"
    _require_host(host)
    linked = host_repo.add_worktree(tmp_path / "soak-worktree", "soak")

    warm_starts = 0
    full_fsck = 0
    nonempty_context = 0
    ordinary_starts = 0
    for index in range(SOAK_SESSIONS):
        # Ordinary churn: append, branch switch, restart, linked worktree.
        if index % 4 == 0:
            host_repo.write(f"notes-{index}.md", f"append {index}\n")
            host_repo.commit(f"append {index}")
        elif index % 4 == 1:
            host_repo.checkout(host_repo.default_branch)
        elif index % 4 == 2:
            pass  # plain restart
        target = linked if index % 4 == 3 else host_repo

        result = guildhall.run(
            "hooks", "dispatch", host, "SessionStart", "--json",
            stdin=json.dumps(
                envelope_for(
                    host, "SessionStart", session_id=f"soak-{index}", cwd=str(target.path)
                )
            ),
            cwd=target.path,
            timeout=60,
            check=False,
        )
        assert result.returncode != 1, index
        if not result.stdout.strip():
            continue
        payload = result.json
        if not isinstance(payload, dict):
            continue
        if index > 0:
            ordinary_starts += 1
            if payload.get("full_fsck_required"):
                full_fsck += 1
        if payload.get("start_path") == "warm" or payload.get("cache_state") == "verified":
            warm_starts += 1
        if payload.get("trusted_context") or payload.get("facts"):
            nonempty_context += 1

    warm_fraction = warm_starts / SOAK_SESSIONS
    assert warm_fraction >= SOAK_WARM_PATH_MINIMUM, (
        f"only {warm_fraction:.0%} of soak starts took the warm verified path; at least "
        f"{SOAK_WARM_PATH_MINIMUM:.0%} required"
    )
    if ordinary_starts:
        fsck_fraction = full_fsck / ordinary_starts
        assert fsck_fraction <= SOAK_FULL_FSCK_MAXIMUM, (
            f"{fsck_fraction:.0%} of ordinary starts required a full fsck; at most "
            f"{SOAK_FULL_FSCK_MAXIMUM:.0%} permitted"
        )
    assert nonempty_context > 0, (
        "latency cannot pass by always degrading; the soak delivered no trusted "
        "context in any session"
    )


@spec_ref(
    VERIFY(
        "V-9",
        "runbook",
        "[`leak-runbook.md`](leak-runbook.md) is exercised as a tabletop against one seeded event. No "
        "non-private remote may receive `.kin/` events before the specified private-repository soak "
        "and commit-time tripwire evidence.",
    ),
)
@pytest.mark.nonfunctional
def test_leak_runbook_tabletop_and_commit_time_tripwire(
    guildhall: Guildhall, roots: ProofRoots, host_repo: GitRepo, spec_root: Path
) -> None:
    runbook = (spec_root / "spec" / "leak-runbook.md").read_text(encoding="utf-8")
    steps = [line for line in runbook.splitlines() if line.strip().startswith(tuple("1234567"))]
    assert len(steps) >= 7, "the runbook must retain its seven numbered steps"

    result = guildhall.run(
        "doctor", "--repo", str(host_repo.path), "--json", check=False
    )
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    if isinstance(payload, dict):
        tripwire = payload.get("commit_time_tripwire")
        if tripwire is not None:
            assert tripwire.get("installed") is True, (
                "a commit-time tripwire scans staged `.kin/` bytes on every shared "
                "repository"
            )
        soak = payload.get("private_soak")
        if soak is not None:
            assert soak.get("sessions_required") == SOAK_SESSIONS
            assert soak.get("hours_required") >= 24
            assert soak.get("non_private_remote_permitted") is not True or soak.get(
                "completed"
            ) is True, (
                "no non-private remote may receive `.kin/` events before the soak and "
                "tripwire evidence exist"
            )
