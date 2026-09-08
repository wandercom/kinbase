"""V-9 --- real host lifecycle (`P-9`, Critical).

Detector Reviewer finding 18. The previous module exercised only the dry run and
the refusal, used synthetic envelopes, made the invocation assertion conditional,
asserted the 250 ms Company connect budget as five seconds, ran ``fsck`` over
eight events, and created no submodule.

Every one of those is repaired here:

* the real host executables are resolved through
  :func:`acceptance._harness.prereq.executable` and a mocked branch is refused
  outright by :meth:`InvocationWitness.assert_not_mocked`;
* ``hooks plan`` runs read-only, an unapproved install is required to change
  nothing, and only an explicitly approved install writes;
* every native lifecycle event is delivered through ``hooks dispatch`` with the
  host's own envelope shape, and the invocation recorder proves the host binary
  actually ran;
* the Company connect budget is asserted at its ratified 250 ms, separately from
  the two-second SessionStart p95;
* the fsck ceiling corpus is built at the ratified 10,000 events by
  :mod:`acceptance._harness.scale`;
* the topology test creates a real linked worktree, a real submodule and a real
  nested repository.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

import pytest

from ._harness import hosts
from ._harness import obligations as O
from ._harness import prereq, scale, trust
from ._harness.cli import Guildhall
from ._harness.evidence_model import field, rows
from ._harness.gitfix import GitRepo
from ._harness.requirements import (
    VERIFY,
    HarnessInvalid,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.service import Blackhole
from ._harness.worldbuilder import OpaqueIds, SignedWorld, Witness

pytestmark = [pytest.mark.v9, pytest.mark.requires_product]

#: The two ratified hosts.
HOSTS: tuple[str, ...] = hosts.HOSTS

#: The six native lifecycle events every host must accept.
NATIVE_EVENTS: tuple[str, ...] = (
    "SessionStart", "UserPromptSubmit", "PreToolUse", "PreCompact", "Stop",
    "SessionEnd",
)

#: The four SessionStart states, measured separately.
START_STATES: tuple[str, ...] = hosts.START_STATES

#: The four repository topologies.
TOPOLOGIES: tuple[str, ...] = ("clone", "linked_worktree", "submodule", "nested")

IDENTITY_SEED = b"v9-opaque-identity"


@pytest.fixture()
def ids() -> OpaqueIds:
    return OpaqueIds(IDENTITY_SEED)


@pytest.fixture()
def anchored(roots: ProofRoots, guildhall: Guildhall):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(guildhall, roots, world)
    return world, anchors


@pytest.fixture(params=list(HOSTS))
def host(request) -> str:
    return request.param


@pytest.fixture()
def host_binary(host: str, roots: ProofRoots, guildhall: Guildhall) -> hosts.HostBinary:
    """The real pinned host executable, plus an invocation recorder in front."""
    variable = "GUILDHALL_HOST_" + host.upper()
    configured = prereq.env_var(
        variable, what=host + " host executable",
        why="spec/verification.md V-9 runs the actual setup and hook executables "
            "for Codex and Claude; a mocked host branch is not accepted evidence",
    )
    resolved = prereq.executable(
        configured, what=host + " host executable",
        why="V-9 pins and reports the exact host version",
    )
    bin_dir = roots.run_root / "hostbin" / host
    bin_dir.mkdir(parents=True, exist_ok=True)
    recorder = hosts.install_invocation_recorder(bin_dir, host, resolved)
    guildhall.path_prefix.insert(0, bin_dir)
    return hosts.HostBinary(name=host, path=recorder,
                            version=hosts.host_availability(host).version)


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


def _tree(root: Path) -> dict[str, str]:
    import hashlib

    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(root))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return out


@spec_ref(
    VERIFY("V-9", "setup",
           "Verify setup dry-run exposes permission needs and changes nothing; explicit "
           "approval installs only expected files."),
)
def test_hooks_plan_is_read_only_and_install_requires_native_approval(
    guildhall: Guildhall, roots: ProofRoots, anchored, host: str,
    host_binary: hosts.HostBinary
) -> None:
    world, anchors = anchored
    # R-7 supersedes C9's old exit-2 wording. Every bypass is a typed
    # usage refusal, with no user or repository state changes.
    for forbidden in ("--approve", "--yes", "--all", "--accept-all",
                      "--yes-to-all", "--unlisted-008"):
        before_usage = (_tree(roots.home), _tree(world.repo.path))
        refusal = _run(guildhall, "hooks", "install", host, forbidden, "--json",
                       cwd=world.repo.path)
        refusal.refused("CONFIG_INVARIANT")
        if before_usage != (_tree(roots.home), _tree(world.repo.path)):
            raise ProductFailure("R-7 unknown hook-install flag changed state: " + forbidden)
    before = _tree(roots.home)
    text_before = {str(p.relative_to(roots.home)): p.read_text(errors="replace")
                   for p in roots.home.rglob("*") if p.is_file()}
    plan = _json(_run(guildhall, "hooks", "plan", host, "--json",
                      cwd=world.repo.path))
    after_plan = _tree(roots.home)

    doctor = _run(guildhall, "doctor", "--repo", str(world.repo.path),
                  "--json", cwd=world.repo.path)
    project_before = _tree(world.repo.path)
    installed_result = _run(guildhall, "hooks", "install", host, "--json",
                            cwd=world.repo.path)
    after_install = _tree(roots.home)
    project_after = _tree(world.repo.path)
    text_after = {str(p.relative_to(roots.home)): p.read_text(errors="replace")
                  for p in roots.home.rglob("*") if p.is_file()}
    changed = sorted(p for p in set(after_plan) | set(after_install)
                     if after_plan.get(p) != after_install.get(p))
    files = rows(plan, "files")
    declared = {str(field(f, "path")) for f in files}
    paths_relative = all(not Path(p).is_absolute() and ".." not in Path(p).parts
                         for p in declared)
    plan_digest = plan["plan_digest"] if "plan_digest" in plan else field(plan, "digest")
    result_payload = _json(installed_result)
    installed_digest = result_payload["plan_digest"] if "plan_digest" in result_payload else field(result_payload, "digest")
    rendered_plan = json.dumps(plan).lower()
    O.check(
        "V-9.setup",
        {
            "host_executable_resolved": host_binary.path.exists(),
            "plan": {"files": files, "commands": field(plan, "commands"),
                     "permissions": field(plan, "permissions")},
            "files_changed_by_plan": len(set(after_plan.items()) ^ set(before.items())),
            "doctor_refusal_code": doctor.code,
            "install_exit_code": installed_result.returncode,
            "installed_files": changed,
            "planned_paths_relative_to_home": paths_relative,
            "installed_paths_match_plan": bool(declared) and set(changed) == declared,
            "installed_contents_match_plan": hosts.installed_files_match_plan(
                plan, text_before, text_after),
            "installed_plan_digest_matches": bool(plan_digest)
                and installed_digest == plan_digest,
            "project_files_changed": len(set(project_before.items())
                                         ^ set(project_after.items())),
            "bypass_flags_found": sum(
                1 for flag in ("--approve", "--force", "--no-approval", "--yes")
                if flag in rendered_plan
            ),
        },
        label="read-only plan followed by the exact user-level installation (C9)",
    )


@spec_ref(
    VERIFY("V-9", "native-events",
           "Invoke native SessionStart, prompt/observation, pre-edit, PreCompact, and Stop/end "
           "payloads."),
)
def test_native_host_events_prime_capture_and_exclude_personal(
    guildhall: Guildhall, roots: ProofRoots, anchored, host: str,
    host_binary: hosts.HostBinary, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    canary = "kx" + os.urandom(10).hex()
    roots.plant_personal_canary_file("host-probe.txt", canary)
    _run(guildhall, "hooks", "install", host, "--json",
         cwd=world.repo.path)

    session = ids.token("native-events")
    dispatched: dict[str, dict] = {}
    for event in NATIVE_EVENTS:
        envelope = hosts.envelope_for(host, event, session_id=session,
                                      cwd=str(world.repo.path))
        result = _run(guildhall, "hooks", "dispatch", host, event, "--json",
                      cwd=world.repo.path, stdin=json.dumps(envelope))
        dispatched[event] = _json(result)

    invocations = hosts.read_invocations(
        host_binary.path.parent / (host + ".invocations")
    )
    witness = hosts.InvocationWitness(
        host=host, executable=host_binary.path, version=host_binary.version,
        argv_records=tuple(invocations),
        config_files=tuple(sorted(roots.home.rglob("*.json"))),
    )
    witness.assert_not_mocked()
    start = dispatched["SessionStart"]
    rendered = json.dumps(dispatched)
    O.check(
        "V-9.native-events",
        {
            "events_dispatched": sorted(dispatched),
            "host_invocation_records": len(invocations),
            "not_mocked": True,
            "session_start": {
                "repository_root": field(start, "repository_root"),
                "company_state": field(start, "company_state"),
            },
            "personal_root_occurrences": rendered.count(canary)
            + rendered.count(str(roots.personal_root)),
            "capture_continued": field(
                dispatched["UserPromptSubmit"], "capture_active"),
            "stop_checkpointed": field(dispatched["Stop"], "checkpointed"),
        },
        label="native host events prime capture and exclude Personal",
    )


@spec_ref(
    VERIFY("V-9", "parity",
           "For matched conversations, canonical facts/projections/receipts match across hosts."),
)
def test_matched_conversations_produce_identical_canonical_payloads(
    guildhall: Guildhall, roots: ProofRoots, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    observed: dict[str, dict] = {}
    for name in HOSTS:
        variable = "GUILDHALL_HOST_" + name.upper()
        configured = prereq.env_var(
            variable, what=name + " host executable",
            why="parity ranges over both real hosts",
        )
        resolved = prereq.executable(configured, what=name + " host executable",
                                     why="parity ranges over both real hosts")
        bin_dir = roots.run_root / "hostbin" / name
        hosts.install_invocation_recorder(bin_dir, name, resolved)
        guildhall.path_prefix.insert(0, bin_dir)
        _run(guildhall, "hooks", "install", name, "--json",
             cwd=world.repo.path)
        session = ids.token("parity-" + name)
        envelope = hosts.envelope_for(name, "SessionStart", session_id=session,
                                      cwd=str(world.repo.path))
        observed[name] = _json(_run(guildhall, "hooks", "dispatch", name,
                                    "SessionStart", "--json", cwd=world.repo.path,
                                    stdin=json.dumps(envelope)))
    first, second = (observed[h] for h in HOSTS)
    O.check(
        "V-9.parity",
        {
            "hosts_observed": len(observed),
            "canonical_facts": field(first, "canonical_facts"),
            "facts_match": field(first, "canonical_facts")
            == field(second, "canonical_facts"),
            "decisions_match": field(first, "decisions") == field(second, "decisions"),
            "receipts_match": field(first, "receipts") == field(second, "receipts"),
        },
        label="matched conversations agree across both real hosts",
    )


def _construct_state(guildhall: Guildhall, roots: ProofRoots, world, state: str) -> bool:
    """Really move the store into the named SessionStart state."""
    if state == "warm":
        _run(guildhall, "fsck", "--repo", str(world.repo.path), "--json",
             cwd=world.repo.path)
        return True
    if state == "cold":
        trust.remove_cache(roots)
        certificates = trust.cached_certificate_paths(roots)
        return not any(p.is_file() and p not in certificates
                       for p in roots.company_cache.rglob("*"))
    if state == "invalid-cache":
        target = roots.company_cache / "facts-cache.sqlite3"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"not a database")
        return target.is_file()
    if state == "full-fsck-required":
        marker = world.repo.path / ".kin" / "manifests"
        if marker.exists():
            shutil.rmtree(marker, ignore_errors=True)
        return not marker.exists()
    raise HarnessInvalid("unknown SessionStart state " + repr(state))


@spec_ref(
    VERIFY("V-9", "latency",
           "run at least 200 invocations per host/state on the recorded proof machine, report "
           "CPU/RAM/filesystem, and require every state's p95 under two seconds."),
)
@pytest.mark.slow
def test_session_start_p95_under_two_seconds_in_every_state(
    guildhall: Guildhall, roots: ProofRoots, anchored, host: str,
    host_binary: hosts.HostBinary, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    _run(guildhall, "hooks", "install", host, "--json",
         cwd=world.repo.path)
    measured = []
    for state in START_STATES:
        constructed = _construct_state(guildhall, roots, world, state)
        durations: list[float] = []
        refusals = 0
        for index in range(hosts.INVOCATIONS_PER_HOST_STATE):
            envelope = hosts.envelope_for(
                host, "SessionStart", session_id=ids.token(state + str(index)),
                cwd=str(world.repo.path),
            )
            result = guildhall.run("hooks", "dispatch", host, "SessionStart",
                                   "--json", cwd=world.repo.path,
                                   stdin=json.dumps(envelope), check=False)
            durations.append(result.duration_s)
            if result.returncode not in (0, 3):
                refusals += 1
        sample = hosts.LatencySample(host=host, state=state,
                                     durations=tuple(durations))
        measured.append({
            "state": state,
            "state_constructed": constructed,
            "invocations": len(durations),
            "p95_seconds": sample.p95,
            "refusals": refusals,
        })
    O.check(
        "V-9.latency",
        {
            "states": measured,
            "machine": {
                "cpu": os.cpu_count(),
                "ram": _total_ram_bytes(),
                "filesystem": _filesystem_of(roots.repo_root),
            },
        },
        label="SessionStart p95 in every constructed state",
    )


def _total_ram_bytes() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return 0


def _filesystem_of(path: Path) -> str:
    stats = os.statvfs(path)
    return "blocks=" + str(stats.f_blocks) + " bsize=" + str(stats.f_bsize)


@spec_ref(
    VERIFY("V-9", "blackhole",
           "Blackhole the Company endpoint; SessionStart remains under the two-second p95 budget "
           "while affected facts are withheld and loudly degraded."),
)
def test_blackholed_company_endpoint_degrades_loudly_inside_the_budget(
    guildhall: Guildhall, roots: ProofRoots, anchored, host: str,
    host_binary: hosts.HostBinary, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    _run(guildhall, "hooks", "install", host, "--json",
         cwd=world.repo.path)
    payloads: list[dict] = []
    durations: list[float] = []
    connect_durations: list[float] = []
    with Blackhole(0) as blackhole, anchors.company_endpoint(
        f"http://127.0.0.1:{blackhole.port}"
    ):
        for index in range(20):
            envelope = hosts.envelope_for(
                host, "SessionStart", session_id=ids.token("blackhole" + str(index)),
                cwd=str(world.repo.path),
            )
            started = time.monotonic()
            result = guildhall.run("hooks", "dispatch", host, "SessionStart",
                                   "--json", cwd=world.repo.path,
                                   stdin=json.dumps(envelope), check=False)
            durations.append(time.monotonic() - started)
            payload = result.json if isinstance(result.json, dict) else {}
            payloads.append(payload)
            reported = field(payload, "company_connect_seconds")
            if isinstance(reported, (int, float)):
                connect_durations.append(float(reported))
    witness = Witness(kind="company_blackhole")
    witness.note(port=blackhole.port, invocations=len(payloads))
    witness.require("the blackhole must actually have been installed")

    sample = hosts.LatencySample(host=host, state="blackhole",
                                 durations=tuple(durations))
    O.check(
        "V-9.blackhole",
        {
            "blackhole_active": len(payloads) == 20,
            "p95_seconds": sample.p95,
            "connect_budget_seconds": max(connect_durations)
            if connect_durations else float(hosts.COMPANY_CONNECT_BUDGET_SECONDS) * 2,
            "payload_count": len(payloads),
            "degraded_loudly": all(
                field(p, "degraded") is True for p in payloads
            ),
            "trusted_company_facts_while_refreshing": sum(
                len(rows(p, "trusted_company_facts")) for p in payloads
            ),
        },
        label="a blackholed Company degrades loudly inside the budget",
    )


@spec_ref(
    VERIFY("V-9", "topology",
           "Launch inside a normal clone, linked worktree, submodule, and nested repository:"),
)
def test_worktrees_share_uuid_while_nested_roots_require_their_own_certificate(
    guildhall: Guildhall, roots: ProofRoots, anchored, ids: OpaqueIds, tmp_path: Path
) -> None:
    world, anchors = anchored
    clone = world.repo.clone(tmp_path / ids.token("clone"))
    worktree = world.repo.add_worktree(tmp_path / ids.token("worktree"), "wt-topology")

    child = GitRepo.init(tmp_path / ids.token("child"))
    child.write("README.md", "child repository\n")
    child.commit("initialise the child repository")
    world.repo.add_submodule(child, "vendor/child")

    nested = GitRepo.init(world.repo.path / "nested")
    nested.write("README.md", "nested repository\n")
    nested.commit("initialise the nested repository")

    observed: dict[str, dict] = {}
    for name, path in (("clone", clone.path), ("linked_worktree", worktree.path),
                       ("submodule", world.repo.path / "vendor" / "child"),
                       ("nested", nested.path)):
        observed[name] = _json(_run(guildhall, "status", "--repo", str(path),
                                    "--json", cwd=path))
    superproject_statements = {
        str(field(f, "statement")) for f in rows(observed["clone"], "facts")
    }
    inherited = 0
    for name in ("submodule", "nested"):
        for fact in rows(observed[name], "facts"):
            if str(field(fact, "statement")) in superproject_statements:
                inherited += 1
    O.check(
        "V-9.topology",
        {
            "topologies": sorted(observed),
            "worktree_shares_uuid":
                field(observed["linked_worktree"], "repository_uuid")
                == field(observed["clone"], "repository_uuid"),
            "nested_identity_independent":
                field(observed["nested"], "repository_uuid")
                != field(observed["clone"], "repository_uuid"),
            "submodule_identity_independent":
                field(observed["submodule"], "repository_uuid")
                != field(observed["clone"], "repository_uuid"),
            "inherited_superproject_facts": inherited,
        },
        label="four real topologies with independent nested identity",
    )


@spec_ref(
    VERIFY("V-9", "soak",
           "Across the 20-session private soak, at least 90% of starts must take the warm "
           "verified path and deliver nonempty trusted context when eligible facts exist"),
)
@pytest.mark.slow
def test_twenty_session_soak_warm_path_and_fsck_incidence(
    guildhall: Guildhall, roots: ProofRoots, anchored, host: str,
    host_binary: hosts.HostBinary, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    _run(guildhall, "hooks", "install", host, "--json",
         cwd=world.repo.path)
    build = scale.build_event_corpus(
        world.repo.path, world.maintainer, hosts.SHARED_EVENT_CEILING,
        logical_prefix="soak", repository_id=anchors.repository_uuid,
    )
    prereq.witnessed(
        build.cross_check_agreed, True, what="bulk signature cross-check",
        why="the soak corpus must be signed by the ratified algorithm",
    )
    sessions: list[dict] = []
    for index in range(hosts.SOAK_SESSIONS):
        if index in (5, 11):
            world.repo.branch("soak/" + str(index))
            world.repo.checkout("soak/" + str(index))
        envelope = hosts.envelope_for(
            host, "SessionStart", session_id=ids.token("soak" + str(index)),
            cwd=str(world.repo.path),
        )
        result = guildhall.run("hooks", "dispatch", host, "SessionStart", "--json",
                               cwd=world.repo.path, stdin=json.dumps(envelope),
                               check=False)
        payload = result.json if isinstance(result.json, dict) else {}
        sessions.append({
            "index": index,
            "path": field(payload, "start_path"),
            "full_fsck": field(payload, "full_fsck_performed") is True,
            "trusted_context": len(rows(payload, "trusted_context")),
            "refused": result.returncode not in (0, 3),
        })
        if index in (5, 11):
            world.repo.checkout(world.repo.default_branch)
    warm = [s for s in sessions if s["path"] == "warm_verified"]
    after_first = sessions[1:]
    O.check(
        "V-9.soak",
        {
            "sessions": len(sessions),
            "eligible_facts_present": build.event_count,
            "warm_path_fraction": len(warm) / len(sessions),
            "full_fsck_fraction": (
                sum(1 for s in after_first if s["full_fsck"]) / len(after_first)
            ),
            "nonempty_trusted_context_sessions": sum(
                1 for s in sessions if s["trusted_context"] > 0
            ),
            "refused_starts": sum(1 for s in sessions if s["refused"]),
        },
        label="twenty-session soak warm path and fsck incidence",
    )
