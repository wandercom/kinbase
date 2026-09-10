"""Current ruling contract, exercised only through the worktree release binary.

The large-volume fixtures deliberately retain distinct evidence identities. No
expected standing, verdict or case selector is passed to a product command.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from ._harness import canonical, synth, trust
from ._harness import obligations as O
from ._harness.cli import Kinbase
from ._harness.admission import required_rows
from ._harness.gitfix import GitRepo
from ._harness.requirements import ProductFailure, RULING, spec_ref
from ._harness.roots import ProofRoots
from ._harness.worldbuilder import SignedWorld, start_session

pytestmark = [pytest.mark.v6, pytest.mark.requires_product]

DIRECT = RULING("V-6", "direct-admission", "facts are admitted directly, with a signed, content-addressed, revocable record;")
UNKNOWN = RULING("V-6", "unknown", "Conflicting evidence with no authority in scope opens an Unknown and an `awaiting_authority` question.")
STANDING = RULING("V-6", "standing", "Given N `present` facts saying X and one `ratified` fact saying Y, the reduced view must say Y.")
PROVENANCE = RULING("V-6", "provenance", "A fact whose provenance is `ai_generated` may never reach `prevalent`, however often the pattern recurs.")
SHRUG = RULING("V-6", "shrug", "Once something is ruled `shrug`, the system never opens another question about it.")
UNLABELLED = RULING("V-6", "unlabelled", "A commit with no authorship marker is `unknown`, never `human`.")


@pytest.fixture
def local(tmp_path):
    # No Company listener or host executable is required for local admission.
    roots = ProofRoots.create(tmp_path / "ruling", company_port=0)
    GitRepo.init(roots.repo_root)
    driver = Kinbase(home=roots.home, xdg_config_home=roots.xdg_config_home, cwd=roots.repo_root)
    return roots, driver


@pytest.fixture
def ruled_world(roots, kinbase):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(kinbase, roots, world)
    return world, anchors, kinbase


def record_file(driver, name, store="codebase-personal"):
    return driver.home / ".local/state/kinbase" / store / name


def read_records(path):
    if not path.exists():
        raise ProductFailure(f"required durable record missing: {path}")
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def observe(driver, roots, texts, session=None):
    session = session or start_session(driver, roots.repo_root)
    path = roots.run_root / "ruling-input.jsonl"
    stamp = synth.receipt_stamp()
    path.write_text("".join(json.dumps({"id": f"message-{i}", "role": "user", "text": text,
                                      "source_kind": "codex_jsonl", "observed_at": stamp}) + "\n"
                            for i, text in enumerate(texts)))
    result = driver.run("session", "observe", session, "--event", str(path), "--json").ok().json
    return session, path, result


def project(driver, world, key):
    result = driver.run("project", "--repo", str(world.repo.path), "--task", key,
                        "--decision", f"Which rule governs {key}?", "--json", check=False)
    if result.returncode not in (0, 2, 3):
        raise ProductFailure(f"project failed: {result.stdout} {result.stderr}")
    return result.json


def current(driver, world, key):
    result = driver.run("explain", key, "--repo", str(world.repo.path),
                        "--decision", f"Which rule governs {key}?", "--json", check=False)
    if result.returncode not in (0, 3):
        raise ProductFailure(f"explain failed: {result.stdout} {result.stderr}")
    body = result.json
    value = body.get("current")
    if not isinstance(value, dict):
        raise ProductFailure(f"no current fact for {key}: {body}")
    return value


@spec_ref(DIRECT)
def test_direct_admission_exceeds_old_prompt_limit_and_replays(local):
    roots, driver = local
    session, path, observed = observe(driver, roots, [f"I prefer concise explanations for topic {i}." for i in range(12)])
    first = required_rows(observed, "admissions")
    replay = driver.run("session", "observe", session, "--event", str(path), "--json").ok().json
    checkpoint = driver.run("session", "checkpoint", session, "--json").ok().json
    events = list(record_file(driver, "events").rglob("*.json"))
    documents = [json.loads(path.read_bytes()) for path in events]
    addresses = ["".join(path.relative_to(record_file(driver, "events")).parts).removesuffix(".json") for path in events]
    O.check("RULING.direct", {
        "admitted": len(first),
        "all_committed": bool(first) and all(row.get("state") == "committed" and row.get("decision") == "admit" for row in first),
        "signatures_valid": bool(documents) and all(synth.verify_document("fact-event", doc) for doc in documents),
        "addresses_valid": bool(events) and all(hashlib.sha256(path.read_bytes()).hexdigest() == address for path, address in zip(events, addresses)),
        "events": len(events),
        "replayed": [row.get("receipt_id") for row in first] == [row.get("receipt_id") for row in required_rows(replay, "admissions")],
        "checkpoint_receipts": len(required_rows(checkpoint, "admissions")),
    }, label="automatic admission retains signed content addresses and stable receipts")


@spec_ref(UNKNOWN)
def test_unresolved_session_question_is_durable_and_deduplicated(local):
    roots, driver = local
    session, path, first = observe(driver, roots, ["Maybe we should ask whether this is correct."])
    second = driver.run("session", "observe", session, "--event", str(path), "--json").ok().json
    questions = required_rows(driver.run("questions", "list", "--json").ok().json, "questions")
    unknowns = read_records(record_file(driver, "unknowns.jsonl", "company-cache"))
    O.check("RULING.durable", {"questions": len(questions), "unknowns": len(unknowns),
        "awaiting": bool(questions) and all(q.get("status") == "awaiting_authority" for q in questions),
        "signed": bool(unknowns) and all(synth.verify_document("unknown-event", u) for u in unknowns),
        "stable": bool(first.get("questions")) and first.get("questions") == second.get("questions"),
    }, label="ownerless uncertainty survives a fresh process and repeated observation")


@spec_ref(UNKNOWN)
def test_conflicting_evidence_without_answering_authority_opens_question(ruled_world):
    world, anchors, driver = ruled_world
    # Retain trusted evidence-signing identities but remove answering capability.
    anchors.registry.entries = [dataclasses.replace(entry, capabilities=()) for entry in anchors.registry.entries]
    anchors.republish_registry(cursor="1001")
    key = "scheduler/ruling-conflict"
    for statement in ("Scheduler must retry exactly twice.", "Scheduler must retry exactly five times."):
        world.plant_event(world.maintainer, store_kind="codebase", logical_key=key, statement=statement,
                          standing="present", provenance="human")
    project(driver, world, key)
    questions = required_rows(driver.run("questions", "list", "--json").ok().json, "questions")
    matching = [q for q in questions if q.get("logical_key") == key]
    driver.run("corpus", "rebuild", "--repo", str(world.repo.path), "--json", check=False)
    project(driver, world, key)
    again = required_rows(driver.run("questions", "list", "--json").ok().json, "questions")
    O.check("RULING.conflict", {"visible": len(matching),
        "awaiting": bool(matching) and all(q.get("status") == "awaiting_authority" for q in matching),
        "stable": bool(matching) and {q["question_id"] for q in matching} == {q["question_id"] for q in again if q.get("logical_key") == key},
    }, label="contested evidence produces a persistent question without a registered answering authority")


@spec_ref(STANDING)
@pytest.mark.parametrize("ruling_first", [True, False])
def test_one_ratified_fact_outweighs_256_present_facts(ruled_world, ruling_first):
    world, anchors, driver = ruled_world
    key = "scheduler/standing"
    def ruling():
        world.plant_event(world.maintainer, store_kind="codebase", logical_key=key,
                          statement="Scheduler must use bounded exponential backoff.",
                          standing="ratified", provenance="human", commit=False)
    if ruling_first:
        ruling()
    for i in range(256):
        world.plant_event(world.maintainer, store_kind="codebase", logical_key=key,
                          statement="Scheduler must retry immediately without backoff.", evidence_refs=[f"independent-source-{i}"],
                          standing="present", provenance="human", commit=False)
    if not ruling_first:
        ruling()
    world.repo.commit("Record competing evidence and one ratified rule")
    fact = current(driver, world, key)
    O.check("RULING.volume", {"statement": fact.get("statement"), "standing": fact.get("standing"),
                              "fixture_events": world.event_count(), "ruling_first": ruling_first},
            label="a ratified rule wins in either arrival order against 256 distinct present facts")


@spec_ref(PROVENANCE)
@pytest.mark.parametrize("claimed", ["authoritative", "ratified", "enforced", "exemplary", "prevalent"])
def test_ai_generated_standing_is_clamped_in_reduced_view(ruled_world, claimed):
    world, anchors, driver = ruled_world
    key = "scheduler/provenance-ceiling"
    world.plant_event(world.maintainer, store_kind="codebase", logical_key=key,
                      statement="Scheduler retries use this pattern.", standing=claimed, provenance="ai_generated")
    fact = current(driver, world, key)
    O.check("RULING.ceiling", {"standing": fact.get("standing"), "provenance": fact.get("provenance"), "claimed": claimed},
            label="a signed agent-authored event cannot claim human standing")


@spec_ref(PROVENANCE, UNLABELLED)
@pytest.mark.parametrize("agent", [True, False])
def test_git_authorship_survives_ingestion_without_inventing_human_review(ruled_world, agent):
    world, anchors, driver = ruled_world
    repo = world.repo
    revisions = set()
    for i in range(32):
        repo.write(f"src/pattern_{i}.rs", f"pub fn pattern_{i}() -> bool {{ true }}\n")
        message = f"Record scheduler pattern {i}"
        if agent:
            message += "\n\nCo-authored-by: Claude <noreply@anthropic.com>"
        revisions.add(repo.commit(message))
    result = driver.run("ingest", "git_history", str(repo.path), "--repo", str(repo.path), "--json").ok().json
    observations = [row for row in required_rows(result, "observations") if row.get("revision") in revisions]
    expected = "ai_generated" if agent else "unknown"
    O.check("RULING.git", {"observations": len(observations),
        "provenance_correct": bool(observations) and all(row.get("provenance") == expected for row in observations),
        "standing_capped": bool(observations) and all(row.get("standing") in ("present", "unruled") for row in observations),
        "agent": agent,
    }, label="git trailers record agent contribution; unmarked human identities do not establish authorship or review")


@spec_ref(SHRUG, UNKNOWN)
@pytest.mark.parametrize("disposition", ["shrug", "unruled"])
def test_shrug_is_terminal_while_unruled_remains_actionable(ruled_world, disposition):
    world, anchors, driver = ruled_world
    key = "scheduler/optional-style"
    parents = []
    for text in ("Scheduler uses one blank line.", "Scheduler uses two blank lines."):
        parents.append(world.plant_event(world.maintainer, store_kind="codebase", logical_key=key,
                                         statement=text, standing="present", provenance="human")["event_id"])
    project(driver, world, key)
    before_questions = required_rows(driver.run("questions", "list", "--json").ok().json, "questions")
    if not any(q.get("logical_key") == key for q in before_questions):
        raise ProductFailure("the contested fixture did not open a question before the ruling")
    world.plant_event(world.maintainer, store_kind="codebase", logical_key=key,
                      statement="No direction is prescribed for scheduler whitespace.",
                      atom_kind="shrug" if disposition == "shrug" else "constraint",
                      standing="authoritative" if disposition == "shrug" else "unruled",
                      provenance="human", parents=parents, supersedes=parents)
    snapshots = []
    for _ in range(3):
        project(driver, world, key)
        snapshots.append(required_rows(driver.run("questions", "list", "--json").ok().json, "questions"))
        driver.run("corpus", "rebuild", "--repo", str(world.repo.path), "--json", check=False)
    matching = [[q for q in qs if q.get("logical_key") == key and q.get("status") in ("open", "asked", "awaiting_authority")] for qs in snapshots]
    O.check("RULING.terminal", {"correct": all(not qs for qs in matching) if disposition == "shrug" else all(bool(qs) for qs in matching),
                               "disposition": disposition, "reads": len(snapshots)},
            label="shrug survives repeated projection/rebuild; unruled remains visible")


@spec_ref(DIRECT)
def test_automatically_admitted_shared_fact_remains_revocable(ruled_world):
    world, anchors, driver = ruled_world
    # Supply the registered fixture principal's local destination key before
    # observation. Key provisioning is fixture setup, never an approval action.
    key_dir = world.repo.path / ".kin/local/keys"
    key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = key_dir / "ed25519.key"
    key_path.write_bytes(world.maintainer.seed)
    key_path.chmod(0o600)
    (key_dir / "ed25519.pub").write_text(world.maintainer.public_hex)
    session = start_session(driver, world.repo.path)
    source = world.repo.path.parent / "direct-shared.jsonl"
    source.write_text(json.dumps({"id": "shared-rule", "role": "user",
                                 "text": "The scheduler must bound retries to five attempts.",
                                 "observed_at": synth.receipt_stamp(), "source_kind": "codex_jsonl"}) + "\n")
    driver.run("session", "observe", session, "--event", str(source), "--json").ok()
    paths = list((world.repo.path / ".kin/events").rglob("*.json"))
    if not paths:
        raise ProductFailure("automatic shared admission produced no signed Codebase event")
    path = paths[0]
    event = json.loads(path.read_bytes())
    if not synth.verify_document("fact-event", event):
        raise ProductFailure("automatically admitted shared event has an invalid signature")
    address = "".join(path.relative_to(world.repo.path / ".kin/events").parts).removesuffix(".json")
    if hashlib.sha256(path.read_bytes()).hexdigest() != address:
        raise ProductFailure("automatically admitted shared event has the wrong content address")
    key = event["logical_key"]
    before = current(driver, world, key)
    anchors.revoke(world.maintainer, cursor="1001")
    after_result = driver.run("explain", key, "--repo", str(world.repo.path), "--decision", "Which rule remains?", "--json", check=False)
    if after_result.returncode not in (0, 3):
        raise ProductFailure(f"revocation read failed: {after_result.stdout}")
    after = after_result.json
    O.check("RULING.revocable", {"before": before.get("status"),
        "withdrawn": after.get("projection_state") == "withheld" and after.get("trusted") is False,
        "record_retained": path.exists()},
        label="signed evidence is withheld after signer revocation while its record survives")


@spec_ref(RULING("V-6", "commands", "Retired commands must be absent from CLI help."))
def test_approval_and_study_commands_are_absent(local):
    roots, driver = local
    result = driver.run("--help").ok()
    commands = {line.split()[0] for line in result.stdout.splitlines() if line.startswith("  ") and line.split()}
    O.check("RULING.commands", {"retired_absent": not ({"proposals", "experiment"} & commands),
                                "ruling_present": "questions" in commands and "session" in commands},
            label="CLI exposes sessions and rulings without the retired approval or study commands")
