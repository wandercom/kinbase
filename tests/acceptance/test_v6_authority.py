"""V-6 --- real authority round trip (`P-6`, Critical).

Detector Reviewer finding 16. The fixture registered nothing: no key, no scope
and no channel entered the ``AuthorityRegistry``, and the test invoked the
answering helper itself. "A targeted question is delivered to that authority"
was therefore asserted about a call the instrument made.

:mod:`acceptance._harness.authority` now starts an independent answering
process on its own loopback port, and :mod:`acceptance._harness.trust` publishes
its key, scope and channel endpoint through the live registry before any
question exists. The product must resolve that channel from Company and deliver
to it; the delivery evidence is the helper's own append-only log and the digest
of the exact request bytes it received, neither of which the assertion can
produce on its own.

The frozen answer service also enforces V-6's own ceiling: it refuses a third
call for one task and returns a fact and rationale only, never code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ._harness import authority, canonical, ed25519_pure
from ._harness import obligations as O
from ._harness import prereq, synth, trust
from ._harness.cli import Guildhall
from ._harness.evidence_model import Origin, field, require_nonempty, rows
from ._harness.requirements import (
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.service import Blackhole
from ._harness.worldbuilder import SignedWorld, Witness

pytestmark = [pytest.mark.v6, pytest.mark.requires_product]

#: The ratified degraded policies. Guessing is not among them.
DEGRADED_POLICIES: tuple[str, ...] = (
    "block_dependent_decision", "reversible_sandbox_only_experiment",
    "named_human_granted_exception",
)

#: The architectural ambiguity the corpus cannot resolve.
TASK = "extend the scheduler diagnosis path"
DECISION = "which compatibility invariant constrains the change"
LOGICAL_KEY = "architecture/scheduler/wire-format-invariant"


@pytest.fixture()
def authority_process(roots: ProofRoots):
    """A separate, signed answering process. Stopped after the test."""
    signer = synth.make_signer(
        "chief-architect-1", "architecture:scheduling", seed_byte=3
    )
    process = authority.start(signer, roots.run_root / "authority")
    try:
        yield process
    finally:
        process.stop()


@pytest.fixture()
def registered(roots: ProofRoots, guildhall: Guildhall, authority_process):
    """A world whose registry publishes the running authority's channel."""
    world = SignedWorld.create(roots.repo_root)
    world.architect = authority_process.signer
    anchors = trust.establish(
        guildhall, roots, world,
        extra_authorities=((authority_process.signer, authority_process.channel),),
    )
    prereq.registered(
        [e for e in anchors.registry.entries
         if e.channel == authority_process.channel],
        what="authority channel registration", minimum=1,
        why="the product must resolve the channel from the published registry, "
            "not from anything the test passes it",
    )
    return world, anchors, authority_process


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


def _plant_ambiguity(world: SignedWorld) -> dict:
    """Exhaust the corpus tiers, leaving a high-distortion open Unknown."""
    world.plant_event(
        world.maintainer, store_kind="codebase", logical_key=LOGICAL_KEY,
        statement="the wire format version is referenced but never fixed here",
        distortion={"severity": "high", "reversibility": "irreversible"},
    )
    return world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key=LOGICAL_KEY + "/unknown",
        statement="which compatibility invariant constrains the change is open",
        atom_kind="unknown", disposition="open",
        distortion={"severity": "high", "reversibility": "irreversible"},
    )


def _questions(guildhall: Guildhall, repo: Path) -> list[dict]:
    listing = _json(_run(guildhall, "questions", "list", "--json", cwd=repo))
    return rows(listing, "questions")


@spec_ref(
    VERIFY("V-6", "registration",
           "Start `guildhalld` and register a named Chief Architect with a test signing key and "
           "a live channel endpoint/process separate from the caller."),
)
def test_service_starts_and_registers_a_named_chief_architect(
    guildhall: Guildhall, registered
) -> None:
    world, anchors, process = registered
    entry = anchors.registry.entry_for(process.signer.authority_id)
    published = _json(_run(guildhall, "questions", "list", "--json",
                           cwd=world.repo.path))
    O.check(
        "V-6.registration",
        {
            "service_started": process.process.poll() is None,
            "registration_performed": anchors.registry.admitted_by_service,
            "registry_entry": {
                "authority_id": entry.authority_id,
                "public_key": entry.public_key,
                "channel_reference": entry.channel,
            },
            "registered_public_key_matches_helper":
                entry.public_key == process.signer.public_hex,
            "questions_surface_reachable": published is not None,
        },
        label="a named Chief Architect registered with a live separate channel",
    )


@spec_ref(
    VERIFY("V-6", "question",
           "Assert a targeted question is delivered to that authority, dependent trusted "
           "guidance is withheld, and another role's signature is rejected."),
)
def test_high_distortion_unknown_sends_a_targeted_question_and_withholds_guidance(
    guildhall: Guildhall, registered
) -> None:
    world, anchors, process = registered
    _plant_ambiguity(world)
    _run(guildhall, "ingest", "kindex", str(world.repo.path / ".kin"),
         "--repo", str(world.repo.path), "--json", cwd=world.repo.path)
    projected = _json(_run(guildhall, "project", "--repo", str(world.repo.path),
                           "--task", TASK, "--decision", DECISION, "--json",
                           cwd=world.repo.path))
    questions = _questions(guildhall, world.repo.path)
    require_nonempty(
        questions, obligation="V-6.question",
        why="an exhausted high-distortion decision must raise a question",
        origin=Origin.PRODUCT,
    )
    identifier = str(field(questions[0], "question_id"))
    asked = _run(guildhall, "questions", "ask", identifier, "--json",
                 cwd=world.repo.path)
    deliveries = process.deliveries()
    witness = Witness(kind="authority_delivery")
    witness.note(deliveries=len(deliveries), log_digest=process.log_digest(),
                 ask_exit=asked.returncode)
    O.check(
        "V-6.question",
        {
            "question_count": len(questions),
            "question": questions[0],
            "delivered": len(deliveries) >= 1,
            "delivery_receipt": deliveries[0] if deliveries else None,
            "trusted_recommendation_present":
                field(projected, "trusted_recommendation") is not None,
        },
        label="a targeted question reaches the registered channel",
    )


@spec_ref(
    VERIFY("V-6", "round-trip",
           "Return a signed answer from the authority process; ingest it; close the exact "
           "Unknown; rebuild; assert the projected decision changes and cites the answer."),
)
def test_signed_answer_from_a_separate_process_materially_changes_the_decision(
    guildhall: Guildhall, registered, roots: ProofRoots
) -> None:
    world, anchors, process = registered
    _plant_ambiguity(world)
    _run(guildhall, "ingest", "kindex", str(world.repo.path / ".kin"),
         "--repo", str(world.repo.path), "--json", cwd=world.repo.path)
    before = _json(_run(guildhall, "project", "--repo", str(world.repo.path),
                        "--task", TASK, "--decision", DECISION, "--json",
                        cwd=world.repo.path))
    questions = _questions(guildhall, world.repo.path)
    require_nonempty(
        questions, obligation="V-6.round-trip",
        why="there must be a question for the authority to answer",
        origin=Origin.PRODUCT,
    )
    identifier = str(field(questions[0], "question_id"))
    _run(guildhall, "questions", "ask", identifier, "--json", cwd=world.repo.path)

    signed = _fetch_signed_answer(process, identifier)
    answer_file = roots.run_root / "authority" / "answer.json"
    answer_file.write_bytes(canonical.jcs(signed))
    key_file = roots.run_root / "authority" / "signer.pub"
    key_file.write_text(process.signer.public_hex + "\n", encoding="utf-8")
    admitted = _run(guildhall, "questions", "answer", identifier,
                    "--answer-file", str(answer_file),
                    "--key-file", str(key_file), "--json", cwd=world.repo.path)
    _run(guildhall, "corpus", "rebuild", "--store", "codebase",
         "--repo", str(world.repo.path), "--json", cwd=world.repo.path)
    after = _json(_run(guildhall, "project", "--repo", str(world.repo.path),
                       "--task", TASK, "--decision", DECISION, "--json",
                       cwd=world.repo.path))
    status = _json(_run(guildhall, "questions", "status", identifier, "--json",
                        cwd=world.repo.path))
    rendered_after = json.dumps(after)
    O.check(
        "V-6.round-trip",
        {
            "answer_from_separate_process": process.process.pid != os.getpid(),
            "answer_admitted": admitted.returncode == 0,
            "unknown_status": field(status, "status"),
            "closure_event_id": field(status, "closure_event_id"),
            "decision_changed": json.dumps(before) != rendered_after,
            "decision_cites_answer": identifier in rendered_after,
            "trusted_recommendation_released":
                field(after, "trusted_recommendation") is not None,
            "authority_process_log_digest": process.log_digest(),
        },
        label="a signed answer from the registered process changes the decision",
    )


def _fetch_signed_answer(process: authority.AuthorityProcess, question_id: str) -> dict:
    """Ask the running authority for its signed answer and verify the signature."""
    import urllib.request

    body = json.dumps({"task_id": question_id, "question_id": question_id}).encode()
    request = urllib.request.Request(
        process.channel, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    signature = bytes.fromhex(payload["signature"])
    signer = bytes.fromhex(payload["signer"])
    unsigned = {k: v for k, v in payload.items() if k != "signature"}
    digest = canonical.signing_digest("answer", canonical.jcs(unsigned))
    if not ed25519_pure.verify(signer, digest, signature):
        raise prereq.missing(
            "service", "authority answer signature",
            "the answering process returned a signature the instrument cannot "
            "verify, so the round trip has no valid input",
        )
    return payload


@spec_ref(
    VERIFY("V-6", "wrong-role",
           "another role's signature is rejected"),
)
def test_another_roles_signature_is_rejected(
    guildhall: Guildhall, registered, roots: ProofRoots
) -> None:
    world, anchors, process = registered
    _plant_ambiguity(world)
    _run(guildhall, "ingest", "kindex", str(world.repo.path / ".kin"),
         "--repo", str(world.repo.path), "--json", cwd=world.repo.path)
    questions = _questions(guildhall, world.repo.path)
    require_nonempty(
        questions, obligation="V-6.wrong-role",
        why="a question must exist for the wrong role to attempt to answer",
        origin=Origin.PRODUCT,
    )
    identifier = str(field(questions[0], "question_id"))
    impostor = synth.make_signer("repo-maintainer-1", "codebase:example", seed_byte=13)
    payload = synth.authority_answer(
        impostor, question_id=identifier,
        answer="the invariant is whatever this role says",
        rationale="signed under a scope that does not own the decision",
    )
    answer_file = roots.run_root / "authority" / "impostor.json"
    answer_file.parent.mkdir(parents=True, exist_ok=True)
    answer_file.write_bytes(canonical.jcs(payload))
    key_file = roots.run_root / "authority" / "impostor.pub"
    key_file.write_text(impostor.public_hex + "\n", encoding="utf-8")
    attempt = _run(guildhall, "questions", "answer", identifier,
                   "--answer-file", str(answer_file), "--key-file", str(key_file),
                   "--json", cwd=world.repo.path)
    status = _json(_run(guildhall, "questions", "status", identifier, "--json",
                        cwd=world.repo.path))
    O.check(
        "V-6.wrong-role",
        {
            "attempt_made": attempt.returncode is not None,
            "refusal_code": field(_json(attempt), "error", "code"),
            "unknown_closed": field(status, "status") in ("closed", "superseded"),
        },
        label="a different role's signature cannot close the Unknown",
    )


@spec_ref(
    VERIFY("V-6", "degraded",
           "Repeat with authority unavailable and cache expired: verify the declared degraded "
           "policy rather than guessed guidance."),
)
def test_unavailable_authority_yields_declared_degraded_policy(
    guildhall: Guildhall, registered, roots: ProofRoots
) -> None:
    world, anchors, process = registered
    _plant_ambiguity(world)
    _run(guildhall, "ingest", "kindex", str(world.repo.path / ".kin"),
         "--repo", str(world.repo.path), "--json", cwd=world.repo.path)
    process.stop()
    cache = roots.company_cache
    removed = 0
    for path in sorted(cache.rglob("*")):
        if path.is_file():
            path.unlink()
            removed += 1
    witness = Witness(kind="authority_unavailable")
    witness.note(helper_exit=process.process.returncode, cache_entries_removed=removed)
    witness.require("the authority process must actually have stopped")

    with Blackhole(roots.company_port):
        projected = _json(_run(guildhall, "project", "--repo", str(world.repo.path),
                               "--task", TASK, "--decision", DECISION, "--json",
                               cwd=world.repo.path))
    rendered = json.dumps(projected).lower()
    O.check(
        "V-6.degraded",
        {
            "cache_state_constructed": removed >= 0 and not any(
                p.is_file() for p in cache.rglob("*")
            ),
            "degraded_policy": field(projected, "degraded_policy"),
            "trusted_recommendation_present":
                field(projected, "trusted_recommendation") is not None,
            "model_prior_answer": "model prior" in rendered
            or "synthesised" in rendered,
        },
        label="an unavailable authority yields the declared degraded policy",
    )


def _call_service(process: authority.AuthorityProcess,
                  task: str) -> tuple[int, dict]:
    """One call to the frozen answer service, returning status and body.

    An HTTP refusal is the *expected* observation past the ceiling, so it is
    returned as data rather than raised. No claim is made inside the handler.
    """
    import urllib.error
    import urllib.request

    body = json.dumps({"task_id": task, "question_id": task}).encode()
    request = urllib.request.Request(
        process.channel, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as refusal:
        return refusal.code, json.loads(refusal.read().decode("utf-8"))


@spec_ref(
    VERIFY("V-6", "call-ceiling",
           "the service refuses more than two calls per task."),
)
def test_frozen_answer_service_refuses_the_third_call_and_returns_no_code(
    registered
) -> None:
    """The frozen answer service is a Tester-owned instrument, checked directly."""
    world, anchors, process = registered
    task = "t" + os.urandom(6).hex()
    responses: list[dict] = []
    third_code = ""
    for index in range(authority.CALL_CEILING + 1):
        status, payload = _call_service(process, task)
        if status == 200:
            responses.append({
                "answer": payload["answer"],
                "rationale": payload["rationale"],
                "contains_code": bool(payload["contains_code"]),
            })
        else:
            third_code = str(payload["error"]["code"])
    O.check(
        "V-6.call-ceiling",
        {
            "accepted_calls": len(responses),
            "third_call_refusal_code": third_code,
            "responses": responses,
            "service_request_log_digest": process.log_digest(),
        },
        label="the frozen answer service refuses a third call for one task",
    )
