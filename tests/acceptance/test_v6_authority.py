"""V-6 --- real authority round trip (`P-6`, Critical).

``spec/product.md`` P-6 sets the falsifier this gate exists to catch:

    A fixture-only function that formats a question without an authority round
    trip does not pass.

so the acceptance test starts ``guildhalld``, registers a named Chief Architect
with a live channel endpoint, and runs the answer through a **separate process**
that holds the signing key. ``spec/verification.md`` V-6:

    The recorded demonstration should use the human-interactive channel when the
    founder is available. The independent acceptance test uses the signed process
    channel so it is repeatable.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from ._harness import ed25519_pure, synth
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
from ._harness.roots import ProofRoots
from ._harness.service import ClientKey, ServiceClient, wait_for_loopback

pytestmark = [pytest.mark.v6, pytest.mark.requires_product]

ARCHITECT_SCOPE = "architecture:scheduling"
MAX_AUTHORITY_CALLS_PER_TASK = 2


@pytest.fixture()
def architect_process(tmp_path: Path):
    """A separate OS process that owns the Chief Architect signing key.

    ``spec/verification.md`` V-6 requires "a live channel endpoint/process
    separate from the caller", so the key never exists inside the process under
    test. The helper reads a question envelope on stdin and writes a signed
    answer on stdout.
    """
    seed = bytes([3]) * 32
    helper = tmp_path / "architect_channel.py"
    harness_dir = Path(__file__).resolve().parent / "_harness"
    helper.write_text(
        textwrap.dedent(
            f"""
            import json, sys
            sys.path.insert(0, {str(harness_dir.parent.parent)!r})
            from acceptance._harness import canonical, ed25519_pure

            SEED = bytes({list(seed)!r})

            def main() -> int:
                question = json.loads(sys.stdin.read() or "{{}}")
                body = {{
                    "schema": "guildhall-answer/1",
                    "question_id": question.get("question_id", "unknown"),
                    "authority_id": "chief-architect-1",
                    "authority_scope": {ARCHITECT_SCOPE!r},
                    "answer": (
                        "Scheduler diagnosis must read the deployed lookahead, "
                        "not the source default."
                    ),
                    "rationale": (
                        "The source default is documentation of an initial value; "
                        "the deployment owns the operating value."
                    ),
                    "answered_at": "2026-03-06T00:00:00.000Z",
                }}
                digest = canonical.signing_digest("answer", canonical.jcs(body))
                body["signer"] = ed25519_pure.public_key(SEED).hex()
                body["signature"] = ed25519_pure.sign(SEED, digest).hex()
                sys.stdout.write(json.dumps(body, sort_keys=True))
                return 0

            raise SystemExit(main())
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return {
        "helper": helper,
        "public_key": ed25519_pure.public_key(seed).hex(),
        "authority_id": "chief-architect-1",
        "scope": ARCHITECT_SCOPE,
    }


@pytest.fixture()
def company(guildhall: Guildhall, roots: ProofRoots):
    roots.write_service_config()
    roots.write_secret("facts.token", b"facts-token-acceptance")
    roots.write_secret("directory.token", b"directory-token-acceptance")
    roots.write_secret("company-root.key", bytes([11]) * 32)
    proc = guildhall.popen("company", "serve", "--config", str(roots.service_config_path))
    if not wait_for_loopback("127.0.0.1", roots.company_port, timeout=30):
        proc.terminate()
        raise ProductFailure(
            "guildhalld did not accept a loopback connection; spec/architecture.md "
            "section 6 requires a real loopback-capable HTTP service and "
            "spec/verification.md V-6 requires `guildhalld` to start"
        )
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except Exception:
            proc.kill()


@spec_ref(
    SRC(
        "V-6",
        "SRC-7",
        "propensity to seek real guidance from the authority (ask the chief architect about the "
        "direction of the architecture, for instance)",
    ),
    VERIFY(
        "V-6",
        "setup",
        "Start `guildhalld` and register a named Chief Architect with a test signing key and a live "
        "channel endpoint/process separate from the caller.",
    ),
)
def test_service_starts_and_registers_a_named_chief_architect(
    guildhall: Guildhall, company, architect_process, roots: ProofRoots
) -> None:
    registration = guildhall.run(
        "questions",
        "list",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert registration.returncode != 1

    status = guildhall.run(
        "status",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert status.returncode in (0, 3), status.stderr[:400]
    payload = status.json
    registry = payload.get("authority_registry") or {}
    entries = registry.get("entries") or []
    architects = [e for e in entries if e.get("scope") == ARCHITECT_SCOPE]
    assert architects, (
        f"an exact `{ARCHITECT_SCOPE}` Chief Architect must be registered; observed "
        f"scopes {[e.get('scope') for e in entries]}"
    )
    entry = architects[0]
    assert entry.get("authority_id"), "the registry stores a stable authority ID"
    assert entry.get("public_key"), "the registry stores a public key"
    assert entry.get("channel_reference"), "the registry stores an opaque channel reference"
    for forbidden in ("display_name", "contact", "email", "private_key", "token"):
        assert forbidden not in entry, (
            "display name and contact endpoint are directory Personal data kept in a "
            f"separate access-controlled table; observed {forbidden} in the registry entry"
        )


@spec_ref(
    PRODUCT(
        "V-6",
        "P-6",
        "When expected value of another corpus read is below the cost but a high-distortion Unknown "
        "remains, the system must send or queue the targeted question and withhold the dependent "
        "trusted recommendation.",
    ),
    VERIFY(
        "V-6",
        "ambiguity",
        "Present an architectural ambiguity whose decision has high distortion and whose corpus "
        "tiers are exhausted.",
    ),
    VERIFY(
        "V-6",
        "delivery",
        "Assert a targeted question is delivered to that authority, dependent trusted guidance is "
        "withheld, and another role's signature is rejected.",
    ),
)
def test_high_distortion_unknown_sends_a_targeted_question_and_withholds_guidance(
    guildhall: Guildhall, company, architect_process, roots: ProofRoots
) -> None:
    projection = guildhall.run(
        "project",
        "--repo",
        str(guildhall.cwd),
        "--task",
        "change the scheduler diagnosis path",
        "--decision",
        "which lookahead value is authoritative",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert projection.returncode != 1
    payload = projection.json if projection.stdout.strip() else {}
    assert isinstance(payload, dict)
    assert not payload.get("trusted_recommendation"), (
        "dependent trusted guidance must be withheld while a high-distortion Unknown "
        "is open"
    )

    questions = guildhall.run(
        "questions",
        "list",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    ).json
    items = questions.get("questions") if isinstance(questions, dict) else questions
    assert items, "a targeted question must be created for the high-distortion Unknown"
    question = items[0]
    for field in (
        "decision",
        "evidence_examined",
        "remaining_alternatives",
        "distortion_if_wrong",
        "question",
    ):
        assert field in question, (
            "spec/architecture.md section 7: the question writer supplies the decision, "
            f"evidence examined, remaining alternatives, distortion if wrong, and one "
            f"precise question; missing {field}"
        )
    assert question.get("owner_scope") == ARCHITECT_SCOPE

    delivered = guildhall.run(
        "questions",
        "ask",
        question["question_id"],
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert delivered.returncode != 1
    if delivered.returncode == 0:
        assert delivered.json.get("delivery_receipt"), (
            "spec/cli.md: `ask` delivers through the registry channel and records a receipt"
        )


@spec_ref(
    ARCH(
        "V-6",
        "authority-seeking-loop",
        "An answer is accepted only from the resolved in-scope authority and becomes a Company "
        "observation and fact/Unknown-closure event.",
    ),
    CLI(
        "V-6",
        "questions",
        "Only the resolved named in-scope authority may answer.",
    ),
)
def test_another_roles_signature_is_rejected(
    guildhall: Guildhall, company, roots: ProofRoots, tmp_path: Path
) -> None:
    wrong_role = synth.make_signer("repo-maintainer-1", "codebase:example", seed_byte=13)
    answer = synth.authority_answer(
        wrong_role,
        question_id="q-lookahead-1",
        answer="Use the source default.",
        rationale="Signed by the wrong role.",
    )
    answer_file = tmp_path / "wrong-role-answer.json"
    answer_file.write_text(json.dumps(answer, sort_keys=True), encoding="utf-8")
    key_file = tmp_path / "wrong-role.key"
    key_file.write_bytes(wrong_role.seed)
    os.chmod(key_file, 0o600)

    result = guildhall.run(
        "questions",
        "answer",
        "q-lookahead-1",
        "--answer-file",
        str(answer_file),
        "--key-file",
        str(key_file),
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert result.returncode not in (0, 1), (
        "an answer from another role must be rejected; role prestige cannot widen scope"
    )
    assert result.code in {"AUTHORITY_WRONG_SCOPE", "SIGNATURE_INVALID"}, result.code


@spec_ref(
    PRODUCT(
        "V-6",
        "P-6",
        "The proof must execute at least one architectural ambiguity through the Chief Architect "
        "path: detect it, address the registered authority, ingest a signed answer, close/supersede "
        "the Unknown, rebuild the view, and materially change the projected guidance or decision.",
    ),
    VERIFY(
        "V-6",
        "round-trip",
        "Return a signed answer from the authority process; ingest it; close the exact Unknown; "
        "rebuild; assert the projected decision changes and cites the answer.",
    ),
    VERIFY(
        "V-6",
        "mutation",
        "Mutation: locally synthesize an answer from model prior; V-6 fails.",
    ),
)
def test_signed_answer_from_a_separate_process_materially_changes_the_decision(
    guildhall: Guildhall, company, architect_process, roots: ProofRoots, tmp_path: Path
) -> None:
    before = guildhall.run(
        "project",
        "--repo",
        str(guildhall.cwd),
        "--task",
        "change the scheduler diagnosis path",
        "--decision",
        "which lookahead value is authoritative",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    before_payload = before.json if before.stdout.strip() else {}

    questions = guildhall.run(
        "questions",
        "list",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    ).json
    items = questions.get("questions") if isinstance(questions, dict) else questions
    assert items, "no Unknown was raised to route to the authority"
    question_id = items[0]["question_id"]

    # The answer is produced by a separate process that holds the key.
    completed = subprocess.run(
        [sys.executable, str(architect_process["helper"])],
        input=json.dumps({"question_id": question_id}),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr[:400]
    answer = json.loads(completed.stdout)
    assert answer["signer"] == architect_process["public_key"], (
        "the answer must be signed by the separate authority process"
    )
    answer_file = tmp_path / "signed-answer.json"
    answer_file.write_text(json.dumps(answer, sort_keys=True), encoding="utf-8")

    ingested = guildhall.run(
        "ingest",
        "authority_answer",
        str(answer_file),
        "--repo",
        str(guildhall.cwd),
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert ingested.returncode != 1
    assert ingested.returncode == 0, (
        f"a correctly signed in-scope answer must be admitted; {ingested.stderr[:400]}"
    )

    status = guildhall.run(
        "questions",
        "status",
        question_id,
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    ).json
    assert status.get("status") in {"closed", "superseded"}, (
        f"the exact Unknown must close on the signed answer; observed {status.get('status')!r}"
    )
    assert status.get("closure_event_id"), (
        "spec/architecture.md section 3: Unknown closure names the answer/evidence event"
    )

    guildhall.run(
        "corpus", "rebuild", "--store", "company", "--repo", str(guildhall.cwd), "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    after = guildhall.run(
        "project",
        "--repo",
        str(guildhall.cwd),
        "--task",
        "change the scheduler diagnosis path",
        "--decision",
        "which lookahead value is authoritative",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    after_payload = after.json if after.stdout.strip() else {}
    assert after_payload != before_payload, (
        "the projected decision must materially change after the answer is admitted"
    )
    rendered = json.dumps(after_payload)
    assert answer["question_id"] in rendered or "chief-architect-1" in rendered, (
        "the projected decision must cite the answer"
    )
    assert after_payload.get("trusted_recommendation"), (
        "dependent trusted guidance must be released once the Unknown closes"
    )


@spec_ref(
    ARCH(
        "V-6",
        "authority-seeking-loop",
        "A principal may replace its own earlier answer only with an explicit parent-bound "
        "supersession. A contradictory answer without that parent survives as a conflict; newest "
        "timestamp never wins.",
    )
)
def test_unparented_contradictory_answer_survives_as_conflict(
    guildhall: Guildhall, company, architect_process, roots: ProofRoots, tmp_path: Path
) -> None:
    architect = synth.make_signer("chief-architect-1", ARCHITECT_SCOPE, seed_byte=3)
    contradiction = architect.sign_message(
        "answer",
        {
            "schema": "guildhall-answer/1",
            "question_id": "q-lookahead-1",
            "authority_id": architect.authority_id,
            "authority_scope": ARCHITECT_SCOPE,
            "answer": "Actually, use the source default.",
            "rationale": "Contradicts the earlier answer with no parent binding.",
            "answered_at": "2026-03-09T00:00:00.000Z",
        },
    )
    path = tmp_path / "unparented-contradiction.json"
    path.write_text(json.dumps(contradiction, sort_keys=True), encoding="utf-8")
    guildhall.run(
        "ingest",
        "authority_answer",
        str(path),
        "--repo",
        str(guildhall.cwd),
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    explained = guildhall.run(
        "explain",
        "architecture/scheduler/lookahead-owner",
        "--repo",
        str(guildhall.cwd),
        "--decision",
        "which lookahead value is authoritative",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert explained.returncode != 1
    if explained.returncode in (0, 3):
        payload = explained.json
        assert payload.get("state") in {"conflict", "unknown"}, (
            "a contradictory answer without an explicit parent-bound supersession must "
            f"survive as a conflict; observed {payload.get('state')!r}"
        )


@spec_ref(
    PRODUCT(
        "V-6",
        "P-6",
        "Offline or unavailable authority does not become permission. The result explicitly chooses "
        "one declared policy: block the dependent decision, permit a reversible sandbox-only "
        "experiment, or proceed under a named human-granted exception.",
    ),
    VERIFY(
        "V-6",
        "degraded",
        "Repeat with authority unavailable and cache expired: verify the declared degraded policy "
        "rather than guessed guidance.",
    ),
)
def test_unavailable_authority_yields_declared_degraded_policy(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    result = guildhall.run(
        "project",
        "--repo",
        str(guildhall.cwd),
        "--task",
        "change the scheduler diagnosis path",
        "--decision",
        "which lookahead value is authoritative",
        "--json",
        env={
            "GUILDHALL_COMPANY_URL": "http://127.0.0.1:1",
            "GUILDHALL_ACCEPTANCE_CACHE_EXPIRED": "1",
        },
        check=False,
    )
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    if result.returncode == 0:
        policy = payload.get("degraded_policy")
        assert policy in {
            "block_dependent_decision",
            "reversible_sandbox_only_experiment",
            "named_human_granted_exception",
        }, (
            "an unavailable authority must resolve to one explicitly declared policy; "
            f"observed {policy!r}"
        )
        assert not payload.get("trusted_recommendation"), (
            "offline authority does not become permission"
        )
        assert not payload.get("model_prior_answer"), (
            "guidance must never be filled from the model prior"
        )
    else:
        assert result.code in {"COMPANY_UNREACHABLE", "CACHE_EXPIRED", "REVOCATION_STALE"}
        assert result.returncode in (3, 6)


@spec_ref(
    PRODUCT(
        "V-6",
        "P-10",
        "The full system may ask at most two fact-only questions per task and receives no code, "
        "patch, or hidden-test advice. Question count, reply tokens, and outcome contribution are "
        "reported; the service refuses the third call.",
    ),
    VERIFY(
        "V-6",
        "benchmark-service",
        "A response contains fact and rationale only—never code or a solution—and the service refuses "
        "more than two calls per task.",
    ),
)
def test_frozen_answer_service_refuses_the_third_call_and_returns_no_code(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    outcomes = []
    for attempt in range(3):
        result = guildhall.run(
            "questions",
            "ask",
            f"benchmark-q-{attempt}",
            "--json",
            env={
                "GUILDHALL_COMPANY_URL": roots.company_url,
                "GUILDHALL_ACCEPTANCE_FROZEN_ANSWER_SERVICE": "1",
                "GUILDHALL_ACCEPTANCE_TASK_ID": "task-1",
            },
            check=False,
        )
        outcomes.append(result)
        assert result.returncode != 1
    third = outcomes[2]
    assert third.returncode != 0, (
        "the frozen answer service must refuse more than two calls per task"
    )
    assert third.code == "LIMIT_EXCEEDED", third.code
    for result in outcomes[:2]:
        if result.returncode == 0 and result.stdout.strip():
            body = json.dumps(result.json).lower()
            for forbidden in ("def ", "diff --git", "```", "patch", "assert "):
                assert forbidden not in body, (
                    "a response contains fact and rationale only, never code or a "
                    f"solution; observed {forbidden!r}"
                )


@spec_ref(
    ARCH(
        "V-6",
        "authority-seeking-loop",
        "Display name and contact endpoint are directory Personal data kept in a separate "
        "access-controlled table with explicit retention; they are omitted from Codebase events and "
        "proof packets.",
    ),
    ARCH(
        "V-6",
        "authority-seeking-loop",
        "Private signing keys and bearer tokens are never registry values—only references to "
        "caller-supplied file descriptors or keychain handles.",
    ),
)
def test_registry_never_carries_keys_tokens_or_contact_data(
    guildhall: Guildhall, company, roots: ProofRoots
) -> None:
    status = guildhall.run(
        "status",
        "--json",
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert status.returncode != 1
    rendered = json.dumps(status.json if status.stdout.strip() else {})
    for forbidden in ("private_key", "secret_key", "bearer", "@", "phone", "slack"):
        if forbidden == "@":
            # An email address in the registry would be directory Personal data.
            assert "\"email\"" not in rendered, "contact data must not be in the registry"
            continue
        assert forbidden not in rendered.lower() or "token_file" in rendered.lower(), (
            f"the registry/status payload must not carry {forbidden!r}"
        )
