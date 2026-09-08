"""Synthetic source generators for every ratified adapter.

Nothing here is derived from a real private conversation. ``spec/verification.md``
"Evidence packet":

    Acceptance and committed fixtures are synthetic or licensed public material
    and may not derive from real private conversations. Committed V-2/V-3
    fixtures contain only generators, placeholder IDs, structural gold labels,
    and policies.

Each generator emits the *native* format of its source class, because
``spec/product.md`` P-1 requires that "adapters must also execute against their
native formats" and ``spec/verification.md`` V-1 requires that "Both transcript
adapters parse exports produced by their actual host layouts".

The ten source classes, from ``spec/product.md`` P-1:

    1. Codex rollout/session JSONL;
    2. Claude Code session JSONL;
    3. repository source and interface/type declarations;
    4. tests and executable verification results;
    5. Git commits, diffs, branches, and merge/rejection status;
    6. repository documentation and ADRs;
    7. GitHub issue and pull-request exports, including review/disposition state;
    8. runtime/configuration evidence supplied as files or command-result envelopes;
    9. existing Kindex export/SQLite facts and repository `.kin/` events;
    10. signed human-authority answers.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import canonical, ed25519_pure

#: Adapter identifiers, verbatim from the ``spec/verification.md`` V-1 matrix.
ADAPTERS: tuple[str, ...] = (
    "codex_jsonl",
    "claude_jsonl",
    "repo_code",
    "repo_tests",
    "git_history",
    "docs_adr",
    "github_export",
    "runtime_evidence",
    "kindex",
    "authority_answer",
)

#: The frozen lifecycle matrix from ``spec/verification.md`` V-1. Every declared
#: cell needs an expected observation/current-fact/Unknown state and at least one
#: negative mutation; a semantically inapplicable cell needs a ratified reason
#: and cannot disappear from the report.
LIFECYCLE_MATRIX: dict[str, tuple[str, ...]] = {
    "codex_jsonl": (
        "create",
        "append",
        "edited/duplicate event",
        "end",
        "raw expiry",
        "missing source",
        "restart",
    ),
    "claude_jsonl": (
        "create",
        "append",
        "edited/duplicate event",
        "stop",
        "raw expiry",
        "missing source",
        "restart",
    ),
    "repo_code": (
        "create",
        "modify",
        "delete",
        "rename",
        "branch divergence",
        "rebase/force-push",
        "shallow/sparse view",
    ),
    "repo_tests": (
        "create",
        "pass-to-fail",
        "fail-to-pass",
        "superseded result",
        "delete",
        "out-of-order result",
    ),
    "git_history": (
        "branch",
        "merge",
        "reject",
        "revert",
        "delete ref",
        "rebase/force-push",
        "shallow fetch",
        "clock skew",
    ),
    "docs_adr": (
        "proposed",
        "accepted",
        "rejected",
        "superseded",
        "retracted/deleted",
        "conflicting heads",
    ),
    "github_export": (
        "open",
        "edit",
        "approve/request-change",
        "merge/close/reopen",
        "missing/withdrawn object",
    ),
    "runtime_evidence": (
        "create",
        "changed value",
        "owner change",
        "expiry",
        "late arrival",
        "bounded clock skew",
    ),
    "kindex": (
        "duplicate import",
        "supersede",
        "retract",
        "revoke",
        "expire",
        "conflict",
        "deterministic rebuild",
    ),
    "authority_answer": (
        "answer",
        "explicit parent supersession",
        "unparented conflict",
        "revoke",
        "late arrival",
    ),
}

#: Origin trust classes, ``spec/architecture.md`` section 4.
ORIGIN_TRUST_CLASSES: tuple[str, ...] = (
    "merged-default",
    "approved-pr",
    "unreviewed-branch",
    "uncommitted-worktree",
)

#: Destination vocabulary, ``spec/product.md`` P-2.
DESTINATIONS: tuple[str, ...] = ("personal", "company", "codebase", "none")

#: Atom kinds, ``spec/product.md`` P-2. Closed: Validator ruling C13 --
#: ``atom_kind`` is exactly one of these six; lifecycle actions are dispositions.
ATOM_KINDS: tuple[str, ...] = (
    "claim",
    "question",
    "decision",
    "constraint",
    "rationale",
    "observation",
)

#: Lifecycle actions the spec names but omits from the message-type enum.
#: Validator ruling C13: each is a ``FactEvent`` signed as ``fact-event`` whose
#: ``disposition`` is the action name and whose ``parents``/``supersedes`` name
#: the affected events.
LIFECYCLE_ACTIONS: tuple[str, ...] = (
    "misextraction",
    "never_true",
    "support_withdrawn",
    "orphan_abandoned",
    "manifest_observation_expired",
    "relaxation",
    "exception_request",
    "unreachable_clone_residual",
)

#: Closed disposition vocabulary, Validator ruling C13.
DISPOSITIONS: tuple[str, ...] = (
    "draft",
    "proposed",
    "accepted",
    "approved",
    "merged",
    "rejected",
    "reverted",
    "deployed",
    "retracted",
    "superseded",
) + LIFECYCLE_ACTIONS

#: ``distortion`` is exactly this field set (``spec/architecture.md`` section 3).
DISTORTION_FIELDS: tuple[str, ...] = ("trigger", "loss_if_absent", "rationale")

#: Closed approval decision vocabulary, ``spec/architecture.md`` section 5.
DECISIONS: tuple[str, ...] = ("approve", "reject", "defer", "escalate")

#: Closed reset reason codes, ``spec/cli.md``.
RESET_REASON_CODES: tuple[str, ...] = (
    "new-primary-task",
    "operator-recovery",
    "host-restart",
)


def receipt_stamp(offset_seconds: int = 0) -> str:
    """R-14 receipt time on the proof clock; validity dates use _stamp instead."""
    import os
    import time

    offset = int(os.environ.get("GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS", "0"))
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                         time.gmtime(time.time() + offset + offset_seconds))


def _stamp(day: int = 1, hour: int = 0, minute: int = 0) -> str:
    stamp = datetime(2026, 3, 1) + timedelta(days=day - 1, hours=hour, minutes=minute)
    return stamp.isoformat(timespec="milliseconds") + "Z"


# --------------------------------------------------------------------------
# 1. Codex rollout/session JSONL
# --------------------------------------------------------------------------


def codex_session_jsonl(
    path: Path,
    *,
    session_id: str,
    cwd: str,
    turns: Sequence[Mapping[str, Any]],
) -> Path:
    """Emit a Codex rollout JSONL file in its host layout.

    ``spec/architecture.md`` section 4: "``codex_jsonl``: parses Codex rollout
    JSONL and recorded cwd/repo metadata".
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        json.dumps(
            {
                "type": "session_meta",
                "id": session_id,
                "timestamp": _stamp(),
                "cwd": cwd,
                "originator": "codex_cli_rs",
                "cli_version": "0.0.0-acceptance",
            }
        )
    ]
    for index, turn in enumerate(turns):
        lines.append(
            json.dumps(
                {
                    "type": "response_item",
                    "id": f"{session_id}-{index:04d}",
                    "timestamp": _stamp(minute=index),
                    "payload": {
                        "type": turn.get("role", "message"),
                        "role": turn.get("role", "user"),
                        "content": [
                            {"type": "input_text", "text": turn["text"]}
                        ],
                    },
                }
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# 2. Claude Code session JSONL
# --------------------------------------------------------------------------


def claude_session_jsonl(
    path: Path,
    *,
    session_id: str,
    cwd: str,
    turns: Sequence[Mapping[str, Any]],
) -> Path:
    """Emit a Claude Code project-session JSONL file in its host layout.

    ``spec/architecture.md`` section 4: "``claude_jsonl``: parses Claude Code
    project-session JSONL". The Claude layout differs from Codex: one record per
    turn with ``parentUuid`` chaining, which is why V-1 requires both transcript
    adapters to parse "exports produced by their actual host layouts" rather than
    one normalised shape.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    parent: str | None = None
    for index, turn in enumerate(turns):
        record_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{session_id}/{index}"))
        lines.append(
            json.dumps(
                {
                    "parentUuid": parent,
                    "isSidechain": False,
                    "userType": "external",
                    "cwd": cwd,
                    "sessionId": session_id,
                    "version": "0.0.0-acceptance",
                    "type": turn.get("role", "user"),
                    "message": {
                        "role": turn.get("role", "user"),
                        "content": [{"type": "text", "text": turn["text"]}],
                    },
                    "uuid": record_uuid,
                    "timestamp": _stamp(minute=index),
                }
            )
        )
        parent = record_uuid
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# 3/4. Repository source, interface declarations, tests and results
# --------------------------------------------------------------------------


PY_MODULE = '''"""Scheduling service (acceptance fixture)."""

from dataclasses import dataclass


DEFAULT_LOOKAHEAD_MINUTES: int = 90


@dataclass(frozen=True)
class SchedulingWindow:
    """Interface declaration exercised by the repo_code adapter."""

    lookahead_minutes: int
    tenant_id: str


def diagnose(window: SchedulingWindow) -> str:
    return f"lookahead={window.lookahead_minutes}"
'''

TS_MODULE = """export interface SchedulingWindow {
  lookaheadMinutes: number;
  tenantId: string;
}

export const DEFAULT_LOOKAHEAD_MINUTES = 90;

export function diagnose(window: SchedulingWindow): string {
  return `lookahead=${window.lookaheadMinutes}`;
}
"""

TEST_MODULE = '''from scheduler import SchedulingWindow, diagnose


def test_diagnose_reports_lookahead():
    assert diagnose(SchedulingWindow(90, "t-1")) == "lookahead=90"
'''


def command_result_envelope(
    path: Path,
    *,
    command: Sequence[str],
    exit_code: int,
    stdout: str,
    observed_at: str,
    environment_id: str | None = None,
    effective_until: str | None = None,
    owner: str | None = None,
) -> Path:
    """Canonical command/config/trace envelope for ``repo_tests``/``runtime_evidence``.

    ``spec/architecture.md`` section 4: "Runtime evidence names the
    environment/deployment owner and a freshness-bounded ``effective_until``."
    """
    payload: dict[str, Any] = {
        "schema": "guildhall-command-result/1",
        "command": list(command),
        "exit_code": exit_code,
        "stdout": stdout,
        "observed_at": observed_at,
    }
    if environment_id is not None:
        payload["environment_id"] = environment_id
    if effective_until is not None:
        payload["effective_until"] = effective_until
    if owner is not None:
        payload["environment_owner"] = owner
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical.jcs(payload))
    return path


# --------------------------------------------------------------------------
# 6. ADRs
# --------------------------------------------------------------------------


def adr(
    path: Path,
    *,
    number: int,
    title: str,
    status: str,
    body: str,
    supersedes: int | None = None,
) -> Path:
    """Markdown ADR with explicit lifecycle status metadata."""
    front = [
        "---",
        f"adr: {number:04d}",
        f"title: {title}",
        f"status: {status}",
    ]
    if supersedes is not None:
        front.append(f"supersedes: {supersedes:04d}")
    front.append("---")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(front) + f"\n\n# {title}\n\n{body}\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# 7. GitHub export
# --------------------------------------------------------------------------


def github_export(
    path: Path,
    *,
    issues: Sequence[Mapping[str, Any]] = (),
    pulls: Sequence[Mapping[str, Any]] = (),
) -> Path:
    """`gh` style JSON export including review and disposition state."""
    payload = {
        "schema": "gh-export/1",
        "issues": list(issues),
        "pullRequests": list(pulls),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def pull_request(
    *,
    number: int,
    title: str,
    state: str,
    merged: bool,
    reviews: Sequence[Mapping[str, Any]] = (),
    body: str = "",
) -> dict[str, Any]:
    return {
        "number": number,
        "title": title,
        "state": state,
        "merged": merged,
        "body": body,
        "reviews": list(reviews),
        "updatedAt": _stamp(day=2),
    }


# --------------------------------------------------------------------------
# 9. Kindex export / legacy SQLite
# --------------------------------------------------------------------------


def kindex_sqlite_export(path: Path, nodes: Sequence[Mapping[str, Any]]) -> Path:
    """A minimal Kindex-shaped SQLite graph export.

    ``spec/architecture.md`` section 4: "``kindex``: exported SQLite graph facts
    and ``.kin/`` events/indexes". Guildhall must read it through public seams;
    the fixture simply provides a real SQLite file with text and blob columns so
    the V-3 blob scan has something to find.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS nodes ("
            "id TEXT PRIMARY KEY, node_type TEXT, title TEXT, content TEXT, "
            "payload BLOB, created_at TEXT)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS edges ("
            "src TEXT, dst TEXT, relationship TEXT, reason TEXT)"
        )
        for node in nodes:
            conn.execute(
                "INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,?,?)",
                (
                    node["id"],
                    node.get("node_type", "concept"),
                    node.get("title", ""),
                    node.get("content", ""),
                    node.get("payload", b""),
                    node.get("created_at", _stamp()),
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return path


def legacy_kin_inventory(root: Path) -> list[Path]:
    """A fully populated pinned-Kindex ``.kin/`` inventory.

    ``spec/architecture.md`` section 11: "Acceptance initializes against a fully
    populated real pinned-Kindex repository, proves every legacy byte is
    preserved, and injects one deliberate path collision that must refuse."
    """
    kin = root / ".kin"
    created: list[Path] = []
    files = {
        "config": (
            "name: legacy-service\n"
            "description: pre-existing Kindex repository graph\n"
            "audience: team\n"
            "data_dir: .kin/local\n"
        ),
        "index.json": json.dumps(
            {
                "domains": ["scheduling"],
                "node_count": 2,
                "nodes": [
                    {"id": "n1", "title": "legacy concept", "type": "concept"},
                    {"id": "n2", "title": "legacy decision", "type": "decision"},
                ],
                "repo": "legacy-service",
                "version": 2,
            },
            indent=2,
            sort_keys=True,
        ),
        "code-map.json": json.dumps({"files": {}, "version": 1}, sort_keys=True),
        ".gitignore": "local/\n",
        "local/kindex.db": "",
    }
    for rel, body in files.items():
        target = kin / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        created.append(target)
    return created


# --------------------------------------------------------------------------
# 10. Signed events, answers, certificates
# --------------------------------------------------------------------------


@dataclass
class Signer:
    """A fictional principal with a generated Ed25519 key."""

    authority_id: str
    scope: str
    seed: bytes

    @property
    def public_hex(self) -> str:
        return ed25519_pure.public_key(self.seed).hex()

    def sign_message(self, message_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Sign under the one instrument-wide convention (Validator ruling C4).

        The signed bytes are the JCS of the document with ``signature`` removed
        and ``signer`` (the 64-hex Ed25519 public key) present; ``signature`` is
        128 hex over ``signing_digest(message_type, jcs_bytes)``.
        """
        return signed_document(self.seed, message_type, payload)

    def sign_over_other_type(
        self, sign_as: str, claim_as: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Deliberately cross-domain signature for attack family 12."""
        body = dict(payload)
        body["claimed_message_type"] = claim_as
        return signed_document(self.seed, sign_as, body)


def signed_bytes(document: Mapping[str, Any]) -> bytes:
    """The exact bytes every signer signs and every verifier checks (C4)."""
    body = {k: v for k, v in document.items() if k != "signature"}
    if "signer" not in body:
        raise ValueError("a signed document carries its signer inside the signed bytes")
    return canonical.jcs(body)


def signed_document(seed: bytes, message_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(payload)
    body.pop("signature", None)
    body["signer"] = ed25519_pure.public_key(seed).hex()
    digest = canonical.signing_digest(message_type, signed_bytes(body))
    body["signature"] = ed25519_pure.sign(seed, digest).hex()
    return body


def verify_document(message_type: str, document: Mapping[str, Any]) -> bool:
    """Verify a document under the one convention. False on any malformation."""
    try:
        signature = bytes.fromhex(str(document["signature"]))
        public = bytes.fromhex(str(document["signer"]))
        digest = canonical.signing_digest(message_type, signed_bytes(document))
    except (KeyError, ValueError, TypeError, canonical.CanonicalisationError):
        return False
    if len(signature) != 64 or len(public) != 32:
        return False
    return ed25519_pure.verify(public, digest, signature)


def make_signer(authority_id: str, scope: str, *, seed_byte: int = 7) -> Signer:
    return Signer(authority_id=authority_id, scope=scope, seed=bytes([seed_byte]) * 32)


def fact_event(
    *,
    store_kind: str,
    authority_id: str,
    authority_scope: str,
    logical_key: str,
    statement: str,
    atom_kind: str = "constraint",
    repository_id: str | None = None,
    asserted_at: str | None = None,
    effective_from: str | None = None,
    effective_until: str | None = None,
    disposition: str = "accepted",
    parents: Sequence[str] = (),
    supersedes: Sequence[str] = (),
    evidence_refs: Sequence[str] = (),
    company_refs: Sequence[Mapping[str, Any]] = (),
    distortion: Mapping[str, Any] | None = None,
    authority_snapshot_cursor: str = "1",
    confidence: str = "high",
    unresolved_uncertainty: str = "",
    unchecked: bool = False,
) -> dict[str, Any]:
    """A ``FactEvent`` shaped exactly as ``spec/architecture.md`` section 3 lists.

    ``event_id`` is derived from the event's own content (Validator ruling C14),
    so two events with different bytes never share an id and a retraction or
    supersession never collides with the event it retires. ``atom_kind`` and
    ``disposition`` are checked against the closed vocabularies (C13) unless
    ``unchecked`` is set, which only an explicit malformed-input probe may do.
    """
    if not unchecked:
        if atom_kind not in ATOM_KINDS:
            raise ValueError(
                f"atom_kind {atom_kind!r} is not one of the closed {ATOM_KINDS}"
            )
        if disposition not in DISPOSITIONS:
            raise ValueError(
                f"disposition {disposition!r} is not in the closed vocabulary"
            )
        if distortion is not None and tuple(sorted(distortion)) != tuple(
            sorted(DISTORTION_FIELDS)
        ):
            raise ValueError(
                f"distortion must be exactly {DISTORTION_FIELDS}, got {sorted(distortion)}"
            )
    payload: dict[str, Any] = {
        "schema": "guildhall-event/1",
        "store_kind": store_kind,
        "authority_id": authority_id,
        "authority_scope": authority_scope,
        "fact_id": f"fact_{abs(hash(logical_key)) % (10**12):012d}",
        "logical_key": logical_key,
        "atom_kind": atom_kind,
        "scope": authority_scope,
        "statement": statement,
        "evidence_refs": list(evidence_refs),
        "asserted_at": asserted_at or _stamp(),
        "effective_from": effective_from or _stamp(),
        "disposition": disposition,
        "distortion": dict(
            distortion
            or {
                "trigger": "scheduler diagnosis edit",
                "loss_if_absent": "safety_critical" if store_kind == "company" else "high",
                "rationale": "dependent edit selects the wrong lookahead",
            }
        ),
        "parents": list(parents),
        "supersedes": list(supersedes),
        "redundancy_with": [],
        "complements": [],
        "company_refs": [dict(r) for r in company_refs],
        "authority_snapshot_cursor": authority_snapshot_cursor,
        "confidence": confidence,
        "unresolved_uncertainty": unresolved_uncertainty,
    }
    if repository_id is not None:
        payload["repository_id"] = repository_id
    if effective_until is not None:
        payload["effective_until"] = effective_until
    payload["event_id"] = content_event_id("evt", payload)
    return payload


def content_event_id(prefix: str, payload: Mapping[str, Any]) -> str:
    """``<prefix>_<sha256 of the JCS body without id, signer, signature>``."""
    body = {
        k: v for k, v in payload.items()
        if k not in ("event_id", "signer", "signature")
    }
    return prefix + "_" + hashlib.sha256(canonical.jcs(body)).hexdigest()


def unknown_event(
    *,
    store_kind: str,
    logical_key: str,
    decision_blocked: str,
    owner_role: str,
    owner_identity: str,
    question: str,
    closure_evidence: str,
    authority_id: str = "",
    authority_scope: str = "",
    repository_id: str | None = None,
    statement: str | None = None,
    parents: Sequence[str] = (),
    status: str = "open",
    response_due_at: str | None = None,
    expiry_policy: str = "block",
    distortion: Mapping[str, Any] | None = None,
    authority_snapshot_cursor: str = "1",
) -> dict[str, Any]:
    """An ``UnknownEvent``; ``spec/architecture.md`` section 3.

    "``UnknownEvent`` adds ``decision_blocked``, ``owner_role``,
    ``owner_identity``, ``question``, ``closure_evidence``, ``status``,
    ``response_due_at``, and ``expiry_policy``" to the ``FactEvent`` field set,
    so the body is a question-kind fact event plus those eight fields.
    """
    payload = fact_event(
        store_kind=store_kind,
        authority_id=authority_id,
        authority_scope=authority_scope,
        logical_key=logical_key,
        statement=statement or question,
        atom_kind="question",
        repository_id=repository_id,
        disposition="proposed",
        parents=parents,
        distortion=distortion,
        authority_snapshot_cursor=authority_snapshot_cursor,
        confidence="low",
        unresolved_uncertainty=question,
    )
    payload.pop("event_id")
    payload["schema"] = "guildhall-unknown/1"
    payload.update({
        "decision_blocked": decision_blocked,
        "owner_role": owner_role,
        "owner_identity": owner_identity,
        "question": question,
        "closure_evidence": closure_evidence,
        "status": status,
        "response_due_at": response_due_at or _stamp(day=5),
        "expiry_policy": expiry_policy,
    })
    payload["event_id"] = content_event_id("unk", payload)
    return payload


def company_reference(
    *,
    company_id: str,
    fact_id: str,
    semantic_digest: str,
    digest_alg_version: str,
    authority: str,
    valid_from: str,
    valid_until: str,
    company_criticality: str,
    relation: str,
) -> dict[str, Any]:
    """A ``CompanyReference``; ``spec/architecture.md`` section 3.

    Note that ``local_dependence_class`` is deliberately absent: it "is a
    Codebase fact owned by the in-scope repository maintainer", not a field
    Company owns.
    """
    if relation not in {
        "applies",
        "specializes",
        "implements",
        "contradicts",
        "exception_request",
    }:
        raise ValueError(f"unsupported relation {relation!r}")
    return {
        "company_id": company_id,
        "fact_id": fact_id,
        "semantic_digest": semantic_digest,
        "digest_alg_version": digest_alg_version,
        "authority": authority,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "company_criticality": company_criticality,
        "relation": relation,
    }


def repo_certificate(
    steward: Signer, *, repository_uuid: str, lineage_parent: str | None = None
) -> dict[str, Any]:
    """Out-of-worktree Company-steward repository certificate."""
    payload: dict[str, Any] = {
        "schema": "guildhall-repo-certificate/1",
        "repository_uuid": repository_uuid,
        "issued_at": _stamp(),
        "company_id": "company-demo",
    }
    if lineage_parent is not None:
        payload["lineage_parent_uuid"] = lineage_parent
    return steward.sign_message("repo-certificate", payload)


def authority_answer(
    authority: Signer, *, question_id: str, answer: str, rationale: str
) -> dict[str, Any]:
    """A signed answer containing fact and rationale only.

    ``spec/verification.md`` V-6: "A response contains fact and rationale
    only---never code or a solution".
    """
    return authority.sign_message(
        "answer",
        {
            "schema": "guildhall-answer/1",
            "question_id": question_id,
            "authority_id": authority.authority_id,
            "authority_scope": authority.scope,
            "answer": answer,
            "rationale": rationale,
            "answered_at": _stamp(day=3),
        },
    )


# --------------------------------------------------------------------------
# Held-out routing corpus generator (structure only)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RoutingCase:
    """One held-out message with gold atom boundaries and destination sets.

    ``spec/verification.md`` V-2: "Tester freezes at least 120 held-out natural
    messages with gold atom boundaries and destination sets; at least 40 are
    mixed and at least 100 contain varied private/safety canaries or
    transformations."
    """

    message_id: str
    template: str
    gold_atoms: tuple[tuple[str, str, tuple[str, ...]], ...]
    mixed: bool
    canary_slots: tuple[str, ...]
    stratum: str

    @property
    def destination_set(self) -> frozenset[str]:
        out: set[str] = set()
        for _, _, dests in self.gold_atoms:
            out.update(dests)
        return frozenset(out)


def render_case(case: RoutingCase, values: Mapping[str, str]) -> str:
    """Instantiate a template. Raw values live only in the Tester vault."""
    text = case.template
    for slot in case.canary_slots:
        if slot not in values:
            raise KeyError(f"missing canary value for slot {slot!r}")
        text = text.replace(f"{{{slot}}}", values[slot])
    return text
