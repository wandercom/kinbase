"""Causal, pre-execution mutation planters with independent witnesses.

Detector Reviewer finding 7. The previous planters were an interposer: a wrapper
that ran the real product to completion and then rewrote its stdout and exit
status. That mutates the *observation*, not the behaviour. A gate could pass its
mutation run while the product was never wrong, and the mutation proved only
that the assertion reads the field the wrapper edited.

Every planter here changes **raw state the product will later read**, before the
product is started:

* ``world.*`` --- the bytes of a signed event, its claim, or its signature;
* ``trust.*`` --- the repository certificate, the external trust root, or the
  published ``AuthorityRegistry`` scope;
* ``native.*`` --- an adapter's own native source file;
* ``config.*`` --- the user or service configuration the product loads;
* ``corpus.*`` --- a product-bound corpus record;
* ``fault.*`` --- an ordering or crash schedule applied at a real seam.

The harness calls :func:`mutate` at each seam as it constructs state. When a
planter is active and its point is reached, the value is transformed and an
**independent witness** is recorded: for a path, the bytes are re-read from disk
after the write; for a document, the canonical form is re-digested. A mutation
run in which the seam was never reached is ``INVALID_HARNESS`` --- the planter
did not apply, so nothing was tested --- which :func:`require_applied` enforces.

Nothing here reads or edits product output. If the product behaves correctly in
a world that is genuinely defective, the gate's obligation is genuinely unmet
and the named node fails in its declared channel. That is the kill.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from .mutations import CATALOG, Mutation, active_mutation
from .requirements import HarnessInvalid

#: Every seam at which raw state passes from the instrument to the product.
POINTS: dict[str, str] = {
    "world.event_body": "the claim inside a fact event, before it is signed",
    "world.event_bytes": "the signed event's canonical bytes, before they are written",
    "world.unknown": "an Unknown record, before it is written",
    "trust.certificate": "the steward-signed repository certificate",
    "trust.root_key": "the external Company root public key and its location",
    "trust.registry": "the published AuthorityRegistry document",
    "native.source": "a native adapter source file produced by a lifecycle cell",
    "config.user": "the user configuration the shared processes load",
    "config.service": "the Company service configuration",
    "corpus.record": "one product-bound corpus record, before it is emitted",
    "fault.schedule": "an ordering, interleave or crash schedule at a real seam",
    "host.envelope": "a native host lifecycle payload, before it is delivered",
}

WORLD_DEFECT = "world_defect"
TRUST_DEFECT = "trust_defect"
CONFIG_DEFECT = "config_defect"
CORPUS_DEFECT = "corpus_defect"
FAULT_SCHEDULE = "fault_schedule"

PRODUCT_CHANNEL = "PRODUCT_FAILURE"
INSTRUMENT_CHANNEL = "INVALID_HARNESS"


@dataclass(frozen=True)
class Planter:
    """One executable, pre-execution realisation of a catalogued mutation."""

    mutation_id: str
    point: str
    kind: str
    description: str
    transform: Callable[[Any, Mapping[str, Any]], Any]
    expected_channel: str = PRODUCT_CHANNEL

    def __post_init__(self) -> None:
        if self.mutation_id not in CATALOG:
            raise HarnessInvalid(
                f"planter names {self.mutation_id!r}, which the frozen catalog "
                "does not declare"
            )
        if self.point not in POINTS:
            raise HarnessInvalid(f"unknown mutation point {self.point!r}")
        if self.kind not in (WORLD_DEFECT, TRUST_DEFECT, CONFIG_DEFECT,
                             CORPUS_DEFECT, FAULT_SCHEDULE):
            raise HarnessInvalid(f"unknown planter kind {self.kind!r}")

    @property
    def mutation(self) -> Mutation:
        return CATALOG[self.mutation_id]

    @property
    def must_fail_nodes(self) -> tuple[str, ...]:
        return self.mutation.must_fail_nodes

    def as_json(self) -> dict:
        return {
            "mutation_id": self.mutation_id,
            "gate": self.mutation.gate,
            "point": self.point,
            "point_meaning": POINTS[self.point],
            "kind": self.kind,
            "description": self.description,
            "expected_channel": self.expected_channel,
            "semantics": self.mutation.semantics,
            "requirement": self.mutation.requirement_quote,
            "must_fail_nodes": list(self.must_fail_nodes),
            "applies_before_product_execution": True,
        }


# --------------------------------------------------------------------------
# Transforms. Each takes the raw value about to be handed to the product.
# --------------------------------------------------------------------------


def _set(body: Any, path: str, value: Any) -> Any:
    out = copy.deepcopy(body)
    node = out
    parts = path.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    return out


def _drop(body: Any, path: str) -> Any:
    out = copy.deepcopy(body)
    node = out
    parts = path.split(".")
    for part in parts[:-1]:
        node = node.get(part)
        if not isinstance(node, dict):
            return out
    node.pop(parts[-1], None)
    return out


def _observations_to_count(body, ctx):
    """V-1: an adapter reports a source count and no observations."""
    out = _set(body, "observations", [])
    return _set(out, "observations_count_only", 1)


def _approver_mints_never_true(body, ctx):
    """V-1: the approver, not the steward/maintainer, signs semantic withdrawal.

    Validator ruling C13: ``never_true`` is a disposition on a FactEvent, not
    an atom kind.
    """
    out = _set(body, "disposition", "never_true")
    return _set(out, "authority_scope", "approver:local")


def _single_label(record, ctx):
    """V-2: one label for the whole message instead of per-atom destinations."""
    out = copy.deepcopy(record)
    out["atoms"] = [{"text": out.get("text", ""), "destination": "company"}]
    return out


def _shared_by_default(record, ctx):
    out = copy.deepcopy(record)
    out["confidence"] = "low"
    out["destination_default"] = "company"
    return out


def _common_transaction(document, ctx):
    """V-2: one transaction spanning both destinations."""
    return _set(document, "fanout_transaction", "common")


def _nonce_retention_zero(document, ctx):
    """V-2/V-3: nonce retention shorter than candidate lifetime plus skew."""
    return _set(document, "nonce_retention_seconds", 0)


def _transcript_digest_into_event(body, ctx):
    """V-3: bind the raw transcript digest into a shared record."""
    return _set(body, "transcript_digest",
                hashlib.sha256(b"raw-transcript").hexdigest())


def _personal_root_into_user_config(document, ctx):
    """V-3: the Personal path becomes readable from shared configuration."""
    personal = str(ctx.get("personal_root", "/personal"))
    out = _set(document, "personal_data_root", personal)
    return _set(out, "classifier_args", ["--json", "--extra-root=" + personal])


def _mount_personal_in_query(document, ctx):
    return _set(document, "projection_roots",
                [str(ctx.get("personal_root", "/personal"))])


def _trust_kin_trust_json(document, ctx):
    """V-3: a worktree-local trust file becomes the trust root."""
    return _set(document, "trust_root_path", ".kin/trust.json")


def _clear_taint(record, ctx):
    out = copy.deepcopy(record)
    out["taint"] = []
    out["deidentified"] = True
    return out


def _candidate_path_swap(record, ctx):
    """V-3: the approved bytes and the committed path diverge."""
    out = copy.deepcopy(record)
    out["candidate_path"] = str(ctx.get("swap_path", "candidate.swapped"))
    return out


def _worktree_only_key(body, ctx):
    """V-3: the signing authority is absent from the published registry."""
    return _set(body, "authority_id", "worktree-only-key-1")


def _signature_reuse(raw: bytes, ctx) -> bytes:
    """V-3: a signature valid for one message type is presented for another."""
    payload = json.loads(raw.decode("utf-8"))
    payload["message_type"] = "authority-answer"
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_one_apply_another(raw: bytes, ctx) -> bytes:
    """V-3: the verified bytes and the parsed bytes differ."""
    payload = json.loads(raw.decode("utf-8"))
    payload["statement"] = str(payload.get("statement", "")) + " shadow"
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _wildcard_scope(document, ctx):
    out = copy.deepcopy(document)
    for entry in out.get("entries", []):
        entry["scope"] = "*"
    return out


def _sql_interpolation(record, ctx):
    out = copy.deepcopy(record)
    out["logical_key"] = "architecture/'; DROP TABLE facts; --"
    return out


def _remove_scoped_token_enforcement(document, ctx):
    return _set(document, "facts_token_scopes", ["*"])


def _race_concurrent_approvals(schedule, ctx):
    out = dict(schedule)
    out["interleave"] = "both_approvals_between_check_and_commit"
    out["barrier"] = "release_simultaneously"
    return out


def _raw_terminal_output(record, ctx):
    """V-3: request raw rendering of a carriage-return/ANSI preview payload."""
    out = copy.deepcopy(record)
    out["preview_escaping"] = "raw"
    out["statement"] = "approved" + chr(13) + "DENIED" + chr(27) + "[2K"
    return out


def _greatest_timestamp_wins(document, ctx):
    return _set(document, "conflict_resolution", "greatest_timestamp")


def _omit_as_of(document, ctx):
    """V-4: the rebuild takes ``as_of`` from the ambient clock instead of the
    pinned input, which is exactly the omission the requirement forbids."""
    out = _drop(document, "as_of")
    return _set(out, "rebuild_as_of", "ambient")


def _stale_head_as_authority(document, ctx):
    return _set(document, "manifest_authority", "company_head_observation")


def _worktree_local_lock(document, ctx):
    return _set(document, "lock_path", ".git/worktrees/local/kinbase.lock")


def _content_path_before_revocation(document, ctx):
    return _set(document, "admission_order", ["content_path", "authority", "revocation"])


def _newest_wins(document, ctx):
    return _set(document, "reducer_policy", "newest_wins")


def _highest_authority_wins(document, ctx):
    return _set(document, "reducer_policy", "highest_authority_always_wins")


def _repetition_as_independence(record, ctx):
    """V-5: ten copies of one statement, each presented as a separate source."""
    out = copy.deepcopy(record)
    out["independent_source_id"] = "copy-" + str(ctx.get("index", 0))
    out["copied_from"] = None
    return out


def _synthesize_answer(document, ctx):
    return _set(document, "authority_channel", "local_model_prior")


def _independent_scalar_topk(document, ctx):
    return _set(document, "selection_policy", "independent_scalar_topk")


def _codebase_authorizes_exception(body, ctx):
    out = _set(body, "atom_kind", "exception_to")
    return _set(out, "store_kind", "codebase")


def _disable_mid_session_capture(envelope, ctx):
    out = copy.deepcopy(envelope)
    out["capture"] = {"session_start": True, "mid_session": False}
    return out


def _reservation_after_render(schedule, ctx):
    out = dict(schedule)
    out["reservation_order"] = "render_then_reserve"
    return out


def _check_outside_transaction(schedule, ctx):
    out = dict(schedule)
    out["transaction_scope"] = "reissue_check_outside_begin_immediate"
    return out


# --------------------------------------------------------------------------
# The frozen planter set: one per catalogued product mutation.
# --------------------------------------------------------------------------


def _p(mutation_id, point, kind, description, transform) -> Planter:
    return Planter(mutation_id, point, kind, description, transform)


PLANTERS: tuple[Planter, ...] = (
    # V-1
    _p("v1.adapter_count_without_observations", "world.event_body", WORLD_DEFECT,
       "the adapter receipt carries a source count and an empty observation list",
       _observations_to_count),
    _p("v1.approver_mints_never_true", "world.event_body", WORLD_DEFECT,
       "the semantic withdrawal is signed under an approver scope rather than "
       "the steward/maintainer scope the requirement names",
       _approver_mints_never_true),
    # V-2
    _p("v2.whole_message_single_label", "corpus.record", CORPUS_DEFECT,
       "the message arrives pre-collapsed to one label, so per-atom destinations "
       "cannot be recovered from the raw record", _single_label),
    _p("v2.shared_by_default_low_confidence", "corpus.record", CORPUS_DEFECT,
       "the record declares a shared default at low confidence", _shared_by_default),
    _p("v2.common_fanout_transaction", "config.service", CONFIG_DEFECT,
       "the service is configured with one fan-out transaction across "
       "destinations", _common_transaction),
    _p("v2.remove_nonce_uniqueness_recovery", "config.service", CONFIG_DEFECT,
       "nonce retention is shorter than candidate lifetime plus clock skew",
       _nonce_retention_zero),
    # V-3
    _p("v3.transcript_digest_in_receipt", "world.event_body", WORLD_DEFECT,
       "a raw transcript digest is bound into a durable shared record",
       _transcript_digest_into_event),
    _p("v3.mount_personal_in_coding_query", "config.user", CONFIG_DEFECT,
       "the shared projection root list includes the Personal root",
       _mount_personal_in_query),
    _p("v3.trust_kin_trust_json", "config.user", CONFIG_DEFECT,
       "the trust root is redirected to a worktree-local file",
       _trust_kin_trust_json),
    _p("v3.clear_taint_after_deidentification", "corpus.record", CORPUS_DEFECT,
       "the record arrives with its taint list cleared and a de-identification "
       "flag set", _clear_taint),
    _p("v3.reread_candidate_path_after_approval", "corpus.record", CORPUS_DEFECT,
       "the candidate path names different bytes than the approved buffer",
       _candidate_path_swap),
    _p("v3.worktree_only_key_admission", "world.event_body", WORLD_DEFECT,
       "the event is signed by an authority the published registry does not "
       "contain", _worktree_only_key),
    _p("v3.signature_reuse_across_message_types", "world.event_bytes", WORLD_DEFECT,
       "the message type is rewritten after signing, so one signature is "
       "presented for a different type", _signature_reuse),
    _p("v3.verify_one_parse_apply_another", "world.event_bytes", WORLD_DEFECT,
       "the canonical bytes carry a shadow statement after the signed digest",
       _verify_one_apply_another),
    _p("v3.wildcard_authority_scope", "trust.registry", TRUST_DEFECT,
       "every published authority scope becomes a wildcard", _wildcard_scope),
    _p("v3.sql_interpolation", "corpus.record", CORPUS_DEFECT,
       "a logical key carries a statement-terminating SQL fragment",
       _sql_interpolation),
    _p("v3.personal_path_in_shared_argv_config", "config.user", CONFIG_DEFECT,
       "the Personal root is written into the shared configuration and the "
       "classifier argument vector", _personal_root_into_user_config),
    _p("v3.remove_scoped_token_enforcement", "config.service", CONFIG_DEFECT,
       "the facts token is issued with a wildcard scope set",
       _remove_scoped_token_enforcement),
    _p("v3.remove_nonce_uniqueness", "config.service", CONFIG_DEFECT,
       "nonce retention is set to zero", _nonce_retention_zero),
    _p("v3.race_concurrent_approvals", "fault.schedule", FAULT_SCHEDULE,
       "two approvals are released simultaneously between the slot check and "
       "the commit", _race_concurrent_approvals),
    _p("v3.raw_terminal_output", "corpus.record", CORPUS_DEFECT,
       "the preview record requests raw terminal rendering of a control payload",
       _raw_terminal_output),
    # V-4
    _p("v4.greatest_timestamp_wins", "config.user", CONFIG_DEFECT,
       "conflict resolution is configured to take the greatest timestamp",
       _greatest_timestamp_wins),
    _p("v4.omit_as_of", "config.user", CONFIG_DEFECT,
       "the rebuild inputs omit as_of entirely", _omit_as_of),
    _p("v4.stale_company_head_as_git_authority", "config.user", CONFIG_DEFECT,
       "a stale Company head observation is configured as the manifest "
       "authority", _stale_head_as_authority),
    _p("v4.worktree_local_lock", "config.user", CONFIG_DEFECT,
       "the admission lock is placed in a worktree-local directory rather than "
       "Git's common directory", _worktree_local_lock),
    _p("v4.content_path_before_revocation", "config.user", CONFIG_DEFECT,
       "admission checks the content path before authority and revocation",
       _content_path_before_revocation),
    # V-5
    _p("v5.newest_wins", "config.user", CONFIG_DEFECT,
       "the reducer policy is newest-wins", _newest_wins),
    _p("v5.highest_authority_always_wins", "config.user", CONFIG_DEFECT,
       "the reducer policy is highest-authority-always-wins",
       _highest_authority_wins),
    _p("v5.repetition_as_independence", "corpus.record", CORPUS_DEFECT,
       "each copied comment is relabelled as an independent source",
       _repetition_as_independence),
    # V-6
    _p("v6.synthesize_answer_from_model_prior", "config.user", CONFIG_DEFECT,
       "the authority channel is redirected to a local model prior",
       _synthesize_answer),
    # V-7
    _p("v7.independent_scalar_topk", "config.user", CONFIG_DEFECT,
       "the selection policy becomes an independent scalar top-k",
       _independent_scalar_topk),
    # V-8
    _p("v8.codebase_authorizes_exception_to", "world.event_body", WORLD_DEFECT,
       "the exception_to relation is asserted by a Codebase-scoped event",
       _codebase_authorizes_exception),
    # V-9
    _p("v9.disable_mid_session_capture", "host.envelope", CONFIG_DEFECT,
       "the delivered host payload disables mid-session capture while leaving "
       "SessionStart enabled", _disable_mid_session_capture),
    _p("v9.reservation_after_render", "fault.schedule", FAULT_SCHEDULE,
       "the reservation increment is scheduled after the render",
       _reservation_after_render),
    _p("v9.check_outside_transaction", "fault.schedule", FAULT_SCHEDULE,
       "the reissue eligibility check is scheduled outside BEGIN IMMEDIATE",
       _check_outside_transaction),
)

BY_ID: dict[str, Planter] = {p.mutation_id: p for p in PLANTERS}


# --------------------------------------------------------------------------
# Application and independent witnessing
# --------------------------------------------------------------------------


@dataclass
class Application:
    """An independently witnessed application of a planter."""

    mutation_id: str
    point: str
    before_digest: str
    after_digest: str
    context: dict[str, Any] = field(default_factory=dict)
    readback_digest: str = ""

    @property
    def effective(self) -> bool:
        return self.before_digest != self.after_digest

    def as_json(self) -> dict:
        return {
            "mutation_id": self.mutation_id,
            "point": self.point,
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "readback_digest": self.readback_digest,
            "independently_readback": bool(self.readback_digest),
            "effective": self.effective,
            "context": {k: str(v)[:200] for k, v in self.context.items()},
        }


_APPLICATIONS: list[Application] = []


def reset() -> None:
    _APPLICATIONS.clear()


def active() -> Planter | None:
    mutation_id = active_mutation()
    if mutation_id is None:
        return None
    if mutation_id.startswith("detector."):
        return None
    try:
        return BY_ID[mutation_id]
    except KeyError as exc:
        raise HarnessInvalid(
            "mutation " + repr(mutation_id) + " has no executable pre-execution "
            "planter; a catalogued mutation with no planter cannot be run"
        ) from exc


def _digest(value: Any) -> str:
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def mutate(point: str, value: Any, **context: Any) -> Any:
    """Apply the active planter at this seam, before the product sees ``value``.

    Returns ``value`` unchanged when no planter is active or the active planter
    belongs to a different seam.
    """
    if point not in POINTS:
        raise HarnessInvalid("unknown mutation point " + repr(point))
    planter = active()
    if planter is None or planter.point != point:
        return value
    before = _digest(value)
    mutated = planter.transform(value, context)
    after = _digest(mutated)
    _APPLICATIONS.append(
        Application(
            mutation_id=planter.mutation_id,
            point=point,
            before_digest=before,
            after_digest=after,
            context=dict(context),
        )
    )
    return mutated


def witness_path(path: Path) -> None:
    """Independently re-read a written path to confirm the mutation landed."""
    if not _APPLICATIONS:
        return
    application = _APPLICATIONS[-1]
    if path.is_file():
        application.readback_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        application.context["readback_path"] = str(path)


def applications() -> tuple[Application, ...]:
    return tuple(_APPLICATIONS)


def require_applied() -> Application:
    """A mutation run whose seam was never reached tested nothing."""
    planter = active()
    if planter is None:
        raise HarnessInvalid("no product mutation is active")
    matching = [a for a in _APPLICATIONS if a.mutation_id == planter.mutation_id]
    if not matching:
        raise HarnessInvalid(
            "mutation " + planter.mutation_id + " never reached its seam "
            + repr(planter.point) + ", so the run exercised no defect at all; a "
            "node failing here would be an infrastructure failure, not a kill"
        )
    ineffective = [a for a in matching if not a.effective]
    if len(ineffective) == len(matching):
        raise HarnessInvalid(
            "mutation " + planter.mutation_id + " produced no byte change at "
            + repr(planter.point) + "; an inert planter cannot kill anything"
        )
    return matching[0]


def as_json() -> dict:
    return {
        "schema": "kinbase-preexecution-planters/1",
        "points": dict(POINTS),
        "planters": [p.as_json() for p in PLANTERS],
        "applications": [a.as_json() for a in _APPLICATIONS],
    }


def digest() -> str:
    return hashlib.sha256(
        json.dumps(
            {"planters": [p.as_json() for p in PLANTERS], "points": POINTS},
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def coverage() -> tuple[str, ...]:
    """Catalogued product mutations with no executable planter."""
    return tuple(sorted(
        mid for mid, mutation in CATALOG.items()
        if mutation.method != "detector" and mid not in BY_ID
    ))
