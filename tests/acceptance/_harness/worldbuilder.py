"""Construct the real state each gate obligation ranges over.

Detector Reviewer findings 7 through 16 share one cause: the instrument told the
product *what answer to give* --- through a case ID, a scenario string, a fixture
mode flag or a gold-labelled input file --- instead of building the state whose
correct interpretation is the answer.

This module builds that state. It plants signed events at their computed
content-addressed paths, runs a real Company service, ingests real candidate
corpora, and hands the product nothing but raw input.

Two rules govern everything here:

**Opaque identity.** Where the instrument must correlate a product output with
tester-held gold, it uses a per-run random opaque ID. The product sees the ID but
the ID carries no information: the mapping to gold exists only in the harness. A
stable ``message_id`` or ``case_id`` would let an implementation memorise the
answer key, which is what the Reviewer demonstrated for V-2, V-5 and V-9.

**Witnessed perturbation only.** The only controls that may reach the system
under test are timing, ordering and failure schedules, and each must be
independently witnessed --- an observed crash, an observed clock, an observed
concurrent arrival --- so a product cannot satisfy the obligation by recognising
the request rather than surviving the event.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import secrets
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import canonical, ed25519_pure, planters, synth
from .gitfix import REQUIRED_ATTRIBUTE_LINES, GitRepo
from .requirements import HarnessInvalid, ProductFailure
from .roots import ProofRoots

REPO_UUID = "018f0000-0000-7000-8000-000000000001"


# --------------------------------------------------------------------------
# Opaque identity
# --------------------------------------------------------------------------


class OpaqueIds:
    """Per-run opaque identifiers with a harness-only mapping to gold.

    The product receives only :meth:`token`. Nothing about the expected answer
    is recoverable from it, so a correct output must come from the raw content.
    """

    def __init__(self, seed: bytes | None = None) -> None:
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._entropy = seed or secrets.token_bytes(16)

    def token(self, private_key: str) -> str:
        if private_key not in self._forward:
            token = hashlib.sha256(
                self._entropy + private_key.encode("utf-8")
            ).hexdigest()[:24]
            self._forward[private_key] = token
            self._reverse[token] = private_key
        return self._forward[private_key]

    def resolve(self, token: str) -> str:
        try:
            return self._reverse[token]
        except KeyError as exc:
            raise HarnessInvalid(
                f"product returned unknown opaque id {token!r}; the instrument "
                "cannot attribute it to any planted input"
            ) from exc

    def known(self, token: str) -> bool:
        return token in self._reverse


# --------------------------------------------------------------------------
# Signed shared state
# --------------------------------------------------------------------------


@dataclass
class SignedWorld:
    """A repository carrying genuinely signed, content-addressed events."""

    repo: GitRepo
    steward: synth.Signer
    maintainer: synth.Signer
    architect: synth.Signer
    planted: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(cls, repo_root: Path) -> "SignedWorld":
        repo = GitRepo.init(repo_root)
        repo.write(
            ".kin/config",
            'schema_version = "guildhall-repo/1"\n'
            f'repository_uuid_hint = "{REPO_UUID}"\n'
            'safe_name = "example-service"\n'
            'domains = ["scheduling"]\n',
        )
        repo.install_attributes(REQUIRED_ATTRIBUTE_LINES)
        repo.commit("initialise repository")
        return cls(
            repo=repo,
            steward=synth.make_signer("company-steward-1", "company:root", seed_byte=11),
            maintainer=synth.make_signer(
                "repo-maintainer-1", f"codebase:{REPO_UUID}", seed_byte=13
            ),
            architect=synth.make_signer(
                "chief-architect-1", "architecture:scheduling", seed_byte=3
            ),
        )

    # -- planting ---------------------------------------------------------

    def plant_event(
        self,
        signer: synth.Signer,
        *,
        store_kind: str,
        logical_key: str,
        statement: str,
        atom_kind: str = "constraint",
        disposition: str = "accepted",
        asserted_at: str | None = None,
        effective_from: str | None = None,
        effective_until: str | None = None,
        supersedes: Sequence[str] = (),
        parents: Sequence[str] = (),
        evidence_refs: Sequence[str] = (),
        company_refs: Sequence[Mapping[str, Any]] = (),
        distortion: Mapping[str, Any] | None = None,
        authority_snapshot_cursor: str = "1000",
        confidence: str = "high",
        commit: bool = True,
    ) -> dict[str, Any]:
        """Write one genuinely signed event at its computed content path."""
        body = synth.fact_event(
            store_kind=store_kind,
            authority_id=signer.authority_id,
            authority_scope=signer.scope,
            logical_key=logical_key,
            statement=statement,
            atom_kind=atom_kind,
            repository_id=REPO_UUID if store_kind == "codebase" else None,
            asserted_at=asserted_at,
            effective_from=effective_from,
            effective_until=effective_until,
            disposition=disposition,
            parents=parents,
            supersedes=supersedes,
            evidence_refs=evidence_refs,
            company_refs=company_refs,
            distortion=distortion,
            authority_snapshot_cursor=authority_snapshot_cursor,
            confidence=confidence,
        )
        # Detector Reviewer finding 7: a mutation must change the state the
        # product reads, before it reads it. Both seams are pre-execution: the
        # claim before it is signed, and the canonical bytes before they land at
        # their content path.
        body = planters.mutate(
            "world.event_body", body, logical_key=logical_key, store_kind=store_kind
        )
        signed = signer.sign_message("fact-event", body)
        raw = canonical.jcs(signed)
        raw = planters.mutate("world.event_bytes", raw, logical_key=logical_key)
        digest = canonical.content_digest_hex(raw)
        rel = ".kin/events/" + canonical.event_shard_path(digest)
        self.repo.write_bytes(rel, raw)
        planters.witness_path(self.repo.path / rel)
        record = {
            "event_id": signed["event_id"],
            "digest": digest,
            "path": rel,
            "logical_key": logical_key,
            "statement": statement,
            "signer": signer.authority_id,
            "scope": signer.scope,
            "disposition": disposition,
        }
        self.planted.append(record)
        if commit:
            self.repo.commit(f"plant {digest[:12]}")
        return record

    def verify_planted(self) -> None:
        """The instrument's own events must verify before the product sees them.

        Under an active ``world.*`` planter the world is *deliberately* defective,
        so this check is skipped for that seam only and the planter's independent
        witness stands in its place. Every other run must hand the product a
        world the instrument itself can verify.
        """
        planter = planters.active()
        if planter is not None and planter.point.startswith("world."):
            planters.require_applied()
            return
        for record in self.planted:
            path = self.repo.path / record["path"]
            if not path.is_file():
                raise HarnessInvalid(f"planted event missing at {record['path']}")
            raw = path.read_bytes()
            if canonical.content_digest_hex(raw) != record["digest"]:
                raise HarnessInvalid(
                    f"planted event {record['digest'][:12]} is not at its content path"
                )
            payload = json.loads(raw.decode("utf-8"))
            signature = bytes.fromhex(payload.pop("signature"))
            public = bytes.fromhex(payload["signer"])
            body = dict(payload)
            body.pop("signer", None)
            digest = canonical.signing_digest("fact-event", canonical.jcs(body))
            if not ed25519_pure.verify(public, digest, signature):
                raise HarnessInvalid(
                    f"planted event {record['digest'][:12]} does not verify; the "
                    "instrument must not hand the product invalid state"
                )

    def event_count(self) -> int:
        root = self.repo.path / ".kin" / "events"
        return len(list(root.rglob("*.json"))) if root.exists() else 0


# --------------------------------------------------------------------------
# Frozen temporal histories (V-5)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TemporalCase:
    """One ratified V-5 row, established by planted signed history alone."""

    case_id: str
    description: str
    logical_key: str
    decision: str
    expected_state: str
    expected_fragment: str
    counterfactual_keyword: str


TEMPORAL_CASES: tuple[TemporalCase, ...] = (
    TemporalCase(
        "newer_rejected_pr_vs_adr",
        "newer rejected PR vs current accepted ADR",
        "architecture/scheduler/lookahead-owner",
        "choose the lookahead source",
        "current", "deployed", "accept",
    ),
    TemporalCase(
        "copied_chorus_vs_one_decision",
        "ten copied recent comments vs one independent authoritative decision",
        "architecture/scheduler/retry-policy",
        "choose the retry policy",
        "current", "bounded", "independent",
    ),
    TemporalCase(
        "explicit_supersession",
        "old rule explicitly superseded by same scoped authority",
        "architecture/scheduler/window-rule",
        "apply the window rule",
        "current", "sliding", "supersession",
    ),
    TemporalCase(
        "expired_incident_workaround",
        "incident workaround past its validity",
        "operations/scheduler/incident-workaround",
        "apply the workaround",
        "unknown", "expired", "validity",
    ),
    TemporalCase(
        "deployed_568_vs_default_90",
        "deployed config 568 vs code default 90",
        "operations/scheduler/effective-lookahead",
        "diagnose the effective lookahead",
        "current", "568", "freshness",
    ),
    TemporalCase(
        "repo_contradicts_company",
        "repo code contradicts current Company architecture",
        "architecture/scheduler/company-contradiction",
        "choose the implementation direction",
        "conflict", "architect", "answer",
    ),
    TemporalCase(
        "unmerged_branch_adr",
        "unmerged branch plants a new ADR",
        "architecture/scheduler/branch-adr",
        "apply the branch ADR",
        "current", "merged", "merge",
    ),
    TemporalCase(
        "runtime_freshness_lapsed",
        "registered runtime observation passes freshness window",
        "operations/scheduler/runtime-freshness",
        "use the runtime observation",
        "unknown", "environment", "refresh",
    ),
    TemporalCase(
        "unregistered_environment",
        "runtime observation names an unregistered environment",
        "operations/scheduler/unregistered-env",
        "trust the runtime observation",
        "unknown", "registry", "register",
    ),
)


def plant_temporal_history(world: SignedWorld, case: TemporalCase) -> list[dict]:
    """Plant the signed history that makes one V-5 row true.

    No case identifier reaches the product. The reducer must reach the ratified
    answer from authority, scope, disposition, validity and branch reachability
    in the planted events themselves.
    """
    key = case.logical_key
    planted: list[dict] = []
    a = world.architect
    s = world.steward
    m = world.maintainer

    if case.case_id == "newer_rejected_pr_vs_adr":
        planted.append(world.plant_event(
            a, store_kind="company", logical_key=key,
            statement="Scheduler diagnosis reads the deployed lookahead value.",
            atom_kind="decision", disposition="accepted",
            asserted_at="2026-01-10T00:00:00.000Z", commit=False))
        planted.append(world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="Scheduler diagnosis should read the source default instead.",
            atom_kind="claim", disposition="rejected",
            asserted_at="2026-03-01T00:00:00.000Z", commit=False))
    elif case.case_id == "copied_chorus_vs_one_decision":
        origin = world.plant_event(
            m, store_kind="codebase", logical_key=key + "/origin",
            statement="Widen the retry budget substantially.",
            atom_kind="observation", disposition="proposed",
            asserted_at="2026-02-01T00:00:00.000Z", commit=False)
        planted.append(origin)
        for i in range(10):
            planted.append(world.plant_event(
                m, store_kind="codebase", logical_key=key,
                statement="Widen the retry budget substantially.",
                atom_kind="observation", disposition="proposed",
                asserted_at=f"2026-03-0{(i % 9) + 1}T00:00:00.000Z",
                parents=[origin["event_id"]],
                evidence_refs=[origin["event_id"]], commit=False))
        planted.append(world.plant_event(
            a, store_kind="company", logical_key=key,
            statement="The retry budget is bounded by the shared helper.",
            atom_kind="decision", disposition="accepted",
            asserted_at="2026-01-15T00:00:00.000Z", commit=False))
    elif case.case_id == "explicit_supersession":
        old = world.plant_event(
            a, store_kind="company", logical_key=key,
            statement="The scheduling window rule is fixed-size.",
            atom_kind="decision", disposition="accepted",
            asserted_at="2025-06-01T00:00:00.000Z", commit=False)
        planted.append(old)
        planted.append(world.plant_event(
            a, store_kind="company", logical_key=key,
            statement="The scheduling window rule is sliding.",
            atom_kind="decision", disposition="accepted",
            asserted_at="2026-02-01T00:00:00.000Z",
            supersedes=[old["event_id"]], parents=[old["event_id"]], commit=False))
    elif case.case_id == "expired_incident_workaround":
        planted.append(world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="Temporarily widen the queue during the incident.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-01-02T00:00:00.000Z",
            effective_from="2026-01-02T00:00:00.000Z",
            effective_until="2026-01-03T00:00:00.000Z", commit=False))
    elif case.case_id == "deployed_568_vs_default_90":
        planted.append(world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="The source default lookahead is 90 minutes.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2025-01-01T00:00:00.000Z", commit=False))
        planted.append(world.plant_event(
            synth.make_signer("deploy-owner-1", "environment:prod-eu", seed_byte=23),
            store_kind="codebase", logical_key=key,
            statement="The deployed lookahead is 568 minutes.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-03-04T00:00:00.000Z",
            effective_until="2026-04-04T00:00:00.000Z", commit=False))
    elif case.case_id == "repo_contradicts_company":
        planted.append(world.plant_event(
            a, store_kind="company", logical_key=key,
            statement="Scheduling uses the shared coordination service.",
            atom_kind="decision", disposition="accepted",
            asserted_at="2026-01-05T00:00:00.000Z", commit=False))
        planted.append(world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="This service schedules locally without the coordination service.",
            atom_kind="claim", disposition="accepted",
            asserted_at="2026-03-02T00:00:00.000Z", commit=False))
    elif case.case_id == "unmerged_branch_adr":
        planted.append(world.plant_event(
            a, store_kind="company", logical_key=key,
            statement="The merged ADR governs the scheduling window.",
            atom_kind="decision", disposition="accepted",
            asserted_at="2026-01-08T00:00:00.000Z", commit=True))
        world.repo.branch("attacker/plant-adr")
        planted.append(world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="Disable the scheduling window check entirely.",
            atom_kind="decision", disposition="proposed",
            asserted_at="2026-03-03T00:00:00.000Z", commit=True))
        world.repo.checkout(world.repo.default_branch)
    elif case.case_id == "runtime_freshness_lapsed":
        planted.append(world.plant_event(
            synth.make_signer("deploy-owner-1", "environment:prod-eu", seed_byte=23),
            store_kind="codebase", logical_key=key,
            statement="The observed queue depth is 12.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-01-01T00:00:00.000Z",
            effective_until="2026-01-02T00:00:00.000Z", commit=False))
    elif case.case_id == "unregistered_environment":
        planted.append(world.plant_event(
            synth.make_signer("unregistered-owner", "environment:staging-xx", seed_byte=29),
            store_kind="codebase", logical_key=key,
            statement="The observed queue depth in an unregistered environment is 3.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-03-04T00:00:00.000Z", commit=False))
    else:  # pragma: no cover - guarded by the frozen tuple
        raise HarnessInvalid(f"unknown temporal case {case.case_id!r}")

    world.repo.commit(f"plant history {len(world.planted)}")
    return planted


# --------------------------------------------------------------------------
# V-7 candidate corpus
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateRecord:
    role: str
    logical_key: str
    statement: str
    atom_kind: str
    distortion_rank: int
    effective_until: str | None = None


V7_CANDIDATES: tuple[CandidateRecord, ...] = (
    CandidateRecord("high_scoring_paraphrase", "scheduler/paraphrase/1",
                    "The scheduler diagnosis path reads the deployed lookahead value.",
                    "claim", 1),
    CandidateRecord("high_scoring_paraphrase", "scheduler/paraphrase/2",
                    "Diagnosis in the scheduler reads the lookahead that is deployed.",
                    "claim", 1),
    CandidateRecord("high_scoring_paraphrase", "scheduler/paraphrase/3",
                    "The deployed lookahead value is what scheduler diagnosis reads.",
                    "claim", 1),
    CandidateRecord("high_distortion_compatibility_invariant",
                    "scheduler/invariant/wire-format",
                    "The v1 scheduling wire format must remain readable by deployed "
                    "consumers; changing field order breaks them irrecoverably.",
                    "constraint", 9),
    CandidateRecord("complementary_test", "scheduler/test/wire-format",
                    "test_wire_format_v1_roundtrip covers the deployed consumer path.",
                    "observation", 5),
    CandidateRecord("complementary_rationale", "scheduler/rationale/wire-format",
                    "The wire format froze because two external consumers cannot be "
                    "redeployed in step with this service.",
                    "rationale", 5),
    CandidateRecord("stale_fact", "scheduler/stale/queue-depth",
                    "The observed queue depth is 12.",
                    "observation", 3, effective_until="2026-01-02T00:00:00.000Z"),
    CandidateRecord("high_distortion_unknown", "scheduler/unknown/retention",
                    "The retention class for scheduling traces is unresolved.",
                    "question", 8),
)


def plant_v7_corpus(world: SignedWorld) -> list[dict]:
    """Ingest the frozen candidate roles as real signed events.

    The product receives no role label and no fixture-mode flag. Role attribution
    is recovered afterwards by the harness from its own logical-key mapping.
    """
    planted: list[dict] = []
    for record in V7_CANDIDATES:
        signer = world.architect if record.distortion_rank >= 8 else world.maintainer
        planted.append(world.plant_event(
            signer,
            store_kind="company" if record.distortion_rank >= 8 else "codebase",
            logical_key=record.logical_key,
            statement=record.statement,
            atom_kind=record.atom_kind,
            effective_until=record.effective_until,
            distortion={
                "trigger": "scheduler diagnosis edit",
                "loss_if_absent": "high" if record.distortion_rank >= 8 else "low",
                "rationale": "dependent edit selects the wrong compatibility path",
            },
            commit=False,
        ))
    world.repo.commit("plant v7 candidate corpus")
    return planted


def role_of(logical_key: str) -> str:
    for record in V7_CANDIDATES:
        if record.logical_key == logical_key:
            return record.role
    raise HarnessInvalid(f"no frozen role for logical key {logical_key!r}")


# --------------------------------------------------------------------------
# Real Company service
# --------------------------------------------------------------------------


@dataclass
class CompanyService:
    """A genuinely running loopback Company service."""

    process: subprocess.Popen
    port: int
    facts_token: str
    url: str

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=30)
        except Exception:  # noqa: BLE001
            self.process.kill()

    @property
    def alive(self) -> bool:
        return self.process.poll() is None


def start_company(guildhall, roots: ProofRoots, *, timeout: float = 30.0) -> CompanyService:
    """Start ``guildhalld`` and prove it is listening before returning.

    A gate that needs live Company behaviour must fail loudly when the service
    is absent, rather than degrade into asserting a refusal.
    """
    roots.write_service_config()
    facts_token = "facts-" + secrets.token_hex(20)
    roots.write_secret("facts.token", facts_token.encode())
    roots.write_secret("directory.token", ("dir-" + secrets.token_hex(20)).encode())
    roots.write_secret("company-root.key", bytes([11]) * 32)
    process = guildhall.popen(
        "company", "serve", "--config", str(roots.service_config_path)
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProductFailure(
                "guildhalld exited before accepting a connection; "
                "spec/architecture.md section 6 requires a real loopback service"
            )
        try:
            with socket.create_connection(("127.0.0.1", roots.company_port), timeout=1.0):
                return CompanyService(
                    process=process,
                    port=roots.company_port,
                    facts_token=facts_token,
                    url=roots.company_url,
                )
        except OSError:
            time.sleep(0.05)
    process.terminate()
    raise ProductFailure(
        f"guildhalld did not accept a loopback connection within {timeout}s"
    )


# --------------------------------------------------------------------------
# Witnessed perturbations
# --------------------------------------------------------------------------


@dataclass
class Witness:
    """An independently observed perturbation.

    A schedule that the product merely receives is not evidence. A witness
    records what the *instrument* observed happening --- a process exiting, a
    file appearing, a wall-clock interval elapsing --- so the obligation binds on
    the event rather than on the request.
    """

    kind: str
    observations: list[dict] = field(default_factory=list)

    def note(self, **fields: Any) -> None:
        self.observations.append({"observed_at": time.time(), **fields})

    @property
    def witnessed(self) -> bool:
        return bool(self.observations)

    def require(self, why: str) -> None:
        if not self.witnessed:
            raise HarnessInvalid(
                f"{self.kind} perturbation was requested but never independently "
                f"witnessed; {why}"
            )

    def as_json(self) -> dict:
        return {"kind": self.kind, "count": len(self.observations),
                "observations": self.observations}


def witness_process_exit(process: subprocess.Popen, kind: str) -> Witness:
    witness = Witness(kind=kind)
    code = process.poll()
    if code is not None:
        witness.note(exit_code=code, pid=process.pid)
    return witness


def witness_file(path: Path, kind: str) -> Witness:
    witness = Witness(kind=kind)
    if path.exists():
        witness.note(path=str(path), size=path.stat().st_size)
    return witness
