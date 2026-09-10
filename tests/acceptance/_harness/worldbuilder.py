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
import secrets
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import canonical, planters, synth
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
    """A repository carrying genuinely signed, content-addressed events.

    Validator ruling C7: only Codebase events enter ``.kin/events/``. Company
    facts are admitted through the live service (``company`` is the
    :class:`~acceptance._harness.trust.TrustAnchors` that owns the client) and
    Personal material reaches the product only through host transcripts, never
    through this planter.
    """

    repo: GitRepo
    steward: synth.Signer
    maintainer: synth.Signer
    architect: synth.Signer
    planted: list[dict[str, Any]] = field(default_factory=list)
    company: Any = None

    @classmethod
    def create(cls, repo_root: Path) -> "SignedWorld":
        repo = GitRepo.init(repo_root)
        repo.write(
            ".kin/config",
            'schema_version = "kinbase-repo/1"\n'
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
        may_refuse: bool = False,
    ) -> dict[str, Any]:
        """Plant one genuinely signed event in the store its ``store_kind`` names.

        ``may_refuse`` marks a Company admission whose *refusal* is the
        expected observation (an out-of-scope signer); the record then carries
        the admission outcome instead of raising.

        ``codebase`` events are written at their computed content path under
        ``.kin/events/``; ``company`` events are admitted through ``POST
        /facts`` on the live Company (C7, C22); ``personal`` is refused here
        because Personal facts never enter ``.kin/`` and the instrument plants
        Personal material only through host transcripts.
        """
        if store_kind == "personal":
            raise HarnessInvalid(
                "Personal facts are never planted into .kin/ or Company; plant "
                "Personal material through a host transcript instead (Validator "
                "ruling C7)"
            )
        if store_kind not in ("codebase", "company"):
            raise HarnessInvalid(f"unknown store_kind {store_kind!r}")
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
        if store_kind == "company":
            return self._admit_company_event(
                signer, signed, record_disposition=disposition, may_refuse=may_refuse,
            )
        raw = canonical.jcs(signed)
        raw = planters.mutate("world.event_bytes", raw, logical_key=logical_key)
        digest = canonical.content_digest_hex(raw)
        # ``spec/architecture.md`` "Codebase": event paths are constructed only
        # from the computed lowercase SHA-256 digest of the exact canonical
        # bytes, sharded ``<hex-0:2>/<hex-2:4>/<remaining-60-hex>.json``.
        rel = ".kin/events/" + canonical.event_shard_path(digest)
        target = self.repo.write_bytes(rel, raw)
        planters.witness_path(target)
        # Independent plant-time witness, before any product command can touch
        # the repository: re-read the path and bind what the instrument itself
        # observed. A later absence is then attributable -- the instrument
        # proved the bytes were there.
        witness = self._witness_write(target, raw, digest)
        record = {
            "event_id": signed["event_id"],
            "digest": digest,
            "path": rel,
            "store": "codebase",
            "message_type": "fact-event",
            "logical_key": logical_key,
            "statement": statement,
            "signer": signer.authority_id,
            "scope": signer.scope,
            "disposition": disposition,
            "witness": witness,
        }
        self.planted.append(record)
        if commit:
            self.repo.commit(f"plant {digest[:12]}")
        witness["head_at_witness"] = self.repo.head()
        witness["tracked_at_witness"] = self._tracked(rel)
        return record

    def plant_unknown(
        self,
        signer: synth.Signer,
        *,
        logical_key: str,
        question: str,
        decision_blocked: str,
        owner_role: str,
        owner_identity: str,
        closure_evidence: str = "",
        parents: Sequence[str] = (),
        distortion: Mapping[str, Any] | None = None,
        commit: bool = True,
    ) -> dict[str, Any]:
        """Write one genuinely signed ``UnknownEvent`` into the Codebase store.

        ``spec/architecture.md`` section 3: an ``UnknownEvent`` is a
        ``FactEvent`` plus the eight Unknown fields, signed as ``unknown-event``.
        """
        body = synth.unknown_event(
            store_kind="codebase",
            authority_id=signer.authority_id,
            authority_scope=signer.scope,
            repository_id=REPO_UUID,
            logical_key=logical_key,
            question=question,
            decision_blocked=decision_blocked,
            owner_role=owner_role,
            owner_identity=owner_identity,
            closure_evidence=closure_evidence,
            parents=parents,
            distortion=distortion,
        )
        signed = signer.sign_message("unknown-event", body)
        raw = canonical.jcs(signed)
        digest = canonical.content_digest_hex(raw)
        rel = ".kin/events/" + canonical.event_shard_path(digest)
        target = self.repo.write_bytes(rel, raw)
        planters.witness_path(target)
        witness = self._witness_write(target, raw, digest)
        record = {
            "event_id": signed["event_id"],
            "digest": digest,
            "path": rel,
            "store": "codebase",
            "message_type": "unknown-event",
            "logical_key": logical_key,
            "statement": question,
            "signer": signer.authority_id,
            "scope": signer.scope,
            "disposition": "proposed",
            "witness": witness,
        }
        self.planted.append(record)
        if commit:
            self.repo.commit(f"plant {digest[:12]}")
        witness["head_at_witness"] = self.repo.head()
        witness["tracked_at_witness"] = self._tracked(rel)
        return record

    def _admit_company_event(self, signer: synth.Signer, signed: dict[str, Any],
                             *, record_disposition: str,
                             may_refuse: bool = False) -> dict[str, Any]:
        """Admit a signed Company FactEvent through the live service (C7)."""
        if self.company is None:
            raise HarnessInvalid(
                "a Company fact can only be admitted through the live service; "
                "establish the trust anchors before planting store_kind='company'"
            )
        if not may_refuse and not self.company.registry.is_registered(signer.authority_id):
            raise HarnessInvalid(
                f"{signer.authority_id} is not in the published registry, so "
                "the instrument cannot expect Company to admit its fact"
            )
        admission = self.company.admit_fact(signed)
        raw = canonical.jcs(signed)
        record = {
            "event_id": signed["event_id"],
            "digest": canonical.content_digest_hex(raw),
            "path": None,
            "store": "company",
            "message_type": "fact-event",
            "logical_key": signed["logical_key"],
            "statement": signed["statement"],
            "signer": signer.authority_id,
            "scope": signer.scope,
            "disposition": record_disposition,
            "admission": admission,
            "document": signed,
        }
        self.planted.append(record)
        if not admission["admitted"] and not may_refuse:
            raise ProductFailure(
                "Company refused a FactEvent signed by a registered in-scope "
                f"authority ({signer.authority_id}, scope {signer.scope}) with a "
                "valid token and request signature; spec/architecture.md "
                "'Company / Kinbase' and Validator ruling C6 make such a fact "
                "admissible. Observation: " + json.dumps(admission, default=str)
            )
        return record

    def company_records(self) -> list[dict[str, Any]]:
        return [r for r in self.planted if r.get("store") == "company"]

    def codebase_records(self) -> list[dict[str, Any]]:
        return [r for r in self.planted if r.get("path")]

    # -- plant-time witness -------------------------------------------------

    def _witness_write(self, target: Path, raw: bytes, digest: str) -> dict[str, Any]:
        """Re-read a freshly planted event and bind the observation.

        Runs before the planted event is committed and before any product
        command runs against the repository. A failure here is the planter's
        own: nothing else has had a channel to the path yet.
        """
        if not target.is_file():
            raise HarnessInvalid(
                f"planter wrote {target} but cannot re-read it; the instrument "
                "could not witness its own write"
            )
        observed = target.read_bytes()
        observed_digest = canonical.content_digest_hex(observed)
        if observed != raw or observed_digest != digest:
            raise HarnessInvalid(
                f"planter wrote {len(raw)} bytes with digest {digest[:12]} to "
                f"{target} and read back digest {observed_digest[:12]}; the "
                "instrument cannot hand the product a world it cannot witness"
            )
        return {
            "witnessed_at": time.time(),
            "witnessed_bytes": len(observed),
            "witnessed_digest": observed_digest,
            "witnessed_before_product": True,
        }

    def _tracked(self, rel: str) -> bool:
        """Whether ``rel`` is a blob in the current HEAD tree."""
        listing = self.repo.run("ls-tree", "HEAD", "--", rel, check=False)
        return bool(listing.strip())

    def _installed_hooks(self) -> list[str]:
        """Non-sample hooks present in the fixture repository's hook directory.

        The instrument installs none. Any present hook is a channel through
        which a product ``repo init`` could act on the working tree during the
        instrument's own ``git commit``.
        """
        hooks_dir = Path(self.repo.run("rev-parse", "--git-path", "hooks").strip())
        if not hooks_dir.is_absolute():
            hooks_dir = self.repo.path / hooks_dir
        if not hooks_dir.is_dir():
            return []
        return sorted(
            p.name for p in hooks_dir.iterdir()
            if p.is_file() and not p.name.endswith(".sample")
        )

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
            if not record.get("path"):
                # A Company fact: admitted through the service at plant time,
                # refusal already raised there. Nothing in the work tree to check.
                continue
            path = self.repo.path / record["path"]
            raw = path.read_bytes() if path.is_file() else None
            observed_digest = (
                canonical.content_digest_hex(raw) if raw is not None else None
            )
            if raw is None or observed_digest != record["digest"]:
                self._report_planted_loss(record, observed_digest)
            payload = json.loads(raw.decode("utf-8"))
            message_type = "unknown-event" if payload.get(
                "schema") == "kinbase-unknown/1" else "fact-event"
            if not synth.verify_document(message_type, payload):
                raise HarnessInvalid(
                    f"planted event {record['digest'][:12]} does not verify; the "
                    "instrument must not hand the product invalid state"
                )

    def _report_planted_loss(self, record: dict[str, Any], observed_digest: str | None) -> None:
        """A witnessed event is gone or altered. Say whose fault that is.

        The plant-time witness proved the bytes were at their content path
        before any product command ran. Two actors have had a channel since:
        the instrument's own Git operations, and the product. If HEAD has moved
        to a tree that does not carry the event, the instrument moved it and
        the sequencing is an instrument fault. Otherwise the working-tree file
        was removed or rewritten by something other than the instrument's Git
        history, which is a product observation: ``spec/architecture.md``
        "Codebase" makes ``.kin/events/`` signed shared state, and
        ``spec/verification.md`` V-4 requires a deleted or modified event to be
        *reported* by the product, never silently removed.
        """
        witness = record.get("witness") or {}
        head_now = self.repo.head()
        tracked_now = self._tracked(record["path"])
        head_moved = witness.get("head_at_witness") not in (None, head_now)
        observation = {
            "path": record["path"],
            "expected_digest": record["digest"],
            "observed_digest": observed_digest,
            "witnessed_before_product": witness.get("witnessed_before_product", False),
            "witnessed_digest": witness.get("witnessed_digest"),
            "head_at_witness": witness.get("head_at_witness"),
            "head_now": head_now,
            "tracked_at_witness": witness.get("tracked_at_witness"),
            "tracked_in_head_now": tracked_now,
            "installed_hooks": self._installed_hooks(),
        }
        rendered = json.dumps(observation, sort_keys=True)
        if not witness.get("witnessed_before_product"):
            raise HarnessInvalid(
                "planted event was never witnessed by the instrument before the "
                f"product ran; the planter is at fault: {rendered}"
            )
        if head_moved and not tracked_now:
            raise HarnessInvalid(
                "planted event is absent because the instrument moved HEAD to a "
                f"tree that does not carry it; instrument sequencing fault: {rendered}"
            )
        what = "missing" if observed_digest is None else "rewritten"
        raise ProductFailure(
            f"planted signed event {record['digest'][:12]} is {what} at its content "
            "path after the instrument witnessed it there and before the product's "
            "output was read; spec/architecture.md 'Codebase' makes .kin/events/ "
            "signed shared state and spec/verification.md V-4 requires a deleted or "
            "modified event to be reported, not removed. Observation: " + rendered
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


#: The registered deploy owner V-5 rows 5 and 8 rely on. ``environment:prod-eu``
#: is published through the registry (Validator ruling C3); the
#: ``environment:staging-xx`` signer in row 9 deliberately is not.
DEPLOY_OWNER = synth.make_signer("deploy-owner-1", "environment:prod-eu", seed_byte=23)
DEPLOY_OWNER_CHANNEL = "environment:prod-eu"


def temporal_extra_authorities() -> tuple[tuple[synth.Signer, str], ...]:
    return ((DEPLOY_OWNER, DEPLOY_OWNER_CHANNEL),)


def plant_temporal_history(world: SignedWorld, case: TemporalCase) -> list[dict]:
    """Plant the signed history that makes one V-5 row true.

    No case identifier reaches the product. The reducer must reach the ratified
    answer from authority, scope, disposition, validity and branch reachability
    in the planted events themselves.
    """
    key = case.logical_key
    planted: list[dict] = []
    a = world.architect
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
        old = world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="Temporarily widen the queue until the incident handover.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-01-01T00:00:00.000Z",
            effective_from="2026-01-01T00:00:00.000Z",
            effective_until="2026-01-02T00:00:00.000Z", commit=False)
        planted.append(old)
        planted.append(world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="Temporarily widen the queue during the incident.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-01-02T00:00:00.000Z",
            effective_from="2026-01-02T00:00:00.000Z",
            effective_until="2026-01-03T00:00:00.000Z",
            parents=[old["event_id"]], supersedes=[old["event_id"]], commit=False))
    elif case.case_id == "deployed_568_vs_default_90":
        planted.append(world.plant_event(
            m, store_kind="codebase", logical_key=key,
            statement="The source default lookahead is 90 minutes.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2025-01-01T00:00:00.000Z", commit=False))
        planted.append(world.plant_event(
            DEPLOY_OWNER,
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
        # Capture the signed observation while the branch carrying it is checked
        # out, then publish that proposed observation on the reducer's revision.
        # The ADR branch remains unmerged; proposed is never accepted/merged.
        branch_event = planted[-1]
        branch_bytes = (world.repo.path / branch_event["path"]).read_bytes()
        world.repo.checkout(world.repo.default_branch)
        target = world.repo.write_bytes(branch_event["path"], branch_bytes)
        branch_event["witness"] = world._witness_write(
            target, branch_bytes, branch_event["digest"])
        world.repo.commit("observe the unmerged branch ADR as proposed")
        branch_event["witness"].update(
            head_at_witness=world.repo.head(), tracked_at_witness=True)
    elif case.case_id == "runtime_freshness_lapsed":
        old = world.plant_event(
            DEPLOY_OWNER, store_kind="codebase", logical_key=key,
            statement="The observed queue depth is 8.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2025-12-31T00:00:00.000Z",
            effective_until="2026-01-01T00:00:00.000Z", commit=False)
        planted.append(old)
        planted.append(world.plant_event(
            DEPLOY_OWNER,
            store_kind="codebase", logical_key=key,
            statement="The observed queue depth is 12.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-01-01T00:00:00.000Z",
            effective_until="2026-01-02T00:00:00.000Z",
            parents=[old["event_id"]], supersedes=[old["event_id"]], commit=False))
    elif case.case_id == "unregistered_environment":
        unregistered = synth.make_signer(
            "unregistered-owner", "environment:staging-xx", seed_byte=29)
        old = world.plant_event(
            unregistered, store_kind="codebase", logical_key=key,
            statement="The observed queue depth in an unregistered environment is 2.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-03-03T00:00:00.000Z", commit=False)
        planted.append(old)
        planted.append(world.plant_event(
            unregistered,
            store_kind="codebase", logical_key=key,
            statement="The observed queue depth in an unregistered environment is 3.",
            atom_kind="observation", disposition="accepted",
            asserted_at="2026-03-04T00:00:00.000Z",
            parents=[old["event_id"]], supersedes=[old["event_id"]], commit=False))
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
    freshness_seconds: int | None = None


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
                    "observation", 3, freshness_seconds=-60),
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
            effective_until=(synth.receipt_stamp(record.freshness_seconds)
                             if record.freshness_seconds is not None else None),
            distortion={
                "trigger": "scheduler diagnosis edit",
                "loss_if_absent": "safety_critical" if record.distortion_rank >= 8 else "advisory",
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


def start_company(kinbase, roots: ProofRoots, *, timeout: float = 30.0) -> CompanyService:
    """Start ``kinbased`` and prove it is listening before returning.

    A gate that needs live Company behaviour must fail loudly when the service
    is absent, rather than degrade into asserting a refusal.
    """
    roots.write_service_config()
    facts_token = "facts-" + secrets.token_hex(20)
    roots.write_secret("facts.token", facts_token.encode())
    roots.write_secret("directory.token", ("dir-" + secrets.token_hex(20)).encode())
    roots.write_secret("company-root.key", bytes([11]) * 32)
    process = kinbase.popen(
        "company", "serve", "--config", str(roots.service_config_path)
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProductFailure(
                "kinbased exited before accepting a connection; "
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
        f"kinbased did not accept a loopback connection within {timeout}s"
    )


# --------------------------------------------------------------------------
# Product-issued session identity (Validator ruling C8)
# --------------------------------------------------------------------------


SESSION_ID_KEYS: tuple[str, ...] = ("session_id", "session", "id")


def start_session(kinbase, repo: Path, *, host: str = "codex") -> str:
    """``kinbase session start --host H --repo R --json`` and return its id.

    ``spec/cli.md`` "Session, candidates, and approval": ``SESSION`` is the id
    the product issued at ``session start``; the instrument never mints one.
    """
    result = kinbase.run(
        "session", "start", "--host", host, "--repo", str(repo), "--json",
        cwd=repo, check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`session start` returned the reserved ambiguous exit 1")
    if result.returncode not in (0, 3):
        try:
            error = result.error
        except ProductFailure as exc:
            error = {"unparsed": str(exc)[:400]}
        raise ProductFailure(
            "`session start` refused although the repository is certified and "
            "Company is reachable; observation: " + json.dumps(error, default=str)
        )
    payload = result.json
    if not isinstance(payload, dict):
        raise ProductFailure("`session start --json` did not return an object")
    for key in SESSION_ID_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    raise ProductFailure(
        "`session start --json` returned no session identifier under any of "
        f"{SESSION_ID_KEYS}; spec/cli.md makes SESSION the product-issued id "
        f"every later session command takes. Payload keys: {sorted(payload)}"
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
