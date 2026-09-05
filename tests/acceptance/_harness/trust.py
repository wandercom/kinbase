"""External trust prerequisites, established before any positive fixture runs.

Detector Reviewer finding 14. ``SignedWorld`` wrote a ``repository_uuid_hint``
into ``.kin/config`` and signed events with locally minted keys. Nothing else
existed: no Company root outside the worktree, no repository certificate, no
published ``AuthorityRegistry``. ``spec/verification.md`` V-8 is explicit that

    Fresh clone with no certificate or Company access yields zero trusted facts
    and one actionable certificate Unknown.

so a *conforming* product must refuse every fixture the previous instrument
offered as a positive control --- and the instrument would have recorded that
correct refusal as a product failure.

This module builds the four anchors the ratified architecture requires, in
order, and refuses to proceed when any one of them is unavailable:

1. a live Company service;
2. the Company root public key at an external path **outside** the worktree, so
   a repository cannot certify itself;
3. a steward-signed repository certificate binding the repository UUID;
4. a signed ``AuthorityRegistry`` publishing every signer's key, scope and
   delivery channel, admitted through Company's own API.

Every failure here is :class:`~acceptance._harness.prereq.PrerequisiteMissing`,
which is ``INVALID_HARNESS``. A gate may not interpret a missing trust anchor as
a product refusal, and may not interpret an unrefused untrusted fixture as a
pass.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import canonical, planters, prereq, synth
from .requirements import HarnessInvalid
from .roots import ProofRoots
from .service import ClientKey, ServiceClient

#: Where the Company root public key lives. Outside the repository work tree by
#: construction: ``ProofRoots.company_root`` is a sibling of ``repo_root``.
ROOT_KEY_NAME = "company-root.pub"

#: The repository certificate the architecture requires inside ``.kin/``.
CERTIFICATE_PATH = ".kin/certificate.json"

#: The published registry document.
REGISTRY_PATH = "authority-registry.json"


@dataclass(frozen=True)
class RegisteredAuthority:
    """One authority published through the live registry."""

    authority_id: str
    scope: str
    public_key: str
    channel: str
    capabilities: tuple[str, ...]

    def as_json(self) -> dict:
        return {
            "authority_id": self.authority_id,
            "scope": self.scope,
            "public_key": self.public_key,
            "channel": self.channel,
            "capabilities": list(self.capabilities),
        }


@dataclass
class AuthorityRegistry:
    """A steward-signed registry, published to Company and mirrored externally."""

    steward: synth.Signer
    entries: list[RegisteredAuthority] = field(default_factory=list)
    published_path: Path | None = None
    admitted_by_service: bool = False
    service_receipt: dict[str, Any] = field(default_factory=dict)

    def register(
        self,
        signer: synth.Signer,
        *,
        channel: str,
        capabilities: Sequence[str] = ("answer",),
    ) -> RegisteredAuthority:
        entry = RegisteredAuthority(
            authority_id=signer.authority_id,
            scope=signer.scope,
            public_key=signer.public_hex(),
            channel=channel,
            capabilities=tuple(capabilities),
        )
        self.entries.append(entry)
        return entry

    def document(self, *, cursor: str) -> dict[str, Any]:
        body = {
            "schema": "guildhall-authority-registry/1",
            "authority_cursor": cursor,
            "entries": [e.as_json() for e in self.entries],
        }
        return self.steward.sign_message("authority-registry", body)

    def entry_for(self, authority_id: str) -> RegisteredAuthority:
        for entry in self.entries:
            if entry.authority_id == authority_id:
                return entry
        raise prereq.missing(
            "registry", authority_id,
            "the instrument never registered this authority, so the product "
            "cannot be required to deliver a question to it",
        )


@dataclass
class TrustAnchors:
    """The four external prerequisites, each independently verified."""

    roots: ProofRoots
    company_url: str
    root_key_path: Path
    certificate_path: Path
    registry: AuthorityRegistry
    client: ServiceClient
    facts_token: str
    repository_uuid: str
    #: Digest of every anchor, so a gate can bind the exact trust state it used.
    anchors_digest: str = ""

    def verify(self) -> "TrustAnchors":
        """Re-check every anchor. Any gap is an instrument prerequisite."""
        prereq.certificate_installed(
            self.root_key_path, what="company root public key",
            why="a repository may not certify itself; spec/architecture.md places "
                "the trust root outside the work tree",
        )
        if self._inside_worktree(self.root_key_path):
            raise prereq.missing(
                "certificate", "company root public key",
                f"{self.root_key_path} lies inside the repository work tree, so a "
                "clone would carry its own trust root",
            )
        prereq.certificate_installed(
            self.certificate_path, what="repository certificate",
            why="spec/verification.md V-8: a fresh clone with no certificate "
                "yields zero trusted facts and one actionable certificate Unknown",
        )
        prereq.registered(
            self.registry.entries, what="AuthorityRegistry", minimum=3,
            why="steward, maintainer and architect must each be published before "
                "a signed event from them can be admissible",
        )
        prereq.service_ready(
            self.registry.admitted_by_service, what="AuthorityRegistry admission",
            why="the registry must be admitted through Company's own API; a file "
                "the instrument wrote is not a published registry",
        )
        return self

    def _inside_worktree(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.roots.repo_root.resolve())
        except ValueError:
            return False
        return True

    def as_json(self) -> dict:
        return {
            "company_url": self.company_url,
            "root_key_path": str(self.root_key_path),
            "root_key_outside_worktree": not self._inside_worktree(self.root_key_path),
            "certificate_path": str(self.certificate_path),
            "certificate_present": self.certificate_path.is_file(),
            "registered_authorities": [e.as_json() for e in self.registry.entries],
            "registry_admitted_by_service": self.registry.admitted_by_service,
            "registry_receipt": dict(self.registry.service_receipt),
            "repository_uuid": self.repository_uuid,
        }

    def digest(self) -> str:
        import hashlib

        return hashlib.sha256(
            json.dumps(self.as_json(), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()


def install_external_root(roots: ProofRoots, steward: synth.Signer) -> Path:
    """Place the Company root public key outside the repository work tree."""
    target = roots.company_root / ROOT_KEY_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    material = planters.mutate(
        "trust.root_key", {"public_key": steward.public_hex()}, target=str(target)
    )
    target.write_text(str(material["public_key"]) + "\n", encoding="utf-8")
    planters.witness_path(target)
    return target


def install_repository_certificate(
    world, steward: synth.Signer, *, repository_uuid: str,
    lineage_parent: str | None = None, commit: bool = True,
) -> Path:
    """Write the steward-signed certificate that binds this repository's UUID."""
    certificate = synth.repo_certificate(
        steward, repository_uuid=repository_uuid, lineage_parent=lineage_parent
    )
    certificate = planters.mutate(
        "trust.certificate", certificate, repository_uuid=repository_uuid
    )
    raw = canonical.jcs(certificate)
    world.repo.write_bytes(CERTIFICATE_PATH, raw)
    planters.witness_path(world.repo.path / CERTIFICATE_PATH)
    if commit:
        world.repo.commit("install repository certificate")
    return world.repo.path / CERTIFICATE_PATH


def publish_registry(
    registry: AuthorityRegistry,
    client: ServiceClient,
    roots: ProofRoots,
    *,
    cursor: str = "1000",
) -> AuthorityRegistry:
    """Admit the registry through Company and mirror it to the external root.

    The mirror is the offline snapshot the degraded path reads; the admission
    through Company is what makes the registry *published*. Only the second one
    can make a signed event admissible, so a service that refuses the document
    leaves the run without its prerequisite.
    """
    document = planters.mutate(
        "trust.registry", registry.document(cursor=cursor), cursor=cursor
    )
    mirror = roots.company_root / REGISTRY_PATH
    mirror.parent.mkdir(parents=True, exist_ok=True)
    mirror.write_bytes(canonical.jcs(document))
    planters.witness_path(mirror)
    registry.published_path = mirror

    response = client.post("/v1/authority-registry", body=document)
    if response.status not in (200, 201, 202):
        raise prereq.missing(
            "registry", "AuthorityRegistry publication",
            f"Company answered {response.status} to the registry admission; "
            "without an admitted registry no planted signature is admissible, so "
            "the run has no valid positive fixture",
        )
    body = response.json() if response.body else {}
    registry.admitted_by_service = True
    registry.service_receipt = body if isinstance(body, dict) else {"body": str(body)}
    return registry


def establish(
    guildhall,
    roots: ProofRoots,
    world,
    *,
    extra_authorities: Sequence[tuple[synth.Signer, str]] = (),
    start_service=None,
) -> TrustAnchors:
    """Build every external trust prerequisite, in ratified order.

    ``start_service`` is injected so a gate can supply an already-running
    Company rather than starting a second one.
    """
    from . import worldbuilder

    service = start_service or worldbuilder.start_company(guildhall, roots)
    prereq.listening(
        "127.0.0.1", service.port, what="Company service",
        why="V-8 and V-6 range over live Company behaviour; a gate may not "
            "substitute a static file for the service",
    )

    root_key = install_external_root(roots, world.steward)
    certificate = install_repository_certificate(
        world, world.steward, repository_uuid=worldbuilder.REPO_UUID
    )

    client = ServiceClient(
        host="127.0.0.1",
        port=service.port,
        token=service.facts_token,
        client_key=ClientKey(seed=secrets.token_bytes(32)),
        authority_scopes=(world.steward.scope, world.maintainer.scope,
                          world.architect.scope),
    )

    registry = AuthorityRegistry(steward=world.steward)
    registry.register(world.steward, channel="company:root", capabilities=("publish",))
    registry.register(
        world.maintainer, channel=f"codebase:{worldbuilder.REPO_UUID}",
        capabilities=("request", "publish-manifest"),
    )
    registry.register(
        world.architect, channel="process:architecture-answer",
        capabilities=("answer", "supersede"),
    )
    for signer, channel in extra_authorities:
        registry.register(signer, channel=channel)

    publish_registry(registry, client, roots)

    anchors = TrustAnchors(
        roots=roots,
        company_url=service.url,
        root_key_path=root_key,
        certificate_path=certificate,
        registry=registry,
        client=client,
        facts_token=service.facts_token,
        repository_uuid=worldbuilder.REPO_UUID,
    ).verify()
    anchors.anchors_digest = anchors.digest()
    return anchors


def untrusted_clone_expectation() -> dict[str, Any]:
    """What a conforming product must do with a world that has no anchors.

    Used as the *negative* trust fixture: a clone carrying planted events but
    neither certificate nor Company access must project zero trusted facts and
    exactly one actionable certificate Unknown.
    """
    return {
        "trusted_fact_count": 0,
        "certificate_unknown_count": 1,
        "requirement": (
            "Fresh clone with no certificate or Company access yields zero "
            "trusted facts and one actionable certificate Unknown."
        ),
    }
