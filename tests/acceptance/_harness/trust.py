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

Validator dispatch 007 then found that the anchors were still incomplete: no
user config was ever written (C1), the certificate lived inside the worktree
(C2), and Company events were planted into ``.kin/`` (C7). This module now
builds every anchor the ratified contract names, in the order ``spec/cli.md``
"First working session" performs them, and refuses to proceed when any one of
them is unavailable:

1. a live Company service (``guildhall company serve``);
2. the Company root public key at an external path **outside** the worktree;
3. the launcher-only user config at
   ``${XDG_CONFIG_HOME:-$HOME/.config}/guildhall/config.toml`` (0600) naming the
   Company URL, the facts-token file, the root public key, the cache root, the
   Personal ``data_root``, the classifier and the host version ranges;
4. a signed ``AuthorityRegistry`` publishing every signer's key, scope and
   delivery channel, admitted through Company's own API;
5. a steward-signed repository certificate written **outside** the worktree and
   installed with ``guildhall repo init --repo PATH --certificate FILE``.

Company facts are then admitted through ``POST /facts`` (C7, C22); nothing but
Codebase events ever enters ``.kin/events/``.

Every instrument-side failure here is
:class:`~acceptance._harness.prereq.PrerequisiteMissing`, which is
``INVALID_HARNESS``. A gate may not interpret a missing trust anchor as a
product refusal, and may not interpret an unrefused untrusted fixture as a
pass. A product refusal of a valid anchor (a steward-signed certificate with
Company reachable, a registered in-scope fact) is a typed ``ProductFailure``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

from . import canonical, planters, prereq, synth
from .requirements import HarnessInvalid, ProductFailure
from .roots import ProofRoots
from .service import FACTS_PATH, REGISTRY_PATH, ClientKey, ServiceClient

#: Where the Company root public key lives. Outside the repository work tree by
#: construction: ``ProofRoots.company_root`` is a sibling of ``repo_root``.
ROOT_KEY_NAME = "company-root.pub"

#: Where the instrument writes the steward certificate before ``repo init``
#: copies it into the Company cache. Under ``ProofRoots.client_root``, outside
#: the work tree (Validator ruling C2).
CERTIFICATE_DIR = "certificates"

#: The published registry mirror, kept beside the service for the evidence
#: packet. Publication is the admission through Company, never this file.
REGISTRY_MIRROR = "authority-registry.json"

# R-11: classifier executable and argv come from the resolved product binary.



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
    """A steward-signed registry, published to Company and mirrored externally.

    Validator ruling C4: the registry is one document
    ``{"schema": "guildhall-authority-registry/1", "authority_cursor",
    "entries": [...]}`` signed by the steward root key as message type
    ``authority-registry-entry``.
    """

    steward: synth.Signer
    entries: list[RegisteredAuthority] = field(default_factory=list)
    cursor: str = "1000"
    published_path: Path | None = None
    admitted_by_service: bool = False
    service_receipt: dict[str, Any] = field(default_factory=dict)
    #: Every cursor at which a document was admitted, oldest first.
    publications: list[dict[str, Any]] = field(default_factory=list)

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
            public_key=signer.public_hex,
            channel=channel,
            capabilities=tuple(capabilities),
        )
        self.entries.append(entry)
        return entry

    def remove(self, authority_id: str) -> RegisteredAuthority:
        """Drop an authority from the entry list (the revocation primitive)."""
        entry = self.entry_for(authority_id)
        self.entries = [e for e in self.entries if e.authority_id != authority_id]
        return entry

    def document(self, *, cursor: str | None = None) -> dict[str, Any]:
        body = {
            "schema": "guildhall-authority-registry/1",
            "authority_cursor": cursor or self.cursor,
            "entries": [e.as_json() for e in self.entries],
        }
        return self.steward.sign_message("authority-registry-entry", body)

    def entry_for(self, authority_id: str) -> RegisteredAuthority:
        for entry in self.entries:
            if entry.authority_id == authority_id:
                return entry
        raise prereq.missing(
            "registry", authority_id,
            "the instrument never registered this authority, so the product "
            "cannot be required to deliver a question to it",
        )

    def is_registered(self, authority_id: str) -> bool:
        return any(e.authority_id == authority_id for e in self.entries)


@dataclass
class Classifier:
    """The classifier executable the user config pins."""

    path: Path
    sha256: str
    args: tuple[str, ...]
    source: str          # "product"
    model: str | None = None

    def as_json(self) -> dict:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "args": list(self.args),
            "source": self.source,
            "model": self.model,
        }


@dataclass
class TrustAnchors:
    """The external prerequisites, each independently verified."""

    roots: ProofRoots
    company_url: str
    root_key_path: Path
    certificate_path: Path
    user_config_path: Path
    cache_root: Path
    registry: AuthorityRegistry
    client: ServiceClient
    facts_token: str
    facts_token_path: Path
    repository_uuid: str
    classifier: Classifier
    service: Any = None
    guildhall: Any = None
    repo_init: dict[str, Any] = field(default_factory=dict)
    #: Digest of every anchor, so a gate can bind the exact trust state it used.
    anchors_digest: str = ""

    def verify(self) -> "TrustAnchors":
        """Re-check every instrument-owned anchor. Any gap is a prerequisite."""
        prereq.certificate_installed(
            self.root_key_path, what="company root public key",
            why="a repository may not certify itself; spec/architecture.md places "
                "the trust root outside the work tree",
        )
        for label, path in (("company root public key", self.root_key_path),
                            ("repository certificate", self.certificate_path),
                            ("user config", self.user_config_path)):
            if self._inside_worktree(path):
                raise prereq.missing(
                    "certificate", label,
                    f"{path} lies inside the repository work tree, so a clone "
                    "would carry its own trust material",
                )
        prereq.certificate_installed(
            self.certificate_path, what="repository certificate",
            why="spec/verification.md V-8: a fresh clone with no certificate "
                "yields zero trusted facts and one actionable certificate Unknown",
        )
        prereq.certificate_installed(
            self.user_config_path, what="launcher user config",
            why="spec/cli.md: missing config selects Codebase-only mode with "
                "zero trusted facts, so no positive fixture exists without it",
        )
        if stat.S_IMODE(self.user_config_path.stat().st_mode) != 0o600:
            raise prereq.missing(
                "environment", "user config mode",
                f"{self.user_config_path} must be mode 0600 (spec/cli.md)",
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

    # -- Company fact admission (C7, C22) ----------------------------------

    def admit_fact(self, document: dict[str, Any]) -> dict[str, Any]:
        """Admit one signed FactEvent through ``POST /facts``.

        Validator ruling C22: bodies are FactEvents (architecture section 3
        field set, ``schema: "guildhall-event/1"``) signed as ``fact-event``.
        C6: admission is authorised by the registered in-scope authority's
        signature plus a valid token and request signature.
        """
        response = self.client.post(FACTS_PATH, body=document)
        body: Any = None
        if response.body:
            try:
                body = response.json
            except ProductFailure:
                body = {"raw": response.body[:400].decode("utf-8", "replace")}
        return {
            "path": FACTS_PATH,
            "status": response.status,
            "admitted": response.status in (200, 201, 202),
            "receipt": body if isinstance(body, dict) else {"body": body},
        }

    # -- registry lifecycle -------------------------------------------------

    def republish_registry(self, *, cursor: str) -> dict[str, Any]:
        """Publish the registry again at a strictly newer cursor."""
        if int(cursor) <= int(self.registry.cursor):
            raise HarnessInvalid(
                f"registry cursor {cursor} must advance past {self.registry.cursor}"
            )
        self.registry.cursor = cursor
        publish_registry(self.registry, self.client, self.roots, cursor=cursor)
        return dict(self.registry.service_receipt)

    def revoke(self, signer: synth.Signer, *, cursor: str) -> dict[str, Any]:
        """Revoke an authority's key by republishing the registry without it.

        ``spec/architecture.md`` "Trust and key lifecycle": "Revocation is a
        signed Company event with its own cursor and effective time" and
        "Post-revocation events refuse." The steward-signed registry document at
        the new cursor no longer lists the key; the cursor at which it vanished
        is the revocation cursor.
        """
        removed = self.registry.remove(signer.authority_id)
        receipt = self.republish_registry(cursor=cursor)
        return {
            "revoked_authority": removed.as_json(),
            "revocation_cursor": cursor,
            "receipt": receipt,
        }

    # -- alternative environments ------------------------------------------

    @contextlib.contextmanager
    def company_endpoint(self, url: str) -> Iterator[Path]:
        """Temporarily point the user config at another Company endpoint.

        Validator ruling C28: the product never reads a Company endpoint from
        the environment; a blackhole or timeout probe configures its endpoint
        through the user config.
        """
        original = dict(self.roots.user_config_kwargs)
        path = self.roots.rewrite_user_config(company_url=url)
        try:
            yield path
        finally:
            self.roots.write_user_config(**original)

    def uncertified_driver(self, name: str):
        """A driver whose roots carry no user config, cache or certificate."""
        from .cli import Guildhall

        home, xdg = self.roots.uncertified_environment(name)
        driver = Guildhall(home=home, xdg_config_home=xdg, cwd=self.roots.repo_root)
        if self.guildhall is not None:
            driver.path_prefix = list(self.guildhall.path_prefix)
        return driver

    def as_json(self) -> dict:
        return {
            "company_url": self.company_url,
            "root_key_path": str(self.root_key_path),
            "root_key_outside_worktree": not self._inside_worktree(self.root_key_path),
            "certificate_path": str(self.certificate_path),
            "certificate_outside_worktree":
                not self._inside_worktree(self.certificate_path),
            "certificate_present": self.certificate_path.is_file(),
            "user_config_path": str(self.user_config_path),
            "user_config_mode": oct(stat.S_IMODE(self.user_config_path.stat().st_mode))
            if self.user_config_path.exists() else None,
            "cache_root": str(self.cache_root),
            "classifier": self.classifier.as_json(),
            "registered_authorities": [e.as_json() for e in self.registry.entries],
            "registry_cursor": self.registry.cursor,
            "registry_admitted_by_service": self.registry.admitted_by_service,
            "registry_receipt": dict(self.registry.service_receipt),
            "repository_uuid": self.repository_uuid,
            "repo_init": dict(self.repo_init),
        }

    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.as_json(), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()


# --------------------------------------------------------------------------
# Installers
# --------------------------------------------------------------------------


def install_external_root(roots: ProofRoots, steward: synth.Signer) -> Path:
    """Place the Company root public key outside the repository work tree."""
    target = roots.company_root / ROOT_KEY_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    material = planters.mutate(
        "trust.root_key", {"public_key": steward.public_hex}, target=str(target)
    )
    target.write_text(str(material["public_key"]) + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    planters.witness_path(target)
    return target


def write_certificate_file(
    roots: ProofRoots, steward: synth.Signer, *, repository_uuid: str,
    lineage_parent: str | None = None, name: str | None = None,
) -> Path:
    """Write a steward-signed certificate to a file outside the work tree."""
    certificate = synth.repo_certificate(
        steward, repository_uuid=repository_uuid, lineage_parent=lineage_parent
    )
    certificate = planters.mutate(
        "trust.certificate", certificate, repository_uuid=repository_uuid
    )
    target = roots.client_root / CERTIFICATE_DIR / ((name or repository_uuid) + ".json")
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    target.write_bytes(canonical.jcs(certificate))
    os.chmod(target, 0o600)
    planters.witness_path(target)
    return target


def install_repository_certificate(
    guildhall, roots: ProofRoots, world, certificate: Path, *,
    driver=None,
) -> dict[str, Any]:
    """``guildhall repo init --repo PATH --certificate FILE`` (Validator ruling C2).

    The product copies the certificate into the out-of-worktree Company cache
    root keyed by repository UUID and reads it only from there. The instrument
    then commits only what ``spec/cli.md`` step 5 allows a maintainer to commit:
    ``.kin/config``, ``.kin/events/``, ``.kin/manifests/`` and ``.gitattributes``.
    """
    runner = driver or guildhall
    tree_before = _worktree_listing(world.repo.path)
    result = runner.run(
        "repo", "init", "--repo", str(world.repo.path),
        "--certificate", str(certificate), "--json",
        cwd=world.repo.path, check=False,
    )
    tree_after = _worktree_listing(world.repo.path)
    written = sorted(set(tree_after) - set(tree_before))
    changed = sorted(
        p for p in set(tree_after) & set(tree_before)
        if tree_after[p] != tree_before[p]
    )
    allowed = (".kin/config", ".kin/events/", ".kin/manifests/", ".gitattributes")
    outside = [
        p for p in written + changed
        if not (p in allowed or any(p.startswith(a) for a in allowed if a.endswith("/"))
                or p.startswith(".kin/local/"))
    ]
    record = {
        "argv": list(result.argv),
        "exit_code": result.returncode,
        "worktree_paths_written": written,
        "worktree_paths_changed": changed,
        "paths_outside_step_5_allowance": outside,
        "cache_files_after": sorted(
            str(p.relative_to(roots.company_cache))
            for p in roots.company_cache.rglob("*") if p.is_file()
        ),
    }
    if result.returncode == 1:
        raise ProductFailure(
            "`repo init` returned the reserved ambiguous exit 1; spec/cli.md "
            "reserves exit 1. Observation: " + json.dumps(record)
        )
    if result.returncode != 0:
        try:
            record["error"] = result.error
        except ProductFailure as exc:
            record["error"] = {"unparsed": str(exc)[:400]}
        raise ProductFailure(
            "`repo init --certificate <steward-signed file outside the worktree>` "
            "was refused although the Company root key, user config and a live "
            "Company were all in place; spec/cli.md 'First working session' step "
            "5 and Validator ruling C2 make this the certificate installation "
            "path. Observation: " + json.dumps(record, default=str)
        )
    cached = [p for p in roots.company_cache.rglob("*") if p.is_file()
              and p.read_bytes() == certificate.read_bytes()]
    repository_uuid = json.loads(certificate.read_bytes())["repository_uuid"]
    if not any(repository_uuid in str(p.relative_to(roots.company_cache)) for p in cached):
        raise ProductFailure("C2: repo init did not cache the certificate keyed by repository UUID")
    if stat.S_IMODE(roots.company_cache.stat().st_mode) != 0o700:
        raise ProductFailure("C2: Company cache root is not mode 0700 after repo init")
    record["cached_certificate_paths"] = [str(p) for p in cached]
    to_stage = [p for p in written + changed if p not in outside]
    if to_stage:
        world.repo.run("add", "--", *to_stage)
        world.repo.commit("install repository certificate")
    return record


def _worktree_listing(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        if path.is_file():
            out[str(path.relative_to(root))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return out


def publish_registry(
    registry: AuthorityRegistry,
    client: ServiceClient,
    roots: ProofRoots,
    *,
    cursor: str = "1000",
) -> AuthorityRegistry:
    """Admit the registry through Company and mirror it to the external root.

    The mirror is the offline snapshot the evidence packet reads; the admission
    through Company is what makes the registry *published*. Only the second one
    can make a signed event admissible, so a service that refuses the document
    leaves the run without its prerequisite.
    """
    registry.cursor = cursor
    document = planters.mutate(
        "trust.registry", registry.document(cursor=cursor), cursor=cursor
    )
    mirror = roots.company_root / REGISTRY_MIRROR
    mirror.parent.mkdir(parents=True, exist_ok=True)
    mirror.write_bytes(canonical.jcs(document))
    planters.witness_path(mirror)
    registry.published_path = mirror

    response = client.post(REGISTRY_PATH, body=document)
    if response.status not in (200, 201, 202):
        raise prereq.missing(
            "registry", "AuthorityRegistry publication",
            f"Company answered {response.status} to the registry admission at "
            f"{REGISTRY_PATH}; without an admitted registry no planted signature "
            "is admissible, so the run has no valid positive fixture",
        )
    body: Any = {}
    if response.body:
        try:
            body = response.json
        except ProductFailure:
            body = {"raw": response.body[:400].decode("utf-8", "replace")}
    registry.admitted_by_service = True
    registry.service_receipt = body if isinstance(body, dict) else {"body": str(body)}
    registry.publications.append({
        "cursor": cursor,
        "entries": [e.authority_id for e in registry.entries],
        "status": response.status,
    })
    return registry


# --------------------------------------------------------------------------
# Classifier
# --------------------------------------------------------------------------


def resolve_classifier(roots: ProofRoots, guildhall, *, model: str | None = None) -> Classifier:
    """R-11: pin the same executable used for product commands, without spawning it."""
    import shutil

    model = os.environ.get("GUILDHALL_CLASSIFIER_MODEL", model)
    entrypoint = tuple(guildhall.entrypoint)
    if len(entrypoint) != 1:
        raise HarnessInvalid("R-11 requires GUILDHALL_BIN to name the single product executable")
    resolved = shutil.which(entrypoint[0])
    if resolved is None:
        raise prereq.missing("binary", "product classifier", "product executable is absent")
    path = prereq.executable(resolved, what="product classifier executable",
                            why="R-11 pins the product binary with SHA-256")
    if model is not None and (not model.startswith("ollama:") or
                              not model[len("ollama:"):].strip()):
        raise HarnessInvalid("R-11 live model must use ollama:<name>")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return Classifier(path=path.resolve(), sha256=digest,
                      args=("classifier", "--json"),
                      source="product", model=model)


def classifier_pinned(anchors: TrustAnchors, *, what: str) -> Classifier:
    """Extraction requires a reverified product classifier, never an empty stub."""
    classifier = anchors.classifier
    if classifier.source != "product" or hashlib.sha256(
            classifier.path.read_bytes()).hexdigest() != classifier.sha256:
        raise HarnessInvalid(what + ": product classifier pin changed")
    return classifier


def verify_classifier_spawn(guildhall, repo: Path) -> None:
    """R-11 doctor attests the pin after an extraction has spawned the child."""
    import tomllib

    config = guildhall.xdg_config_home / "guildhall" / "config.toml"
    table = tomllib.loads(config.read_text(encoding="utf-8"))["classifier"]
    doctor = guildhall.run("doctor", "--repo", str(repo), "--json",
                          cwd=repo, check=False).json
    reported = doctor.get("classifier", {}) if isinstance(doctor, dict) else {}
    pinned = doctor.get("classifier_pinned") if isinstance(doctor, dict) else None
    provider = reported.get("provider")
    if reported.get("executable_sha256") != table["executable_sha256"] or pinned is not True:
        raise ProductFailure("R-11 doctor did not reverify the classifier pin after spawn")
    if not isinstance(provider, str) or not provider:
        raise ProductFailure("R-11 doctor omitted classifier.provider")
    if table.get("model") is not None and "ollama" not in provider.lower():
        raise ProductFailure("R-11 live-model measurement requires the Ollama provider")


# --------------------------------------------------------------------------
# The whole prerequisite set
# --------------------------------------------------------------------------


def write_user_config(roots: ProofRoots, *, company_url: str,
                      facts_token: str, root_key: Path,
                      classifier: Classifier) -> tuple[Path, Path]:
    """Write the client token copy and the launcher user config (C1)."""
    token_path = roots.client_root / "facts.token"
    token_path.write_bytes(facts_token.encode("utf-8"))
    os.chmod(token_path, 0o600)
    config = roots.write_user_config(
        classifier_path=classifier.path,
        classifier_sha256=classifier.sha256,
        classifier_args=classifier.args,
        classifier_model=classifier.model,
        facts_token_file=token_path,
        root_public_key_file=root_key,
        company_url=company_url,
    )
    return config, token_path


def establish(
    guildhall,
    roots: ProofRoots,
    world,
    *,
    extra_authorities: Sequence[tuple[synth.Signer, str]] = (),
    start_service=None,
    classifier_model: str | None = None,
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
    classifier = resolve_classifier(roots, guildhall, model=classifier_model)
    user_config, token_path = write_user_config(
        roots, company_url=service.url, facts_token=service.facts_token,
        root_key=root_key, classifier=classifier,
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

    certificate = write_certificate_file(
        roots, world.steward, repository_uuid=worldbuilder.REPO_UUID
    )
    repo_init = install_repository_certificate(guildhall, roots, world, certificate)

    anchors = TrustAnchors(
        roots=roots,
        company_url=service.url,
        root_key_path=root_key,
        certificate_path=certificate,
        user_config_path=user_config,
        cache_root=roots.company_cache,
        registry=registry,
        client=client,
        facts_token=service.facts_token,
        facts_token_path=token_path,
        repository_uuid=worldbuilder.REPO_UUID,
        classifier=classifier,
        service=service,
        guildhall=guildhall,
        repo_init=repo_init,
    ).verify()
    anchors.anchors_digest = anchors.digest()
    # Company facts are admitted through the service from now on (C7).
    world.company = anchors
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


def cached_certificate_paths(roots: ProofRoots) -> set[Path]:
    """Locate installed copies by exact bytes, without guessing cache filenames."""
    expected = {p.read_bytes() for p in
                (roots.client_root / CERTIFICATE_DIR).glob("*.json") if p.is_file()}
    return {p for p in roots.company_cache.rglob("*")
            if p.is_file() and p.read_bytes() in expected}


def remove_cache(roots: ProofRoots) -> int:
    """Delete derived cache material while retaining the C2 installed identity."""
    certificates = cached_certificate_paths(roots)
    removed = 0
    for path in sorted(roots.company_cache.rglob("*")):
        if path.is_file() and path not in certificates:
            path.unlink()
            removed += 1
    for path in sorted(roots.company_cache.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    return removed
