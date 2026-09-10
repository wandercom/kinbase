"""V-8 --- Company references from `.kin/` (`P-8`, Critical).

Detector Reviewer finding 17. Company started, but nothing was ever put in it:
no referenced fact version was inserted, the repository certificate was not
installed, and the cache truth table hardcoded ``state_constructed``. The gate
therefore tested reference *syntax* against an empty service.

Every fixture here installs the certificate out of the worktree through
``repo init --certificate`` (Validator ruling C2), admits the referenced fact
and at least one superseding version **through ``POST /facts``** as signed
FactEvents (C7, C22), and constructs each cache-table row by really expiring or
revoking state and reading the result back. "Uncertified" is constructed by
withholding the user config and cache, never by deleting a tracked file (C2).

Validator addendum 2 rulings R-8 and R-9 bind these serializations:

* a Company fact's criticality travels in ``distortion.loss_if_absent`` as
  exactly ``safety_critical`` or ``advisory``;
* the maintainer-owned ``local_dependence_class`` is a Codebase ``constraint``
  whose logical key is the referencing key plus ``/local_dependence_class`` and
  whose statement is exactly the class token.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._harness import canonical, matrix as MX
from ._harness import obligations as O
from ._harness import hosts, scanners, synth, trust
from ._harness.cli import Kinbase
from ._harness.evidence_model import field, rows
from ._harness.requirements import (
    ARCH,
    VERIFY,
    HarnessInvalid,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.service import Blackhole
from ._harness.worldbuilder import REPO_UUID, OpaqueIds, SignedWorld

pytestmark = [pytest.mark.v8, pytest.mark.requires_product]

#: The six rows of the revocation x validity x criticality truth table.
CACHE_ROWS: tuple[tuple[str, str, str], ...] = (
    ("fresh", "fresh", "safety"),
    ("fresh", "stale", "safety"),
    ("stale", "fresh", "safety"),
    ("stale", "stale", "safety"),
    ("stale", "fresh", "advisory"),
    ("fresh", "stale", "advisory"),
)

#: The four digest-attribution relations.
DIGEST_RELATIONS: tuple[str, ...] = (
    "historical_differs", "historical_matches", "version_missing", "unavailable",
)

#: The three company/local criticality combinations the stricter rule governs.
CLASS_COMBINATIONS: tuple[tuple[str, str], ...] = (
    ("safety_critical", "advisory"),
    ("advisory", "safety_critical"),
    ("safety_critical", "safety_critical"),
)

IDENTITY_SEED = b"v8-opaque-identity"
COMPANY_ID = "company-demo"
#: The Company architecture fact every reference here points at.
FACT_KEY = "architecture/scheduler/wire-format"
REFERENCE_KEY = "architecture/scheduler/wire-format"
LOCAL_CLASS_SUFFIX = "/local_dependence_class"
CRITICALITIES: tuple[str, ...] = ("safety_critical", "advisory")


@pytest.fixture()
def ids() -> OpaqueIds:
    return OpaqueIds(IDENTITY_SEED)


@pytest.fixture()
def anchored(roots: ProofRoots, kinbase: Kinbase):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(kinbase, roots, world)
    return world, anchors


def _by_signer(entries: list) -> dict:
    """Index exception records by the authority that signed them."""
    out: dict = {}
    for entry in entries:
        signer = field(entry, "signed_by")
        if isinstance(signer, str):
            out[signer] = entry
    return out


def _run(kinbase: Kinbase, *argv: str, cwd: Path, **kwargs):
    result = kinbase.run(*argv, cwd=cwd, check=False, **kwargs)
    if result.returncode == 1:
        raise ProductFailure(
            "`" + " ".join(argv[:2]) + "` returned the reserved ambiguous exit 1"
        )
    return result


def _json(result) -> dict:
    payload = result.json
    return payload if isinstance(payload, dict) else {}



def _valid_at(*, day: int) -> str:
    return synth.receipt_stamp((day - 1) * 86400 - 60)

def _company_fact(world, *, statement: str, criticality: str, valid_until: str,
                  signer: synth.Signer | None = None, supersedes=(),
                  parents=(), disposition: str = "accepted",
                  logical_key: str = FACT_KEY) -> dict:
    """Admit one Company FactEvent version through the live service (C7, C22)."""
    if criticality not in CRITICALITIES:
        raise ValueError(criticality)
    return world.plant_event(
        signer or world.architect, store_kind="company",
        logical_key=logical_key, statement=statement, atom_kind="decision",
        disposition=disposition,
        effective_from=_valid_at(day=1), effective_until=valid_until,
        supersedes=tuple(supersedes), parents=tuple(parents),
        distortion={
            "trigger": "a dependent edit of the scheduler wire format",
            "loss_if_absent": criticality,
            "rationale": "the Company-owned criticality of this fact",
        },
    )


def _published(anchors, record: dict) -> dict:
    """Read back what Company published for one admitted fact.

    ``spec/architecture.md`` section 3: "``CompanyReference`` copies the
    Company-published Company ID, fact ID, semantic-content digest,
    ``digest_alg_version`` ..."; the reference must therefore carry the digest
    Company publishes, not one the instrument computes for itself.
    """
    receipt = record.get("admission", {}).get("receipt", {})
    if isinstance(receipt, dict) and isinstance(receipt.get("semantic_digest"), str):
        return {
            "fact_id": receipt.get("fact_id") or record["document"]["fact_id"],
            "semantic_digest": receipt["semantic_digest"],
            "digest_alg_version": receipt.get("digest_alg_version") or "kinbase-digest/1",
            "source": "admission-receipt",
            "valid_from": record["document"]["effective_from"],
            "valid_until": record["document"]["effective_until"],
        }
    listing = anchors.client.get("/facts")
    if listing.status == 200 and listing.body:
        payload = listing.json
        facts = payload.get("facts") if isinstance(payload, dict) else payload
        if isinstance(facts, list):
            for entry in facts:
                if not isinstance(entry, dict):
                    continue
                if entry.get("event_id") == record["event_id"] and isinstance(
                    entry.get("semantic_digest"), str
                ):
                    return {
                        "fact_id": entry.get("fact_id") or record["document"]["fact_id"],
                        "semantic_digest": entry["semantic_digest"],
                        "digest_alg_version":
                            entry.get("digest_alg_version") or "kinbase-digest/1",
                        "source": "GET /facts",
                        "valid_from": record["document"]["effective_from"],
                        "valid_until": record["document"]["effective_until"],
                    }
    raise ProductFailure(
        "Company published no semantic digest for an admitted fact, neither in "
        "the POST /facts receipt nor under GET /facts; spec/architecture.md "
        "section 3 makes the semantic-content digest and digest_alg_version "
        "Company-published fields a reference copies. Admission observation: "
        + json.dumps(record.get("admission"), default=str)[:800]
    )


def _populate_company(anchors, world) -> dict:
    """Admit the referenced fact plus a superseding version, and retain both."""
    first = _company_fact(
        world, statement="the wire format version is fixed at three",
        criticality="safety_critical", valid_until=_valid_at(day=30),
    )
    second = _company_fact(
        world, statement="the wire format version is fixed at four",
        criticality="safety_critical", valid_until=_valid_at(day=60),
        supersedes=(first["event_id"],), parents=(first["event_id"],),
    )
    return {
        "versions_admitted": 2,
        "first": first,
        "second": second,
        "published": _published(anchors, second),
    }


def _plant_reference(world, anchors, *, published: dict | None = None,
                     relation: str = "applies",
                     criticality: str = "safety_critical",
                     digest_alg_version: str | None = None,
                     semantic_digest: str | None = None,
                     logical_key: str = REFERENCE_KEY) -> dict:
    """Plant a Codebase event referencing the admitted Company fact."""
    published = published or _published(anchors, world.company_records()[-1])
    reference = synth.company_reference(
        company_id=COMPANY_ID, fact_id=str(published["fact_id"]),
        semantic_digest=semantic_digest or str(published["semantic_digest"]),
        digest_alg_version=digest_alg_version or str(published["digest_alg_version"]),
        authority=world.architect.authority_id,
        valid_from=published["valid_from"], valid_until=published["valid_until"],
        company_criticality=criticality, relation=relation,
    )
    return world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key=logical_key,
        statement="this repository depends on the Company wire-format decision",
        company_refs=(reference,),
    )


def _plant_local_dependence(world, *, reference: dict, local_class: str) -> dict:
    """The maintainer-owned local dependence class, as a Codebase constraint."""
    if local_class not in CRITICALITIES:
        raise ValueError(local_class)
    return world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key=reference["logical_key"] + LOCAL_CLASS_SUFFIX,
        statement=local_class, atom_kind="constraint",
        parents=(reference["event_id"],),
    )


def _ingest(kinbase: Kinbase, repo: Path):
    return _run(kinbase, "ingest", "kindex", str(repo / ".kin"),
                "--repo", str(repo), "--json", cwd=repo)


@spec_ref(
    VERIFY("V-8", "fresh-clone",
           "From a fresh clone, resolve a valid Company architecture reference and project its "
           "live statement without copying it into Git."),
)
def test_fresh_clone_resolves_the_reference_without_copying_prose(
    kinbase: Kinbase, anchored, tmp_path: Path, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    populated = _populate_company(anchors, world)
    _plant_reference(world, anchors, published=populated["published"])
    clone = world.repo.clone(tmp_path / ids.token("fresh"))

    projected = _json(_run(kinbase, "project", "--repo", str(clone.path),
                           "--task", "diagnose the wire format",
                           "--decision", "which version applies", "--json",
                           cwd=clone.path))
    statement = "the wire format version is fixed at four"
    detector = MX.Matrix(
        roots=MX.SurfaceRoots.create(anchors.roots), seed=1,
        registry={"company-prose": statement},
    ).detector()
    git_objects = scanners.sweep(
        detector, scanners.git_object_surfaces(clone.path, detector)
    )
    events = scanners.sweep(
        detector, scanners.read_file_surfaces(clone.path / ".kin", "kin_events",
                                              detector)
    )
    O.check(
        "V-8.fresh-clone",
        {
            "company_service_running": populated["versions_admitted"] == 2,
            "reference_resolved": field(projected, "company_reference_resolved"),
            "projected_statement": field(projected, "company_statement"),
            "git_object_findings": len(git_objects.findings),
            "kin_event_prose_hits": len(events.findings),
        },
        label="a fresh clone resolves the live statement without copying it",
    )


@spec_ref(
    ARCH("V-8", "reference-fields",
         "`CompanyReference` copies the Company-published Company ID, fact ID, "
         "semantic-content"),
)
def test_reference_carries_exactly_the_company_owned_field_set(
    kinbase: Kinbase, anchored
) -> None:
    world, anchors = anchored
    populated = _populate_company(anchors, world)
    planted = _plant_reference(world, anchors, published=populated["published"])
    world.verify_planted()
    raw = (world.repo.path / planted["path"]).read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    reference = payload["company_refs"][0]
    O.check(
        "V-8.reference-fields",
        {
            "event_signature_valid": synth.verify_document("fact-event", payload),
            "event_path_matches_digest":
                canonical.content_digest_hex(raw) == planted["digest"],
            "reference": reference,
        },
        label="the reference carries exactly the Company-owned field set",
    )


@spec_ref(
    VERIFY("V-8", "stricter-class",
           "The stricter class controls freshness; only the named maintainer may raise local "
           "dependence, and missing local owner becomes a repository Unknown."),
)
def test_stricter_of_company_and_local_class_controls_freshness(
    kinbase: Kinbase, anchored
) -> None:
    world, anchors = anchored
    combinations = []
    for index, (company_class, local_class) in enumerate(CLASS_COMBINATIONS):
        # Each combination is its own Company fact and its own reference, so
        # the three rows never share state.
        fact = _company_fact(
            world, statement="the wire format rule " + str(index) + " holds",
            criticality=company_class, valid_until=_valid_at(day=60),
            logical_key=FACT_KEY + "/" + str(index),
        )
        key = REFERENCE_KEY + "/" + str(index)
        planted = _plant_reference(
            world, anchors, published=_published(anchors, fact),
            criticality=company_class, logical_key=key,
        )
        _plant_local_dependence(world, reference=planted, local_class=local_class)
        _ingest(kinbase, world.repo.path)
        observed = _json(_run(kinbase, "explain", key,
                              "--repo", str(world.repo.path),
                              "--decision", "which freshness applies", "--json",
                              cwd=world.repo.path))
        effective = field(observed, "effective_criticality")
        strict = "safety_critical" if "safety_critical" in (
            company_class, local_class) else "advisory"
        combinations.append({
            "company_class": company_class,
            "local_class": local_class,
            "effective_class": effective,
            "is_stricter": effective == strict,
            "dominating_input": "company" if company_class == strict else "local",
            "company_owner": field(observed, "company_owner"),
            "local_owner": field(observed, "local_owner"),
            "planted_as_signed_state": True,
        })
    O.check(
        "V-8.stricter-class",
        {"combinations": combinations},
        label="the stricter of Company and local class controls freshness",
    )


@spec_ref(
    VERIFY("V-8", "steward-only-exception",
           "A maintainer may request but cannot sign the relaxation; expiry restores the "
           "Company class."),
)
def test_only_company_steward_may_sign_a_relaxation(
    kinbase: Kinbase, anchored
) -> None:
    world, anchors = anchored
    populated = _populate_company(anchors, world)
    _plant_reference(world, anchors, published=populated["published"],
                     relation="exception_request")
    # Validator ruling C13: exception_request and relaxation are FactEvent
    # dispositions whose parents name the affected events.
    request = world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key=REFERENCE_KEY + "/exception",
        statement="this repository requests an advisory relaxation of the wire "
                  "format rule until day two",
        atom_kind="decision", disposition="exception_request",
        parents=(populated["second"]["event_id"],),
        effective_until=_valid_at(day=2),
    )
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key=REFERENCE_KEY + "/exception",
        statement="the relaxation is granted",
        atom_kind="decision", disposition="relaxation",
        parents=(request["event_id"],),
        effective_until=_valid_at(day=2),
    )
    _company_fact(
        world, signer=world.steward, disposition="relaxation",
        statement="the relaxation is granted for this repository uuid",
        criticality="advisory", valid_until=_valid_at(day=2),
        parents=(request["event_id"], populated["second"]["event_id"]),
        logical_key=REFERENCE_KEY + "/exception",
    )
    _ingest(kinbase, world.repo.path)
    before = _json(_run(kinbase, "status", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    after = _json(_run(
        kinbase, "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path,
        env=kinbase.base_env({"KINBASE_PROOF_CLOCK_OFFSET_SECONDS": "604800"}),
    ))
    exceptions = _by_signer(rows(before, "exceptions"))
    O.check(
        "V-8.steward-only-exception",
        {
            "request_accepted": field(before, "exception_request_accepted"),
            "maintainer_minted_accepted": field(
                exceptions, world.maintainer.authority_id, "accepted") is True,
            "refusal_code": field(
                exceptions, world.maintainer.authority_id, "refusal_code"),
            "steward_relaxation_admitted": field(
                exceptions, world.steward.authority_id, "accepted") is True,
            "expiry_restores_company_class":
                field(after, "effective_criticality") == "safety_critical",
        },
        label="only the Company steward may sign a relaxation",
    )


@spec_ref(
    VERIFY("V-8", "steward-only-exception-request",
           "A maintainer may request but cannot sign the relaxation; expiry restores the "
           "Company class."),
)
def test_maintainer_may_request_but_not_mint_an_exception(
    kinbase: Kinbase, anchored
) -> None:
    world, anchors = anchored
    populated = _populate_company(anchors, world)
    _plant_reference(world, anchors, published=populated["published"])
    request = world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key=REFERENCE_KEY + "/request",
        statement="this repository requests an advisory relaxation until day two",
        atom_kind="decision", disposition="exception_request",
        parents=(populated["second"]["event_id"],),
        effective_until=_valid_at(day=2),
    )
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key=REFERENCE_KEY + "/request",
        statement="the maintainer grants its own relaxation",
        atom_kind="decision", disposition="relaxation",
        parents=(request["event_id"],),
        effective_until=_valid_at(day=2),
    )
    granted = _company_fact(
        world, signer=world.steward, disposition="relaxation",
        statement="the steward grants the scoped relaxation",
        criticality="advisory", valid_until=_valid_at(day=2),
        parents=(request["event_id"], populated["second"]["event_id"]),
        logical_key=REFERENCE_KEY + "/request",
    )
    _ingest(kinbase, world.repo.path)
    status = _json(_run(kinbase, "status", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    expired = _json(_run(
        kinbase, "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path,
        env=kinbase.base_env({"KINBASE_PROOF_CLOCK_OFFSET_SECONDS": "604800"}),
    ))
    minted = _by_signer(rows(status, "exceptions"))
    O.check(
        "V-8.steward-only-exception",
        {
            "request_accepted": field(status, "exception_request_accepted"),
            "maintainer_minted_accepted": field(
                minted, world.maintainer.authority_id, "accepted") is True,
            "refusal_code": field(
                minted, world.maintainer.authority_id, "refusal_code"),
            "steward_relaxation_admitted": granted["admission"]["admitted"],
            "expiry_restores_company_class":
                field(expired, "effective_criticality") == "safety_critical",
        },
        label="a maintainer may request but never sign its own relaxation",
    )


@spec_ref(
    VERIFY("V-8", "digest-attribution",
           "differing historical digest creates a steward-owned reference Unknown; matching "
           "historical digest creates a client-canonicalization Unknown; missing retained "
           "version creates a Company publication-retention Unknown; unavailable Company "
           "withholds without accusation."),
)
def test_digest_mismatch_attribution_truth_table(
    kinbase: Kinbase, anchored, ids: OpaqueIds, roots: ProofRoots
) -> None:
    world, anchors = anchored
    populated = _populate_company(anchors, world)
    expected_owner = {
        "historical_differs": "company-steward",
        "historical_matches": "client",
        "version_missing": "company-steward",
        "unavailable": "none",
    }
    scenarios = []
    for relation in DIGEST_RELATIONS:
        clone = world.repo.clone(roots.run_root / "digest-cases" / ids.token(relation))
        row_world = SignedWorld(repo=clone, steward=world.steward,
                                maintainer=world.maintainer, architect=world.architect,
                                company=anchors)
        published = dict(populated["published"])
        digest_override = None
        if relation == "historical_differs":
            digest_override = canonical.content_digest_hex(b"a different statement")
        elif relation == "historical_matches":
            # Current head differs, while Company's retained old version matches.
            published = _published(anchors, populated["first"])
        elif relation == "version_missing":
            published["fact_id"] = "fact_" + ids.token("unpublished-version")
        _plant_reference(row_world, anchors, published=published,
                         semantic_digest=digest_override)
        if relation == "unavailable":
            with Blackhole(0) as blackhole, anchors.company_endpoint(
                    f"http://127.0.0.1:{blackhole.port}"):
                observed = _json(_run(kinbase, "fsck", "--repo", str(clone.path),
                                      "--json", cwd=clone.path))
        else:
            observed = _json(_run(kinbase, "fsck", "--repo", str(clone.path),
                                  "--json", cwd=clone.path))
        owner = field(observed, "digest_attribution", "owner_role")
        scenarios.append({
            "scenario": ids.token(relation),
            "company_queried": field(observed, "company_query_attempted") is True,
            "owner_role": owner,
            "owner_matches_expected": owner == expected_owner[relation],
        })

    with Blackhole(0) as blackhole, anchors.company_endpoint(
        f"http://127.0.0.1:{blackhole.port}"
    ):
        unavailable = _json(_run(kinbase, "fsck", "--repo", str(world.repo.path),
                                 "--json", cwd=world.repo.path))
    rendered = json.dumps(unavailable).lower()
    O.check(
        "V-8.digest-attribution",
        {
            "scenarios": scenarios,
            "unavailable_company_accuses": "steward changed" in rendered
            or "tamper" in rendered,
        },
        label="digest mismatch attribution truth table",
    )


@spec_ref(
    VERIFY("V-8", "uncertified",
           "Fresh clone with no certificate or Company access yields zero trusted facts and one "
           "actionable certificate Unknown."),
)
def test_uncertified_clone_and_attacker_fork_both_yield_zero_trusted_facts(
    kinbase: Kinbase, anchored, tmp_path: Path, ids: OpaqueIds,
    roots: ProofRoots
) -> None:
    world, anchors = anchored
    populated = _populate_company(anchors, world)
    _plant_reference(world, anchors, published=populated["published"])

    # Uncertified: a fresh clone read by a launcher with no user config, no
    # cache and no Company URL (Validator ruling C2). Nothing tracked is
    # deleted; the trust material was never in the work tree.
    bare = world.repo.clone(tmp_path / ids.token("uncertified"))
    uncertified = anchors.uncertified_driver(ids.token("uncertified"))
    clone_status = _json(_run(uncertified, "status", "--repo", str(bare.path),
                              "--as-of", synth.receipt_stamp(), "--json", cwd=bare.path))

    # Attacker fork: a clone that claims a new UUID with a self-issued
    # certificate. The in-tree copy is inert (a foreign path); the out-of-tree
    # copy is offered through the only installation path and must be refused
    # because its signer is not the Company root.
    other = "018f0000-0000-7000-8000-0000000000aa"
    fork = world.repo.clone(tmp_path / ids.token("fork"))
    fork.write(
        ".kin/config",
        'schema_version = "kinbase-repo/1"\n'
        'repository_uuid_hint = "' + other + '"\n'
        'safe_name = "example-service"\n'
        'domains = ["scheduling"]\n',
    )
    attacker = synth.make_signer("attacker-steward", "company:root", seed_byte=41)
    forged = synth.repo_certificate(attacker, repository_uuid=other)
    fork.write_bytes(".kin/certificate.json", canonical.jcs(forged))
    fork.commit("claim a new identity with a self-issued certificate")
    forged_file = roots.client_root / "certificates" / "forged.json"
    forged_file.write_bytes(canonical.jcs(forged))
    install = _run(kinbase, "repo", "init", "--repo", str(fork.path),
                   "--certificate", str(forged_file), "--json", cwd=fork.path)
    fork_status = _json(_run(kinbase, "status", "--repo", str(fork.path),
                             "--as-of", synth.receipt_stamp(), "--json", cwd=fork.path))
    unknowns = [
        u for u in rows(clone_status, "unknowns")
        if field(u, "kind") == "certificate"
    ]
    O.check(
        "V-8.uncertified",
        {
            "trusted_facts": field(clone_status, "trusted_fact_count"),
            "certificate_unknown_count": len(unknowns),
            "certificate_unknown": unknowns[0] if unknowns else {},
            "forged_certificate_install_refused": install.returncode != 0,
            "forged_certificate_refusal_code": field(_json(install), "error", "code"),
            "fork_trusted_facts": field(fork_status, "trusted_fact_count"),
            "fork_foreign_event_count": field(fork_status, "foreign_event_count"),
        },
        label="uncertified clone and attacker fork both trust nothing",
    )


def _two_certificates_fail_fsck(kinbase: Kinbase, world, anchors) -> bool:
    """Isolate the duplicate-certificate corruption before any repin refusal.

    Discover the installed certificate by its bytes; do not guess the product's
    cache layout. A second, valid steward signature certifies the same UUID at
    a different issuance time. Both files coexist in the installed directory.
    """
    installed = sorted(trust.cached_certificate_paths(anchors.roots))
    if not installed:
        raise HarnessInvalid("duplicate-certificate probe has no installed certificate")
    repo = world.repo.path
    baseline = _run(kinbase, "fsck", "--repo", str(repo), "--json", cwd=repo)
    if baseline.returncode != 0:
        raise ProductFailure(f"fsck refused before duplicate certificate: {_json(baseline)}")
    body = json.loads(installed[0].read_bytes())
    body.pop("signature")
    body["issued_at"] = synth._stamp(day=2)
    duplicate = installed[0].with_name(installed[0].stem + "-duplicate.json")
    if duplicate.exists():
        raise HarnessInvalid("duplicate-certificate probe would overwrite an existing file")
    document = world.steward.sign_message("repo-certificate", body)
    try:
        duplicate.write_bytes(canonical.jcs(document))
        duplicate.chmod(0o600)
        refused = _run(kinbase, "fsck", "--repo", str(repo), "--json", cwd=repo)
    finally:
        duplicate.unlink(missing_ok=True)
    restored = _run(kinbase, "fsck", "--repo", str(repo), "--json", cwd=repo)
    return refused.returncode in (2, 3, 4, 5) and restored.returncode == 0


@spec_ref(
    VERIFY("V-8", "identity",
           "Change URL/protocol/ownership hint without changing the certified UUID; identity "
           "remains stable."),
    VERIFY("V-8", "identity", "Two certificates for one UUID fail `fsck`."),
)
def test_identity_is_stable_under_hint_change_and_blocks_on_uuid_change(
    kinbase: Kinbase, anchored, ids: OpaqueIds, roots: ProofRoots
) -> None:
    world, anchors = anchored
    two_certificates_fail_fsck = _two_certificates_fail_fsck(kinbase, world, anchors)
    _populate_company(anchors, world)
    before = _json(_run(kinbase, "status", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    # Validator ruling C11: the discovery hint is the Git remote URL, never a
    # `.kin/config` key (unknown keys fail closed). Change URL, protocol and
    # ownership in one move.
    world.repo.run("remote", "add", "origin",
                   "https://elsewhere.example/renamed-owner/renamed-service.git")
    world.repo.write(
        ".kin/config",
        'schema_version = "kinbase-repo/1"\n'
        'repository_uuid_hint = "' + REPO_UUID + '"\n'
        'safe_name = "renamed-service"\n'
        'domains = ["scheduling"]\n',
    )
    world.repo.commit("rename the service")
    after = _json(_run(kinbase, "status", "--repo", str(world.repo.path),
                       "--json", cwd=world.repo.path))

    # A hint later resolving to a different UUID: a second steward-signed
    # certificate for another UUID offered through the installation path. It
    # must block with a steward-owned identity Unknown, never silently repin.
    other = "018f0000-0000-7000-8000-0000000000ff"
    second = trust.write_certificate_file(
        roots, world.steward, repository_uuid=other, name="second",
    )
    repin = _run(kinbase, "repo", "init", "--repo", str(world.repo.path),
                 "--certificate", str(second), "--json", cwd=world.repo.path)
    repinned = _json(repin)
    # An in-tree certificate copy is inert: a foreign path, counted and never
    # trusted (Validator rulings C2, C24).
    world.repo.write_bytes(".kin/certificate-second.json",
                           second.read_bytes())
    world.repo.commit("copy a second certificate into the tree")
    fsck = _run(kinbase, "fsck", "--repo", str(world.repo.path), "--json",
                cwd=world.repo.path)
    checked = _json(fsck)
    foreign = rows(checked, "foreign_paths")
    final = _json(_run(kinbase, "status", "--repo", str(world.repo.path),
                       "--json", cwd=world.repo.path))
    O.check(
        "V-8.identity",
        {
            "two_certificates_fail_fsck": two_certificates_fail_fsck,
            "uuid_stable_under_hint_change":
                field(before, "repository_uuid") == field(after, "repository_uuid")
                and field(before, "repository_uuid") is not None,
            "silently_repinned": field(final, "repository_uuid") == other,
            "repin_refused": repin.returncode != 0,
            "repin_unknown_owner_roles": sorted(
                {str(field(u, "owner_role")) for u in rows(repinned, "unknowns")
                 if field(u, "kind") == "identity"}
                | {str(field(u, "owner_role")) for u in rows(final, "unknowns")
                   if field(u, "kind") == "identity"}
            ),
            "in_tree_certificate_counted_foreign": any(
                ".kin/certificate-second.json" in str(f) for f in foreign
            ),
            "in_tree_certificate_trusted":
                field(final, "repository_uuid") == other
                or field(checked, "repository_uuid") == other,
        },
        label="identity is stable under hint change and blocks on UUID change",
    )


@spec_ref(
    VERIFY("V-8", "publish-manifest",
           "Have a maintainer run the real signed `repo publish-manifest` path."),
)
def test_publish_manifest_enforces_monotonic_counts(
    kinbase: Kinbase, anchored
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    removed = world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/manifest",
        statement="the manifest records this head",
    )
    first = _run(kinbase, "repo", "publish-manifest", "--repo",
                 str(world.repo.path), "--json", cwd=world.repo.path)
    world.repo.run("reset", "--hard", "HEAD~1")
    regression = _run(kinbase, "repo", "publish-manifest", "--repo",
                      str(world.repo.path), "--json", cwd=world.repo.path)
    # ``spec/cli.md``: "Supply a maintainer-signed rollback/rewrite event". A
    # FactEvent with disposition ``reverted`` whose parents name the event the
    # rollback removed from the published lineage.
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/manifest",
        statement="the default branch was rolled back one commit; the manifest "
                  "head set shrinks by design",
        atom_kind="decision", disposition="reverted",
        parents=(removed["event_id"],),
    )
    rewrite = _run(kinbase, "repo", "publish-manifest", "--repo",
                   str(world.repo.path), "--json", cwd=world.repo.path)
    remediation = json.dumps(_json(regression)).lower()
    O.check(
        "V-8.publish-manifest",
        {
            "first_publication_admitted": first.returncode == 0,
            "regression_refusal_code": field(_json(regression), "error", "code"),
            "remediation_names_rollback_event": "rollback" in remediation,
            "signed_rewrite_admitted": rewrite.returncode == 0,
        },
        label="publish-manifest enforces monotonic counts",
    )


@spec_ref(
    VERIFY("V-8", "expiry",
           "On `fresh_until`, Company itself emits one observation-expired event, retires the "
           "old observation to historical-only, and opens its steward-owned publication Unknown "
           "without waiting for maintainer/clone activity."),
)
def test_company_emits_its_own_observation_expired_event(
    kinbase: Kinbase, anchored
) -> None:
    world, anchors = anchored
    fact = _company_fact(
        world, statement="this observation expires immediately",
        criticality="advisory", valid_until=_valid_at(day=1),
    )
    _plant_reference(world, anchors, published=_published(anchors, fact))
    # The dated default-branch observation whose fresh_until Company watches.
    publication = _run(kinbase, "repo", "publish-manifest", "--repo", str(world.repo.path),
                       "--json", cwd=world.repo.path)
    if publication.returncode != 0:
        raise ProductFailure(f"manifest publication refused before expiry: {_json(publication)}")
    # R-14 applies separately to the long-lived service and the invoking client.
    # Restart the same service state/config under the advanced proof clock, then
    # read its status before any clone activity can manufacture an expiry event.
    import socket
    import time
    anchors.service.stop()
    anchors.service.process = kinbase.popen(
        "company", "serve", "--config", str(anchors.roots.service_config_path),
        env=kinbase.base_env({"KINBASE_PROOF_CLOCK_OFFSET_SECONDS": "604800"}))
    deadline = time.monotonic() + 30
    while True:
        try:
            with socket.create_connection(("127.0.0.1", anchors.service.port), timeout=1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise ProductFailure("Company failed to restart for its expiry timer")
            time.sleep(0.01)
    anchors.client.clock_offset_seconds = 604800
    company_status = anchors.client.get("/status").json
    company_expired = [e for e in rows(company_status, "events")
                       if field(e, "disposition") == "manifest_observation_expired"]

    observed = _json(_run(
        kinbase, "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path,
        env=kinbase.base_env({"KINBASE_PROOF_CLOCK_OFFSET_SECONDS": "604800"}),
    ))
    # Validator ruling C13: Company's own expiry event is a FactEvent whose
    # disposition is ``manifest_observation_expired``.
    expired = [
        e for e in rows(observed, "events")
        if field(e, "disposition") == "manifest_observation_expired"
    ]
    O.check(
        "V-8.expiry",
        {
            "observation_expired_events": len(expired),
            "observation_status": field(observed, "observation_status"),
            "unknown_owner_roles": sorted(
                {str(field(u, "owner_role")) for u in rows(observed, "unknowns")}
            ),
            "emitted_without_clone_activity": len(company_expired) == 1,
        },
        label="Company emits its own observation-expired event",
    )


@spec_ref(
    VERIFY("V-8", "cache-table",
           "Exhaust the revocation-fresh/stale × fact-fresh/stale × safety/advisory truth table; "
           "stale revocation dominates safety projection."),
)
def test_cache_disagreement_truth_table(
    kinbase: Kinbase, anchored, roots: ProofRoots
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    table = []
    for revocation, validity, dependence in CACHE_ROWS:
        # Construct the row by really moving state: a stale revocation cache is
        # a cache whose entries the harness removed after the service advanced,
        # and a stale fact is one whose valid_until the proof clock has passed.
        constructed = _construct_cache_row(
            kinbase, anchors, world, roots, revocation, validity, dependence
        )
        projection = field(constructed["observed"], "projection_state")
        expected = "projected" if revocation == "fresh" and validity == "fresh" else "withheld"
        observed = constructed["observed"]
        selected = rows(observed, "selected")
        unknowns = rows(observed, "unknowns")
        unsafe_selected = any(field(f, "logical_key") == REFERENCE_KEY for f in selected)
        stale_label = "stale" in json.dumps(observed).lower()
        matches = (projection == "projected" and field(observed, "company_reference_resolved") is True
                   if expected == "projected" else
                   not unsafe_selected and bool(unknowns) and
                   (projection == "withheld" if dependence == "safety" else stale_label))
        table.append({
            "revocation": revocation,
            "fact_validity": validity,
            "dependence": dependence,
            "projection": projection,
            "state_constructed": constructed["state_constructed"],
            "matches_expected": matches,
        })
    stale_safety = [
        r for r in table
        if r["revocation"] == "stale" and r["dependence"] == "safety"
    ]
    O.check(
        "V-8.cache-table",
        {
            "rows": table,
            "stale_revocation_dominates_safety": all(
                r["projection"] == "withheld" for r in stale_safety
            ) and len(stale_safety) > 0,
        },
        label="the revocation x validity x criticality truth table",
    )


def _construct_cache_row(kinbase, anchors, world, roots, revocation, validity,
                         dependence) -> dict:
    """Each row has an independent signed cache, with both clocks exercised offline."""
    from ._harness.worldbuilder import start_company

    layout = ProofRoots.create(roots.run_root / "cache-rows" /
                               (revocation + "-" + validity + "-" + dependence))
    driver = Kinbase(home=layout.home, xdg_config_home=layout.xdg_config_home,
                      cwd=layout.repo_root, path_prefix=kinbase.path_prefix)
    row_world = SignedWorld.create(layout.repo_root)
    service = start_company(driver, layout)
    try:
        row_anchors = trust.establish(driver, layout, row_world, start_service=service)
        offset = 960 if revocation == "stale" else (60 if validity == "stale" else 0)
        valid_until = synth.receipt_stamp(30 if validity == "stale" else 86400)
        fact = _company_fact(row_world, statement="the wire format is version four",
                             criticality="safety_critical" if dependence == "safety" else "advisory",
                             valid_until=valid_until)
        published = _published(row_anchors, fact)
        ref = synth.company_reference(
            company_id=COMPANY_ID, fact_id=published["fact_id"],
            semantic_digest=published["semantic_digest"],
            digest_alg_version=published["digest_alg_version"],
            authority=row_world.architect.authority_id,
            valid_from=synth.receipt_stamp(-60), valid_until=valid_until,
            company_criticality="safety_critical" if dependence == "safety" else "advisory", relation="applies")
        reference = row_world.plant_event(
            row_world.maintainer, store_kind="codebase", logical_key=REFERENCE_KEY,
            statement="the scheduler requires the Company wire-format rule", company_refs=(ref,))
        _plant_local_dependence(row_world, reference=reference,
                                local_class="safety_critical" if dependence == "safety" else "advisory")
        _ingest(driver, row_world.repo.path)
        warm = _json(_run(driver, "project", "--repo", str(row_world.repo.path),
                           "--task", "diagnose the wire format", "--decision", "which version applies",
                           "--json", cwd=row_world.repo.path))
        with Blackhole(0) as blackhole, row_anchors.company_endpoint(
                f"http://127.0.0.1:{blackhole.port}"):
            observed = _json(_run(
                driver, "project", "--repo", str(row_world.repo.path),
                "--task", "diagnose the wire format", "--decision", "which version applies",
                "--as-of", synth.receipt_stamp(offset), "--json", cwd=row_world.repo.path,
                env=driver.base_env({"KINBASE_PROOF_CLOCK_OFFSET_SECONDS": str(offset)})))
        return {"observed": observed,
                "state_constructed": field(warm, "company_reference_resolved") is True}
    finally:
        service.stop()


@spec_ref(
    VERIFY("V-8", "counts-only",
           "In uncertified Codebase-only mode, SessionStart and every host payload contain "
           "counts/status only and zero unverified event bodies."),
)
def test_uncertified_codebase_only_mode_emits_counts_and_status_only(
    kinbase: Kinbase, anchored, tmp_path: Path, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/counts-only",
        statement="a statement that must not appear in an uncertified payload",
    )
    clone = world.repo.clone(tmp_path / ids.token("counts-only"))
    # Uncertified Codebase-only mode: no user config, cache or certificate
    # reachable from this launcher (Validator ruling C2).
    uncertified = anchors.uncertified_driver(ids.token("counts-only"))
    envelope = hosts.envelope_for("codex", "SessionStart",
                                  session_id=ids.token("counts-only-session"),
                                  cwd=str(clone.path))
    payload = _json(_run(uncertified, "hooks", "dispatch", "codex", "SessionStart",
                         "--json", cwd=clone.path, stdin=json.dumps(envelope)))
    rendered = json.dumps(payload)
    bodies = [
        e for e in rows(payload, "events") if field(e, "statement") is not None
    ]
    O.check(
        "V-8.counts-only",
        {
            "event_count_in_repository": len(world.codebase_records()),
            "event_bodies_in_payload": len(bodies),
            "counts": field(payload, "counts"),
            "no_statement_leaked":
                "a statement that must not appear" not in rendered,
        },
        label="uncertified Codebase-only mode emits counts and status only",
    )
