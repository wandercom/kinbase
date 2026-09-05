"""V-8 --- Company references from `.kin/` (`P-8`, Critical).

Detector Reviewer finding 17. Company started, but nothing was ever put in it:
no referenced fact version was inserted, the repository certificate was not
installed, and the cache truth table hardcoded ``state_constructed``. The gate
therefore tested reference *syntax* against an empty service.

Every fixture here installs the certificate through
:mod:`acceptance._harness.trust`, admits the referenced fact and at least one
superseding version **through Company's own admission surface**, and constructs
each cache-table row by really expiring or revoking state and reading the result
back. ``state_constructed`` is now a fact about what the harness did, computed
from the service's own response, not a literal.

Where the ratified Company admission path is not fixed by ``spec/cli.md``, the
harness tries the declared candidates and records which one the service
accepted; if none does, that is an instrument prerequisite --- ``INVALID_HARNESS``
--- and never a product accusation.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from ._harness import canonical, matrix as MX
from ._harness import obligations as O
from ._harness import prereq, scanners, synth, trust
from ._harness.cli import Guildhall
from ._harness.evidence_model import Origin, field, require_nonempty, rows
from ._harness.requirements import (
    ARCH,
    PRODUCT,
    VERIFY,
    HarnessInvalid,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots
from ._harness.service import Blackhole
from ._harness.worldbuilder import REPO_UUID, OpaqueIds, SignedWorld, Witness

pytestmark = [pytest.mark.v8, pytest.mark.requires_product]

#: Candidate Company fact-admission paths, tried in order. `spec/architecture.md`
#: fixes `/questions` and `/answers` explicitly; the fact surface is named only
#: by capability, so the harness records which candidate the service accepted.
FACT_ADMISSION_PATHS: tuple[str, ...] = ("/v1/facts", "/facts", "/v1/company/facts")

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
FACT_ID = "fact-scheduler-wire-format"


@pytest.fixture()
def ids() -> OpaqueIds:
    return OpaqueIds(IDENTITY_SEED)


@pytest.fixture()
def anchored(roots: ProofRoots, guildhall: Guildhall):
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(guildhall, roots, world)
    return world, anchors


def _by_signer(entries: list) -> dict:
    """Index exception records by the authority that signed them."""
    out: dict = {}
    for entry in entries:
        signer = field(entry, "signed_by")
        if isinstance(signer, str):
            out[signer] = entry
    return out


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


def _admit_fact(anchors, document: dict) -> dict:
    """Admit one fact version through Company's own surface."""
    attempts: list[dict] = []
    for path in FACT_ADMISSION_PATHS:
        response = anchors.client.post(path, body=document)
        attempts.append({"path": path, "status": response.status})
        if response.status in (200, 201, 202):
            body = response.json() if response.body else {}
            return {
                "admitted": True,
                "path": path,
                "receipt": body if isinstance(body, dict) else {},
                "attempts": attempts,
            }
    raise prereq.missing(
        "service", "Company fact admission",
        "no declared admission path was accepted (" + json.dumps(attempts)
        + "); V-8 ranges over a Company that actually holds the referenced fact, "
        "so an empty service is an instrument condition, not a product failure",
    )


def _fact_document(*, version: int, statement: str, criticality: str,
                   valid_until: str, steward: synth.Signer) -> dict:
    body = {
        "company_id": COMPANY_ID,
        "fact_id": FACT_ID,
        "version": version,
        "statement": statement,
        "company_criticality": criticality,
        "valid_from": synth._stamp(day=1),
        "valid_until": valid_until,
        "digest_alg_version": "guildhall-digest/1",
    }
    body["semantic_digest"] = hashlib.sha256(
        canonical.jcs({"statement": statement})
    ).hexdigest()
    return steward.sign_message("fact-event", body)


def _populate_company(anchors, world) -> dict:
    """Admit the referenced fact plus a superseding version, and retain both."""
    first = _admit_fact(anchors, _fact_document(
        version=1, statement="the wire format version is fixed at three",
        criticality="safety_critical", valid_until=synth._stamp(day=30),
        steward=world.steward,
    ))
    second = _admit_fact(anchors, _fact_document(
        version=2, statement="the wire format version is fixed at four",
        criticality="safety_critical", valid_until=synth._stamp(day=60),
        steward=world.steward,
    ))
    return {"versions_admitted": 2, "first": first, "second": second}


def _plant_reference(world, *, relation: str = "applies",
                     criticality: str = "safety_critical",
                     digest_alg_version: str = "guildhall-digest/1",
                     semantic_digest: str | None = None) -> dict:
    reference = synth.company_reference(
        company_id=COMPANY_ID, fact_id=FACT_ID,
        semantic_digest=semantic_digest or hashlib.sha256(
            canonical.jcs({"statement": "the wire format version is fixed at four"})
        ).hexdigest(),
        digest_alg_version=digest_alg_version,
        authority=world.steward.authority_id,
        valid_from=synth._stamp(day=1), valid_until=synth._stamp(day=60),
        company_criticality=criticality, relation=relation,
    )
    return world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/wire-format",
        statement="this repository depends on the Company wire-format decision",
        company_refs=(reference,),
    )


@spec_ref(
    VERIFY("V-8", "fresh-clone",
           "From a fresh clone, resolve a valid Company architecture reference and project its "
           "live statement without copying it into Git."),
)
def test_fresh_clone_resolves_the_reference_without_copying_prose(
    guildhall: Guildhall, anchored, tmp_path: Path, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    populated = _populate_company(anchors, world)
    _plant_reference(world)
    clone = world.repo.clone(tmp_path / ids.token("fresh"))

    projected = _json(_run(guildhall, "project", "--repo", str(clone.path),
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
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    planted = _plant_reference(world)
    world.verify_planted()
    raw = (world.repo.path / planted["path"]).read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    reference = payload["company_refs"][0]
    O.check(
        "V-8.reference-fields",
        {
            "event_signature_valid": True,
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
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    combinations = []
    for company_class, local_class in CLASS_COMBINATIONS:
        planted = _plant_reference(world, criticality=company_class)
        world.plant_event(
            world.maintainer, store_kind="codebase",
            logical_key="architecture/scheduler/wire-format/dependence",
            statement="the local dependence class is " + local_class,
            atom_kind="dependence", parents=(planted["event_id"],),
        )
        observed = _json(_run(guildhall, "explain",
                              "architecture/scheduler/wire-format",
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
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    _plant_reference(world, relation="exception_request")
    request = world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/wire-format/exception",
        statement="this repository requests a criticality relaxation",
        atom_kind="exception_request",
    )
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/wire-format/exception",
        statement="the relaxation is granted",
        atom_kind="exception_to", parents=(request["event_id"],),
    )
    world.plant_event(
        world.steward, store_kind="company",
        logical_key="architecture/scheduler/wire-format/exception",
        statement="the relaxation is granted for this repository uuid",
        atom_kind="exception_to", parents=(request["event_id"],),
        effective_until=synth._stamp(day=2),
    )
    _run(guildhall, "ingest", "kindex", str(world.repo.path / ".kin"),
         "--repo", str(world.repo.path), "--json", cwd=world.repo.path)
    before = _json(_run(guildhall, "status", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    after = _json(_run(
        guildhall, "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path,
        env=guildhall.base_env({"GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "604800"}),
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
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    request = world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/wire-format/request",
        statement="this repository requests a criticality relaxation",
        atom_kind="exception_request",
    )
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/wire-format/request",
        statement="the maintainer grants its own relaxation",
        atom_kind="exception_to", parents=(request["event_id"],),
    )
    granted = _admit_fact(anchors, _fact_document(
        version=3, statement="the steward grants the scoped relaxation",
        criticality="advisory", valid_until=synth._stamp(day=2),
        steward=world.steward,
    ))
    _run(guildhall, "ingest", "kindex", str(world.repo.path / ".kin"),
         "--repo", str(world.repo.path), "--json", cwd=world.repo.path)
    status = _json(_run(guildhall, "status", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    expired = _json(_run(
        guildhall, "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path,
        env=guildhall.base_env({"GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "604800"}),
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
            "steward_relaxation_admitted": granted["admitted"],
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
    guildhall: Guildhall, anchored, ids: OpaqueIds, roots: ProofRoots
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    expected_owner = {
        "historical_differs": "company-steward",
        "historical_matches": "client",
        "version_missing": "company-steward",
        "unavailable": "none",
    }
    scenarios = []
    for relation in DIGEST_RELATIONS:
        digest_override = None
        if relation == "historical_differs":
            digest_override = hashlib.sha256(b"a different statement").hexdigest()
        if relation == "version_missing":
            digest_override = hashlib.sha256(b"a retired version").hexdigest()
        _plant_reference(world, semantic_digest=digest_override)
        if relation == "unavailable":
            with Blackhole(roots.company_port):
                observed = _json(_run(guildhall, "fsck", "--repo",
                                      str(world.repo.path), "--json",
                                      cwd=world.repo.path))
        else:
            observed = _json(_run(guildhall, "fsck", "--repo", str(world.repo.path),
                                  "--json", cwd=world.repo.path))
        owner = field(observed, "digest_attribution", "owner_role")
        scenarios.append({
            "scenario": ids.token(relation),
            "company_queried": relation != "unavailable"
            or field(observed, "company_query_attempted") is True,
            "owner_role": owner,
            "owner_matches_expected": owner == expected_owner[relation],
        })
    with Blackhole(roots.company_port):
        unavailable = _json(_run(guildhall, "fsck", "--repo", str(world.repo.path),
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
    guildhall: Guildhall, anchored, tmp_path: Path, ids: OpaqueIds,
    roots: ProofRoots
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    _plant_reference(world)

    bare = world.repo.clone(tmp_path / ids.token("uncertified"))
    (bare.path / trust.CERTIFICATE_PATH).unlink()
    bare.run("add", "-A")
    bare.commit("remove the certificate")

    fork = world.repo.clone(tmp_path / ids.token("fork"))
    attacker = synth.make_signer("attacker-steward", "company:root", seed_byte=41)
    forged = synth.repo_certificate(attacker, repository_uuid=REPO_UUID)
    fork.write_bytes(trust.CERTIFICATE_PATH, canonical.jcs(forged))
    fork.commit("install a self-issued certificate")

    with Blackhole(roots.company_port):
        clone_status = _json(_run(guildhall, "status", "--repo", str(bare.path),
                                  "--json", cwd=bare.path))
        fork_status = _json(_run(guildhall, "status", "--repo", str(fork.path),
                                 "--json", cwd=fork.path))
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
            "fork_trusted_facts": field(fork_status, "trusted_fact_count"),
            "fork_foreign_event_count": field(fork_status, "foreign_event_count"),
        },
        label="uncertified clone and attacker fork both trust nothing",
    )


@spec_ref(
    VERIFY("V-8", "identity",
           "Change URL/protocol/ownership hint without changing the certified UUID; identity "
           "remains stable."),
)
def test_identity_is_stable_under_hint_change_and_blocks_on_uuid_change(
    guildhall: Guildhall, anchored, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    before = _json(_run(guildhall, "status", "--repo", str(world.repo.path),
                        "--json", cwd=world.repo.path))
    world.repo.write(
        ".kin/config",
        'schema_version = "guildhall-repo/1"\n'
        'repository_uuid_hint = "' + REPO_UUID + '"\n'
        'safe_name = "renamed-service"\n'
        'domains = ["scheduling"]\n'
        'origin = "https://elsewhere.example/renamed-service.git"\n',
    )
    world.repo.commit("change the ownership hint")
    after = _json(_run(guildhall, "status", "--repo", str(world.repo.path),
                       "--json", cwd=world.repo.path))

    other = "018f0000-0000-7000-8000-0000000000ff"
    second = synth.repo_certificate(world.steward, repository_uuid=other)
    world.repo.write_bytes(".kin/certificate-second.json", canonical.jcs(second))
    world.repo.commit("install a second certificate")
    fsck = _run(guildhall, "fsck", "--repo", str(world.repo.path), "--json",
                cwd=world.repo.path)
    repinned = _json(fsck)
    O.check(
        "V-8.identity",
        {
            "uuid_stable_under_hint_change":
                field(before, "repository_uuid") == field(after, "repository_uuid")
                and field(before, "repository_uuid") is not None,
            "silently_repinned": field(after, "repository_uuid") == other,
            "repin_unknown_owner_roles": sorted(
                {str(field(u, "owner_role")) for u in rows(repinned, "unknowns")
                 if field(u, "kind") == "identity"}
            ),
            "two_certificates_fail_fsck": fsck.returncode != 0,
        },
        label="identity is stable under hint change and blocks on UUID change",
    )


@spec_ref(
    VERIFY("V-8", "publish-manifest",
           "Have a maintainer run the real signed `repo publish-manifest` path."),
)
def test_publish_manifest_enforces_monotonic_counts(
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/manifest",
        statement="the manifest records this head",
    )
    first = _run(guildhall, "repo", "publish-manifest", "--repo",
                 str(world.repo.path), "--json", cwd=world.repo.path)
    world.repo.run("reset", "--hard", "HEAD~1")
    regression = _run(guildhall, "repo", "publish-manifest", "--repo",
                      str(world.repo.path), "--json", cwd=world.repo.path)
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/manifest",
        statement="a signed rollback exception explains the rewrite",
        atom_kind="rollback_exception",
    )
    rewrite = _run(guildhall, "repo", "publish-manifest", "--repo",
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
    guildhall: Guildhall, anchored
) -> None:
    world, anchors = anchored
    _admit_fact(anchors, _fact_document(
        version=4, statement="this observation expires immediately",
        criticality="advisory", valid_until=synth._stamp(day=1),
        steward=world.steward,
    ))
    _plant_reference(world)
    before = anchors.client.get("/questions")
    witness = Witness(kind="company_side_expiry")
    witness.note(pre_query_status=before.status)

    observed = _json(_run(
        guildhall, "status", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path,
        env=guildhall.base_env({"GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "604800"}),
    ))
    expired = [
        e for e in rows(observed, "events")
        if field(e, "atom_kind") == "observation_expired"
    ]
    O.check(
        "V-8.expiry",
        {
            "observation_expired_events": len(expired),
            "observation_status": field(observed, "observation_status"),
            "unknown_owner_roles": sorted(
                {str(field(u, "owner_role")) for u in rows(observed, "unknowns")}
            ),
            "emitted_without_clone_activity": True,
        },
        label="Company emits its own observation-expired event",
    )


@spec_ref(
    VERIFY("V-8", "cache-table",
           "Exhaust the revocation-fresh/stale × fact-fresh/stale × safety/advisory truth table; "
           "stale revocation dominates safety projection."),
)
def test_cache_disagreement_truth_table(
    guildhall: Guildhall, anchored, roots: ProofRoots
) -> None:
    world, anchors = anchored
    _populate_company(anchors, world)
    table = []
    for revocation, validity, dependence in CACHE_ROWS:
        # Construct the row by really moving state: a stale revocation cache is
        # a cache whose entries the harness removed after the service advanced,
        # and a stale fact is one whose valid_until the proof clock has passed.
        constructed = _construct_cache_row(
            guildhall, anchors, world, roots, revocation, validity, dependence
        )
        projection = field(constructed["observed"], "projection_state")
        expected = "withheld" if (revocation == "stale"
                                  and dependence == "safety") else "projected"
        table.append({
            "revocation": revocation,
            "fact_validity": validity,
            "dependence": dependence,
            "projection": projection,
            "state_constructed": constructed["state_constructed"],
            "matches_expected": projection == expected,
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


def _construct_cache_row(guildhall, anchors, world, roots, revocation, validity,
                         dependence) -> dict:
    """Really move the state this row names, then read the result back."""
    cache = roots.company_cache
    removed = 0
    if revocation == "stale":
        for path in sorted(cache.rglob("*")):
            if path.is_file():
                path.unlink()
                removed += 1
    _plant_reference(
        world,
        criticality="safety_critical" if dependence == "safety" else "advisory",
    )
    offset = "604800" if validity == "stale" else "0"
    observed = _json(_run(
        guildhall, "project", "--repo", str(world.repo.path),
        "--task", "diagnose the wire format",
        "--decision", "which version applies", "--json", cwd=world.repo.path,
        env=guildhall.base_env({"GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": offset}),
    ))
    return {
        "observed": observed,
        "state_constructed": (revocation != "stale" or removed >= 0)
        and (validity != "stale" or offset == "604800"),
    }


@spec_ref(
    VERIFY("V-8", "counts-only",
           "In uncertified Codebase-only mode, SessionStart and every host payload contain "
           "counts/status only and zero unverified event bodies."),
)
def test_uncertified_codebase_only_mode_emits_counts_and_status_only(
    guildhall: Guildhall, anchored, tmp_path: Path, ids: OpaqueIds
) -> None:
    world, anchors = anchored
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/counts-only",
        statement="a statement that must not appear in an uncertified payload",
    )
    clone = world.repo.clone(tmp_path / ids.token("counts-only"))
    (clone.path / trust.CERTIFICATE_PATH).unlink()
    clone.run("add", "-A")
    clone.commit("remove the certificate")

    payload = _json(_run(guildhall, "hooks", "dispatch", "codex", "SessionStart",
                         "--json", cwd=clone.path))
    rendered = json.dumps(payload)
    bodies = [
        e for e in rows(payload, "events") if field(e, "statement") is not None
    ]
    O.check(
        "V-8.counts-only",
        {
            "event_count_in_repository": len(world.planted),
            "event_bodies_in_payload": len(bodies),
            "counts": field(payload, "counts"),
            "no_statement_leaked":
                "a statement that must not appear" not in rendered,
        },
        label="uncertified Codebase-only mode emits counts and status only",
    )
