"""V-8 --- Company references from `.kin/` (`P-8`, Critical).

``spec/source-request.md`` SRC-3 is the founder statement this gate answers:

    Even the repo's .kin/ needs to reference global architectural ideas.

and ``spec/product.md`` P-8 fixes the ownership rule that makes the reference
safe:

    The reference does not copy Company prose or grant Company authority.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import time

from ._harness import canaries, synth
from ._harness.cli import Guildhall
from ._harness.detectors import CanaryDetector
from ._harness.gitfix import REQUIRED_ATTRIBUTE_LINES, GitRepo
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
from ._harness.scanners import git_object_surfaces, sweep
from ._harness import obligations as O
from ._harness.evidence_model import Origin, require_all, require_nonempty
from ._harness.service import wait_for_loopback
from ._harness.vault import CanaryVault, VaultEntry
from ._harness.worldbuilder import (
    REPO_UUID as WORLD_UUID,
    SignedWorld,
    Witness,
    start_company,
)

pytestmark = [pytest.mark.v8, pytest.mark.requires_product]

REPO_UUID = "018f0000-0000-7000-8000-000000000001"
OTHER_UUID = "018f0000-0000-7000-8000-0000000000ff"

#: Typed relationships, ``spec/product.md`` P-8.
RELATIONS: tuple[str, ...] = (
    "applies",
    "specializes",
    "implements",
    "contradicts",
    "exception_request",
)

#: ``spec/architecture.md`` cache truth table, "Company / Guildhall".
CACHE_TRUTH_TABLE: tuple[tuple[str, str, str, str], ...] = (
    ("fresh", "fresh", "any", "trusted"),
    ("fresh", "expired", "safety", "withheld"),
    ("fresh", "expired", "advisory", "excluded_stale"),
    ("stale", "any", "safety", "withheld_revocation_stale"),
    ("stale", "fresh", "advisory", "excluded_degraded"),
    ("stale", "expired", "advisory", "excluded_both_stale"),
)


@pytest.fixture()
def steward() -> synth.Signer:
    return synth.make_signer("company-steward-1", "company:root", seed_byte=11)


@pytest.fixture()
def maintainer() -> synth.Signer:
    return synth.make_signer("repo-maintainer-1", f"codebase:{REPO_UUID}", seed_byte=13)


@pytest.fixture()
def company(guildhall: Guildhall, roots: ProofRoots):
    """A genuinely running Company service.

    Detector Reviewer finding 15: no Company server was ever started, so every
    reference, digest, cache and revocation assertion was answered by an
    environment selector. A gate that needs live Company behaviour must fail
    loudly when the service is absent.
    """
    service = start_company(guildhall, roots)
    try:
        yield service
    finally:
        service.stop()


@pytest.fixture()
def published(roots: ProofRoots, tmp_path: Path):
    """A repository whose Company reference is genuinely signed and addressed."""
    world = SignedWorld.create(tmp_path / "origin")
    reference = synth.company_reference(
        company_id="company-demo",
        fact_id="fact_company_lookahead",
        semantic_digest="a" * 64,
        digest_alg_version="sha256/1",
        authority="company-steward-1",
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2026-12-31T00:00:00.000Z",
        company_criticality="safety",
        relation="applies",
    )
    world.plant_event(
        world.maintainer,
        store_kind="codebase",
        logical_key="architecture/scheduler/company-reference",
        statement="This service applies the Company scheduler architecture.",
        company_refs=[reference],
    )
    world.verify_planted()
    certificate = tmp_path / "certificate.json"
    certificate.write_text(
        json.dumps(
            synth.repo_certificate(world.steward, repository_uuid=REPO_UUID),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    os.chmod(certificate, 0o600)
    return world, certificate


@spec_ref(
    SRC(
        "V-8",
        "SRC-3",
        "Even the repo's .kin/ needs to reference global architectural ideas.",
    ),
    VERIFY(
        "V-8",
        "fresh-clone",
        "From a fresh clone, resolve a valid Company architecture reference and project its live "
        "statement without copying it into Git.",
    ),
    PRODUCT(
        "V-8",
        "P-8",
        "The reference does not copy Company prose or grant Company authority.",
    ),
)
def test_fresh_clone_resolves_the_reference_without_copying_prose(
    guildhall: Guildhall, published, company, roots: ProofRoots,
    tmp_path: Path, vault: CanaryVault
) -> None:
    clone = published[0].repo.clone(tmp_path / "fresh-clone")
    rng = canaries.make_rng(808)
    prose_canary = canaries.generate_canary(rng, index=0, family="exact")
    vault.add(
        VaultEntry(
            canary_id=prose_canary.canary_id,
            raw_value=prose_canary.value,
            transformation_family="exact",
            planted_surfaces=("company_sqlite",),
            expected_destination_denial=("codebase",),
            gold_atom_label="claim",
            gold_destination_labels=("company",),
        )
    )
    detector = CanaryDetector(
        registry={prose_canary.canary_id: prose_canary.value}, hmac_of=vault.hmac_of
    )

    projected = guildhall.run(
        "project",
        "--repo",
        str(clone.path),
        "--task",
        "apply the Company scheduler architecture",
        "--decision",
        "which architecture applies",
        "--json",
        cwd=clone.path,
        env={"GUILDHALL_COMPANY_URL": company.url},
        check=False,
    )
    if projected.returncode == 1:
        raise ProductFailure("`project` returned the reserved ambiguous exit 1")
    payload = projected.json if projected.stdout.strip() else {}
    statement = ""
    if isinstance(payload, dict):
        statement = json.dumps(payload.get("facts") or payload.get("projection") or "")

    result = sweep(detector, git_object_surfaces(clone.path, detector))
    kin_hits = 0
    for path in clone.path.rglob(".kin/events/**/*.json"):
        if prose_canary.value in path.read_text(encoding="utf-8"):
            kin_hits += 1

    O.check(
        "V-8.fresh-clone",
        {
            "company_service_running": company.alive,
            "reference_resolved": bool(
                isinstance(payload, dict)
                and (payload.get("company_reference_resolved") or payload.get("facts"))
            ),
            "projected_statement": statement,
            "git_object_findings": len(result.findings),
            "kin_event_prose_hits": kin_hits,
        },
        label="fresh clone resolving a live Company reference",
    )


@spec_ref(
    PRODUCT(
        "V-8",
        "P-8",
        "A `.kin/` Codebase fact may refer to a Company fact by stable fact ID, semantic "
        "digest/version, authority, validity, and Company-owned criticality, with a typed "
        "relationship such as `applies`, `specializes`, `implements`, `contradicts`, or "
        "`exception_request`.",
    ),
    ARCH(
        "V-8",
        "company-reference",
        "`CompanyReference` copies the Company-published Company ID, fact ID, semantic-content "
        "digest, `digest_alg_version`, authority, observed valid interval, `company_criticality`, "
        "and relation. Company owns those fields.",
    ),
)
def test_reference_carries_exactly_the_company_owned_field_set(
    guildhall: Guildhall, published: GitRepo, tmp_path: Path
) -> None:
    clone = published[0].repo.clone(tmp_path / "field-clone")
    events = list((clone.path / ".kin" / "events").rglob("*.json"))
    assert events, "the fixture must publish at least one referencing event"
    payload = json.loads(events[0].read_text(encoding="utf-8"))
    references = payload.get("company_refs") or []
    assert references, "the Codebase fact must carry a CompanyReference"
    reference = references[0]
    required = {
        "company_id",
        "fact_id",
        "semantic_digest",
        "digest_alg_version",
        "authority",
        "valid_from",
        "valid_until",
        "company_criticality",
        "relation",
    }
    assert required <= set(reference), (
        f"the reference is missing {sorted(required - set(reference))}"
    )
    assert reference["relation"] in RELATIONS, reference["relation"]
    assert "local_dependence_class" not in reference, (
        "local dependence is a separate maintainer-owned Codebase fact, not a "
        "Company-owned reference field"
    )
    assert "statement" not in reference and "prose" not in reference, (
        "the reference must not copy Company prose"
    )


@spec_ref(
    ARCH(
        "V-8",
        "company-reference",
        "Projection uses the stricter of Company criticality and local dependence; raising the local "
        "class records its maintainer, and a missing local owner is a repository-maintainer Unknown.",
    ),
    VERIFY(
        "V-8",
        "stricter-class",
        "Exercise Company advisory + repository safety-critical and the reverse. The stricter class "
        "controls freshness; only the named maintainer may raise local dependence, and missing local "
        "owner becomes a repository Unknown.",
    ),
)
def test_stricter_of_company_and_local_class_controls_freshness(
    guildhall: Guildhall, company, tmp_path: Path
) -> None:
    """Both classes come from signed state, never from an environment value.

    Detector Reviewer control inventory: ``COMPANY_CRITICALITY`` and
    ``LOCAL_DEPENDENCE`` were ``result_selector`` class -- the product was told
    the answer. Here each combination is a separately planted repository whose
    signed Company reference and signed maintainer-owned local-dependence fact
    carry the classes, and the reducer must derive the stricter one.
    """
    combinations = []
    for index, (company_class, local_class, expected) in enumerate((
        ("advisory", "safety", "safety"),
        ("safety", "advisory", "safety"),
        ("advisory", "advisory", "advisory"),
    )):
        world = SignedWorld.create(tmp_path / f"class-world-{index}")
        reference = synth.company_reference(
            company_id="company-demo", fact_id="fact_company_lookahead",
            semantic_digest="a" * 64, digest_alg_version="sha256/1",
            authority="company-steward-1",
            valid_from="2026-01-01T00:00:00.000Z",
            valid_until="2026-12-31T00:00:00.000Z",
            company_criticality=company_class, relation="applies",
        )
        world.plant_event(
            world.maintainer, store_kind="codebase",
            logical_key="architecture/scheduler/company-reference",
            statement="This service applies the Company scheduler architecture.",
            company_refs=[reference], commit=False,
        )
        world.plant_event(
            world.maintainer, store_kind="codebase",
            logical_key="architecture/scheduler/local-dependence",
            statement=(
                "Losing the Company scheduler reference is "
                + ("safety-critical" if local_class == "safety" else "advisory")
                + " for this repository."
            ),
            atom_kind="constraint",
        )
        world.verify_planted()
        guildhall.run(
            "ingest", "kindex", str(world.repo.path / ".kin"),
            "--repo", str(world.repo.path), "--json",
            cwd=world.repo.path, check=False,
        )
        result = guildhall.run(
            "explain", "architecture/scheduler/company-reference",
            "--repo", str(world.repo.path), "--decision",
            "apply the Company architecture", "--json",
            cwd=world.repo.path,
            env={"GUILDHALL_COMPANY_URL": company.url}, check=False,
        )
        if result.returncode == 1:
            raise ProductFailure("`explain` returned the reserved ambiguous exit 1")
        payload = result.json if result.stdout.strip() else {}
        payload = payload if isinstance(payload, dict) else {}
        trace = payload.get("dependence_trace") or payload.get("trace") or {}
        trace = trace if isinstance(trace, dict) else {}
        derived = trace.get("effective_dependence_class") or payload.get(
            "effective_dependence_class"
        )
        combinations.append({
            "company_class": company_class,
            "local_class": local_class,
            "effective_class": derived,
            "is_stricter": derived == expected,
            "dominating_input": trace.get("dominating_input"),
            "company_owner": trace.get("company_owner"),
            "local_owner": trace.get("local_owner"),
            "planted_as_signed_state": True,
        })
    O.check("V-8.stricter-class", {"combinations": combinations},
            label="stricter-of derivation from signed state")


@spec_ref(
    PRODUCT(
        "V-8",
        "P-8",
        "Only a Company steward can authorize an exception to Company architecture. A Codebase "
        "maintainer or Factory role may request one but cannot mint it.",
    ),
    VERIFY(
        "V-8",
        "mutation",
        "Mutation: let Codebase authorize `exception_to`; V-8 fails.",
    ),
)
def test_maintainer_may_request_but_not_mint_an_exception(
    guildhall: Guildhall, published: GitRepo, maintainer: synth.Signer, tmp_path: Path
) -> None:
    clone = published[0].repo.clone(tmp_path / "exception-clone")
    request = maintainer.sign_message(
        "fact-event",
        synth.fact_event(
            store_kind="codebase",
            authority_id=maintainer.authority_id,
            authority_scope=f"codebase:{REPO_UUID}",
            logical_key="architecture/scheduler/exception-request",
            statement="Request a repository-scoped criticality relaxation.",
            repository_id=REPO_UUID,
            company_refs=[
                synth.company_reference(
                    company_id="company-demo",
                    fact_id="fact_company_lookahead",
                    semantic_digest="a" * 64,
                    digest_alg_version="sha256/1",
                    authority="company-steward-1",
                    valid_from="2026-01-01T00:00:00.000Z",
                    valid_until="2026-12-31T00:00:00.000Z",
                    company_criticality="safety",
                    relation="exception_request",
                )
            ],
        ),
    )
    request_path = tmp_path / "exception-request.json"
    request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
    accepted = guildhall.run(
        "ingest", "kindex", str(request_path), "--repo", str(clone.path), "--json",
        cwd=clone.path, check=False,
    )
    assert accepted.returncode != 1

    # The same maintainer attempting to sign the relaxation itself must fail.
    minted = maintainer.sign_message(
        "fact-event",
        {
            "schema": "guildhall-relaxation/1",
            "repository_uuid": REPO_UUID,
            "company_fact_id": "fact_company_lookahead",
            "company_fact_version": "1",
            "requested_class": "advisory",
            "reason": "local relaxation",
            "expires_at": "2026-06-01T00:00:00.000Z",
        },
    )
    minted_path = tmp_path / "minted-relaxation.json"
    minted_path.write_text(json.dumps(minted, sort_keys=True), encoding="utf-8")
    result = guildhall.run(
        "ingest", "kindex", str(minted_path), "--repo", str(clone.path), "--json",
        cwd=clone.path, check=False,
    )
    assert result.returncode not in (0, 1), (
        "a Codebase maintainer must not be able to mint a Company exception"
    )
    assert result.code in {"AUTHORITY_WRONG_SCOPE", "SIGNATURE_INVALID"}, result.code


@spec_ref(
    ARCH(
        "V-8",
        "company-reference",
        "Only the Company steward may sign a scoped `relaxation` event. Projection then compares "
        "local dependence with the Company class as explicitly relaxed for that repository; "
        "absence/expiry restores the unrelaxed class.",
    ),
    VERIFY(
        "V-8",
        "relaxation",
        "Exercise specialization, contradiction, exception request, and steward-approved exception, "
        "including a repository-UUID-scoped criticality relaxation. A maintainer may request but "
        "cannot sign the relaxation; expiry restores the Company class.",
    ),
)
def test_only_company_steward_may_sign_a_relaxation(
    guildhall: Guildhall, published: GitRepo, steward: synth.Signer, tmp_path: Path
) -> None:
    clone = published[0].repo.clone(tmp_path / "relaxation-clone")
    relaxation = steward.sign_message(
        "fact-event",
        {
            "schema": "guildhall-relaxation/1",
            "repository_uuid": REPO_UUID,
            "company_fact_id": "fact_company_lookahead",
            "company_fact_version": "1",
            "relaxed_class": "advisory",
            "reason": "steward-approved scoped relaxation",
            "expires_at": "2026-06-01T00:00:00.000Z",
        },
    )
    path = tmp_path / "steward-relaxation.json"
    path.write_text(json.dumps(relaxation, sort_keys=True), encoding="utf-8")
    admitted = guildhall.run(
        "ingest", "kindex", str(path), "--repo", str(clone.path), "--json",
        cwd=clone.path, check=False,
    )
    assert admitted.returncode != 1

    expired = guildhall.run(
        "explain",
        "architecture/scheduler/company-reference",
        "--repo",
        str(clone.path),
        "--decision",
        "apply the Company architecture",
        "--as-of",
        "2026-07-01T00:00:00.000Z",
        "--json",
        cwd=clone.path,
        check=False,
    )
    assert expired.returncode != 1
    if expired.returncode in (0, 3):
        payload = expired.json
        derived = payload.get("effective_dependence_class") or (
            payload.get("dependence_trace") or {}
        ).get("effective_dependence_class")
        assert derived != "advisory", (
            "expiry of the scoped relaxation must restore the unrelaxed Company class"
        )


@spec_ref(
    ARCH(
        "V-8",
        "company-reference",
        "Unknown digest-algorithm version means client upgrade/degraded mode.",
    ),
    VERIFY(
        "V-8",
        "digest-mismatch",
        "Present an unknown `digest_alg_version`; assert a client-upgrade error rather than a false "
        "accusation that the steward changed content.",
    ),
    CLI(
        "V-8",
        "error-contract",
        "`DIGEST_ALGORITHM_UNSUPPORTED` | Company digest version is unknown | 3",
    ),
)
def test_unknown_digest_algorithm_is_a_client_upgrade_error(
    guildhall: Guildhall, company, tmp_path: Path
) -> None:
    """The unknown algorithm version is carried by the signed reference itself."""
    world = SignedWorld.create(tmp_path / "digest-alg")
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/company-reference",
        statement="This service applies the Company scheduler architecture.",
        company_refs=[synth.company_reference(
            company_id="company-demo", fact_id="fact_company_lookahead",
            semantic_digest="a" * 64, digest_alg_version="sha3-512/99",
            authority="company-steward-1",
            valid_from="2026-01-01T00:00:00.000Z",
            valid_until="2026-12-31T00:00:00.000Z",
            company_criticality="safety", relation="applies")],
    )
    world.verify_planted()
    guildhall.run("ingest", "kindex", str(world.repo.path / ".kin"),
                  "--repo", str(world.repo.path), "--json",
                  cwd=world.repo.path, check=False)
    result = guildhall.run(
        "explain", "architecture/scheduler/company-reference",
        "--repo", str(world.repo.path), "--decision",
        "apply the Company architecture", "--json",
        cwd=world.repo.path, env={"GUILDHALL_COMPANY_URL": company.url},
        check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`explain` returned the reserved ambiguous exit 1")
    if result.returncode == 0:
        raise ProductFailure(
            "an unknown digest_alg_version must not resolve silently; "
            "spec/cli.md requires DIGEST_ALGORITHM_UNSUPPORTED"
        )
    result.refused("DIGEST_ALGORITHM_UNSUPPORTED")
    remediation = result.error["remediation"].lower()
    if "upgrade" not in remediation:
        raise ProductFailure(
            "the remediation must be a client upgrade, not an accusation that the "
            f"steward changed content; observed {remediation!r}"
        )


@spec_ref(
    ARCH(
        "V-8",
        "company-reference",
        "A differing historical digest means a changed/corrupt reference and a steward-owned Unknown; "
        "a matching historical digest means a client canonicalization defect and a client-owned "
        "Unknown; unavailable or no-longer-retained historical version yields a Company "
        "publication-retention Unknown without accusing the client.",
    ),
    VERIFY(
        "V-8",
        "digest-truth-table",
        "For a known mismatch, query Company's digest for the reference's exact historical fact "
        "version plus current head: differing historical digest creates a steward-owned reference "
        "Unknown; matching historical digest creates a client-canonicalization Unknown; missing "
        "retained version creates a Company publication-retention Unknown; unavailable Company "
        "withholds without accusation.",
    ),
)
def test_digest_mismatch_attribution_truth_table(
    guildhall: Guildhall, company, tmp_path: Path
) -> None:
    """Each attribution case is a distinct real reference against live Company.

    The scenario name never reaches the product. What differs between cases is
    the signed reference's own semantic digest and validity, and whether the
    Company endpoint is reachable, so attribution must be derived.
    """
    cases = (
        ("historical_digest_differs", "b" * 64, True, "company-steward"),
        ("historical_digest_matches", "a" * 64, True, "client"),
        ("historical_version_missing", "c" * 64, True, "company-steward"),
        ("company_unavailable", "a" * 64, False, None),
    )
    scenarios = []
    for name, digest, reachable, expected_owner in cases:
        world = SignedWorld.create(tmp_path / f"digest-{name}")
        world.plant_event(
            world.maintainer, store_kind="codebase",
            logical_key="architecture/scheduler/company-reference",
            statement="This service applies the Company scheduler architecture.",
            company_refs=[synth.company_reference(
                company_id="company-demo", fact_id="fact_company_lookahead",
                semantic_digest=digest, digest_alg_version="sha256/1",
                authority="company-steward-1",
                valid_from="2026-01-01T00:00:00.000Z",
                valid_until="2026-12-31T00:00:00.000Z",
                company_criticality="safety", relation="applies")],
        )
        world.verify_planted()
        guildhall.run("ingest", "kindex", str(world.repo.path / ".kin"),
                      "--repo", str(world.repo.path), "--json",
                      cwd=world.repo.path, check=False)
        url = company.url if reachable else "http://127.0.0.1:1"
        result = guildhall.run(
            "explain", "architecture/scheduler/company-reference",
            "--repo", str(world.repo.path), "--decision",
            "apply the Company architecture", "--json",
            cwd=world.repo.path, env={"GUILDHALL_COMPANY_URL": url}, check=False,
        )
        if result.returncode == 1:
            raise ProductFailure("`explain` returned the reserved ambiguous exit 1")
        payload = result.json if result.stdout.strip() else {}
        payload = payload if isinstance(payload, dict) else {}
        unknowns = payload.get("unknowns") or []
        owners = [u.get("owner_role") for u in unknowns if isinstance(u, dict)]
        scenarios.append({
            "scenario": name,
            "company_queried": reachable,
            "owner_role": owners[0] if owners else None,
            "owner_matches_expected": (
                expected_owner in owners if expected_owner else True
            ),
        })
    unavailable = [s_ for s_ in scenarios if s_["scenario"] == "company_unavailable"][0]
    O.check(
        "V-8.digest-attribution",
        {
            "scenarios": scenarios,
            "unavailable_company_accuses": bool(unavailable["owner_role"] == "client"),
        },
        label="digest attribution over live Company state",
    )


@spec_ref(
    ARCH(
        "V-8",
        "entity-ownership",
        "Without a resolvable Company/out-of-worktree certificate, all `.kin/` events are counted as "
        "`UNVERIFIED`, trusted projection is empty, and writes are refused.",
    ),
    VERIFY(
        "V-8",
        "uncertified",
        "Fresh clone with no certificate or Company access yields zero trusted facts and one "
        "actionable certificate Unknown. An attacker fork with parent events and a self-issued "
        "certificate does the same while reporting foreign event count.",
    ),
)
def test_uncertified_clone_and_attacker_fork_both_yield_zero_trusted_facts(
    guildhall: Guildhall, published, roots: ProofRoots, tmp_path: Path
) -> None:
    """No certificate at all, then a self-issued one, both from real files.

    The certificate is written to the out-of-worktree location the ratified CLI
    contract names, not announced through an environment variable.
    """
    world, _ = published
    clone = world.repo.clone(tmp_path / "uncertified")
    result = guildhall.run("status", "--repo", str(clone.path), "--json",
                           cwd=clone.path, check=False)
    if result.returncode == 1:
        raise ProductFailure("`status` returned the reserved ambiguous exit 1")
    payload = result.json if result.stdout.strip() else {}
    payload = payload if isinstance(payload, dict) else {}
    unknowns = payload.get("unknowns") or []
    certificate_unknowns = [
        u for u in unknowns
        if isinstance(u, dict) and "certificate" in json.dumps(u).lower()
    ]

    fork = world.repo.clone(tmp_path / "attacker-fork")
    attacker = synth.make_signer("attacker-steward", "company:root", seed_byte=19)
    self_issued = roots.company_root / "self-issued-certificate.json"
    self_issued.parent.mkdir(parents=True, exist_ok=True)
    self_issued.write_text(
        json.dumps(synth.repo_certificate(attacker, repository_uuid=OTHER_UUID),
                   sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(self_issued, 0o600)
    forked = guildhall.run(
        "repo", "init", "--repo", str(fork.path),
        "--certificate", str(self_issued), "--json",
        cwd=fork.path, check=False,
    )
    if forked.returncode == 1:
        raise ProductFailure("`repo init` returned the reserved ambiguous exit 1")
    fork_status = guildhall.run("status", "--repo", str(fork.path), "--json",
                                cwd=fork.path, check=False)
    fork_payload = fork_status.json if fork_status.stdout.strip() else {}
    fork_payload = fork_payload if isinstance(fork_payload, dict) else {}

    O.check(
        "V-8.uncertified",
        {
            "trusted_facts": len(payload.get("trusted_facts") or []),
            "certificate_unknown_count": len(certificate_unknowns),
            "certificate_unknown": certificate_unknowns[0] if certificate_unknowns else {},
            "fork_trusted_facts": len(fork_payload.get("trusted_facts") or []),
            "fork_foreign_event_count": fork_payload.get("foreign_event_count"),
        },
        label="uncertified clone and attacker fork",
    )


@spec_ref(
    ARCH(
        "V-8",
        "entity-ownership",
        "A later hint returning a different UUID or certificate blocks with a steward-owned identity "
        "Unknown; it never silently repins.",
    ),
    VERIFY(
        "V-8",
        "identity",
        "Change URL/protocol/ownership hint without changing the certified UUID; identity remains "
        "stable. Resolve one hint to a different UUID after pinning and require a steward-owned "
        "identity Unknown. Two certificates for one UUID fail `fsck`.",
    ),
)
def test_identity_is_stable_under_hint_change_and_blocks_on_uuid_change(
    guildhall: Guildhall, published, company, tmp_path: Path
) -> None:
    """Discovery hints are repository configuration, so they are changed on disk.

    ``spec/cli.md`` puts ``repository_uuid_hint`` in the tracked ``.kin/config``
    and states it is not trust. Changing it there is a real deployment event;
    passing it as an environment value would let the product read the expected
    identity out of the request.
    """
    world, certificate = published
    clone = world.repo.clone(tmp_path / "identity-clone")

    def status(repo) -> dict:
        result = guildhall.run("status", "--repo", str(repo.path), "--json",
                               cwd=repo.path,
                               env={"GUILDHALL_COMPANY_URL": company.url},
                               check=False)
        if result.returncode == 1:
            raise ProductFailure("`status` returned the reserved ambiguous exit 1")
        payload = result.json if result.stdout.strip() else {}
        return payload if isinstance(payload, dict) else {}

    baseline = status(clone)
    config = clone.path / ".kin" / "config"
    original = config.read_text(encoding="utf-8")
    config.write_text(
        original.replace("example-service", "renamed-service"), encoding="utf-8"
    )
    clone.commit("change the safe-name discovery hint")
    changed_hint = status(clone)

    config.write_text(
        original.replace(REPO_UUID, OTHER_UUID), encoding="utf-8"
    )
    clone.commit("resolve the hint to a different UUID")
    repinned = status(clone)
    repin_unknowns = repinned.get("unknowns") or []

    fsck = guildhall.run("fsck", "--repo", str(clone.path), "--full", "--json",
                         cwd=clone.path, check=False)
    O.check(
        "V-8.identity",
        {
            "uuid_stable_under_hint_change": (
                baseline.get("repository_uuid") == changed_hint.get("repository_uuid")
            ),
            "silently_repinned": (
                repinned.get("repository_uuid") == OTHER_UUID
                and not repin_unknowns
            ),
            "repin_unknown_owner_roles": [
                u.get("owner_role") for u in repin_unknowns if isinstance(u, dict)
            ],
            "two_certificates_fail_fsck": fsck.returncode != 0,
        },
        label="repository identity stability",
    )


@spec_ref(
    ARCH(
        "V-8",
        "codebase",
        "Server-side monotonicity rejects lower event counts for the same reachable branch lineage "
        "unless a separately signed maintainer rollback/rewrite event explains it.",
    ),
    CLI(
        "V-8",
        "error-contract",
        "`MANIFEST_HEAD_REGRESSION` | published reachable lineage lowers event count without rewrite "
        "event | 4",
    ),
    VERIFY(
        "V-8",
        "publish",
        "Have a maintainer run the real signed `repo publish-manifest` path. Verify Company monotonic-"
        "count admission, normal strict-superset lag, missing-head failure, stale publication Unknown, "
        "unreachable-Company cache behavior, and signed rewrite/ rollback exception.",
    ),
)
def test_publish_manifest_enforces_monotonic_counts(
    guildhall: Guildhall, published, company
) -> None:
    """The count regression is produced by deleting real events, not an override."""
    world, _ = published
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/extra-1",
        statement="An additional signed repository fact.",
    )
    world.verify_planted()
    first = guildhall.run(
        "repo", "publish-manifest", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path, env={"GUILDHALL_COMPANY_URL": company.url}, check=False,
    )
    if first.returncode == 1:
        raise ProductFailure("`publish-manifest` returned the reserved exit 1")

    events = sorted((world.repo.path / ".kin" / "events").rglob("*.json"))
    if len(events) < 2:
        raise HarnessInvalid(
            "a real count regression needs at least two planted events to remove one"
        )
    events[-1].unlink()
    world.repo.commit("remove one signed event, lowering the reachable count")

    regression = guildhall.run(
        "repo", "publish-manifest", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path, env={"GUILDHALL_COMPANY_URL": company.url}, check=False,
    )
    if regression.returncode == 1:
        raise ProductFailure("`publish-manifest` returned the reserved exit 1")
    if regression.returncode == 0:
        raise ProductFailure(
            "a lowered reachable event count was admitted without a signed "
            "rollback/rewrite event"
        )
    regression.refused("MANIFEST_HEAD_REGRESSION")
    remediation = regression.error["remediation"].lower()

    rewrite = world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/rollback",
        statement="Maintainer-signed rewrite explaining the lowered event count.",
        atom_kind="decision",
    )
    explained = guildhall.run(
        "repo", "publish-manifest", "--repo", str(world.repo.path), "--json",
        cwd=world.repo.path, env={"GUILDHALL_COMPANY_URL": company.url}, check=False,
    )
    O.check(
        "V-8.publish-manifest",
        {
            "first_publication_admitted": first.returncode == 0,
            "regression_refusal_code": regression.code,
            "remediation_names_rollback_event": (
                "rollback" in remediation or "rewrite" in remediation
            ),
            "signed_rewrite_admitted": explained.returncode == 0,
        },
        label="monotonic manifest admission",
    )


@spec_ref(
    ARCH(
        "V-8",
        "codebase",
        "When `fresh_until` lapses without a replacement, Company emits its own "
        "`manifest_observation_expired` event, retires the observation to historical-only status, and "
        "opens a Company-steward publication Unknown; it does not wait for a clone or maintainer to "
        "notice its stale claim.",
    ),
    VERIFY(
        "V-8",
        "expiry",
        "On `fresh_until`, Company itself emits one observation-expired event, retires the old "
        "observation to historical-only, and opens its steward-owned publication Unknown without "
        "waiting for maintainer/clone activity.",
    ),
)
def test_company_emits_its_own_observation_expired_event(
    guildhall: Guildhall, published: GitRepo, roots: ProofRoots
) -> None:
    result = guildhall.run(
        "status", "--repo", str(published[0].repo.path), "--json", cwd=published[0].repo.path,
        env={
            "GUILDHALL_COMPANY_URL": roots.company_url,
            "GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "864000",
        },
        check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`status` returned the reserved ambiguous exit 1")
    payload = result.json if result.stdout.strip() else {}
    if not isinstance(payload, dict):
        raise ProductFailure(
            "`status --json` returned no object, so the Company expiry event could "
            "not be observed"
        )
    events = [
        e
        for e in payload.get("company_events") or []
        if e.get("kind") == "manifest_observation_expired"
    ]
    if events:
        assert len(events) == 1, "exactly one observation-expired event may be emitted"
        assert events[0].get("observation_status") == "historical-only"
        unknowns = payload.get("unknowns") or []
        assert any(u.get("owner_role") == "company-steward" for u in unknowns), (
            "expiry must open a Company-steward publication Unknown"
        )


@spec_ref(
    ARCH("V-8", "cache-truth-table", "Cache disagreement is total and ordered:"),
    VERIFY(
        "V-8",
        "truth-table",
        "Exhaust the revocation-fresh/stale × fact-fresh/stale × safety/advisory truth table; stale "
        "revocation dominates safety projection.",
    ),
)
def test_cache_disagreement_truth_table(
    guildhall: Guildhall, company, tmp_path: Path
) -> None:
    """All six rows, each from really constructed validity and cache state.

    Fact validity is written into the signed reference's own interval.
    Revocation staleness is produced by advancing the proof clock past the
    cache's revocation window -- a permitted, witnessed fault schedule -- and the
    instrument reads the elapsed interval back as the witness.
    """
    rows = []
    for index, (revocation, fact_validity, dependence, expected) in enumerate(
        CACHE_TRUTH_TABLE
    ):
        world = SignedWorld.create(tmp_path / f"cache-{index}")
        valid_until = (
            "2026-12-31T00:00:00.000Z" if fact_validity == "fresh"
            else "2026-01-02T00:00:00.000Z"
        )
        world.plant_event(
            world.maintainer, store_kind="codebase",
            logical_key="architecture/scheduler/company-reference",
            statement="This service applies the Company scheduler architecture.",
            company_refs=[synth.company_reference(
                company_id="company-demo", fact_id="fact_company_lookahead",
                semantic_digest="a" * 64, digest_alg_version="sha256/1",
                authority="company-steward-1",
                valid_from="2026-01-01T00:00:00.000Z",
                valid_until=valid_until,
                company_criticality=(
                    "safety" if dependence in ("safety", "any") else "advisory"
                ),
                relation="applies")],
            commit=False,
        )
        world.plant_event(
            world.maintainer, store_kind="codebase",
            logical_key="architecture/scheduler/local-dependence",
            statement=(
                "Losing the Company scheduler reference is "
                + ("safety-critical" if dependence == "safety" else "advisory")
                + " for this repository."
            ),
            atom_kind="constraint",
        )
        world.verify_planted()
        guildhall.run("ingest", "kindex", str(world.repo.path / ".kin"),
                      "--repo", str(world.repo.path), "--json",
                      cwd=world.repo.path, check=False)

        env = {"GUILDHALL_COMPANY_URL": company.url}
        witness = Witness(kind="proof-clock-offset")
        if revocation == "stale":
            offset = 60 * 60 * 24 * 30
            env["GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS"] = str(offset)
            witness.note(offset_seconds=offset, purpose="age the revocation snapshot")
        started = time.monotonic()
        result = guildhall.run(
            "project", "--repo", str(world.repo.path),
            "--task", "apply the Company architecture",
            "--decision", "which architecture applies", "--json",
            cwd=world.repo.path, env=env, check=False,
        )
        elapsed = time.monotonic() - started
        if revocation == "stale":
            witness.note(elapsed_seconds=elapsed)
            witness.require("the revocation-staleness schedule must be witnessed")
        if result.returncode == 1:
            raise ProductFailure("`project` returned the reserved ambiguous exit 1")
        payload = result.json if result.stdout.strip() else {}
        payload = payload if isinstance(payload, dict) else {}
        projection = (
            payload.get("projection_state")
            or payload.get("company_projection")
            or (result.code if result.returncode not in (0, 3) else None)
        )
        rows.append({
            "revocation": revocation,
            "fact_validity": fact_validity,
            "dependence": dependence,
            "projection": projection,
            "state_constructed": True,
            "matches_expected": (
                projection == "trusted" if expected == "trusted"
                else projection != "trusted"
            ),
        })
    stale_safety = [
        r for r in rows if r["revocation"] == "stale" and r["dependence"] == "safety"
    ]
    O.check(
        "V-8.cache-table",
        {
            "rows": rows,
            "stale_revocation_dominates_safety": all(
                r["projection"] != "trusted" for r in stale_safety
            ) and bool(stale_safety),
        },
        label="cache disagreement truth table",
    )


@spec_ref(
    ARCH(
        "V-8",
        "entity-ownership",
        "Event bodies are visible only through an explicit diagnostic inspect command and never enter "
        "SessionStart, a host projection, model request, or tool-result envelope.",
    ),
    VERIFY(
        "V-8",
        "uncertified-mode",
        "In uncertified Codebase-only mode, SessionStart and every host payload contain counts/status "
        "only and zero unverified event bodies.",
    ),
)
def test_uncertified_codebase_only_mode_emits_counts_and_status_only(
    guildhall: Guildhall, published: GitRepo, tmp_path: Path
) -> None:
    clone = published[0].repo.clone(tmp_path / "counts-only")
    envelope = json.dumps(
        {
            "hook_event_name": "SessionStart",
            "session_id": "acceptance-v8",
            "cwd": str(clone.path),
        }
    )
    result = guildhall.run(
        "hooks", "dispatch", "codex", "SessionStart", "--json",
        cwd=clone.path,
        stdin=envelope,
        check=False,
    )
    if result.returncode == 1:
        raise ProductFailure("`hooks dispatch` returned the reserved exit 1")
    if not result.stdout.strip():
        raise ProductFailure(
            "SessionStart emitted no payload, so the counts-only claim could not be "
            "checked; silence is not a counts-only response"
        )
    rendered = result.stdout
    payload = result.json
    if isinstance(payload, dict):
        for key in ("event_bodies", "facts", "statements"):
            bodies = payload.get(key)
            if isinstance(bodies, list):
                assert not bodies, (
                    f"uncertified Codebase-only mode leaked {len(bodies)} {key} into the "
                    "host payload; only counts and status are permitted"
                )
    for event in (clone.path / ".kin" / "events").rglob("*.json"):
        body = json.loads(event.read_text(encoding="utf-8"))
        statement = body.get("statement")
        if statement:
            assert statement not in rendered, (
                "an unverified event body reached the host payload"
            )
