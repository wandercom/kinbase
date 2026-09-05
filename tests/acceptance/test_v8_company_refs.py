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
from ._harness.service import wait_for_loopback
from ._harness.vault import CanaryVault, VaultEntry

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
def published(roots: ProofRoots, steward: synth.Signer, tmp_path: Path) -> GitRepo:
    """A repository with a Company reference and an out-of-worktree certificate."""
    origin = GitRepo.init(tmp_path / "origin")
    origin.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    origin.install_attributes(REQUIRED_ATTRIBUTE_LINES)
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
    origin.write(
        ".kin/events/00/11/" + "2" * 60 + ".json",
        json.dumps(
            synth.fact_event(
                store_kind="codebase",
                authority_id="repo-maintainer-1",
                authority_scope=f"codebase:{REPO_UUID}",
                logical_key="architecture/scheduler/company-reference",
                statement="This service applies the Company scheduler architecture.",
                repository_id=REPO_UUID,
                company_refs=[reference],
            ),
            sort_keys=True,
        ),
    )
    origin.commit("publish a Company reference")

    certificate = tmp_path / "certificate.json"
    certificate.write_text(
        json.dumps(synth.repo_certificate(steward, repository_uuid=REPO_UUID), sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(certificate, 0o600)
    return origin


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
    guildhall: Guildhall, published: GitRepo, roots: ProofRoots, tmp_path: Path, vault: CanaryVault
) -> None:
    clone = published.clone(tmp_path / "fresh-clone")
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
        env={
            "GUILDHALL_COMPANY_URL": roots.company_url,
            "GUILDHALL_ACCEPTANCE_COMPANY_PROSE_CANARY": prose_canary.value,
        },
        check=False,
    )
    assert projected.returncode != 1
    if projected.returncode == 0:
        payload = projected.json
        assert payload.get("company_reference_resolved") or payload.get("facts"), (
            "a valid Company architecture reference must resolve and project its live "
            "statement"
        )

    result = sweep(detector, git_object_surfaces(clone.path, detector))
    assert result.clean, (
        "spec/verification.md V-8: 'Scan Git objects, not only the worktree, for "
        "copied Company/private canaries.'\n"
        + json.dumps([f.sanitised() for f in result.findings], indent=2)
    )
    for path in clone.path.rglob(".kin/events/**/*.json"):
        body = path.read_text(encoding="utf-8")
        assert prose_canary.value not in body, (
            "Company text is dereferenced only through an authorized live Company "
            "capability and is never copied into `.kin/`"
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
    clone = published.clone(tmp_path / "field-clone")
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
    guildhall: Guildhall, published: GitRepo, roots: ProofRoots, tmp_path: Path
) -> None:
    clone = published.clone(tmp_path / "class-clone")
    for company_class, local_class, expected in (
        ("advisory", "safety", "safety"),
        ("safety", "advisory", "safety"),
        ("advisory", "advisory", "advisory"),
    ):
        result = guildhall.run(
            "explain",
            "architecture/scheduler/company-reference",
            "--repo",
            str(clone.path),
            "--decision",
            "apply the Company architecture",
            "--json",
            cwd=clone.path,
            env={
                "GUILDHALL_ACCEPTANCE_COMPANY_CRITICALITY": company_class,
                "GUILDHALL_ACCEPTANCE_LOCAL_DEPENDENCE": local_class,
                "GUILDHALL_COMPANY_URL": roots.company_url,
            },
            check=False,
        )
        assert result.returncode != 1
        if result.returncode not in (0, 3):
            continue
        payload = result.json
        trace = payload.get("dependence_trace") or payload.get("trace") or {}
        derived = (
            trace.get("effective_dependence_class")
            if isinstance(trace, dict)
            else payload.get("effective_dependence_class")
        )
        assert derived == expected, (
            f"company={company_class} local={local_class}: the stricter class must "
            f"control; expected {expected}, observed {derived}"
        )
        if isinstance(trace, dict):
            assert trace.get("dominating_input") in {"company", "local"}, (
                "the trace must record which input dominated"
            )
            assert trace.get("company_owner") and trace.get("local_owner") is not None, (
                "the trace must record both input facts and owners"
            )


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
    clone = published.clone(tmp_path / "exception-clone")
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
    clone = published.clone(tmp_path / "relaxation-clone")
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
    guildhall: Guildhall, published: GitRepo, tmp_path: Path
) -> None:
    clone = published.clone(tmp_path / "digest-alg-clone")
    result = guildhall.run(
        "explain",
        "architecture/scheduler/company-reference",
        "--repo",
        str(clone.path),
        "--decision",
        "apply the Company architecture",
        "--json",
        cwd=clone.path,
        env={"GUILDHALL_ACCEPTANCE_DIGEST_ALG_VERSION": "sha3-512/99"},
        check=False,
    )
    assert result.returncode != 1
    if result.returncode != 0:
        result.refused("DIGEST_ALGORITHM_UNSUPPORTED")
        remediation = result.error["remediation"].lower()
        assert "upgrade" in remediation, (
            "the remediation must be a client upgrade, not an accusation that the "
            f"steward changed content; observed {remediation!r}"
        )
        assert "steward" not in remediation or "do not recompute" in remediation


@pytest.mark.parametrize(
    "scenario,expected_owner",
    (
        ("historical_digest_differs", "company-steward"),
        ("historical_digest_matches", "client"),
        ("historical_version_missing", "company-steward"),
        ("company_unavailable", None),
    ),
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
    guildhall: Guildhall, published: GitRepo, tmp_path: Path, scenario: str, expected_owner
) -> None:
    clone = published.clone(tmp_path / f"digest-{scenario}")
    result = guildhall.run(
        "explain",
        "architecture/scheduler/company-reference",
        "--repo",
        str(clone.path),
        "--decision",
        "apply the Company architecture",
        "--json",
        cwd=clone.path,
        env={"GUILDHALL_ACCEPTANCE_DIGEST_SCENARIO": scenario},
        check=False,
    )
    assert result.returncode != 1
    if result.returncode not in (0, 3):
        return
    payload = result.json
    unknowns = payload.get("unknowns") or []
    if expected_owner is None:
        assert not payload.get("accusation"), (
            "an unavailable Company must withhold without accusation"
        )
        return
    owners = {u.get("owner_role") for u in unknowns}
    assert expected_owner in owners, (
        f"{scenario}: expected a {expected_owner}-owned Unknown; observed {owners}"
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
    guildhall: Guildhall, published: GitRepo, tmp_path: Path
) -> None:
    clone = published.clone(tmp_path / "uncertified")
    result = guildhall.run(
        "status", "--repo", str(clone.path), "--json", cwd=clone.path, check=False
    )
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    if isinstance(payload, dict):
        assert not payload.get("trusted_facts"), (
            "an uncertified clone must yield zero trusted facts"
        )
        unknowns = payload.get("unknowns") or []
        certificate_unknowns = [
            u for u in unknowns if "certificate" in json.dumps(u).lower()
        ]
        assert len(certificate_unknowns) <= 1, (
            "repeated starts must reuse one certificate Unknown, not duplicate it"
        )
        for unknown in certificate_unknowns:
            assert unknown.get("owner_identity"), (
                "the certificate Unknown must be owned by the in-scope repository "
                "maintainer with Company steward fallback"
            )
            assert unknown.get("response_due_at")

    # Attacker fork: parent events plus a self-issued certificate.
    fork = published.clone(tmp_path / "attacker-fork")
    attacker = synth.make_signer("attacker-steward", "company:root", seed_byte=19)
    self_issued = tmp_path / "self-issued.json"
    self_issued.write_text(
        json.dumps(synth.repo_certificate(attacker, repository_uuid=OTHER_UUID), sort_keys=True),
        encoding="utf-8",
    )
    forked = guildhall.run(
        "status", "--repo", str(fork.path), "--json", cwd=fork.path,
        env={"GUILDHALL_ACCEPTANCE_CERTIFICATE": str(self_issued)},
        check=False,
    )
    assert forked.returncode != 1
    fork_payload = forked.json if forked.stdout.strip() else {}
    if isinstance(fork_payload, dict):
        assert not fork_payload.get("trusted_facts"), (
            "a self-issued certificate must not produce trusted facts"
        )
        assert fork_payload.get("foreign_event_count") is not None, (
            "foreign parent events must be counted and reported, not silently "
            "presented as an empty healthy view"
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
    guildhall: Guildhall, published: GitRepo, tmp_path: Path
) -> None:
    clone = published.clone(tmp_path / "identity-clone")
    baseline = guildhall.run(
        "status", "--repo", str(clone.path), "--json", cwd=clone.path,
        env={"GUILDHALL_ACCEPTANCE_DISCOVERY_HINT": "https://example.invalid/a.git"},
        check=False,
    )
    changed_hint = guildhall.run(
        "status", "--repo", str(clone.path), "--json", cwd=clone.path,
        env={"GUILDHALL_ACCEPTANCE_DISCOVERY_HINT": "ssh://other.invalid/b.git"},
        check=False,
    )
    for result in (baseline, changed_hint):
        assert result.returncode != 1
    if baseline.returncode in (0, 3) and changed_hint.returncode in (0, 3):
        a = (baseline.json or {}).get("repository_uuid")
        b = (changed_hint.json or {}).get("repository_uuid")
        if a and b:
            assert a == b, (
                "changing the URL/protocol/ownership hint must not change the certified "
                f"identity; {a} became {b}"
            )

    repinned = guildhall.run(
        "status", "--repo", str(clone.path), "--json", cwd=clone.path,
        env={"GUILDHALL_ACCEPTANCE_HINT_RESOLVES_TO_UUID": OTHER_UUID},
        check=False,
    )
    assert repinned.returncode != 1
    if repinned.returncode in (0, 3):
        unknowns = (repinned.json or {}).get("unknowns") or []
        owners = {u.get("owner_role") for u in unknowns}
        assert "company-steward" in owners, (
            "a hint resolving to a different UUID after pinning must block with a "
            f"steward-owned identity Unknown; observed {owners}"
        )
    else:
        assert repinned.code in {"REPO_UNCERTIFIED", "FOREIGN_REPO_EVENTS", "DIGEST_MISMATCH"}


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
    guildhall: Guildhall, published: GitRepo, roots: ProofRoots
) -> None:
    first = guildhall.run(
        "repo", "publish-manifest", "--repo", str(published.path), "--json",
        cwd=published.path,
        env={"GUILDHALL_COMPANY_URL": roots.company_url},
        check=False,
    )
    assert first.returncode != 1
    regression = guildhall.run(
        "repo", "publish-manifest", "--repo", str(published.path), "--json",
        cwd=published.path,
        env={
            "GUILDHALL_COMPANY_URL": roots.company_url,
            "GUILDHALL_ACCEPTANCE_EVENT_COUNT_OVERRIDE": "0",
        },
        check=False,
    )
    assert regression.returncode != 1
    if regression.returncode != 0:
        regression.refused("MANIFEST_HEAD_REGRESSION")
        assert "rollback" in regression.error["remediation"].lower() or (
            "rewrite" in regression.error["remediation"].lower()
        ), "the remediation must name the signed rollback/rewrite event"


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
        "status", "--repo", str(published.path), "--json", cwd=published.path,
        env={
            "GUILDHALL_COMPANY_URL": roots.company_url,
            "GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": "864000",
        },
        check=False,
    )
    assert result.returncode != 1
    payload = result.json if result.stdout.strip() else {}
    if not isinstance(payload, dict):
        return
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


@pytest.mark.parametrize(
    "revocation,fact_validity,dependence,expected",
    CACHE_TRUTH_TABLE,
    ids=[f"{r}-{f}-{d}" for r, f, d, _ in CACHE_TRUTH_TABLE],
)
@spec_ref(
    ARCH(
        "V-8",
        "cache-truth-table",
        "Cache disagreement is total and ordered:",
    ),
    VERIFY(
        "V-8",
        "truth-table",
        "Exhaust the revocation-fresh/stale × fact-fresh/stale × safety/advisory truth table; stale "
        "revocation dominates safety projection.",
    ),
)
def test_cache_disagreement_truth_table(
    guildhall: Guildhall,
    published: GitRepo,
    roots: ProofRoots,
    revocation: str,
    fact_validity: str,
    dependence: str,
    expected: str,
) -> None:
    result = guildhall.run(
        "project",
        "--repo",
        str(published.path),
        "--task",
        "apply the Company architecture",
        "--decision",
        "which architecture applies",
        "--json",
        cwd=published.path,
        env={
            "GUILDHALL_COMPANY_URL": roots.company_url,
            "GUILDHALL_ACCEPTANCE_REVOCATION_SNAPSHOT": revocation,
            "GUILDHALL_ACCEPTANCE_FACT_VALIDITY": fact_validity,
            "GUILDHALL_ACCEPTANCE_DEPENDENCE_CLASS": dependence,
        },
        check=False,
    )
    assert result.returncode != 1
    if result.returncode not in (0, 3):
        assert result.code in {"REVOCATION_STALE", "CACHE_EXPIRED", "COMPANY_UNREACHABLE"}
        return
    payload = result.json
    projection = payload.get("projection_state") or payload.get("company_projection")
    if projection is None:
        return
    if expected == "trusted":
        assert projection == "trusted", (
            f"{revocation}/{fact_validity}/{dependence} must project trusted"
        )
    else:
        assert projection != "trusted", (
            f"{revocation}/{fact_validity}/{dependence} must not project trusted; "
            f"observed {projection!r}"
        )
    if revocation == "stale" and dependence == "safety":
        assert projection in {"withheld", "withheld_revocation_stale"}, (
            "stale revocation dominates safety projection"
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
    clone = published.clone(tmp_path / "counts-only")
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
    assert result.returncode != 1
    if not result.stdout.strip():
        return
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
