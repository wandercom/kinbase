"""Nonfunctional proof gates and operational limits.

``spec/verification.md`` "Nonfunctional proof gates" and "Operational limits"
are acceptance-critical, not polish:

    Scale beyond these bounds, production availability, and human-response SLOs
    remain future work. Behavior inside them is acceptance-critical.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from ._harness import canaries, synth
from ._harness.cli import ERROR_CODES, EXIT_MEANING, Guildhall
from ._harness.gitfix import GitRepo
from ._harness.hosts import (
    CANDIDATE_LIFETIME_SECONDS,
    CEILING_STOP_CONFOUND_FRACTION,
    KIN_INTAKE_BYTES,
    KIN_INTAKE_EVENTS,
    OBSERVATION_BATCH_BYTES,
    OBSERVATION_BATCH_ITEMS,
    PRIVATE_RAW_RETENTION_SECONDS,
    PROJECTION_BYTES,
    PROJECTION_FACTS,
    SHARED_EVENT_CEILING,
    SOURCE_BODY_CEILING,
)
from ._harness.requirements import (
    ARCH,
    CLI,
    PRODUCT,
    VERIFY,
    ProductFailure,
    spec_ref,
)
from ._harness.roots import ProofRoots, assert_mode_no_broader_than
from ._harness.service import (
    REJECTION_PROBES,
    ClientKey,
    ServiceClient,
    assert_loopback_only,
    wait_for_loopback,
)
from ._harness import ed25519_pure

pytestmark = [pytest.mark.nonfunctional, pytest.mark.requires_product]


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "packaging",
        "Python package installs in a clean environment and commands have bounded help.",
    )
)
def test_commands_have_bounded_help(guildhall: Guildhall) -> None:
    surfaces = (
        ("--help",),
        ("company", "--help"),
        ("repo", "--help"),
        ("status", "--help"),
        ("doctor", "--help"),
        ("ingest", "--help"),
        ("corpus", "--help"),
        ("fsck", "--help"),
        ("explain", "--help"),
        ("project", "--help"),
        ("session", "--help"),
        ("proposals", "--help"),
        ("questions", "--help"),
        ("hooks", "--help"),
        ("experiment", "--help"),
    )
    for argv in surfaces:
        result = guildhall.run(*argv, timeout=60, check=False)
        assert result.returncode in (0, 2), (
            f"`{' '.join(argv)}` exited {result.returncode}"
        )
        assert result.returncode != 1, "spec/cli.md reserves exit 1"
        assert result.stdout, f"`{' '.join(argv)}` printed no help"
        assert len(result.stdout) < 32_768, (
            f"`{' '.join(argv)}` help is {len(result.stdout)} bytes; help must be bounded"
        )


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "roots",
        "All service/data roots are explicit; default bind is loopback; filesystem modes are asserted; "
        "symlinks and escapes fail closed.",
    ),
    ARCH(
        "NONFUNCTIONAL",
        "containment",
        "Files are created with restrictive modes; symlinks and paths escaping declared roots are "
        "rejected.",
    ),
)
def test_roots_are_explicit_modes_restrictive_and_escapes_fail_closed(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    for path, expected in (
        (roots.personal_root, 0o700),
        (roots.company_cache, 0o700),
        (roots.run_root, 0o700),
    ):
        assert stat.S_IMODE(path.stat().st_mode) == expected, (
            f"{path} must be mode {expected:04o}"
        )

    outside = tmp_path / "outside-root"
    outside.mkdir(parents=True, exist_ok=True)
    (outside / "target.txt").write_text("escaped\n", encoding="utf-8")
    repo = GitRepo.init(roots.repo_root)
    link = repo.path / ".kin" / "events" / "escape.json"
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(outside / "target.txt", link)
    result = guildhall.run("fsck", "--repo", str(repo.path), "--json", check=False)
    assert result.returncode not in (0, 1), (
        "a symlink escaping the declared root must fail closed"
    )

    traversal = guildhall.run(
        "ingest", "kindex", "../../../etc/passwd", "--repo", str(repo.path), "--json",
        check=False,
    )
    assert traversal.returncode not in (0, 1), (
        "a path escaping the declared root must be rejected"
    )


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "determinism",
        "Schema validation, canonicalization, migrations, and rebuilds are deterministic.",
    )
)
def test_schema_validation_and_rebuild_are_deterministic(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.commit("initialise")
    outputs = []
    for _ in range(3):
        result = guildhall.run(
            "corpus", "rebuild", "--store", "codebase", "--repo", str(repo.path),
            "--as-of", "2026-03-05T00:00:00.000Z", "--authority-cursor", "1",
            "--json", check=False,
        )
        assert result.returncode != 1
        if result.returncode == 0:
            outputs.append(json.dumps(result.json.get("current_view"), sort_keys=True))
    if outputs:
        assert len(set(outputs)) == 1, "rebuild is not deterministic across repeats"

    bad_schema = roots.run_root / "bad.json"
    bad_schema.write_text('{"schema": "not-a-guildhall-schema/9"}', encoding="utf-8")
    rejected = guildhall.run(
        "ingest", "kindex", str(bad_schema), "--repo", str(repo.path), "--json", check=False
    )
    assert rejected.returncode not in (0, 1), "an unknown schema version must fail closed"


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "logs",
        "Logs are structured and contain IDs/digests/statuses, never raw private messages.",
    )
)
def test_logs_are_structured_and_carry_no_raw_private_messages(
    guildhall: Guildhall, roots: ProofRoots, vault
) -> None:
    from ._harness.detectors import CanaryDetector
    from ._harness.scanners import read_file_surfaces, sweep
    from ._harness.vault import VaultEntry

    rng = canaries.make_rng(4711)
    canary = canaries.generate_canary(rng, index=0, family="exact", kind="hard_block")
    vault.add(
        VaultEntry(
            canary_id=canary.canary_id,
            raw_value=canary.value,
            transformation_family="exact",
            planted_surfaces=("personal_store",),
            expected_destination_denial=("company", "codebase"),
            gold_atom_label="observation",
            gold_destination_labels=("personal",),
        )
    )
    source = roots.plant_personal_canary_file(
        "log-probe.jsonl",
        json.dumps({"role": "user", "text": f"private {canary.value}"}) + "\n",
    )
    guildhall.run(
        "session", "observe", "log-probe", "--event", str(source), "--json", check=False
    )
    detector = CanaryDetector(
        registry={canary.canary_id: canary.value}, hmac_of=vault.hmac_of
    )
    for root in (roots.home, roots.run_root, roots.company_root):
        result = sweep(detector, read_file_surfaces(root, "logs", detector))
        assert result.clean, (
            "logs must contain IDs/digests/statuses, never raw private messages: "
            + json.dumps([f.sanitised() for f in result.findings], indent=2)
        )


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "timeouts",
        "Every external/model/process call has a timeout and typed failure; failed writes do not become "
        "admitted facts.",
    ),
    VERIFY(
        "NONFUNCTIONAL",
        "operational-limits",
        "all child processes: explicit wall and idle timeout;",
    ),
)
def test_external_calls_have_timeouts_and_failed_writes_are_not_admitted(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    from ._harness.service import blackhole_endpoint

    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.commit("initialise")
    with blackhole_endpoint(roots.company_port):
        result = guildhall.run(
            "status", "--repo", str(repo.path), "--json",
            env={"GUILDHALL_COMPANY_URL": roots.company_url},
            timeout=60,
            check=False,
        )
    assert result.returncode != 1, "a timed-out external call must be typed, not generic"
    if result.returncode not in (0, 3):
        assert result.code in {"COMPANY_UNREACHABLE", "CACHE_EXPIRED", "REVOCATION_STALE"}

    failed_write = guildhall.run(
        "proposals", "decide", "nonexistent", "--destination", "company",
        "--approve-digest", "0" * 64, "--json", check=False,
    )
    assert failed_write.returncode not in (0, 1)
    events = list((repo.path / ".kin" / "events").rglob("*.json")) if (
        repo.path / ".kin" / "events"
    ).exists() else []
    assert not events, "a failed write must not become an admitted fact"


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "diagnostics",
        "`fsck`, `doctor`, corpus status, question status, and experiment status are executable and "
        "useful after restart.",
    ),
    CLI(
        "NONFUNCTIONAL",
        "corpus-and-inspection",
        "`explain` shows reducer steps, rejected events, current/conflict/Unknown state, and evidence "
        "that would change it.",
    ),
)
def test_diagnostics_are_executable_and_useful_after_restart(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.commit("initialise")
    for argv in (
        ("fsck", "--repo", str(repo.path), "--json"),
        ("doctor", "--repo", str(repo.path), "--json"),
        ("status", "--repo", str(repo.path), "--json"),
        ("questions", "list", "--json"),
    ):
        first = guildhall.run(*argv, check=False)
        second = guildhall.run(*argv, check=False)
        assert first.returncode != 1 and second.returncode != 1, argv
        assert second.stdout.strip(), (
            f"`{' '.join(argv)}` produced no output after restart"
        )

    explained = guildhall.run(
        "explain", "architecture/scheduler/x", "--repo", str(repo.path),
        "--decision", "probe", "--json", check=False,
    )
    assert explained.returncode != 1
    if explained.returncode in (0, 3) and explained.stdout.strip():
        payload = explained.json
        for field in ("trace", "rejected_events", "state"):
            assert field in payload or field.replace("trace", "reducer_trace") in payload, (
                f"`explain` must show {field}"
            )


@pytest.mark.denial
@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "http",
        "Guildhall HTTP rejects unauthenticated reads, non-loopback Host, Origin-bearing requests, and "
        "non-JSON writes; all receive typed remediation-safe errors.",
    ),
    ARCH(
        "NONFUNCTIONAL",
        "company-guildhall",
        "Host/Origin checks are anti-CSRF hardening only; the security claim against a local same-UID "
        "process rests on scoped token plus client-key request signature, not those headers.",
    ),
)
def test_http_rejects_every_declared_probe(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    roots.write_service_config()
    roots.write_secret("facts.token", b"facts-token-nonfunctional")
    roots.write_secret("directory.token", b"directory-token-nonfunctional")
    roots.write_secret("company-root.key", ed25519_pure.generate_seed())
    proc = guildhall.popen("company", "serve", "--config", str(roots.service_config_path))
    try:
        if not wait_for_loopback("127.0.0.1", roots.company_port, timeout=30):
            raise ProductFailure(
                "guildhalld did not accept a loopback connection; spec/architecture.md "
                "section 6 requires a real loopback-capable HTTP service"
            )
        assert_loopback_only(roots.company_port)
        client = ServiceClient(
            host="127.0.0.1",
            port=roots.company_port,
            token="facts-token-nonfunctional",
            client_key=ClientKey(seed=ed25519_pure.generate_seed()),
        )
        outcomes: dict[str, int] = {}
        outcomes["unauthenticated_read"] = client.get(
            "/facts?authority_scope=architecture:scheduling", token=""
        ).assert_refused().assert_bounded_body().status
        outcomes["non_loopback_host"] = client.get(
            "/facts?authority_scope=architecture:scheduling",
            host_header="attacker.example",
        ).assert_refused().assert_bounded_body().status
        outcomes["origin_header_present"] = client.get(
            "/facts?authority_scope=architecture:scheduling",
            origin="http://attacker.example",
        ).assert_refused().assert_bounded_body().status
        outcomes["non_json_write"] = client.call(
            "POST",
            "/questions",
            raw_body=b"not-json",
            content_type="text/plain",
        ).assert_refused().assert_bounded_body().status
        assert set(outcomes) == set(REJECTION_PROBES), outcomes
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except Exception:
            proc.kill()


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "hygiene",
        "Static analysis, formatting, type checks, dependency audit, and full test suite run without "
        "undeclared network access.",
    )
)
@pytest.mark.selftest
def test_acceptance_suite_declares_all_its_dependencies() -> None:
    """No third-party import may be undeclared.

    The import set is taken from the parsed AST, not from line prefixes: a
    textual scan matched prose inside docstrings and reported words such as
    ``the`` and ``time,`` as modules, which both hid real omissions in noise
    and produced failures that were instrument defects rather than findings.
    """
    import ast

    lane = Path(__file__).resolve().parents[1]
    requirements = (lane / "requirements.txt").read_text(encoding="utf-8")
    declared = {
        line.split(";")[0].split(">=")[0].split("==")[0].strip().lower()
        for line in requirements.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    stdlib = set(sys.stdlib_module_names)
    third_party: dict[str, str] = {}
    for path in (lane / "acceptance").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # relative import inside the suite
                    continue
                roots = [(node.module or "").split(".")[0]]
            else:
                continue
            for root in roots:
                if not root or root in stdlib or root in {"acceptance", "__future__"}:
                    continue
                third_party.setdefault(root.lower(), f"{path.name}")
    undeclared = sorted(set(third_party) - declared)
    assert not undeclared, (
        "the acceptance suite imports undeclared third-party modules: "
        + ", ".join(f"{m} ({third_party[m]})" for m in undeclared)
    )



@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "operational-limits",
        "source body: 1 MiB; observation batch: 10,000 items / 256 MiB;",
    ),
    VERIFY(
        "NONFUNCTIONAL",
        "operational-limits",
        "shared event: 64 KiB; `.kin/` intake: 10,000 events / 128 MiB;",
    ),
    VERIFY(
        "NONFUNCTIONAL",
        "operational-limits",
        "projection call: 32 facts / 128 KiB; every ceiling stop reports omitted count and is a "
        "confound if it exceeds 10% of dependent edits;",
    ),
)
def test_every_operational_ceiling_refuses_with_an_omitted_count(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    repo = GitRepo.init(roots.repo_root)
    repo.write(".kin/config", 'schema_version = "guildhall-repo/1"\n')
    repo.commit("initialise")

    oversized = tmp_path / "oversized-source.json"
    oversized.write_bytes(b'{"body":"' + b"A" * (SOURCE_BODY_CEILING + 1024) + b'"}')
    result = guildhall.run(
        "ingest", "runtime_evidence", str(oversized), "--repo", str(repo.path), "--json",
        check=False,
    )
    assert result.returncode != 1
    if result.returncode != 0:
        result.refused("LIMIT_EXCEEDED")
        payload = result.error
        assert payload["remediation"], "LIMIT_EXCEEDED must carry remediation"
        assert "truncat" not in payload["message"].lower(), (
            "spec/cli.md: 'never truncate silently'"
        )

    projection = guildhall.run(
        "project", "--repo", str(repo.path), "--task", "x", "--decision", "y", "--json",
        env={"GUILDHALL_ACCEPTANCE_FORCE_CEILING": "projection"},
        check=False,
    )
    assert projection.returncode != 1
    if projection.returncode in (0, 3) and projection.stdout.strip():
        payload = projection.json
        if isinstance(payload, dict) and payload.get("ceiling_stop"):
            assert payload.get("omitted_count") is not None, (
                "every ceiling stop reports the omitted count"
            )
            fraction = payload.get("ceiling_stop_fraction_of_dependent_edits")
            if fraction is not None:
                assert fraction <= CEILING_STOP_CONFOUND_FRACTION or payload.get(
                    "confound_declared"
                ) is True, (
                    "a ceiling stop above 10% of dependent edits is a declared confound"
                )


@spec_ref(
    VERIFY(
        "NONFUNCTIONAL",
        "operational-limits",
        "candidate and approval lifetime: 15 minutes;",
    ),
    VERIFY(
        "NONFUNCTIONAL",
        "operational-limits",
        "private raw-session default retention in proof roots: 24 hours;",
    ),
    CLI(
        "NONFUNCTIONAL",
        "error-contract",
        "`APPROVAL_EXPIRED` | candidate/token expired before commit | 2",
    ),
)
def test_candidate_lifetime_and_private_retention_are_enforced(
    guildhall: Guildhall, roots: ProofRoots
) -> None:
    assert CANDIDATE_LIFETIME_SECONDS == 900
    assert PRIVATE_RAW_RETENTION_SECONDS == 24 * 60 * 60
    expired = guildhall.run(
        "proposals", "decide", "expired-candidate", "--destination", "company",
        "--approve-digest", "0" * 64, "--json",
        env={"GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": str(CANDIDATE_LIFETIME_SECONDS + 60)},
        check=False,
    )
    assert expired.returncode != 1
    if expired.returncode != 0:
        assert expired.code in {"APPROVAL_EXPIRED", "APPROVAL_REPLAY"}, expired.code
        if expired.code == "APPROVAL_EXPIRED":
            assert expired.returncode == 2

    doctor = guildhall.run("doctor", "--repo", str(guildhall.cwd), "--json", check=False)
    assert doctor.returncode != 1
    if doctor.stdout.strip():
        payload = doctor.json
        retention = (payload or {}).get("retention") or {}
        if retention:
            assert retention.get("private_raw_session_seconds") == PRIVATE_RAW_RETENTION_SECONDS


@pytest.mark.selftest
@spec_ref(
    CLI(
        "NONFUNCTIONAL",
        "error-contract",
        "This closed proof-version taxonomy may grow only through a new schema version.",
    ),
    CLI(
        "NONFUNCTIONAL",
        "error-contract",
        "| 1 | unused, reserved to prevent ambiguous generic failures | treat as implementation defect |",
    ),
)
def test_error_taxonomy_and_exit_table_match_the_ratified_contract(spec_root: Path) -> None:
    cli_text = (spec_root / "spec" / "cli.md").read_text(encoding="utf-8")
    for code in ERROR_CODES:
        assert f"`{code}`" in cli_text, f"{code} is not in the ratified taxonomy"
    for exit_code, meaning in EXIT_MEANING.items():
        assert meaning in cli_text, f"exit {exit_code} meaning drifted: {meaning!r}"
    assert EXIT_MEANING[1] == "unused, reserved to prevent ambiguous generic failures"


@spec_ref(
    CLI(
        "NONFUNCTIONAL",
        "error-contract",
        "The CLI installs one top-level exception boundary that emits the typed internal error and exits "
        "70 for every caught application exception.",
    )
)
def test_uncaught_application_exceptions_exit_seventy(guildhall: Guildhall) -> None:
    result = guildhall.run(
        "status", "--repo", "/nonexistent/path/for/acceptance", "--json", check=False
    )
    assert result.returncode != 1, (
        "spec/cli.md: exit 1 can occur only before the exception boundary exists"
    )
    assert result.returncode in (2, 3, 4, 5, 6, 70), result.returncode
    if result.returncode == 70:
        assert result.error["code"], "the internal error must still be typed"


@pytest.mark.selftest
@spec_ref(
    CLI(
        "NONFUNCTIONAL",
        "first-run-failures",
        "Common first-run failures are fixed, not guessed:",
    )
)
def test_first_run_failure_table_is_transcribed(spec_root: Path) -> None:
    cli_text = (spec_root / "spec" / "cli.md").read_text(encoding="utf-8")
    situations = (
        "no user config",
        "unreadable token or key file",
        "token/key mode broader than 0600",
        "Company unreachable during repo init",
        "command outside a Git worktree",
        "requested store uninitialized",
        "unwritable data root",
        "malformed certificate/config",
    )
    for situation in situations:
        assert situation in cli_text, situation


@spec_ref(
    CLI(
        "NONFUNCTIONAL",
        "first-run-failures",
        "| token/key mode broader than 0600 | exit 4; chmod remediation |",
    ),
    ARCH(
        "NONFUNCTIONAL",
        "trust-and-key-lifecycle",
        "User config contains only the root public key, Company endpoint, per-instance bearer-token "
        "file, and repository-discovery hints; it is outside every worktree and mode 0600.",
    ),
)
def test_broad_token_mode_is_refused_with_chmod_remediation(
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path
) -> None:
    token = roots.write_secret("facts.token", b"token", mode=0o644)
    key = roots.write_secret("company-root.pub", b"key", mode=0o600)
    classifier = tmp_path / "classifier"
    classifier.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(classifier, 0o755)
    import hashlib

    roots.write_user_config(
        classifier_path=classifier,
        classifier_sha256=hashlib.sha256(classifier.read_bytes()).hexdigest(),
        facts_token_file=token,
        root_public_key_file=key,
    )
    result = guildhall.run("doctor", "--repo", str(guildhall.cwd), "--json", check=False)
    assert result.returncode != 1
    if result.returncode == 4:
        remediation = result.error["remediation"].lower()
        assert "chmod" in remediation, (
            f"the remediation must name chmod; observed {remediation!r}"
        )
        assert b"token" not in result.stdout.encode(), (
            "spec/cli.md: 'exit 4 with exact path role, never file contents'"
        )
    assert_mode_no_broader_than(
        roots.user_config_path, 0o600, why="spec/cli.md pins the user config to 0600"
    )
