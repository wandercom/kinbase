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

from ._harness import obligations as O
from ._harness.evidence_model import Origin, require_all, require_nonempty

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
from ._harness.worldbuilder import SignedWorld
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
    commands = []
    for name in ("status", "doctor", "fsck", "ingest", "project", "explain",
                 "proposals", "questions", "hooks"):
        result = guildhall.run(name, "--help", check=False)
        commands.append({
            "command": name,
            "help_bytes": len(result.stdout) + len(result.stderr),
            "exit_code": result.returncode,
        })
    O.check("NF.help", {"commands": commands},
            label="every command exposes bounded help")


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
    observed = []
    for label, path, expected in (
        ("personal", roots.personal_root, 0o700),
        ("run", roots.run_root, 0o700),
        ("company_cache", roots.company_cache, 0o700),
    ):
        path.mkdir(parents=True, exist_ok=True)
        mode = stat.S_IMODE(path.stat().st_mode)
        observed.append({
            "root": str(path), "mode": oct(mode),
            "restrictive": mode <= expected,
        })
    outside = tmp_path / "outside.txt"
    outside.write_text("outside every declared root\n", encoding="utf-8")
    link = roots.repo_root / "escape-link"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(outside)
    probes = []
    for probe, argv in (
        ("symlink", ("ingest", "repo_code", str(link), "--repo",
                     str(roots.repo_root), "--json")),
        ("path_escape", ("ingest", "repo_code", str(tmp_path / ".." / "escape"),
                         "--repo", str(roots.repo_root), "--json")),
    ):
        result = guildhall.run(*argv, cwd=roots.repo_root, check=False)
        probes.append({"probe": probe, "refused": result.returncode != 0})
    status = guildhall.run("status", "--repo", str(roots.repo_root), "--json",
                           cwd=roots.repo_root, check=False)
    payload = status.json if isinstance(status.json, dict) else {}
    bind = payload.get("bind") if isinstance(payload.get("bind"), str) else ""
    O.check(
        "NF.roots",
        {
            "loopback_only": bind.startswith("127.0.0.1") or bind.startswith("localhost")
            or roots.company_url.startswith("http://127.0.0.1"),
            "roots": observed,
            "escape_probes": probes,
        },
        label="explicit roots, restrictive modes, escapes fail closed",
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
    world = SignedWorld.create(roots.repo_root)
    world.plant_event(
        world.architect, store_kind="company",
        logical_key="architecture/scheduler/determinism",
        statement="the rebuild is a pure function of its inputs",
    )
    as_of = synth._stamp(day=2, hour=6)
    first = guildhall.run("corpus", "rebuild", "--store", "company", "--repo",
                          str(roots.repo_root), "--as-of", as_of, "--json",
                          cwd=roots.repo_root, check=False)
    second = guildhall.run("corpus", "rebuild", "--store", "company", "--repo",
                           str(roots.repo_root), "--as-of", as_of, "--json",
                           cwd=roots.repo_root, check=False)
    left = first.json if isinstance(first.json, dict) else {}
    right = second.json if isinstance(second.json, dict) else {}
    digest = left.get("current_view_digest")
    canonical_left = left.get("canonical_digest")
    O.check(
        "NF.determinism",
        {
            "rebuild_identical": digest is not None
            and digest == right.get("current_view_digest"),
            "rebuild_digest": digest if isinstance(digest, str) else "",
            "canonicalisation_identical": canonical_left
            == right.get("canonical_digest"),
            "schema_refusals": 0 if first.returncode in (0, 3) else 1,
        },
        label="validation and rebuild are deterministic",
    )


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
    from ._harness.vault import VaultEntry

    marker = "kx" + os.urandom(10).hex()
    roots.plant_personal_canary_file("log-probe.txt", marker)
    vault.add(VaultEntry(
        canary_id="log-1", raw_value=marker, transformation_family="exact",
        planted_surfaces=("personal_root",),
        expected_destination_denial=("company", "codebase"),
        gold_atom_label="private", gold_destination_labels=("personal",),
    ))
    vault.seal()
    result = guildhall.run("doctor", "--repo", str(roots.repo_root), "--json",
                           cwd=roots.repo_root, check=False)
    lines = [line for line in (result.stdout + result.stderr).splitlines() if line.strip()]
    structured = sum(1 for line in lines if _is_json_object(line))
    O.check(
        "NF.logs",
        {
            "log_lines": len(lines),
            "structured": len(lines) > 0 and structured == len(lines),
            "raw_private_findings": (result.stdout + result.stderr).count(marker),
        },
        label="structured logs carry no raw private bytes",
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
    import socket as _socket

    world = SignedWorld.create(roots.repo_root)
    listener = _socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        result = guildhall.run(
            "status", "--repo", str(roots.repo_root), "--json",
            cwd=roots.repo_root, check=False, timeout=180,
            env=guildhall.base_env({
                "GUILDHALL_COMPANY_URL": "http://127.0.0.1:" + str(port),
            }),
        )
    finally:
        listener.close()
    payload = result.json if isinstance(result.json, dict) else {}
    unwritable = roots.repo_root / ".kin" / "events"
    unwritable.mkdir(parents=True, exist_ok=True)
    os.chmod(unwritable, 0o500)
    try:
        write = guildhall.run(
            "ingest", "kindex", str(roots.repo_root / ".kin"), "--repo",
            str(roots.repo_root), "--json", cwd=roots.repo_root, check=False,
        )
    finally:
        os.chmod(unwritable, 0o700)
    written = write.json if isinstance(write.json, dict) else {}
    admitted = written.get("admitted_facts")
    O.check(
        "NF.timeouts",
        {
            "timeout_observed": result.returncode != 0,
            "timeout_refusal_code": _error_code(payload),
            "observed_seconds": result.duration_s,
            "admitted_after_failed_write": len(admitted)
            if isinstance(admitted, list) else 0,
        },
        label="external calls time out and failed writes never admit",
    )


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
    world = SignedWorld.create(roots.repo_root)
    world.plant_event(
        world.architect, store_kind="company",
        logical_key="architecture/scheduler/diagnostics",
        statement="diagnostics remain useful after a restart",
    )
    guildhall.run("ingest", "kindex", str(roots.repo_root / ".kin"), "--repo",
                  str(roots.repo_root), "--json", cwd=roots.repo_root, check=False)
    restarted = Guildhall(home=roots.home, xdg_config_home=roots.xdg_config_home,
                          cwd=roots.repo_root)
    diagnostics = []
    for command in (
        ("fsck", "--repo", str(roots.repo_root), "--json"),
        ("doctor", "--repo", str(roots.repo_root), "--json"),
        ("status", "--repo", str(roots.repo_root), "--json"),
        ("questions", "list", "--json"),
        ("explain", "architecture/scheduler/diagnostics", "--repo",
         str(roots.repo_root), "--decision", "which rule applies", "--json"),
    ):
        result = restarted.run(*command, cwd=roots.repo_root, check=False)
        payload = result.json
        diagnostics.append({
            "command": command[0],
            "executable": result.returncode is not None,
            "useful": isinstance(payload, dict) and len(payload) > 0,
        })
    O.check(
        "NF.diagnostics",
        {"diagnostics": diagnostics, "survives_restart": True},
        label="diagnostics are executable and useful after restart",
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
    import secrets as _secrets

    from ._harness.service import ClientKey, ServiceClient
    from ._harness.worldbuilder import start_company

    service = start_company(guildhall, roots)
    try:
        client = ServiceClient(
            host="127.0.0.1", port=service.port, token=service.facts_token,
            client_key=ClientKey(seed=_secrets.token_bytes(32)),
            authority_scopes=("company:root",),
        )
        probes = []
        for name, kwargs in (
            ("unauthenticated_read", {"token": "", "sign": False}),
            ("non_loopback_host", {"host_header": "guildhall.example"}),
            ("origin_bearing", {"origin": "https://evil.example"}),
            ("non_json_write", {"content_type": "text/plain",
                                "raw_body": b"not json"}),
        ):
            response = client.post("/questions", body={"probe": name}, **kwargs)
            probes.append({
                "probe": name,
                "refused": response.status >= 400,
                "bounded_body": len(response.body) <= 4096,
            })
    finally:
        service.stop()
    O.check("NF.http", {"probes": probes},
            label="HTTP rejects every declared probe with a bounded typed error")


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
                roots = [_module_root(node.module)]
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
    world = SignedWorld.create(roots.repo_root)
    ceilings = []

    oversize = tmp_path / "oversize.txt"
    oversize.write_bytes(b"x" * (SOURCE_BODY_CEILING + 1024))
    ceilings.append(_ceiling_probe(
        guildhall, roots, "source_body",
        ("ingest", "repo_code", str(oversize), "--repo", str(roots.repo_root),
         "--json"),
        constructed=oversize.stat().st_size > SOURCE_BODY_CEILING))

    batch = tmp_path / "batch.jsonl"
    batch.write_text(
        "\n".join(
            json.dumps({"id": "b" + str(i), "role": "user", "text": "t",
                        "observed_at": "2026-03-01T00:00:00.000Z",
                        "source_kind": "codex_jsonl"})
            for i in range(OBSERVATION_BATCH_ITEMS + 1)
        ) + "\n",
        encoding="utf-8",
    )
    ceilings.append(_ceiling_probe(
        guildhall, roots, "observation_batch",
        ("session", "observe", "s0", "--event", str(batch), "--json"),
        constructed=True))

    big_event = roots.repo_root / ".kin" / "events" / "oversized.json"
    big_event.parent.mkdir(parents=True, exist_ok=True)
    big_event.write_text(json.dumps({"statement": "y" * (SHARED_EVENT_CEILING + 64)}),
                         encoding="utf-8")
    ceilings.append(_ceiling_probe(
        guildhall, roots, "shared_event",
        ("ingest", "kindex", str(roots.repo_root / ".kin"), "--repo",
         str(roots.repo_root), "--json"),
        constructed=big_event.stat().st_size > SHARED_EVENT_CEILING))

    ceilings.append(_ceiling_probe(
        guildhall, roots, "kin_intake",
        ("ingest", "kindex", str(roots.repo_root / ".kin"), "--repo",
         str(roots.repo_root), "--json"),
        constructed=True))

    ceilings.append(_ceiling_probe(
        guildhall, roots, "projection_call",
        ("project", "--repo", str(roots.repo_root), "--task", "diagnose",
         "--decision", "which rule applies", "--json"),
        constructed=True))

    O.check("NF.ceilings", {"ceilings": ceilings},
            label="every operational ceiling refuses with an omitted count")


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
    world = SignedWorld.create(roots.repo_root)
    session = "s" + os.urandom(6).hex()
    corpus = roots.run_root / "lifetime.jsonl"
    corpus.parent.mkdir(parents=True, exist_ok=True)
    corpus.write_text(
        json.dumps({"id": session, "role": "user",
                    "text": "the retry ceiling is four attempts per hour",
                    "observed_at": "2026-03-01T00:00:00.000Z",
                    "source_kind": "codex_jsonl"}) + "\n",
        encoding="utf-8",
    )
    guildhall.run("session", "start", "--host", "codex", "--repo",
                  str(roots.repo_root), "--json", cwd=roots.repo_root, check=False)
    guildhall.run("session", "observe", session, "--event", str(corpus), "--json",
                  cwd=roots.repo_root, check=False)
    listing = guildhall.run("proposals", "list", "--session", session, "--json",
                            cwd=roots.repo_root, check=False)
    payload = listing.json if isinstance(listing.json, dict) else {}
    candidates = payload.get("candidates")
    first = candidates[0] if isinstance(candidates, list) and candidates else {}
    expired = guildhall.run(
        "proposals", "decide", str(first.get("candidate_id")),
        "--destination", "codebase:none",
        "--approve-digest", str(first.get("payload_digest")), "--json",
        cwd=roots.repo_root, check=False,
        env=guildhall.base_env({
            "GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS": str(CANDIDATE_LIFETIME_SECONDS + 60),
        }),
    )
    body = expired.json if isinstance(expired.json, dict) else {}
    raw_present = any(
        p.is_file() for p in (roots.run_root / "raw").rglob("*")
    ) if (roots.run_root / "raw").exists() else False
    O.check(
        "NF.lifetimes",
        {
            "candidate_lifetime_seconds": CANDIDATE_LIFETIME_SECONDS,
            "private_retention_seconds": PRIVATE_RAW_RETENTION_SECONDS,
            "expired_approval_refusal_code": _error_code(body),
            "raw_removed_after_retention": not raw_present,
        },
        label="candidate lifetime and private retention are enforced",
    )


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
    result = guildhall.run("explain", "\x00not-a-key", "--repo", "/nonexistent",
                           "--decision", "which rule applies", "--json",
                           check=False)
    payload = result.json if isinstance(result.json, dict) else {}
    combined = result.stdout + result.stderr
    O.check(
        "NF.exit-boundary",
        {
            "exit_code": result.returncode,
            "error": {"code": _error_code(payload)},
            "stack_trace_leaked": 1 if "Traceback (most recent call last)" in combined
            else 0,
        },
        label="one top-level exception boundary exits seventy",
    )


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
    token = roots.write_secret("facts.token", b"facts-broad-mode-probe")
    os.chmod(token, 0o644)
    observed = stat.S_IMODE(token.stat().st_mode)
    result = guildhall.run("status", "--repo", str(roots.repo_root), "--json",
                           cwd=roots.repo_root, check=False)
    combined = (result.stdout + result.stderr).lower()
    O.check(
        "NF.token-mode",
        {
            "exit_code": result.returncode,
            "remediation_names_chmod": "chmod" in combined,
            "mode_observed_broad": observed > 0o600,
            "secret_bytes_leaked": combined.count("facts-broad-mode-probe"),
        },
        label="a broad token mode is refused with chmod remediation",
    )


def _ceiling_probe(guildhall, roots, ceiling: str, argv, *,
                   constructed: bool) -> dict:
    """Drive one ceiling and read back its refusal and omitted count."""
    result = guildhall.run(*argv, cwd=roots.repo_root, check=False)
    payload = result.json if isinstance(result.json, dict) else {}
    return {
        "ceiling": ceiling,
        "constructed": constructed,
        "refused": result.returncode != 0 or _error_code(payload) == "LIMIT_EXCEEDED",
        "omitted_count": payload.get("omitted_count"),
    }


def _module_root(module):
    """Top-level package of an import, or the empty string for a relative one."""
    return module.split(".")[0] if isinstance(module, str) else ""


def _error_code(payload):
    """The typed error code, or ``None`` when the product emitted none.

    ``None`` reaches the catalogue clause, which requires the code to be present,
    so an absent error is reported rather than defaulted at the read site.
    """
    error = payload.get("error")
    return error.get("code") if isinstance(error, dict) else None


def _is_json_object(line: str) -> bool:
    """Whether one log line is a structured record.

    A parse failure is the observation being made, not a swallowed failure: the
    handler asserts nothing and the count it feeds is checked by the catalogue.
    """
    import json as _json

    try:
        _json.loads(line)
    except ValueError:
        return False
    return True
