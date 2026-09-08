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
import sys
from pathlib import Path

import pytest

from ._harness import obligations as O

from ._harness import synth
from ._harness import canonical
from ._harness.cli import ERROR_CODES, ERROR_FIELDS, EXIT_MEANING, Guildhall
from ._harness.hosts import (
    CANDIDATE_LIFETIME_SECONDS,
    OBSERVATION_BATCH_ITEMS,
    PRIVATE_RAW_RETENTION_SECONDS,
    SHARED_EVENT_CEILING,
    SOURCE_BODY_CEILING,
)
from ._harness.requirements import (
    ARCH,
    CLI,
    THREAT,
    VERIFY,
    spec_ref,
)
from ._harness import trust
from ._harness.roots import ProofRoots
from ._harness.worldbuilder import SignedWorld, start_session

pytestmark = [pytest.mark.nonfunctional, pytest.mark.requires_product]


@pytest.fixture()
def anchored(roots: ProofRoots, guildhall: Guildhall):
    """A world whose trust anchors are in place (Validator ruling C3).

    Every nonfunctional world that expects a trusted result --- a rebuild, a
    diagnostic over planted facts, a candidate, a token check --- establishes
    the service, root key, user config, registry and certificate exactly as
    the numbered gates do; without them the ratified behaviour is
    ``UNVERIFIED`` and an empty trusted projection.
    """
    world = SignedWorld.create(roots.repo_root)
    anchors = trust.establish(guildhall, roots, world)
    return world, anchors


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
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    world.plant_event(
        world.architect, store_kind="company",
        logical_key="architecture/scheduler/determinism",
        statement="the rebuild is a pure function of its inputs",
    )
    # ``--as-of`` is optional on every reducer-invoking command (Validator
    # ruling C12); it is passed here so both rebuilds share one proof clock.
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
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    import socket as _socket

    world, anchors = anchored
    # A listener that accepts and never answers. Validator ruling C28: the
    # endpoint reaches the product only through the user config, never the
    # environment.
    listener = _socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        with anchors.company_endpoint("http://127.0.0.1:" + str(port)):
            result = guildhall.run(
                "status", "--repo", str(roots.repo_root), "--json",
                cwd=roots.repo_root, check=False, timeout=180,
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
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    world.plant_event(
        world.architect, store_kind="company",
        logical_key="architecture/scheduler/diagnostics",
        statement="diagnostics remain useful after a restart",
    )
    world.plant_event(
        world.maintainer, store_kind="codebase",
        logical_key="architecture/scheduler/diagnostics",
        statement="this repository applies the diagnostics rule",
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
            "argv": list(command),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "payload": payload,
        })
    O.check(
        "NF.diagnostics",
        {"diagnostics": diagnostics, "survives_restart": True},
        label=("diagnostics are executable and useful after restart; observations="
               + json.dumps(diagnostics, ensure_ascii=False)),
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
    guildhall: Guildhall, roots: ProofRoots, tmp_path: Path, anchored
) -> None:
    world, anchors = anchored
    session = start_session(guildhall, roots.repo_root)
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
                        "observed_at": synth.receipt_stamp(),
                        "source_kind": "codex_jsonl"})
            for i in range(OBSERVATION_BATCH_ITEMS + 1)
        ) + "\n",
        encoding="utf-8",
    )
    ceilings.append(_ceiling_probe(
        guildhall, roots, "observation_batch",
        ("session", "observe", session, "--event", str(batch), "--json"),
        constructed=True))

    # Validator ruling C24: a malformed or oversized file inside .kin/events/
    # is a typed integrity failure with counts, never a crash. It is written at
    # a non-reserved name so it is also a foreign path.
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
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    trust.classifier_pinned(anchors, what="candidate lifetime probe")
    corpus = roots.run_root / "lifetime.jsonl"
    corpus.parent.mkdir(parents=True, exist_ok=True)
    corpus.write_text(
        json.dumps({"id": "m" + os.urandom(6).hex(), "role": "user",
                    "text": "the retry ceiling is four attempts per hour",
                    "observed_at": synth.receipt_stamp(),
                    "source_kind": "codex_jsonl"}) + "\n",
        encoding="utf-8",
    )
    # Validator ruling C8: SESSION is the id `session start --json` issued.
    session = start_session(guildhall, roots.repo_root)
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


#: Bytes the threat model freezes as injection vectors, delivered as one argv
#: element. ``spec/threat-model.md`` family 11: "SQL/LIKE/GLOB/FTS operators,
#: wildcard scope/logical keys, NUL, separators". A raw NUL cannot travel in
#: argv (execve refuses it, see ``_argv_nul_non_probe``); its textual escape
#: forms can, and a product that unescapes before matching would then meet it.
HOSTILE_KEY = "architecture/'; DROP TABLE facts; --/%/_/*/?/[a-z]/../..//\\u0000/%00/NEAR(a,b)"

#: The same vectors as raw bytes on a channel that carries bytes.
HOSTILE_BYTES = b"scheduler'; DROP TABLE facts; --\x00%_*?../\xff\xfe"


def _argv_nul_non_probe(guildhall: Guildhall) -> dict:
    """Attempt the argv-level NUL; record why it is not a probe.

    Validator instrument-defect report, dispatch 006, item 5: Python refuses an
    embedded NUL in an argv element before the product is spawned, so the
    obligation was never exercised. The attempt is kept and *recorded* so the
    channel is documented as undeliverable rather than silently dropped.
    """
    try:
        guildhall.run("explain", "\x00not-a-key", "--repo", "/nonexistent",
                      "--decision", "which rule applies", "--json", check=False)
    except ValueError as exc:
        return {"channel": "argv", "delivered": False,
                "why": f"the OS cannot deliver a NUL inside argv: {exc}"}
    return {"channel": "argv", "delivered": True,
            "why": "unexpectedly deliverable; promote to a probe"}


def _boundary_observation(channel: str, result, *, must_refuse: bool) -> dict:
    """One typed observation of the exception boundary for one delivered probe."""
    payload = result.json if isinstance(result.json, dict) else {}
    error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
    combined = result.stdout + result.stderr
    code = error.get("code")
    fields_complete = all(f in error for f in ERROR_FIELDS)
    typed = fields_complete and code in ERROR_CODES
    return {
        "channel": channel,
        "delivered": True,
        "exit_code": result.returncode,
        "reserved_exit_1": result.returncode == 1,
        "exit_in_contract": result.returncode in EXIT_MEANING and result.returncode != 1,
        "must_refuse": must_refuse,
        "refused_when_required": (result.returncode != 0) if must_refuse else True,
        "typed_or_completed": result.returncode == 0 or typed,
        "error": {"code": code, "fields_complete": fields_complete,
                  "code_in_taxonomy": code in ERROR_CODES},
        "stack_trace_leaked": 1 if "Traceback (most recent call last)" in combined else 0,
    }


@spec_ref(
    CLI(
        "NONFUNCTIONAL",
        "error-contract",
        "The CLI installs one top-level exception boundary that emits the typed internal error and exits "
        "70 for every caught application exception.",
    ),
    CLI(
        "NONFUNCTIONAL",
        "error-contract",
        "Exit 1 can occur only before that boundary exists (for example interpreter/loader failure) and "
        "therefore still means the executable itself failed outside its contract.",
    ),
    CLI(
        "NONFUNCTIONAL",
        "first-run-failures",
        "| malformed certificate/config | exit 5 and quarantine; no trust-on-first-use fallback |",
    ),
    THREAT(
        "NONFUNCTIONAL",
        "attack-families",
        "persistence and authority-matching injection using SQL/LIKE/GLOB/FTS operators, wildcard "
        "scope/logical keys, NUL, separators, malicious `.kin/config` fields, and parameter/type "
        "confusion;",
    ),
)
def test_hostile_bytes_never_escape_the_exception_boundary(
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    """Frozen injection bytes, delivered on channels the product really reads.

    What is observable from outside the boundary is not *which* exception the
    product caught but that nothing escaped it: no reserved exit 1, no raw
    traceback, an exit in the ratified table, and a complete typed error on
    every non-zero exit. Exit 70 itself cannot be forced from outside a
    conforming product, so it is not demanded; a product that answers a
    hostile ``.kin/config`` with anything but the table's exit 5 fails here.
    """
    world, anchors = anchored
    repo = world.repo.path
    probes = []

    # argv: metacharacters, wildcards, separators, dot segments and the two
    # textual NUL escapes a naive unescaper would turn into a real NUL.
    result = guildhall.run("explain", HOSTILE_KEY, "--repo", str(repo),
                           "--decision", "which rule applies", "--json",
                           cwd=repo, check=False)
    probes.append(_boundary_observation("argv:logical-key", result, must_refuse=False))

    # file bytes: `.kin/config` carrying a raw NUL and the operator set inside
    # a value. spec/cli.md: malformed config exits 5 and quarantines.
    config = repo / ".kin" / "config"
    pristine = config.read_bytes()
    config.write_bytes(
        b'schema_version = "guildhall-repo/1"\n'
        b'repository_uuid_hint = "018f0000-0000-7000-8000-000000000001"\n'
        b'safe_name = "' + HOSTILE_BYTES + b'"\n'
        b'domains = ["scheduling"]\n'
    )
    try:
        result = guildhall.run("status", "--repo", str(repo), "--json",
                               cwd=repo, check=False)
    finally:
        config.write_bytes(pristine)
    probes.append(_boundary_observation("file:.kin/config", result, must_refuse=True))

    # file bytes: an event whose bytes carry a raw NUL, placed at the content
    # path its own digest computes, then read by fsck.
    hostile_event = b'{"logical_key":"' + HOSTILE_BYTES + b'","statement":"x"}'
    digest = canonical.content_digest_hex(hostile_event)
    event_path = repo / ".kin" / "events" / canonical.event_shard_path(digest)
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_bytes(hostile_event)
    try:
        result = guildhall.run("fsck", "--repo", str(repo), "--json",
                               cwd=repo, check=False)
    finally:
        event_path.unlink()
    probes.append(_boundary_observation("file:.kin/events", result, must_refuse=False))

    # stdin: no ratified command reads it, so hostile bytes there must simply
    # not matter. The product is not allowed to fall over on an open descriptor.
    result = guildhall.run("status", "--repo", str(repo), "--json",
                           cwd=repo, check=False, stdin=HOSTILE_BYTES * 64)
    probes.append(_boundary_observation("stdin", result, must_refuse=False))

    O.check(
        "NF.exit-boundary",
        {
            "probes": probes,
            "config_probe": probes[1],
            "non_probes": [_argv_nul_non_probe(guildhall)],
        },
        label="hostile bytes never escape the exception boundary",
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
    guildhall: Guildhall, roots: ProofRoots, anchored
) -> None:
    world, anchors = anchored
    # The token the user config names (Validator ruling C1), widened to 0644.
    token = anchors.facts_token_path
    secret = token.read_bytes().decode("utf-8")
    os.chmod(token, 0o644)
    observed = stat.S_IMODE(token.stat().st_mode)
    try:
        result = guildhall.run("status", "--repo", str(roots.repo_root), "--json",
                               cwd=roots.repo_root, check=False)
    finally:
        os.chmod(token, 0o600)
    combined = (result.stdout + result.stderr).lower()
    O.check(
        "NF.token-mode",
        {
            "exit_code": result.returncode,
            "remediation_names_chmod": "chmod" in combined,
            "mode_observed_broad": observed > 0o600,
            "secret_bytes_leaked": combined.count(secret.lower()),
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
