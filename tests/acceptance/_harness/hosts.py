"""Real host lifecycle helpers for V-9.

``spec/verification.md`` V-9 requires real host executables in isolated homes and
explicitly refuses simulation:

    Use isolated temporary ``HOME``, config, and repository roots. Run the actual
    setup and hook executables for Codex and Claude.

    Inspect actual host config and executable invocation records; a mocked host
    branch is not accepted evidence.

``spec/product.md`` "Terminal falsifiers" lists "a host adapter is mocked rather
than executed" as a terminal failure, so the suite must be able to *prove* the
host binary ran. :func:`host_availability` therefore resolves real executables
and :func:`invocation_witness` records evidence that a real process executed,
which the tests assert on.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import planters
from .requirements import HarnessInvalid, ProductFailure

HOSTS: tuple[str, ...] = ("codex", "claude")

#: Native host events the adapter must accept, ``spec/architecture.md`` section 9
#: and ``spec/verification.md`` V-9.
HOST_EVENTS: tuple[str, ...] = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PreCompact",
    "Stop",
    "SessionEnd",
)

#: Start states measured separately, ``spec/verification.md`` V-9.
START_STATES: tuple[str, ...] = ("warm", "cold", "invalid-cache", "full-fsck-required")

#: Frozen budgets, ``spec/verification.md`` V-9 and ``spec/architecture.md`` §9.
SESSION_START_P95_SECONDS = 2.0
COMPANY_CONNECT_BUDGET_SECONDS = 0.250
FULL_FSCK_CEILING_SECONDS = 120.0
INVOCATIONS_PER_HOST_STATE = 200
SOAK_SESSIONS = 20
SOAK_WARM_PATH_MINIMUM = 0.90
SOAK_FULL_FSCK_MAXIMUM = 0.05

#: Approval-fatigue budget, ``spec/product.md`` P-9.
PROMPTS_PER_SLIDING_HOUR = 4
MAX_CONSECUTIVE_PROMPTS = 3
OPERATOR_EXERCISE_ITEMS = 20
OPERATOR_ACCURACY_MINIMUM = 0.95
OPERATOR_MEDIAN_DECISION_SECONDS = 30.0

#: Corpus-growth adequacy workload, ``spec/product.md`` P-9.
MAINTENANCE_OBSERVATIONS = 100
MAINTENANCE_DURABLE_FACTS = 20
MAINTENANCE_WINDOWS = 5
MAINTENANCE_SLOTS_MINIMUM = 18
MAINTENANCE_ADMITTED_MINIMUM = 17

#: Projection and intake ceilings, ``spec/verification.md`` "Operational limits".
SOURCE_BODY_CEILING = 1 * 1024 * 1024
OBSERVATION_BATCH_ITEMS = 10_000
OBSERVATION_BATCH_BYTES = 256 * 1024 * 1024
SHARED_EVENT_CEILING = 64 * 1024
KIN_INTAKE_EVENTS = 10_000
KIN_INTAKE_BYTES = 128 * 1024 * 1024
PROJECTION_FACTS = 32
PROJECTION_BYTES = 128 * 1024
CANDIDATE_LIFETIME_SECONDS = 15 * 60
PRIVATE_RAW_RETENTION_SECONDS = 24 * 60 * 60
CEILING_STOP_CONFOUND_FRACTION = 0.10


@dataclass(frozen=True)
class HostBinary:
    name: str
    path: Path
    version: str


def host_availability(name: str, *, env: dict[str, str] | None = None) -> HostBinary | None:
    """Resolve a real host executable, honouring an explicit override.

    ``KINBASE_HOST_CODEX`` / ``KINBASE_HOST_CLAUDE`` let the Validator point
    at the pinned host build. ``spec/verification.md`` V-9: "Pin and report exact
    Codex/Claude versions and native envelope fixtures."
    """
    if name not in HOSTS:
        raise HarnessInvalid(f"unknown host {name!r}")
    override = os.environ.get(f"KINBASE_HOST_{name.upper()}")
    resolved = Path(override) if override else None
    if resolved is None:
        found = shutil.which(name, path=env.get("PATH") if env is not None else None)
        resolved = Path(found) if found else None
    if resolved is None or not resolved.exists():
        return None
    try:
        # A version probe needs PATH and nothing else. Forwarding the caller's whole
        # environment made the name set opaque to the control-policy check, which
        # exists so a product cannot branch on an unlisted environment variable
        # instead of doing the work. Naming the one variable literally keeps that
        # check able to see what reaches the system under test.
        proc = subprocess.run(
            [str(resolved), "--version"], capture_output=True, text=True, timeout=120,
            env={"PATH": (env or {}).get("PATH", os.environ.get("PATH", ""))},
        )
        proc.check_returncode()
        version = (proc.stdout or proc.stderr).strip().splitlines()[0][:200]
    except (OSError, subprocess.SubprocessError, IndexError):
        version = "unknown"
    return HostBinary(name=name, path=resolved, version=version)


# --------------------------------------------------------------------------
# Native hook envelopes
# --------------------------------------------------------------------------


def codex_envelope(event: str, *, session_id: str, cwd: str, **extra: Any) -> dict[str, Any]:
    """A Codex-shaped native hook envelope."""
    payload: dict[str, Any] = {
        "hook_event_name": event,
        "session_id": session_id,
        "cwd": cwd,
        "transcript_path": f"{cwd}/.codex/sessions/{session_id}.jsonl",
        "host": "codex",
    }
    payload.update(extra)
    return payload


def claude_envelope(event: str, *, session_id: str, cwd: str, **extra: Any) -> dict[str, Any]:
    """A Claude-shaped native hook envelope.

    The two shapes differ deliberately: ``spec/product.md`` P-9 allows "Host
    framing may differ; canonical facts, decisions, and receipts may not", and
    ``spec/verification.md`` V-9 requires "For matched conversations, canonical
    facts/projections/receipts match across hosts."
    """
    payload: dict[str, Any] = {
        "hook_event_name": event,
        "session_id": session_id,
        "cwd": cwd,
        "transcript_path": f"{cwd}/.claude/projects/{session_id}.jsonl",
        "permission_mode": "default",
        "host": "claude",
    }
    payload.update(extra)
    return payload


ENVELOPE_BUILDERS = {"codex": codex_envelope, "claude": claude_envelope}


def envelope_for(host: str, event: str, *, session_id: str, cwd: str, **extra: Any) -> dict[str, Any]:
    if host not in ENVELOPE_BUILDERS:
        raise HarnessInvalid(f"unknown host {host!r}")
    if event not in HOST_EVENTS:
        raise HarnessInvalid(f"unknown host event {event!r}")
    envelope = ENVELOPE_BUILDERS[host](event, session_id=session_id, cwd=cwd, **extra)
    return planters.mutate("host.envelope", envelope, host=host, event=event)


# --------------------------------------------------------------------------
# Execution witnesses
# --------------------------------------------------------------------------


@dataclass
class InvocationWitness:
    """Evidence that a real host executable ran, not a simulated branch."""

    host: str
    executable: Path
    version: str
    argv_records: tuple[str, ...]
    config_files: tuple[Path, ...]

    def assert_not_mocked(self) -> None:
        if not self.executable.exists():
            raise ProductFailure(
                "spec/product.md 'Terminal falsifiers': 'a host adapter is mocked "
                f"rather than executed'; {self.executable} does not exist"
            )
        if not self.argv_records:
            raise ProductFailure(
                "no host invocation record captured; spec/verification.md V-9 "
                "requires inspecting 'actual host config and executable "
                "invocation records; a mocked host branch is not accepted evidence'"
            )


def install_invocation_recorder(bin_dir: Path, name: str, real: Path) -> Path:
    """Wrap a real host binary with a recorder that still executes it.

    The wrapper appends the exact argv to a log and then ``exec``s the real
    binary, so evidence of a genuine execution exists without replacing it. A
    stub that only logs would itself be a mock and is deliberately not used.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = bin_dir / f"{name}.invocations"
    wrapper = bin_dir / name
    wrapper.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> {log}\n'
        f'exec "{real}" "$@"\n',
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o755)
    return wrapper


def read_invocations(log: Path) -> tuple[str, ...]:
    if not log.exists():
        return ()
    return tuple(
        line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()
    )


# --------------------------------------------------------------------------
# Payload discipline
# --------------------------------------------------------------------------

#: ``spec/architecture.md`` section 9: the tool-result envelope "has no
#: command/tool/policy/system fields".
FORBIDDEN_ENVELOPE_FIELDS: tuple[str, ...] = (
    "command",
    "tool",
    "tools",
    "policy",
    "system",
    "permissions",
    "destination",
    "approval",
)

#: ``spec/architecture.md`` section 9 label required on every decoded body.
UNTRUSTED_LABEL = "UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS"


def assert_projection_envelope(payload: Mapping[str, Any]) -> None:
    """Validate a host projection envelope against the frozen shape."""
    present = [f for f in FORBIDDEN_ENVELOPE_FIELDS if f in payload]
    if present:
        raise ProductFailure(
            "spec/architecture.md section 9: the tool-result envelope 'has no "
            f"command/tool/policy/system fields'; observed {present}"
        )
    bodies = payload.get("facts") or payload.get("evidence") or []
    for body in bodies:
        if not isinstance(body, Mapping):
            continue
        label = body.get("label") or body.get("trust_label")
        if label != UNTRUSTED_LABEL:
            raise ProductFailure(
                "every decoded body must be labelled "
                f"{UNTRUSTED_LABEL!r}; observed {label!r}"
            )


def decode_length_prefixed(payload: bytes) -> list[dict[str, Any]]:
    """Decode complete decimal-length/newline canonical envelopes; reject tails."""
    from . import canonical

    out = []
    offset = 0
    try:
        while offset < len(payload):
            newline = payload.index(b"\n", offset)
            prefix = payload[offset:newline]
            if not prefix.isdigit():
                raise ValueError("non-decimal length")
            length = int(prefix)
            start = newline + 1
            chunk = payload[start:start + length]
            if length == 0 or len(chunk) != length:
                raise ValueError("truncated or empty envelope")
            document = json.loads(chunk)
            if not isinstance(document, dict) or canonical.jcs(document) != chunk:
                raise ValueError("envelope is not a canonical JSON object")
            out.append(document)
            offset = start + length
        if not out:
            raise ValueError("no envelope")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProductFailure("invalid length-prefixed hook envelope: " + str(exc)) from exc
    return out


def decode_dispatch_json(stdout: str) -> list[dict[str, Any]]:
    """R-12: one host response document carrying a base64 envelope field."""
    import base64
    import binascii

    try:
        response = json.loads(stdout)
        if not isinstance(response, dict) or not isinstance(response.get("envelope"), str):
            raise ValueError("missing base64 envelope field")
        raw = base64.b64decode(response["envelope"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProductFailure("R-12 hooks dispatch --json: " + str(exc)) from exc
    return decode_length_prefixed(raw)


# --------------------------------------------------------------------------
# Latency measurement
# --------------------------------------------------------------------------


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile; deterministic and dependency free."""
    if not values:
        raise HarnessInvalid("percentile of an empty sample")
    if not 0 < q <= 1:
        raise HarnessInvalid("percentile q must be in (0, 1]")
    ordered = sorted(values)
    import math

    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


@dataclass
class LatencySample:
    host: str
    state: str
    durations: tuple[float, ...]

    @property
    def p95(self) -> float:
        return percentile(self.durations, 0.95)

    def within_budget(self, budget: float = SESSION_START_P95_SECONDS) -> bool:
        return self.p95 < budget


def apply_planned_diff(original: str, patch: str) -> str:
    """Apply a displayed unified diff in memory for the C9 installation oracle.

    This never writes a host file or executes anything from a plan. A malformed
    diff is a product observation; it cannot license a changed file.
    """
    import re

    source = original.splitlines(keepends=True)
    lines = patch.splitlines(keepends=True)
    output: list[str] = []
    cursor = 0
    index = 0
    hunks = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
        if not match:
            index += 1
            continue
        old_start, old_size, _, new_size = match.groups()
        old_size = int(old_size) if old_size is not None else 1
        new_size = int(new_size) if new_size is not None else 1
        start = int(old_start) - (1 if old_size else 0)
        if start < cursor or start > len(source):
            raise ValueError("plan diff has an invalid source range")
        output.extend(source[cursor:start])
        cursor = start
        old_count = new_count = 0
        hunks += 1
        index += 1
        while index < len(lines) and (old_count < old_size or new_count < new_size):
            entry = lines[index]
            if not entry or entry[0] not in " +-":
                raise ValueError("plan diff has a malformed hunk")
            mark, text = entry[0], entry[1:]
            if index + 1 < len(lines) and lines[index + 1].startswith("\\ No newline"):
                text = text.rstrip("\r\n")
                index += 1
            if mark in " -":
                if cursor >= len(source) or source[cursor] != text:
                    raise ValueError("plan diff does not match the pre-install file")
                cursor += 1
                old_count += 1
            if mark in " +":
                output.append(text)
                new_count += 1
            index += 1
        if (old_count, new_count) != (old_size, new_size):
            raise ValueError("plan diff hunk size mismatch")
    if not hunks:
        raise ValueError("plan has no displayed diff hunks")
    output.extend(source[cursor:])
    return "".join(output)


def installed_files_match_plan(plan: dict, before: dict[str, str],
                               after: dict[str, str]) -> bool:
    """Check actual content against the displayed plan, beyond claimed digests."""
    files = plan.get("files")
    if not isinstance(files, list) or not files:
        return False
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            return False
        name = entry["path"]
        if Path(name).is_absolute() or ".." in Path(name).parts:
            return False
        # Some renderers show the complete new content instead of diff hunks.
        expected = entry.get("content", entry.get("new_content"))
        if not isinstance(expected, str):
            patch = entry.get("diff", entry.get("patch"))
            if not isinstance(patch, str):
                return False
            try:
                expected = apply_planned_diff(before.get(name, ""), patch)
            except ValueError:
                return False
        if after.get(name) != expected:
            return False
    return True
