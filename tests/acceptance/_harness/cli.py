"""Black-box driver for the ratified Guildhall command contract.

This module is the *only* way the acceptance suite reaches the product. It
never imports product code, never inspects product source, and knows nothing
about internal module layout. It speaks exactly the surface frozen in
``spec/cli.md``:

* commands are spelled as ``spec/cli.md`` spells them;
* ``--json`` output is canonical JSON (``spec/cli.md``: "Commands emit canonical
  JSON under ``--json``");
* errors are objects with ``code``, ``message``, ``remediation``, ``retryable``
  and ``evidence_id`` (``spec/cli.md`` "Error contract");
* exit codes carry the frozen meanings in the ``spec/cli.md`` exit table, with
  exit 1 explicitly reserved: "unused, reserved to prevent ambiguous generic
  failures".

Resolution order for the entry point:

1. ``GUILDHALL_BIN`` (absolute path or argv prefix, shell-split);
2. ``guildhall`` on ``PATH``;
3. ``python -m guildhall`` when that module is importable in the run
   interpreter.

If none resolves, the suite reports a *product* condition -- the combined
snapshot has no ratified entry point -- not an instrument defect.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .requirements import HarnessInvalid, ProductFailure

#: ``spec/cli.md`` "Error contract" exit table, verbatim meanings.
EXIT_OK = 0
EXIT_RESERVED_AMBIGUOUS = 1
EXIT_HUMAN_ACTION_REQUIRED = 2
EXIT_DEGRADED_SAFE = 3
EXIT_POLICY_REFUSAL = 4
EXIT_INTEGRITY_PRIVACY_FAILURE = 5
EXIT_DEPENDENCY_UNAVAILABLE = 6
EXIT_INTERNAL = 70

EXIT_MEANING: dict[int, str] = {
    0: "requested operation completed",
    1: "unused, reserved to prevent ambiguous generic failures",
    2: "named human/user action is required, with no unsafe state change",
    3: "degraded but safe; affected facts withheld",
    4: "policy, capability, or authority refusal",
    5: "integrity/privacy product failure",
    6: "declared dependency unavailable",
    70: "internal or acceptance-instrument failure",
}

#: Closed error-code taxonomy from the ``spec/cli.md`` error table. The suite
#: asserts against these names rather than message prose.
ERROR_CODES: frozenset[str] = frozenset(
    {
        "COMPANY_UNREACHABLE",
        "CACHE_EXPIRED",
        "REVOCATION_STALE",
        "REPO_UNCERTIFIED",
        "FOREIGN_REPO_EVENTS",
        "SIGNATURE_INVALID",
        "DIGEST_MISMATCH",
        "DIGEST_ALGORITHM_UNSUPPORTED",
        "MANIFEST_INCOMPLETE",
        "MANIFEST_HEAD_REGRESSION",
        "LIMIT_EXCEEDED",
        "APPROVAL_EXPIRED",
        "APPROVAL_REPLAY",
        "AUTHORITY_WRONG_SCOPE",
        "AUTHORITY_SCOPE_DENIED",
        "UNKNOWN_OWNER_UNRESOLVED",
        "PERSONAL_TAINT_BLOCKED",
        "HOOK_APPROVAL_REQUIRED",
        "UNSUPPORTED_HOST_VERSION",
        "UNSUPPORTED_KINDEX_VERSION",
        "PROCESSOR_UNAUTHORIZED",
        "MODEL_FINGERPRINT_CHANGED",
        "ORACLE_LEAKAGE",
        "SCORER_UNCALIBRATED",
        "RUN_CENSUS_MISSING",
        "CONFIG_INVARIANT",
        "RUN_INTEGRITY_FAILED",
    }
)

#: ``spec/cli.md`` error-code -> frozen exit expectation. ``None`` marks a code
#: whose table row lists more than one permitted exit; those rows are asserted
#: against the explicit tuple instead.
ERROR_CODE_EXIT: dict[str, tuple[int, ...]] = {
    "COMPANY_UNREACHABLE": (6, 3),
    "CACHE_EXPIRED": (3,),
    "REVOCATION_STALE": (3,),
    "REPO_UNCERTIFIED": (2,),
    "FOREIGN_REPO_EVENTS": (4,),
    "SIGNATURE_INVALID": (5,),
    "DIGEST_MISMATCH": (5,),
    "DIGEST_ALGORITHM_UNSUPPORTED": (3,),
    "MANIFEST_INCOMPLETE": (5, 3),
    "MANIFEST_HEAD_REGRESSION": (4,),
    "LIMIT_EXCEEDED": (4,),
    "APPROVAL_EXPIRED": (2,),
    "APPROVAL_REPLAY": (4,),
    "AUTHORITY_WRONG_SCOPE": (4,),
    "AUTHORITY_SCOPE_DENIED": (4,),
    "UNKNOWN_OWNER_UNRESOLVED": (3,),
    "PERSONAL_TAINT_BLOCKED": (5,),
    "HOOK_APPROVAL_REQUIRED": (2,),
    "UNSUPPORTED_HOST_VERSION": (3,),
    "UNSUPPORTED_KINDEX_VERSION": (3,),
    "PROCESSOR_UNAUTHORIZED": (5,),
    "MODEL_FINGERPRINT_CHANGED": (70,),
    "ORACLE_LEAKAGE": (70,),
    "SCORER_UNCALIBRATED": (70,),
    "RUN_CENSUS_MISSING": (70,),
    "CONFIG_INVARIANT": (4,),
    "RUN_INTEGRITY_FAILED": (70,),
}

ERROR_FIELDS: tuple[str, ...] = (
    "code",
    "message",
    "remediation",
    "retryable",
    "evidence_id",
)


class ProductEntryPointMissing(ProductFailure):
    """No ratified ``guildhall`` entry point exists in the combined snapshot."""


@dataclass
class Result:
    """One black-box command execution."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    cwd: str
    env_overrides: Mapping[str, str] = field(default_factory=dict)

    # -- payload access ---------------------------------------------------

    @property
    def json(self) -> Any:
        """Parse ``--json`` output. A non-JSON body under ``--json`` is a defect."""
        text = self.stdout.strip()
        if not text:
            raise ProductFailure(
                f"empty stdout for {' '.join(self.argv)} (exit {self.returncode});"
                f" stderr={self.stderr[:2000]!r}"
            )
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # A typed error may be emitted on stderr instead.
            try:
                return json.loads(self.stderr.strip())
            except json.JSONDecodeError as exc:
                raise ProductFailure(
                    "spec/cli.md requires canonical JSON under --json; got "
                    f"{text[:2000]!r} for {' '.join(self.argv)}"
                ) from exc

    @property
    def error(self) -> dict[str, Any]:
        """Return the typed error object, asserting the five-field contract."""
        payload = self.json
        if isinstance(payload, dict) and "error" in payload:
            payload = payload["error"]
        if not isinstance(payload, dict):
            raise ProductFailure(
                f"expected a typed error object, got {payload!r}"
            )
        missing = [f for f in ERROR_FIELDS if f not in payload]
        if missing:
            raise ProductFailure(
                "spec/cli.md 'Error contract': errors are JSON objects with "
                f"code, message, remediation, retryable and evidence_id; missing {missing}"
            )
        code = payload["code"]
        if code not in ERROR_CODES:
            raise ProductFailure(
                "spec/cli.md declares a closed proof-version error taxonomy; "
                f"{code!r} is not in it"
            )
        return payload

    @property
    def code(self) -> str:
        return str(self.error["code"])

    # -- assertions -------------------------------------------------------

    def ok(self) -> "Result":
        if self.returncode != EXIT_OK:
            raise ProductFailure(
                f"expected exit 0 from {' '.join(self.argv)}, got "
                f"{self.returncode} ({EXIT_MEANING.get(self.returncode, 'unmapped')})\n"
                f"stdout={self.stdout[:4000]}\nstderr={self.stderr[:4000]}"
            )
        return self

    def refused(self, code: str, *, exits: Sequence[int] | None = None) -> "Result":
        """Assert a typed refusal with the frozen code and a permitted exit."""
        if self.returncode == EXIT_OK:
            raise ProductFailure(
                f"expected typed refusal {code} from {' '.join(self.argv)}, "
                f"but the command succeeded:\n{self.stdout[:4000]}"
            )
        if self.returncode == EXIT_RESERVED_AMBIGUOUS:
            raise ProductFailure(
                "spec/cli.md reserves exit 1 to prevent ambiguous generic "
                f"failures; {' '.join(self.argv)} returned 1"
            )
        observed = self.code
        if observed != code:
            raise ProductFailure(
                f"expected error code {code}, observed {observed} from "
                f"{' '.join(self.argv)}"
            )
        permitted = tuple(exits) if exits is not None else ERROR_CODE_EXIT[code]
        if self.returncode not in permitted:
            raise ProductFailure(
                f"error {code} must exit in {permitted} per the spec/cli.md "
                f"table; observed {self.returncode}"
            )
        return self

    def exited(self, *codes: int) -> "Result":
        if self.returncode not in codes:
            raise ProductFailure(
                f"expected exit in {codes} from {' '.join(self.argv)}, got "
                f"{self.returncode}\nstdout={self.stdout[:2000]}"
                f"\nstderr={self.stderr[:2000]}"
            )
        return self


def _resolve_entrypoint() -> tuple[str, ...]:
    override = os.environ.get("GUILDHALL_BIN")
    if override:
        parts = tuple(shlex.split(override))
        if not parts:
            raise HarnessInvalid("GUILDHALL_BIN is set but empty")
        return parts
    found = shutil.which("guildhall")
    if found:
        return (found,)
    probe = subprocess.run(
        [sys.executable, "-c", "import guildhall"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if probe.returncode == 0:
        return (sys.executable, "-m", "guildhall")
    raise ProductEntryPointMissing(
        "no ratified guildhall entry point resolved. spec/cli.md freezes the "
        "command surface (`guildhall status`, `guildhall doctor`, "
        "`guildhall company serve`, ...); the combined snapshot must expose it "
        "on PATH, as `python -m guildhall`, or via GUILDHALL_BIN."
    )


class Guildhall:
    """Invoke the ratified CLI in a controlled, isolated environment.

    Every invocation runs with a scrubbed environment. ``spec/architecture.md``
    section 5 requires the classifier child to receive "a scrubbed environment";
    the acceptance driver holds itself to the same discipline so no ambient
    ``HOME``, ``XDG_CONFIG_HOME`` or Personal path can leak into an assertion by
    accident, which would silently weaken every V-3 process-capability probe.
    """

    #: Variables that may cross into the product process. Anything else is
    #: dropped so a shared process cannot inherit a Personal hint from the
    #: Tester's own shell (threat-model.md attack family 14).
    ENV_ALLOWLIST: tuple[str, ...] = (
        "PATH",
        "LANG",
        "LC_ALL",
        "TZ",
        "TMPDIR",
        "SYSTEMROOT",
        "PYTHONHASHSEED",
    )

    def __init__(
        self,
        *,
        home: Path,
        xdg_config_home: Path,
        cwd: Path,
        extra_env: Mapping[str, str] | None = None,
        default_timeout: float = 120.0,
    ) -> None:
        self.entrypoint = _resolve_entrypoint()
        self.home = Path(home)
        self.xdg_config_home = Path(xdg_config_home)
        self.cwd = Path(cwd)
        self.extra_env = dict(extra_env or {})
        self.default_timeout = default_timeout
        self.transcript: list[Result] = []

    # -- environment ------------------------------------------------------

    def base_env(self, overrides: Mapping[str, str] | None = None) -> dict[str, str]:
        env = {
            k: os.environ[k]
            for k in self.ENV_ALLOWLIST
            if k in os.environ
        }
        env["HOME"] = str(self.home)
        env["XDG_CONFIG_HOME"] = str(self.xdg_config_home)
        env["XDG_DATA_HOME"] = str(self.home / ".local" / "share")
        env["XDG_STATE_HOME"] = str(self.home / ".local" / "state")
        env["XDG_CACHE_HOME"] = str(self.home / ".cache")
        # Deterministic, non-interactive, no ambient git identity or config.
        env["GIT_CONFIG_GLOBAL"] = str(self.home / ".gitconfig")
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_AUTHOR_NAME"] = "Acceptance Fixture"
        env["GIT_AUTHOR_EMAIL"] = "fixture@invalid.example"
        env["GIT_COMMITTER_NAME"] = "Acceptance Fixture"
        env["GIT_COMMITTER_EMAIL"] = "fixture@invalid.example"
        env["NO_COLOR"] = "1"
        env["TERM"] = "dumb"
        env["PYTHONIOENCODING"] = "utf-8"
        env.update(self.extra_env)
        env.update(overrides or {})
        return env

    # -- invocation -------------------------------------------------------

    def run(
        self,
        *args: str,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        stdin: str | bytes | None = None,
        timeout: float | None = None,
        check: bool = False,
    ) -> Result:
        argv = tuple(self.entrypoint) + tuple(str(a) for a in args)
        run_cwd = Path(cwd or self.cwd)
        run_env = self.base_env(env)
        payload: bytes | None
        if stdin is None:
            payload = None
        elif isinstance(stdin, bytes):
            payload = stdin
        else:
            payload = stdin.encode("utf-8")
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=str(run_cwd),
                env=run_env,
                input=payload,
                capture_output=True,
                timeout=timeout or self.default_timeout,
            )
            rc = completed.returncode
            out = completed.stdout.decode("utf-8", "surrogateescape")
            err = completed.stderr.decode("utf-8", "surrogateescape")
        except subprocess.TimeoutExpired as exc:
            rc = -signal.SIGKILL
            out = (exc.stdout or b"").decode("utf-8", "surrogateescape")
            err = (exc.stderr or b"").decode("utf-8", "surrogateescape") + (
                f"\n<acceptance: timed out after {timeout or self.default_timeout}s>"
            )
        duration = time.monotonic() - started
        result = Result(
            argv=argv,
            returncode=rc,
            stdout=out,
            stderr=err,
            duration_s=duration,
            cwd=str(run_cwd),
            env_overrides=dict(env or {}),
        )
        self.transcript.append(result)
        if check:
            result.ok()
        return result

    def json(self, *args: str, **kwargs: Any) -> Any:
        """Run with ``--json`` appended and return the parsed payload."""
        return self.run(*args, "--json", **kwargs).ok().json

    def popen(
        self,
        *args: str,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.Popen:
        """Start a long-lived product process (for example ``company serve``)."""
        argv = tuple(self.entrypoint) + tuple(str(a) for a in args)
        return subprocess.Popen(
            argv,
            cwd=str(cwd or self.cwd),
            env=self.base_env(env),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
