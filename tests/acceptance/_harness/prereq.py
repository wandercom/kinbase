"""Typed prerequisites, classified by origin before anything is asserted.

Detector Reviewer finding 10. The previous classifier mapped *every* non-selftest
``AssertionError`` to ``PRODUCT_FAILURE``. That included assertions about things
the product does not own: a Tester fixture that failed to load, a gold corpus
below its frozen size, an absent host binary, a Company service that never came
up, a missing repository certificate, an unregistered authority channel, an
un-provisioned timeout plugin, and an empty collection. Each of those is an
instrument condition. ``spec/verification.md`` "Verdict semantics" is explicit
that an unperformed measurement is never proof, and "Instrument validity" makes
an instrument that cannot substantiate its own controls ``INVALID_HARNESS``.

This module is the only sanctioned way for a gate test to establish a
prerequisite. Every function here raises :class:`HarnessInvalid` --- never
``AssertionError``, never ``ProductFailure`` --- and names the origin, so the
census can attribute it without guessing.

The companion static rule lives in ``test_no_green_paths.py``: a gate module may
not contain a bare ``assert``. Every claim goes through a typed checker whose
channel is declared at the call site. With that rule enforced, a bare
``AssertionError`` reaching the classifier can only have come from instrument
code, which is why ``conftest.py`` now classifies it as ``INVALID_HARNESS``.
"""

from __future__ import annotations

import os
import shutil
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .requirements import HarnessInvalid

#: Every prerequisite kind the instrument owns. A failure of any of these is an
#: instrument condition; none of them is evidence about the product.
ORIGINS: tuple[str, ...] = (
    "fixture",       # Tester-authored bytes under tests/fixtures/**
    "gold",          # sealed annotator gold, held outside every product input
    "rights",        # licensed-public auxiliary corpus authority
    "environment",   # HOME/XDG/PATH isolation, temporary roots, plugins
    "binary",        # a real host or product executable the run requires
    "service",       # a live Company/authority process the run requires
    "certificate",   # repository certificate / external trust root
    "registry",      # signed AuthorityRegistry entries
    "collection",    # pytest collection and parameterisation
    "timeout",       # the declared global execution bound
    "witness",       # an independent observation of a planted perturbation
    "corpus",        # a constructed corpus at a declared scale
)


class PrerequisiteMissing(HarnessInvalid):
    """A prerequisite the *instrument* owns was not satisfied.

    Subclassing :class:`HarnessInvalid` keeps every existing classification
    path correct while letting a caller catch the narrower condition.
    """

    def __init__(self, origin: str, what: str, detail: str) -> None:
        if origin not in ORIGINS:
            raise HarnessInvalid(
                f"unknown prerequisite origin {origin!r}; the instrument must "
                f"declare one of {ORIGINS}"
            )
        self.origin = origin
        self.what = what
        self.detail = detail
        super().__init__(
            f"INVALID_HARNESS [{origin}] {what}: {detail}. This is an instrument "
            "prerequisite, not a product observation; the gate cannot report "
            "PASS or PRODUCT_FAILURE from it."
        )


def missing(origin: str, what: str, detail: str) -> PrerequisiteMissing:
    return PrerequisiteMissing(origin, what, detail)


# --------------------------------------------------------------------------
# Files the Tester owns
# --------------------------------------------------------------------------


def fixture_file(path: Path, *, why: str, minimum_bytes: int = 1) -> bytes:
    """Read a Tester-owned fixture. Absence is an instrument condition."""
    if not path.is_file():
        raise missing("fixture", str(path), f"not a file; {why}")
    data = path.read_bytes()
    if len(data) < minimum_bytes:
        raise missing(
            "fixture", str(path),
            f"{len(data)} byte(s), below the declared minimum {minimum_bytes}; {why}",
        )
    return data


def gold_records(
    records: Sequence[Any], *, name: str, minimum: int, why: str
) -> Sequence[Any]:
    """A sealed gold set below its frozen size invalidates the instrument."""
    if len(records) < minimum:
        raise missing(
            "gold", name,
            f"{len(records)} record(s), below the frozen minimum {minimum}; {why}",
        )
    return records


def gold_join(
    predictions: Mapping[str, Any], gold: Mapping[str, Any], *, name: str
) -> tuple[str, ...]:
    """Join opaque product IDs to Tester-held gold; report the exact overlap.

    An empty or partial join is an instrument condition: the harness cannot
    compute a metric over records it cannot attribute, and it must never fall
    back to the product's own reported metric.
    """
    joined = tuple(sorted(set(predictions) & set(gold)))
    if not joined:
        raise missing(
            "gold", name,
            f"no opaque prediction id joined to gold; {len(predictions)} "
            f"prediction(s) and {len(gold)} gold record(s) share no key",
        )
    unjoined = sorted(set(gold) - set(predictions))
    if unjoined:
        raise missing(
            "gold", name,
            f"{len(unjoined)} gold record(s) received no prediction, so a "
            f"harness-computed metric would be over a partial denominator; "
            f"first: {unjoined[0]}",
        )
    return joined


# --------------------------------------------------------------------------
# Environment, binaries, services
# --------------------------------------------------------------------------


def isolated_root(path: Path, *, what: str) -> Path:
    if not path.is_dir():
        raise missing("environment", what, f"{path} is not a directory")
    return path


def private_mode(path: Path, *, what: str, mode: int = 0o700) -> Path:
    if not path.exists():
        raise missing("environment", what, f"{path} does not exist")
    observed = stat.S_IMODE(path.stat().st_mode)
    if observed != mode:
        raise missing(
            "environment", what,
            f"{path} has mode {observed:04o}, the instrument requires {mode:04o}",
        )
    return path


def executable(name_or_path: str, *, what: str, why: str) -> Path:
    """Resolve a real executable. A mocked branch is not acceptable evidence."""
    candidate = Path(name_or_path)
    resolved = candidate if candidate.is_absolute() else None
    if resolved is None:
        found = shutil.which(name_or_path)
        if found is None:
            raise missing("binary", what, f"{name_or_path!r} is not on PATH; {why}")
        resolved = Path(found)
    if not resolved.is_file():
        raise missing("binary", what, f"{resolved} is not a file; {why}")
    if not os.access(resolved, os.X_OK):
        raise missing("binary", what, f"{resolved} is not executable; {why}")
    return resolved


def env_var(name: str, *, what: str, why: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise missing("environment", what, f"{name} is unset or empty; {why}")
    return value


def listening(host: str, port: int, *, what: str, why: str, timeout: float = 2.0) -> None:
    """A service the run requires must actually be accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as exc:
        raise missing(
            "service", what, f"{host}:{port} is not accepting connections ({exc}); {why}"
        ) from exc


def service_ready(ready: bool, *, what: str, why: str) -> None:
    if not ready:
        raise missing("service", what, why)


def certificate_installed(path: Path, *, what: str, why: str) -> Path:
    if not path.is_file():
        raise missing("certificate", what, f"{path} is absent; {why}")
    if path.stat().st_size == 0:
        raise missing("certificate", what, f"{path} is empty; {why}")
    return path


def registered(entries: Iterable[Any], *, what: str, why: str, minimum: int = 1) -> list[Any]:
    materialised = list(entries)
    if len(materialised) < minimum:
        raise missing(
            "registry", what,
            f"{len(materialised)} registered entr(y/ies), at least {minimum} "
            f"required; {why}",
        )
    return materialised


def corpus_at_scale(observed: int, required: int, *, what: str, why: str) -> int:
    if observed < required:
        raise missing(
            "corpus", what,
            f"constructed {observed} of the {required} records the obligation "
            f"ranges over; {why}",
        )
    return observed


def collected(items: Sequence[Any], *, what: str, why: str, minimum: int = 1) -> Sequence[Any]:
    if len(items) < minimum:
        raise missing(
            "collection", what,
            f"{len(items)} collected item(s), at least {minimum} required; {why}",
        )
    return items


def witnessed(observed: Any, expected: Any, *, what: str, why: str) -> Any:
    """An independently captured witness must match what the harness planted."""
    if observed != expected:
        raise missing(
            "witness", what,
            f"independent witness observed {observed!r}, the harness planted "
            f"{expected!r}; an unwitnessed perturbation cannot support the "
            f"obligation. {why}",
        )
    return observed


def rights_granted(granted: bool, *, what: str, why: str) -> None:
    if not granted:
        raise missing("rights", what, why)


@dataclass(frozen=True)
class Prerequisite:
    """A declared prerequisite, for reporting in the evidence packet."""

    origin: str
    what: str
    why: str

    def as_json(self) -> dict:
        return {"origin": self.origin, "what": self.what, "why": self.why}
