"""Typed evidence with total accessors.

Detector Reviewer findings 3, 8, 9, 10, 11, 15 and 16 all reduce to the same
defect: an assertion that can pass without evidence. ``payload.get(k, 0)``
turned a missing counter into a satisfied bound, ``for x in payload.get(k, [])``
turned a missing list into a satisfied loop, and ``if result.returncode == 0:``
turned a refusal into a pass.

This module removes the whole class. Every read of product-reported evidence
goes through :func:`need`, which has no default and raises a *typed* failure
naming the obligation. Every quantified assertion goes through
:func:`require_nonempty` or :func:`require_all`, which refuse an empty domain.

Classification rule, from ``spec/verification.md`` "Verdict semantics":

* evidence the ratified contract requires the product to emit, absent or
  malformed -> ``PRODUCT_FAILURE``;
* evidence the *harness* was supposed to construct, absent or malformed ->
  ``INVALID_HARNESS``.

The two are never merged, because an instrument that cannot tell them apart
cannot support either half of the composition.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

from .requirements import HarnessInvalid, ProductFailure

_MISSING = object()


class Outcome(str, Enum):
    """Per-obligation and per-gate outcome.

    ``NOT_RUN`` is the initial state of every obligation. It is non-green:
    ``spec/verification.md`` "Verdict semantics" makes an unperformed
    measurement terminal ``NOT_PROVEN``, never proof.
    """

    NOT_RUN = "NOT_RUN"
    PASS = "PASS"
    PRODUCT_FAILURE = "PRODUCT_FAILURE"
    INVALID_HARNESS = "INVALID_HARNESS"

    @property
    def green(self) -> bool:
        return self is Outcome.PASS


#: Outcomes that may never be reported as satisfying an obligation.
NON_GREEN: frozenset[Outcome] = frozenset(
    {Outcome.NOT_RUN, Outcome.PRODUCT_FAILURE, Outcome.INVALID_HARNESS}
)


class Origin(str, Enum):
    """Who produced a piece of evidence.

    ``PRODUCT`` evidence is self-reported and can only ever *fail* an
    obligation, never independently establish one that requires raw work.
    ``HARNESS`` evidence is read by the instrument from raw state.
    """

    PRODUCT = "product"
    HARNESS = "harness"
    WITNESS = "witness"


@dataclass(frozen=True)
class Evidence:
    """One content-addressed evidence record."""

    obligation: str
    origin: Origin
    label: str
    payload: Any

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                {"obligation": self.obligation, "origin": self.origin.value,
                 "label": self.label, "payload": self.payload},
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()

    def _fail(self, message: str) -> None:
        if self.origin is Origin.PRODUCT:
            raise ProductFailure(f"[{self.obligation}] {self.label}: {message}")
        raise HarnessInvalid(f"[{self.obligation}] {self.label}: {message}")

    # -- total accessors --------------------------------------------------

    def need(self, path: str, *, why: str) -> Any:
        """Read a required dotted path. No default exists.

        ``path`` may address nested mappings (``a.b.c``). A missing or ``None``
        value is a failure attributed to this record's origin.
        """
        node: Any = self.payload
        walked: list[str] = []
        for part in path.split("."):
            walked.append(part)
            if not isinstance(node, Mapping):
                self._fail(
                    f"required field {path!r} is unreachable at {'.'.join(walked)}; "
                    f"{why}"
                )
            node = node.get(part, _MISSING)
            if node is _MISSING:
                self._fail(f"required field {path!r} is absent; {why}")
        if node is None:
            self._fail(f"required field {path!r} is null; {why}")
        return node

    def need_typed(self, path: str, kind: type | tuple[type, ...], *, why: str) -> Any:
        value = self.need(path, why=why)
        if not isinstance(value, kind):
            names = (
                kind.__name__
                if isinstance(kind, type)
                else "/".join(k.__name__ for k in kind)
            )
            self._fail(
                f"field {path!r} must be {names}, observed {type(value).__name__}; {why}"
            )
        return value

    def need_nonempty(self, path: str, *, why: str) -> Sequence | Mapping | str:
        value = self.need_typed(path, (list, tuple, dict, str), why=why)
        if len(value) == 0:
            self._fail(
                f"field {path!r} is empty; an empty domain cannot satisfy an "
                f"obligation. {why}"
            )
        return value

    def need_int(self, path: str, *, why: str) -> int:
        value = self.need(path, why=why)
        if isinstance(value, bool) or not isinstance(value, int):
            self._fail(f"field {path!r} must be an integer; {why}")
        return int(value)

    def need_number(self, path: str, *, why: str) -> float:
        value = self.need(path, why=why)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            self._fail(f"field {path!r} must be a number; {why}")
        return float(value)

    def need_bool(self, path: str, *, why: str) -> bool:
        value = self.need(path, why=why)
        if not isinstance(value, bool):
            self._fail(f"field {path!r} must be a boolean; {why}")
        return bool(value)

    def need_true(self, path: str, *, why: str) -> None:
        if self.need_bool(path, why=why) is not True:
            self._fail(f"field {path!r} must be true; {why}")

    def need_false(self, path: str, *, why: str) -> None:
        if self.need_bool(path, why=why) is not False:
            self._fail(f"field {path!r} must be false; {why}")

    def need_in(self, path: str, permitted: Iterable[Any], *, why: str) -> Any:
        value = self.need(path, why=why)
        allowed = tuple(permitted)
        if value not in allowed:
            self._fail(f"field {path!r} is {value!r}, not one of {allowed}; {why}")
        return value

    def need_at_least(self, path: str, floor: float, *, why: str) -> float:
        value = self.need_number(path, why=why)
        if value < floor:
            self._fail(f"field {path!r} is {value}, below the frozen floor {floor}; {why}")
        return value

    def need_at_most(self, path: str, ceiling: float, *, why: str) -> float:
        value = self.need_number(path, why=why)
        if value > ceiling:
            self._fail(
                f"field {path!r} is {value}, above the frozen ceiling {ceiling}; {why}"
            )
        return value

    def need_absent(self, path: str, *, why: str) -> None:
        """Assert a forbidden field is genuinely absent."""
        node: Any = self.payload
        for part in path.split("."):
            if not isinstance(node, Mapping):
                return
            node = node.get(part, _MISSING)
            if node is _MISSING:
                return
        self._fail(f"forbidden field {path!r} is present; {why}")


def evidence(obligation: str, label: str, payload: Any, origin: Origin) -> Evidence:
    return Evidence(obligation=obligation, origin=origin, label=label, payload=payload)


def product(obligation: str, label: str, payload: Any) -> Evidence:
    return Evidence(obligation, Origin.PRODUCT, label, payload)


def harness(obligation: str, label: str, payload: Any) -> Evidence:
    return Evidence(obligation, Origin.HARNESS, label, payload)


def witness(obligation: str, label: str, payload: Any) -> Evidence:
    return Evidence(obligation, Origin.WITNESS, label, payload)


# --------------------------------------------------------------------------
# Total quantifiers
# --------------------------------------------------------------------------


def require_nonempty(
    items: Sequence | Mapping, *, obligation: str, why: str, origin: Origin = Origin.HARNESS
) -> Sequence | Mapping:
    """Refuse an empty domain.

    ``assert all(p(x) for x in xs)`` is vacuously true when ``xs`` is empty. The
    Reviewer found that pattern in seven places, each of which turned "the
    product produced nothing" into "the obligation is satisfied".
    """
    if len(items) == 0:
        message = (
            f"[{obligation}] empty domain: {why}. An empty collection cannot "
            "satisfy a quantified obligation."
        )
        if origin is Origin.PRODUCT:
            raise ProductFailure(message)
        raise HarnessInvalid(message)
    return items


def require_all(
    items: Iterable[Any],
    predicate: Callable[[Any], bool],
    *,
    obligation: str,
    why: str,
    minimum: int = 1,
    origin: Origin = Origin.PRODUCT,
) -> list[Any]:
    """Assert a predicate over a domain that must contain at least ``minimum``."""
    materialised = list(items)
    if len(materialised) < minimum:
        message = (
            f"[{obligation}] domain has {len(materialised)} item(s), at least "
            f"{minimum} required: {why}"
        )
        if origin is Origin.PRODUCT:
            raise ProductFailure(message)
        raise HarnessInvalid(message)
    offenders = [x for x in materialised if not predicate(x)]
    if offenders:
        message = (
            f"[{obligation}] {len(offenders)} of {len(materialised)} item(s) "
            f"violate the obligation: {why}\n  first: {offenders[0]!r}"
        )
        if origin is Origin.PRODUCT:
            raise ProductFailure(message)
        raise HarnessInvalid(message)
    return materialised


def require_exactly(
    items: Iterable[Any], count: int, *, obligation: str, why: str,
    origin: Origin = Origin.PRODUCT,
) -> list[Any]:
    materialised = list(items)
    if len(materialised) != count:
        message = (
            f"[{obligation}] expected exactly {count} item(s), observed "
            f"{len(materialised)}: {why}"
        )
        if origin is Origin.PRODUCT:
            raise ProductFailure(message)
        raise HarnessInvalid(message)
    return materialised


def require_total_coverage(
    observed: Iterable[Any],
    expected: Iterable[Any],
    *,
    obligation: str,
    why: str,
    origin: Origin = Origin.PRODUCT,
) -> None:
    """Assert an observed set covers a frozen expected set exactly."""
    observed_set = set(observed)
    expected_set = set(expected)
    missing = sorted(expected_set - observed_set, key=str)
    if missing:
        message = f"[{obligation}] uncovered: {missing}; {why}"
        if origin is Origin.PRODUCT:
            raise ProductFailure(message)
        raise HarnessInvalid(message)


def forbid(condition: bool, *, obligation: str, why: str,
           origin: Origin = Origin.PRODUCT) -> None:
    if condition:
        message = f"[{obligation}] {why}"
        if origin is Origin.PRODUCT:
            raise ProductFailure(message)
        raise HarnessInvalid(message)


def content_address(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def field(node: Any, *path: str) -> Any:
    """Read a nested key with **no default**, returning ``None`` when absent.

    This is not a permissive default. The result is handed to a catalogue clause
    that requires the value to be present, of the right type, or non-empty, so
    an absent field fails with a typed message naming the obligation. The point
    is to keep the *absence* visible to the checker instead of substituting a
    satisfying value at the read site, which is the defect Detector Reviewer
    finding 6 named.
    """
    current = node
    for key in path:
        if not isinstance(current, Mapping):
            return None
        if key not in current:
            return None
        current = current[key]
    return current


def rows(node: Any, *path: str) -> list:
    """Read a list-of-objects field, preserving emptiness for the checker.

    An absent or malformed list becomes an empty list *for the checker*, which
    refuses an empty domain. It is never used as a loop domain in a gate test:
    ``test_no_green_paths.py`` rejects that pattern outright.
    """
    value = field(node, *path)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def find_row(node: Any, *path: str, key: str, value: Any) -> dict:
    """The first object in a list field whose ``key`` equals ``value``.

    Returns an empty mapping when there is none, so the obligation's clauses
    report the exact missing field rather than raising an untyped KeyError.
    """
    for item in rows(node, *path):
        if item.get(key) == value:
            return item
    return {}
