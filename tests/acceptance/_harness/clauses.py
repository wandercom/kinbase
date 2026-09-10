"""Declarative evidence clauses: checker, planter and detector mutation in one.

``spec/verification.md`` "Instrument validity" requires every gate to freeze
four things per obligation --- threshold, positive control, negative control and
detector mutation --- and the Detector Reviewer found that V-1, V-2 and V-4
through V-9 had none of them, only prose.

Writing four artefacts per obligation by hand for ~130 obligations invites the
exact drift the Reviewer caught: a control that does not control, a mutation
that mutates nothing. So each obligation is declared once, as a conjunction of
typed :class:`Clause` objects, and all four artefacts are *derived* from that
single declaration:

* the **threshold** is the clause bound itself;
* the **checker** evaluates the conjunction against evidence;
* the **conforming fixture** (positive control) is synthesised to satisfy every
  clause, so it must pass;
* the **product mutation** violates one named clause, so the checker must raise
  ``ProductFailure``;
* the **detector mutation** deletes that same clause from the checker, so the
  blinded checker must *miss* the planted violation -- which is what makes the
  mutation a real one rather than a label;
* the **negative control** perturbs the evidence in a way the obligation does
  not forbid, so it must stay clean and prove the checker is not trivially
  positive.

A derived planter cannot silently disagree with its checker, because both read
the same clause.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .evidence_model import Evidence
from .requirements import HarnessInvalid

#: Every clause kind the catalog may use. Closed set: an unknown kind is an
#: instrument defect, not a silently ignored declaration.
CLAUSE_KINDS: tuple[str, ...] = (
    "present",      # field exists and is non-null
    "nonempty",     # list/dict/str with len >= min_len
    "equals",       # exact scalar value
    "member",       # value is in a closed set
    "at_least",     # numeric floor (inclusive)
    "at_most",      # numeric ceiling (inclusive)
    "is_true",
    "is_false",
    "absent",       # forbidden field must not appear
    "covers",       # collection covers a frozen expected set
    "every",        # every element of a collection satisfies sub-clauses
    "distinct",     # collection values are pairwise distinct
)


@dataclass(frozen=True)
class Clause:
    """One typed, checkable, mutable obligation clause."""

    kind: str
    path: str
    #: Threshold / expected value, interpreted per ``kind``.
    value: Any = None
    #: Human-readable statement of what this clause enforces.
    why: str = ""
    #: For ``nonempty`` and ``covers``.
    min_len: int = 1
    #: For ``every``: sub-clauses applied to each element (paths are relative).
    each: tuple["Clause", ...] = field(default_factory=tuple)
    #: Stable identifier used by planters and detector mutations.
    tag: str = ""

    def __post_init__(self) -> None:
        if self.kind not in CLAUSE_KINDS:
            raise HarnessInvalid(f"unknown clause kind {self.kind!r}")
        if not self.why:
            raise HarnessInvalid(f"clause {self.kind}:{self.path} has no rationale")
        object.__setattr__(self, "tag", self.tag or f"{self.kind}:{self.path}")

    # -- evaluation -------------------------------------------------------

    def check(self, ev: Evidence) -> None:
        """Raise the origin-appropriate failure when this clause is violated."""
        if self.kind == "present":
            ev.need(self.path, why=self.why)
        elif self.kind == "nonempty":
            value = ev.need_typed(self.path, (list, tuple, dict, str), why=self.why)
            if len(value) < self.min_len:
                ev._fail(
                    f"field {self.path!r} has {len(value)} element(s), at least "
                    f"{self.min_len} required; {self.why}"
                )
        elif self.kind == "equals":
            observed = ev.need(self.path, why=self.why)
            if observed != self.value:
                ev._fail(
                    f"field {self.path!r} is {observed!r}, must equal "
                    f"{self.value!r}; {self.why}"
                )
        elif self.kind == "member":
            ev.need_in(self.path, self.value, why=self.why)
        elif self.kind == "at_least":
            ev.need_at_least(self.path, self.value, why=self.why)
        elif self.kind == "at_most":
            ev.need_at_most(self.path, self.value, why=self.why)
        elif self.kind == "is_true":
            ev.need_true(self.path, why=self.why)
        elif self.kind == "is_false":
            ev.need_false(self.path, why=self.why)
        elif self.kind == "absent":
            ev.need_absent(self.path, why=self.why)
        elif self.kind == "covers":
            observed = ev.need_typed(self.path, (list, tuple), why=self.why)
            missing = sorted(set(self.value) - set(observed), key=str)
            if missing:
                ev._fail(
                    f"field {self.path!r} does not cover {missing}; {self.why}"
                )
        elif self.kind == "distinct":
            observed = ev.need_typed(self.path, (list, tuple), why=self.why)
            rendered = [repr(x) for x in observed]
            if len(set(rendered)) != len(rendered):
                ev._fail(f"field {self.path!r} contains duplicates; {self.why}")
        elif self.kind == "every":
            observed = ev.need_typed(self.path, (list, tuple), why=self.why)
            if len(observed) < self.min_len:
                ev._fail(
                    f"field {self.path!r} has {len(observed)} element(s), at least "
                    f"{self.min_len} required before a universal claim; {self.why}"
                )
            for index, element in enumerate(observed):
                sub = Evidence(
                    obligation=ev.obligation,
                    origin=ev.origin,
                    label=f"{ev.label}[{index}]",
                    payload=element,
                )
                for clause in self.each:
                    clause.check(sub)
        else:  # pragma: no cover - guarded by __post_init__
            raise HarnessInvalid(f"unhandled clause kind {self.kind!r}")

    # -- synthesis --------------------------------------------------------

    def conforming_value(self) -> Any:
        """A value that satisfies this clause, used to build positive controls."""
        if self.kind == "present":
            return self.value if self.value is not None else "present"
        if self.kind == "nonempty":
            return ["element-%d" % i for i in range(max(1, self.min_len))]
        if self.kind == "equals":
            return self.value
        if self.kind == "member":
            return tuple(self.value)[0]
        if self.kind == "at_least":
            return float(self.value)
        if self.kind == "at_most":
            return float(self.value)
        if self.kind == "is_true":
            return True
        if self.kind == "is_false":
            return False
        if self.kind == "covers":
            return list(self.value)
        if self.kind == "distinct":
            return [f"distinct-{i}" for i in range(max(2, self.min_len))]
        if self.kind == "every":
            element: dict[str, Any] = {}
            for sub in self.each:
                if sub.kind == "absent":
                    # An ``absent`` sub-clause forbids the field; assigning it
                    # here would make the conforming element violate its own
                    # positive control.
                    continue
                _assign(element, sub.path, sub.conforming_value())
            return [copy.deepcopy(element) for _ in range(max(1, self.min_len))]
        return None

    def violating_value(self, conforming: Any) -> Any:
        """A value that violates this clause. Drives the product mutation."""
        if self.kind in {"present", "nonempty"}:
            return _DELETE if self.kind == "present" else []
        if self.kind == "equals":
            return f"{self.value!r}-mutated" if not isinstance(self.value, bool) else (
                not self.value
            )
        if self.kind == "member":
            return "value-outside-the-closed-set"
        if self.kind == "at_least":
            return float(self.value) - _EPS
        if self.kind == "at_most":
            return float(self.value) + _EPS
        if self.kind == "is_true":
            return False
        if self.kind == "is_false":
            return True
        if self.kind == "absent":
            return "forbidden-value-present"
        if self.kind == "covers":
            remaining = list(self.value)[1:]
            return remaining
        if self.kind == "distinct":
            base = conforming if isinstance(conforming, list) and conforming else ["a"]
            return [base[0], base[0]]
        if self.kind == "every":
            elements = copy.deepcopy(conforming) if isinstance(conforming, list) else []
            if not elements:
                elements = [{}]
            if self.each:
                sub = self.each[0]
                _assign(
                    elements[-1],
                    sub.path,
                    sub.violating_value(_read(elements[-1], sub.path)),
                )
            return elements
        return None

    def benign_value(self, conforming: Any) -> Any:
        """A perturbation this clause does not forbid. Drives the negative control."""
        if self.kind == "at_least":
            return float(self.value) + abs(float(self.value) or 1.0) * 0.25
        if self.kind == "at_most":
            return float(self.value) - abs(float(self.value) or 1.0) * 0.25
        if self.kind in {"nonempty", "distinct"}:
            base = list(conforming) if isinstance(conforming, (list, tuple)) else []
            if base:
                # Extend with a copy of an existing element so the perturbation
                # stays type-compatible with any sibling ``every`` clause. A bare
                # string here manufactured a false positive.
                extra = copy.deepcopy(base[-1])
                if isinstance(extra, str):
                    extra = f"{extra}-additional"
                return base + [extra]
            return [f"extra-{i}" for i in range(max(2, self.min_len))]
        if self.kind == "covers":
            return list(self.value) + ["additional-unrequired-element"]
        return conforming


_DELETE = object()
_EPS = 1e-6


def _assign(root: dict, path: str, value: Any) -> None:
    if value is _DELETE:
        _delete(root, path)
        return
    node = root
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def _delete(root: dict, path: str) -> None:
    node = root
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            return
        node = nxt
    node.pop(parts[-1], None)


def _read(root: Any, path: str) -> Any:
    node = root
    for part in path.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


# --------------------------------------------------------------------------
# Conjunctions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ClauseSet:
    """The full conjunction for one obligation."""

    clauses: tuple[Clause, ...]

    def __post_init__(self) -> None:
        if not self.clauses:
            raise HarnessInvalid("an obligation must declare at least one clause")
        tags = [c.tag for c in self.clauses]
        if len(set(tags)) != len(tags):
            raise HarnessInvalid(f"duplicate clause tags: {tags}")

    def tags(self) -> tuple[str, ...]:
        return tuple(c.tag for c in self.clauses)

    def check(self, ev: Evidence, *, blind: str | None = None) -> None:
        """Evaluate the conjunction, optionally blinding one clause.

        ``blind`` is the detector mutation: the named clause is not evaluated,
        which is exactly the capability a detector mutation removes.
        """
        if blind is not None and blind not in self.tags():
            raise HarnessInvalid(
                f"detector mutation names clause {blind!r}, which this obligation "
                f"does not declare; tags are {self.tags()}"
            )
        for clause in self.clauses:
            if clause.tag == blind:
                continue
            clause.check(ev)

    # -- derived artefacts -------------------------------------------------

    def conforming(self) -> dict[str, Any]:
        """Positive control: evidence that satisfies every clause."""
        payload: dict[str, Any] = {}
        for clause in self.clauses:
            if clause.kind == "absent":
                continue
            _assign(payload, clause.path, clause.conforming_value())
        return payload

    def violating(self, tag: str) -> dict[str, Any]:
        """Product mutation: conforming evidence with one clause violated."""
        clause = self.clause(tag)
        payload = self.conforming()
        _assign(payload, clause.path, clause.violating_value(_read(payload, clause.path)))
        return payload

    def benign(self, tag: str) -> dict[str, Any]:
        """Negative control: a perturbation the obligation does not forbid."""
        clause = self.clause(tag)
        payload = self.conforming()
        if clause.kind != "absent":
            # An ``absent`` clause forbids the field outright, so the only
            # benign perturbation is to leave it absent. Assigning anything
            # here would manufacture a false positive and make the negative
            # control meaningless.
            _assign(
                payload, clause.path, clause.benign_value(_read(payload, clause.path))
            )
        payload["unrelated_additional_field"] = "must not trip the checker"
        return payload

    def clause(self, tag: str) -> Clause:
        for clause in self.clauses:
            if clause.tag == tag:
                return clause
        raise HarnessInvalid(f"no clause tagged {tag!r}; tags are {self.tags()}")


def clauses(*items: Clause) -> ClauseSet:
    return ClauseSet(tuple(items))


# -- convenience constructors ---------------------------------------------


def present(path: str, why: str, value: Any = None) -> Clause:
    return Clause("present", path, value=value, why=why)


def nonempty(path: str, why: str, min_len: int = 1) -> Clause:
    return Clause("nonempty", path, why=why, min_len=min_len)


def equals(path: str, value: Any, why: str) -> Clause:
    return Clause("equals", path, value=value, why=why)


def member(path: str, allowed: Iterable[Any], why: str) -> Clause:
    return Clause("member", path, value=tuple(allowed), why=why)


def at_least(path: str, floor: float, why: str) -> Clause:
    return Clause("at_least", path, value=floor, why=why)


def at_most(path: str, ceiling: float, why: str) -> Clause:
    return Clause("at_most", path, value=ceiling, why=why)


def is_true(path: str, why: str) -> Clause:
    return Clause("is_true", path, why=why)


def is_false(path: str, why: str) -> Clause:
    return Clause("is_false", path, why=why)


def absent(path: str, why: str) -> Clause:
    return Clause("absent", path, why=why)


def covers(path: str, expected: Iterable[Any], why: str) -> Clause:
    return Clause("covers", path, value=tuple(expected), why=why)


def distinct(path: str, why: str, min_len: int = 2) -> Clause:
    return Clause("distinct", path, why=why, min_len=min_len)


def every(path: str, why: str, *each: Clause, min_len: int = 1) -> Clause:
    return Clause("every", path, why=why, each=tuple(each), min_len=min_len)
