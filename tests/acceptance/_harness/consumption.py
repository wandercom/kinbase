"""Runtime proof that a catalog row was actually consumed by its node.

Detector Reviewer finding 5. 66 of 92 obligations named a test node that never
called the obligation's checker. The census counted the node as executing the
row, so a weak or unrelated assertion satisfied a catalogued control.

The repair is two coupled halves.

**Static.** ``test_backreference_integrity.py`` requires the body of every node
named by an obligation to contain a literal ``O.check("<oid>", ...)`` for that
exact OID. A row whose node cannot possibly consume it is rejected at
collection time, before any product runs.

**Runtime.** :func:`record` is called from ``obligations.check`` on every
evaluation. At session end :func:`unconsumed` reports every (obligation, node)
pair the catalog declared that produced no content-addressed record. The census
turns each into ``INVALID_HARNESS`` for the owning gate --- never a pass, and
never a product accusation, because a missing consumption record is an
instrument defect.

The record is content addressed over the evaluated payload, so two different
nodes cannot share one evaluation and a replayed constant cannot masquerade as a
fresh observation: :func:`duplicate_digests` reports any digest claimed by more
than one node.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Mapping

from .catalog import BY_ID, OBLIGATIONS

#: Set by ``conftest.py`` for the duration of each test call so a record can be
#: attributed to the node that produced it.
CURRENT_NODE: str = ""


@dataclass(frozen=True)
class ConsumptionRecord:
    """One content-addressed evaluation of one catalogued obligation."""

    obligation: str
    node: str
    label: str
    digest: str
    origin: str
    payload_keys: tuple[str, ...]

    def as_json(self) -> dict:
        return {
            "obligation": self.obligation,
            "node": self.node,
            "label": self.label,
            "digest": self.digest,
            "origin": self.origin,
            "payload_keys": list(self.payload_keys),
        }


_RECORDS: list[ConsumptionRecord] = []


def reset() -> None:
    _RECORDS.clear()


def set_node(node: str) -> None:
    global CURRENT_NODE
    CURRENT_NODE = node


def record(obligation: str, label: str, origin: str, payload: Mapping) -> ConsumptionRecord:
    entry = ConsumptionRecord(
        obligation=obligation,
        node=_normalise(CURRENT_NODE),
        label=label,
        digest=hashlib.sha256(
            json.dumps(
                {"obligation": obligation, "payload": payload},
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest(),
        origin=origin,
        payload_keys=tuple(sorted(payload)) if isinstance(payload, Mapping) else (),
    )
    _RECORDS.append(entry)
    return entry


def records() -> tuple[ConsumptionRecord, ...]:
    return tuple(_RECORDS)


def _normalise(node_id: str) -> str:
    tail = node_id.split("/")[-1]
    if "[" in tail:
        tail = tail.split("[", 1)[0]
    return tail


def consumed_pairs() -> frozenset[tuple[str, str]]:
    return frozenset((r.obligation, r.node) for r in _RECORDS)


def expected_pairs(nodes_executed: Iterable[str]) -> frozenset[tuple[str, str]]:
    """Every (obligation, node) pair the catalog declares among executed nodes."""
    executed = {_normalise(n) for n in nodes_executed}
    out: set[tuple[str, str]] = set()
    for obligation in OBLIGATIONS:
        for node in obligation.nodes:
            normalised = _normalise(node)
            if normalised in executed:
                out.add((obligation.oid, normalised))
    return frozenset(out)


def unconsumed(nodes_executed: Iterable[str]) -> tuple[tuple[str, str], ...]:
    """Declared pairs that executed but produced no evaluation record."""
    return tuple(sorted(expected_pairs(nodes_executed) - consumed_pairs()))


def undeclared() -> tuple[tuple[str, str], ...]:
    """Records for pairs the catalog never declared.

    A node evaluating an obligation it does not own is also a coupling defect:
    the census would credit the wrong gate.
    """
    declared = {
        (o.oid, _normalise(n)) for o in OBLIGATIONS for n in o.nodes
    }
    return tuple(sorted(
        pair for pair in consumed_pairs() if pair not in declared and pair[1]
    ))


def duplicate_digests() -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Digests claimed by more than one node, i.e. a shared or replayed payload."""
    by_digest: dict[str, set[str]] = {}
    for entry in _RECORDS:
        by_digest.setdefault(entry.digest, set()).add(entry.node)
    return tuple(
        sorted(
            (digest, tuple(sorted(nodes)))
            for digest, nodes in by_digest.items()
            if len(nodes) > 1
        )
    )


def gates_with_unconsumed(nodes_executed: Iterable[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for oid, node in unconsumed(nodes_executed):
        gate = BY_ID[oid].gate if oid in BY_ID else "INSTRUMENT"
        out.setdefault(gate, []).append(f"{oid} declared by {node} but never evaluated")
    return out


def as_json(nodes_executed: Iterable[str]) -> dict:
    executed = list(nodes_executed)
    return {
        "schema": "guildhall-obligation-consumption/1",
        "records": [r.as_json() for r in _RECORDS],
        "declared_pairs": len(expected_pairs(executed)),
        "consumed_pairs": len(consumed_pairs()),
        "unconsumed": [list(p) for p in unconsumed(executed)],
        "undeclared": [list(p) for p in undeclared()],
        "duplicate_digests": [
            {"digest": d, "nodes": list(n)} for d, n in duplicate_digests()
        ],
    }
