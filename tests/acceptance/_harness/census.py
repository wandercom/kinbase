"""Expected-node census and the two-channel gate result model.

Detector Reviewer findings 3, 4 and 10. The previous model initialised all
fourteen gates to ``PASS``, recorded only failures, and defaulted a missing gate
back to ``PASS`` at report time. Consequences the Reviewer demonstrated:

* ``run-acceptance.sh -m v1`` printed ``PASS`` for V-2 through V-9;
* an empty collection retained an all-``PASS`` vector;
* a skip stayed ``PASS``;
* a selected mutation whose nodes all passed stayed ``PASS``;
* a product assertion could overwrite an invalid detector with no independent
  content address.

The replacement is a census. Every obligation in the catalog names the nodes
that must execute. A gate is green only when *every* expected node for it was
collected, executed and passed. Anything else --- deselected, skipped, never
collected, errored in setup or teardown, empty parameter set --- is
``NOT_RUN``, which is non-green.

Instrument and product outcomes are carried as two independent channels and are
never merged here. ``spec/verification.md`` composes them; this module only
observes them, and records the content address of any product observation so a
later composition can check the independence predicate rather than assume it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .catalog import OBLIGATIONS, REQUIRED_GATES, Obligation
from .evidence_model import Outcome

#: Non-gate reporting groups. They are censused the same way.
AUXILIARY_GROUPS: tuple[str, ...] = (
    "V-10",
    "NONFUNCTIONAL",
    "EVIDENCE",
    "VERDICT",
    "INSTRUMENT",
)

GROUPS: tuple[str, ...] = REQUIRED_GATES + AUXILIARY_GROUPS


@dataclass
class NodeRecord:
    """Execution state of one expected or observed test node."""

    node: str
    gate: str
    expected: bool
    collected: bool = False
    #: setup / call / teardown outcomes, keyed by phase.
    phases: dict[str, str] = field(default_factory=dict)
    outcome: Outcome = Outcome.NOT_RUN
    channel: str = ""
    reason: str = ""
    product_digest: str = ""

    def as_json(self) -> dict:
        return {
            "node": self.node,
            "gate": self.gate,
            "expected": self.expected,
            "collected": self.collected,
            "phases": dict(self.phases),
            "outcome": self.outcome.value,
            "channel": self.channel,
            "reason": self.reason,
            "product_digest": self.product_digest,
        }


@dataclass
class GateState:
    """Two independent channels plus the census for one gate."""

    gate: str
    expected_nodes: tuple[str, ...]
    instrument: Outcome = Outcome.NOT_RUN
    product: Outcome = Outcome.NOT_RUN
    #: Content addresses of independently observed product failures.
    product_observations: list[str] = field(default_factory=list)
    instrument_reasons: list[str] = field(default_factory=list)
    product_reasons: list[str] = field(default_factory=list)

    def observe(self, record: NodeRecord) -> None:
        if record.outcome is Outcome.INVALID_HARNESS:
            self.instrument = Outcome.INVALID_HARNESS
            self.instrument_reasons.append(f"{record.node}: {record.reason}")
        elif record.outcome is Outcome.PRODUCT_FAILURE:
            self.product = Outcome.PRODUCT_FAILURE
            self.product_reasons.append(f"{record.node}: {record.reason}")
            if record.product_digest:
                self.product_observations.append(record.product_digest)

    def resolve(self, records: Mapping[str, NodeRecord]) -> None:
        """Fold executed nodes into the two channels, defaulting to NOT_RUN."""
        expected = [records.get(n) for n in self.expected_nodes]
        missing = [n for n, r in zip(self.expected_nodes, expected) if r is None]
        unrun = [
            n
            for n, r in zip(self.expected_nodes, expected)
            if r is not None and r.outcome is Outcome.NOT_RUN
        ]
        if self.instrument is Outcome.NOT_RUN:
            if missing or unrun:
                self.instrument = Outcome.NOT_RUN
                if missing:
                    self.instrument_reasons.append(
                        f"{len(missing)} expected node(s) never collected"
                    )
                if unrun:
                    self.instrument_reasons.append(
                        f"{len(unrun)} expected node(s) collected but not executed"
                    )
            elif self.expected_nodes:
                self.instrument = Outcome.PASS
        if self.product is Outcome.NOT_RUN and not (missing or unrun) and self.expected_nodes:
            self.product = Outcome.PASS

    @property
    def combined(self) -> Outcome:
        """Reported gate state.

        ``spec/verification.md``: an independently content-addressed product
        failure is retained alongside an invalid detector. Dominance is applied
        only when such an address exists; otherwise the instrument condition is
        reported, because an instrument that may be broken cannot be trusted to
        have produced a product finding.
        """
        if self.product is Outcome.PRODUCT_FAILURE and self.product_observations:
            return Outcome.PRODUCT_FAILURE
        if self.instrument is Outcome.INVALID_HARNESS:
            return Outcome.INVALID_HARNESS
        if self.product is Outcome.PRODUCT_FAILURE:
            return Outcome.PRODUCT_FAILURE
        if self.instrument is Outcome.NOT_RUN or self.product is Outcome.NOT_RUN:
            return Outcome.NOT_RUN
        return Outcome.PASS

    def as_json(self, records: Mapping[str, NodeRecord]) -> dict:
        executed = [
            n
            for n in self.expected_nodes
            if n in records and records[n].outcome is not Outcome.NOT_RUN
        ]
        return {
            "gate": self.gate,
            "reported": self.combined.value,
            "instrument_channel": self.instrument.value,
            "product_channel": self.product.value,
            "independently_content_addressed_product_observations": list(
                self.product_observations
            ),
            "expected_nodes": len(self.expected_nodes),
            "executed_nodes": len(executed),
            "not_run_nodes": len(self.expected_nodes) - len(executed),
            "instrument_reasons": list(self.instrument_reasons),
            "product_reasons": list(self.product_reasons),
        }


@dataclass
class Census:
    """The total execution census for one run."""

    gates: dict[str, GateState]
    records: dict[str, NodeRecord] = field(default_factory=dict)
    #: Kill-ledger digest, when the product-independent ledger ran.
    kill_ledger_digest: str = ""
    kill_ledger_sound: bool = False
    catalog_digest: str = ""
    mutation: str = ""
    detector_mutation: str = ""
    collection_errors: list[str] = field(default_factory=list)

    @classmethod
    def build(cls) -> "Census":
        expected: dict[str, list[str]] = {g: [] for g in GROUPS}
        for obligation in OBLIGATIONS:
            for node in obligation.nodes:
                expected.setdefault(obligation.gate, []).append(node)
        gates = {
            g: GateState(gate=g, expected_nodes=tuple(sorted(set(expected.get(g, ())))))
            for g in GROUPS
        }
        return cls(gates=gates)

    # -- recording --------------------------------------------------------

    def record(self, node: str, gate: str) -> NodeRecord:
        if node not in self.records:
            self.records[node] = NodeRecord(
                node=node,
                gate=gate,
                expected=any(node.endswith(e) for e in self._expected_suffixes()),
            )
        return self.records[node]

    def _expected_suffixes(self) -> tuple[str, ...]:
        out: list[str] = []
        for state in self.gates.values():
            out.extend(state.expected_nodes)
        return tuple(out)

    def resolve(self) -> None:
        # Map full pytest node ids onto the catalog's module::function names.
        normalised: dict[str, NodeRecord] = {}
        for record in self.records.values():
            normalised[_normalise(record.node)] = record
        for state in self.gates.values():
            state.resolve(normalised)

    # -- reporting --------------------------------------------------------

    def as_json(self) -> dict:
        self_json = {
            "schema": "guildhall-acceptance-census/1",
            "catalog_digest": self.catalog_digest,
            "kill_ledger_digest": self.kill_ledger_digest,
            "kill_ledger_sound": self.kill_ledger_sound,
            "mutation": self.mutation,
            "detector_mutation": self.detector_mutation,
            "collection_errors": list(self.collection_errors),
            "gate_vector": {
                g: self.gates[g].combined.value for g in GROUPS
            },
            "gates": {
                g: self.gates[g].as_json(
                    {_normalise(r.node): r for r in self.records.values()}
                )
                for g in GROUPS
            },
            "nodes": [r.as_json() for r in sorted(self.records.values(), key=lambda r: r.node)],
        }
        return self_json

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.as_json(), sort_keys=True).encode("utf-8")
        ).hexdigest()

    def gate_vector(self) -> dict[str, str]:
        return {g: self.gates[g].combined.value for g in GROUPS}

    def any_non_green(self) -> bool:
        return any(o != Outcome.PASS.value for o in self.gate_vector().values())


def _normalise(node_id: str) -> str:
    """Reduce a pytest node id to ``module.py::function``.

    Strips directory prefixes and parametrisation suffixes so a parametrised
    node still counts as executing its catalog-named function.
    """
    tail = node_id.split("/")[-1]
    if "[" in tail:
        tail = tail.split("[", 1)[0]
    return tail
