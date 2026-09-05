"""Product-bound corpora, with gold stripped at the boundary.

Detector Reviewer finding 7, items 1 and 5. The V-2 runtime JSONL was built with
``{**record, "text": text}``, so every message handed to ``session observe``
carried its own ``gold_atoms``, ``mixed`` flag and stratum. The V-9 maintenance
workload was handed to the product whole, including ``durable_shared_fact``,
``gold_label``, ``gold_correct_admission``, trust class and severity rank.

Both are fixed here by construction rather than by discipline. A product-bound
record is *built* from a closed key set; there is no path by which a gold field
can travel, because the builder never copies the source record.

Message identity is a per-run opaque token. A stable ``message_id`` would let an
implementation memorise the answer key across runs; the opaque token carries no
information and the mapping back to gold exists only in the harness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import planters
from .requirements import HarnessInvalid
from .worldbuilder import OpaqueIds

#: The closed set of keys a product-bound record may carry. Enforced by
#: ``test_control_policy.py``; nothing outside it is ever written.
PRODUCT_VISIBLE_KEYS: frozenset[str] = frozenset({
    "id",          # per-run opaque token, no information content
    "role",        # conversational role, part of the native transcript shape
    "text",        # the raw message
    "observed_at", # arrival time, part of the native shape
    "source_kind", # which adapter produced it
})


@dataclass
class BoundCorpus:
    """A product-bound corpus plus the tester-held mapping back to gold."""

    path: Path
    ids: OpaqueIds
    gold: dict[str, dict]           # opaque token -> tester-held gold
    record_count: int
    #: Every key that was written, for the leak assertion.
    written_keys: frozenset[str] = field(default_factory=frozenset)

    def gold_for(self, token: str) -> dict:
        try:
            return self.gold[token]
        except KeyError as exc:
            raise HarnessInvalid(
                f"no tester-held gold for opaque id {token!r}"
            ) from exc

    def assert_no_gold_written(self) -> None:
        leaked = sorted(self.written_keys - PRODUCT_VISIBLE_KEYS)
        if leaked:
            raise HarnessInvalid(
                f"product-bound corpus carries non-visible keys {leaked}"
            )
        raw = self.path.read_text(encoding="utf-8")
        for forbidden in (
            "gold_atoms", "gold_label", "gold_correct_admission", "gold_decision",
            "durable_shared_fact", "expected_state", "stratum", "mixed",
            "distortion_severity_rank", "origin_trust_class",
        ):
            if forbidden in raw:
                raise HarnessInvalid(
                    f"product-bound corpus at {self.path} contains {forbidden!r}"
                )


def _emit(records: Sequence[Mapping[str, Any]], path: Path) -> frozenset[str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    keys: set[str] = set()
    lines: list[str] = []
    for index, record in enumerate(records):
        bound = {k: v for k, v in record.items() if k in PRODUCT_VISIBLE_KEYS}
        # Detector Reviewer finding 7: the corpus the product ingests is raw
        # pre-execution state; a corpus planter defects it here, after gold is
        # stripped and before a single byte is written.
        bound = planters.mutate("corpus.record", bound, index=index, path=str(path))
        keys.update(bound)
        lines.append(json.dumps(bound, sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    planters.witness_path(path)
    return frozenset(keys)


def bind_routing_corpus(
    gold_corpus: Mapping[str, Any],
    canary_values: Mapping[str, str],
    destination: Path,
    *,
    seed: bytes | None = None,
) -> BoundCorpus:
    """Instantiate the held-out V-2 corpus for the product.

    The product receives ``{id, role, text, observed_at, source_kind}`` and
    nothing else. Atom boundaries, destination sets, the mixed flag and the
    stratum stay in the returned ``gold`` map, which never leaves the harness.
    """
    ids = OpaqueIds(seed)
    records: list[dict] = []
    gold: dict[str, dict] = {}
    for index, message in enumerate(gold_corpus["messages"]):
        text = message["template"]
        for slot in message["canary_slots"]:
            if slot not in canary_values:
                raise HarnessInvalid(f"no instantiated value for canary slot {slot!r}")
            text = text.replace("{" + slot + "}", canary_values[slot])
        token = ids.token(message["message_id"])
        records.append({
            "id": token,
            "role": "user",
            "text": text,
            "observed_at": f"2026-03-01T00:{index // 60:02d}:{index % 60:02d}.000Z",
            "source_kind": "codex_jsonl",
        })
        gold[token] = {
            "atoms": message["gold_atoms"],
            "mixed": message["mixed"],
            "stratum": message["stratum"],
            "canary_slots": message["canary_slots"],
            "destinations": sorted(
                {d for _, _, ds in message["gold_atoms"] for d in ds}
            ),
        }
    written = _emit(records, destination)
    corpus = BoundCorpus(
        path=destination, ids=ids, gold=gold, record_count=len(records),
        written_keys=written,
    )
    corpus.assert_no_gold_written()
    return corpus


def bind_maintenance_workload(
    workload: Mapping[str, Any], destination: Path, *, seed: bytes | None = None
) -> BoundCorpus:
    """Instantiate the V-9 maintenance workload for the product.

    ``durable_shared_fact``, ``gold_label``, ``gold_correct_admission``,
    ``origin_trust_class`` and ``distortion_severity_rank`` are tester-held. The
    product sees raw observations in arrival order and must derive priority from
    the content and its own authority reasoning.
    """
    ids = OpaqueIds(seed)
    records: list[dict] = []
    gold: dict[str, dict] = {}
    for observation in workload["observations"]:
        token = ids.token(observation["observation_id"])
        window = observation["arrival_window"]
        records.append({
            "id": token,
            "role": "user",
            "text": _observation_text(observation),
            "observed_at": f"2026-03-{window + 1:02d}T00:00:00.000Z",
            "source_kind": observation["source_kind"],
        })
        gold[token] = {
            "durable": observation["durable_shared_fact"],
            "label": observation["gold_label"],
            "correct_admission": observation["gold_correct_admission"],
            "trust": observation["origin_trust_class"],
            "severity": observation["distortion_severity_rank"],
            "window": window,
        }
    written = _emit(records, destination)
    corpus = BoundCorpus(
        path=destination, ids=ids, gold=gold, record_count=len(records),
        written_keys=written,
    )
    corpus.assert_no_gold_written()
    return corpus


def _observation_text(observation: Mapping[str, Any]) -> str:
    """Render a maintenance observation as raw prose only.

    The text is deliberately built from the *content* the reducer must judge ---
    durability language, authority language, incident language --- never from the
    gold label. A product that reads the prose correctly will rank it correctly;
    one that cannot will not find the answer anywhere in its input.
    """
    label = observation["gold_label"]
    subject = observation["observation_id"]
    if label == "durable_shared_fact":
        return (
            f"Reviewed and merged on the default branch: the {subject} handling "
            "rule is owned by the architecture authority and applies to every "
            "deployment of this service."
        )
    if label == "low_authority_churn":
        return (
            f"Draft note on an unreviewed branch about {subject}; formatting "
            "only, no decision, reverted shortly afterwards."
        )
    return (
        f"During today's incident we temporarily adjusted {subject}; revert once "
        "the incident closes."
    )


def bind_operator_exercise(
    exercise: Mapping[str, Any], destination: Path
) -> BoundCorpus:
    """Instantiate the blinded 20-item operator exercise.

    The operator sees the rendered statement and proposed destination. The gold
    decision and its rationale stay in the harness, so an operator (or a product
    rendering the queue) cannot read the answer off the item.
    """
    ids = OpaqueIds()
    records: list[dict] = []
    gold: dict[str, dict] = {}
    for item in exercise["items"]:
        token = ids.token(item["item_id"])
        records.append({
            "id": token,
            "role": "assistant",
            "text": item["rendered_statement"],
            "observed_at": "2026-03-01T00:00:00.000Z",
            "source_kind": "codex_jsonl",
        })
        gold[token] = {
            "decision": item["gold_decision"],
            "reason": item["gold_reason"],
            "destination": item["proposed_destination"],
            "atom_kind": item["atom_kind"],
        }
    written = _emit(records, destination)
    corpus = BoundCorpus(
        path=destination, ids=ids, gold=gold, record_count=len(records),
        written_keys=written,
    )
    corpus.assert_no_gold_written()
    return corpus


def load_gold(name: str) -> dict:
    """Read a tester-held gold fixture. Never passed to the product."""
    path = Path(__file__).resolve().parents[2] / "fixtures" / "gold" / name
    if not path.is_file():
        raise HarnessInvalid(f"tester-held gold fixture missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))
