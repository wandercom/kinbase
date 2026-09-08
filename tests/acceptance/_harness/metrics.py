"""Classification metrics computed by the harness from raw predictions.

Detector Reviewer finding 12: every V-2 number came from the product's own
report. ``macro_f1``, ``shared_precision``, ``exact_match_atomization`` and the
calibration bounds were read out of the JSON the system under test emitted, so
an implementation could report 0.94 without classifying anything.

Here the product supplies only *raw per-message predictions* --- the atoms it
found and the destinations it chose, keyed by the opaque per-run identifier it
was given. The harness joins those to Tester-held gold, counts the confusion
matrix itself, and derives every bound with the frozen interval methods:
message-stratified bootstrap for macro-F1 and a Wilson interval for each shared
precision. The product's own reported numbers are then compared to the
harness numbers, and a disagreement is a product failure.

The join goes through :func:`acceptance._harness.prereq.gold_join`, so a
prediction set that does not cover the gold set is an instrument condition
rather than a silently partial denominator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from . import prereq, stats
from .requirements import HarnessInvalid

#: The four ratified destination labels.
DESTINATIONS: tuple[str, ...] = ("personal", "company", "codebase", "none")

#: Destinations that leave the Personal boundary. Their precision floor is the
#: one V-2 states separately.
SHARED_DESTINATIONS: tuple[str, ...] = ("company", "codebase")


@dataclass(frozen=True)
class Prediction:
    """One product prediction for one opaque message identifier."""

    token: str
    atoms: tuple[tuple[str, str, tuple[str, ...]], ...]
    confidence: str = "high"

    @property
    def destinations(self) -> frozenset[str]:
        return frozenset(d for _, _, ds in self.atoms for d in ds)


@dataclass(frozen=True)
class GoldRecord:
    """Tester-held gold for one opaque message identifier."""

    token: str
    atoms: tuple[tuple[str, str, tuple[str, ...]], ...]
    mixed: bool
    stratum: str

    @property
    def destinations(self) -> frozenset[str]:
        return frozenset(d for _, _, ds in self.atoms for d in ds)


def parse_predictions(payload: Any) -> dict[str, Prediction]:
    """Read raw per-message predictions from a product payload.

    Nothing derived is accepted here: only the atoms and their destinations.
    A malformed entry is dropped from the mapping, which makes the join in
    :func:`joined` report it as an unanswered gold record.
    """
    out: dict[str, Prediction] = {}
    entries = payload if isinstance(payload, list) else []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        token = entry.get("id")
        atoms = entry.get("atoms")
        if not isinstance(token, str) or not isinstance(atoms, list):
            continue
        parsed: list[tuple[str, str, tuple[str, ...]]] = []
        for atom in atoms:
            if not isinstance(atom, Mapping):
                continue
            kind = atom.get("atom_kind", atom.get("kind"))
            text = atom.get("text")
            destinations = atom.get("proposed_destinations", atom.get("destinations"))
            if isinstance(destinations, str):
                destinations = [destinations]
            if not isinstance(destinations, list):
                continue
            parsed.append((
                str(kind), str(text),
                tuple(sorted(str(d) for d in destinations)),
            ))
        confidence = entry.get("confidence")
        out[token] = Prediction(
            token=token,
            atoms=tuple(parsed),
            confidence=str(confidence) if isinstance(confidence, str) else "high",
        )
    return out


def parse_gold(gold: Mapping[str, Mapping[str, Any]]) -> dict[str, GoldRecord]:
    out: dict[str, GoldRecord] = {}
    for token, record in gold.items():
        atoms = tuple(
            (str(kind), str(text), tuple(sorted(str(d) for d in destinations)))
            for kind, text, destinations in record["atoms"]
        )
        out[token] = GoldRecord(
            token=token, atoms=atoms,
            mixed=bool(record.get("mixed")),
            stratum=str(record.get("stratum", "")),
        )
    return out


@dataclass
class Joined:
    """Predictions joined to gold on the opaque identifier."""

    tokens: tuple[str, ...]
    predictions: dict[str, Prediction]
    gold: dict[str, GoldRecord]

    def per_label_counts(self) -> dict[str, tuple[int, int, int]]:
        counts: dict[str, list[int]] = {d: [0, 0, 0] for d in DESTINATIONS}
        for token in self.tokens:
            predicted = self.predictions[token].destinations
            truth = self.gold[token].destinations
            for destination in DESTINATIONS:
                in_pred = destination in predicted
                in_gold = destination in truth
                if in_pred and in_gold:
                    counts[destination][0] += 1
                elif in_pred and not in_gold:
                    counts[destination][1] += 1
                elif in_gold and not in_pred:
                    counts[destination][2] += 1
        return {k: (v[0], v[1], v[2]) for k, v in counts.items()}

    def per_label_metrics(self) -> list[dict]:
        out = []
        for destination, (tp, fp, fn) in sorted(self.per_label_counts().items()):
            precision, recall, f1 = stats.precision_recall_f1(tp, fp, fn)
            out.append({
                "destination": destination, "tp": tp, "fp": fp, "fn": fn,
                "precision": precision, "recall": recall, "f1": f1,
            })
        return out

    def macro_f1(self) -> float:
        return stats.macro_f1(self.per_label_counts())

    def per_message_f1(self) -> list[tuple[str, float]]:
        """Message-level F1 over destination sets, for the stratified bootstrap."""
        out: list[tuple[str, float]] = []
        for token in self.tokens:
            predicted = self.predictions[token].destinations
            truth = self.gold[token].destinations
            tp = len(predicted & truth)
            fp = len(predicted - truth)
            fn = len(truth - predicted)
            _, _, f1 = stats.precision_recall_f1(tp, fp, fn)
            out.append((self.gold[token].stratum or "unstratified", f1))
        return out

    def macro_f1_lower_bound(self, *, seed: int, resamples: int = 2000) -> float:
        lower, _ = stats.stratified_bootstrap_macro_f1(
            self.per_message_f1(), seed=seed, resamples=resamples
        )
        return lower

    def shared_precision_lower_bounds(self) -> list[dict]:
        counts = self.per_label_counts()
        out = []
        for destination in SHARED_DESTINATIONS:
            tp, fp, _ = counts[destination]
            lower, _ = stats.wilson(tp, tp + fp)
            out.append({
                "destination": destination,
                "value": lower,
                "successes": tp,
                "trials": tp + fp,
            })
        return out

    def exact_match_atomisation(self) -> float:
        """Fraction of messages whose atom boundaries match gold exactly."""
        if not self.tokens:
            return 0.0
        exact = 0
        for token in self.tokens:
            predicted = tuple(sorted(
                (text.strip().lower(), destinations)
                for _, text, destinations in self.predictions[token].atoms
            ))
            truth = tuple(sorted(
                (text.strip().lower(), destinations)
                for _, text, destinations in self.gold[token].atoms
            ))
            if predicted == truth:
                exact += 1
        return exact / len(self.tokens)

    def private_to_shared_detection(self) -> dict:
        """How often a gold-personal atom was routed to a shared destination."""
        leaks = 0
        personal_atoms = 0
        for token in self.tokens:
            truth = {text.strip().lower(): destinations
                     for _, text, destinations in self.gold[token].atoms}
            for _, text, destinations in self.predictions[token].atoms:
                gold_destinations = truth.get(text.strip().lower())
                if gold_destinations is None:
                    continue
                if "personal" in gold_destinations:
                    personal_atoms += 1
                    if set(destinations) & set(SHARED_DESTINATIONS):
                        leaks += 1
        return {
            "gold_personal_atoms": personal_atoms,
            "routed_to_shared": leaks,
            "detection_rate": (
                1.0 - (leaks / personal_atoms) if personal_atoms else 0.0
            ),
        }

    def calibration_and_abstention(self) -> dict:
        low = [t for t in self.tokens if self.predictions[t].confidence == "low"]
        abstained = [
            t for t in self.tokens
            if not (self.predictions[t].destinations - {"none"})
        ]
        return {
            "low_confidence_messages": len(low),
            "abstained_messages": len(abstained),
            "abstention_rate": len(abstained) / len(self.tokens) if self.tokens else 0.0,
        }

    def mixed_message_detail(self) -> list[dict]:
        out = []
        for token in self.tokens:
            if not self.gold[token].mixed:
                continue
            prediction = self.predictions[token]
            out.append({
                "message_id": token,
                "atom_count": len(prediction.atoms),
                "distinct_destination_count": len(prediction.destinations),
            })
        return out

    def as_json(self) -> dict:
        return {
            "joined_messages": len(self.tokens),
            "per_label": self.per_label_metrics(),
            "macro_f1": self.macro_f1(),
            "exact_match_atomization": self.exact_match_atomisation(),
            "private_to_shared_detection": self.private_to_shared_detection(),
            "calibration_and_abstention": self.calibration_and_abstention(),
        }


def joined(predictions: Mapping[str, Prediction],
           gold: Mapping[str, GoldRecord], *, name: str) -> Joined:
    tokens = prereq.gold_join(predictions, gold, name=name)
    return Joined(tokens=tokens, predictions=dict(predictions), gold=dict(gold))


def agrees(reported: Any, computed: float, *, tolerance: float = 1e-6) -> bool:
    """Does the product's own reported metric match the harness computation?"""
    if isinstance(reported, bool) or not isinstance(reported, (int, float)):
        return False
    return abs(float(reported) - computed) <= tolerance


def pooled_shared_precision(runs: Sequence["Joined"]) -> list[dict]:
    """Wilson lower bound per shared destination over *pooled* predictions.

    ``spec/verification.md`` V-2: "shared precision a Wilson interval over
    pooled frozen predictions". Pooling is not an optimisation: a single
    60-message run caps the bound at roughly 0.94 even for a perfect
    classifier, so an unpooled interval would fail the ratified 0.95 floor by
    construction rather than by measurement.
    """
    if not runs:
        raise HarnessInvalid(
            "pooled shared precision needs at least one frozen run; an empty "
            "pool cannot support an interval"
        )
    out = []
    for destination in SHARED_DESTINATIONS:
        tp = 0
        fp = 0
        for run in runs:
            counts = run.per_label_counts()[destination]
            tp += counts[0]
            fp += counts[1]
        lower, upper = stats.wilson(tp, tp + fp)
        out.append({
            "destination": destination,
            "value": lower,
            "upper": upper,
            "successes": tp,
            "trials": tp + fp,
            "pooled_runs": len(runs),
        })
    return out


def pooled_macro_f1_lower_bound(runs: Sequence["Joined"], *, seed: int,
                                resamples: int = 2000) -> float:
    """Message-stratified bootstrap over every frozen run's per-message F1."""
    if not runs:
        raise HarnessInvalid("macro-F1 needs at least one frozen run")
    per_message: list[tuple[str, float]] = []
    for run in runs:
        per_message.extend(run.per_message_f1())
    lower, _ = stats.stratified_bootstrap_macro_f1(
        per_message, seed=seed, resamples=resamples
    )
    return lower
