"""Validity checks and presentation fields for the blinded routing instrument.

Shortcut accuracy is the optimal empirical majority-label lookup for each
metadata value (or tuple), not a guessed heuristic. Statement content is the
task; unique response tokens/timestamps are transport, not predictive features.
Including either in an in-sample lookup would trivially memorize the gold.
"""
from collections import Counter, defaultdict
from itertools import combinations

from .requirements import HarnessInvalid


# The binder renders this same closed metadata set. Global instructions, role
# and source kind are constant, so adding them cannot improve a lookup score.
DISPLAYED_FIELDS = (
    ("atom_kind", "Atom kind"),
    ("proposed_destination", "Proposed destination"),
)
PREDICTABILITY_MAXIMUM = 0.70
REQUIRED_MISROUTES = {
    "organization_to_personal": {"personal"},
    "private_to_shared": {"company", "codebase"},
    "repository_to_company": {"company"},
    "transient_to_store": {"personal", "company", "codebase"},
}


def predictability(exercise):
    """Return all single/pair scores and their maxima, using exact counts."""
    items = exercise["items"]
    fields = [key for key, _ in DISPLAYED_FIELDS]
    scores = {}
    for size in (1, 2):
        for selected in combinations(fields, size):
            groups = defaultdict(Counter)
            for item in items:
                groups[tuple(item[key] for key in selected)][item["gold_decision"]] += 1
            scores[selected] = sum(max(labels.values()) for labels in groups.values()) / len(items)
    return {
        "scores": scores,
        "best_single": max(score for fields, score in scores.items() if len(fields) == 1),
        "best_pair": max(score for fields, score in scores.items() if len(fields) == 2),
    }


def validate(exercise):
    """Refuse defective instruments before presentation or response loading."""
    def require(condition, message):
        if not condition:
            raise HarnessInvalid("operator exercise: " + message)

    items = exercise.get("items", [])
    require(exercise.get("schema") == "guildhall-acceptance-operator-exercise/2",
            "schema must define routing-action decisions")
    require(exercise.get("blinded") is True, "must remain blinded")
    require(exercise.get("item_count") == len(items) == 20, "must contain exactly 20 items")
    require(exercise.get("thresholds") == {
        "accuracy_minimum": 0.95, "median_decision_seconds_maximum": 30.0,
    }, "frozen thresholds changed")
    for key in ("decision_semantics", "routing_context"):
        require(isinstance(exercise.get(key), str) and exercise[key].strip(),
                f"missing {key}")
    for item in items:
        for key in ("item_id", "atom_kind", "proposed_destination",
                    "rendered_statement", "gold_reason"):
            require(isinstance(item.get(key), str) and item[key].strip(),
                    f"missing item {key}")
        require(item.get("gold_decision") in {"approve", "reject"}, "invalid gold label")
    require(len({i["item_id"] for i in items}) == 20, "duplicate item IDs")
    require(len({i["gold_reason"] for i in items}) == 20, "gold reasons must be item-specific")
    require(exercise.get("approval_count") == sum(i["gold_decision"] == "approve" for i in items),
            "approval count differs from gold")
    require({i["proposed_destination"] for i in items} == {"personal", "company", "codebase", "none"},
            "destination coverage changed")
    metrics = predictability(exercise)
    for fields, accuracy in metrics["scores"].items():
        require(accuracy <= PREDICTABILITY_MAXIMUM,
                f"predictability {fields}: {accuracy:.0%} exceeds 70%")
    for destination in ("personal", "company", "codebase", "none"):
        require({i["gold_decision"] for i in items if i["proposed_destination"] == destination}
                == {"approve", "reject"}, f"{destination} must carry both labels")
    for category, destinations in REQUIRED_MISROUTES.items():
        matches = [i for i in items if i.get("gold_misroute") == category]
        require(bool(matches), f"missing misroute coverage: {category}")
        require(all(i["gold_decision"] == "reject" and i["proposed_destination"] in destinations
                    for i in matches), f"invalid misroute coverage: {category}")
    return metrics
