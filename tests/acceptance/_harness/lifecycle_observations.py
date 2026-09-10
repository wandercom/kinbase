"""C15: derive lifecycle evidence from public records, never product cell labels.

Authority: spec/verification.md V-1 lifecycle matrix (digest in requirements.py),
spec/architecture.md section 3 Observation/FactEvent, Validator dispatch 007 C15.
The private matrix labels remain expectations in lifecycle.py. This module joins
observations to facts by evidence_refs and Unknowns by affected logical_key.
No reported mutation outcome participates; the named mutation run owns that fact.
"""
from __future__ import annotations

from . import canonical

STATES = frozenset(("current", "stale", "retracted", "foreign", "quarantined"))
RETIRED = frozenset(("stale", "retracted", "foreign", "quarantined"))


def records(document, key):
    value = document.get(key, [])
    return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []


def _tokens(value):
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return set().union(*(_tokens(v) for v in value)) if value else set()
    if isinstance(value, dict):
        return set().union(*(_tokens(v) for v in value.values())) if value else set()
    return set()


def observations(status, adapter):
    return [r for r in records(status, "observations")
            if r.get("source_kind", r.get("adapter")) == adapter]


def receipt_count(status, adapter):
    counts = status.get("adapter_receipts", status.get("receipt_counts", {}))
    if isinstance(counts, dict):
        count = counts.get(adapter)
        if isinstance(count, int) and not isinstance(count, bool):
            return count
    for row in records(status, "adapters"):
        if row.get("adapter", row.get("source_kind")) == adapter:
            count = row.get("receipt_count")
            if isinstance(count, int) and not isinstance(count, bool):
                return count
    return None


def _facts(status, obs):
    ids = {o.get("observation_id") for o in obs} - {None}
    return [f for f in records(status, "facts")
            if ids & _tokens(f.get("evidence_refs", []))]


def _current(facts):
    return [f for f in facts if f.get("state") == "current"]


def _projection(facts):
    # Identity and meaning of current facts; receipts and timestamps can advance.
    return sorted(canonical.jcs({k: f.get(k) for k in
                                ("logical_key", "statement", "disposition")})
                  for f in _current(facts))


def _questions(status, facts, obs):
    keys = {f.get("logical_key") for f in facts} - {None}
    ids = {o.get("observation_id") for o in obs} - {None}
    return [q for q in records(status, "unknowns")
            if q.get("logical_key") in keys
            or keys & _tokens(q.get("affected_logical_keys", []))
            or ids & _tokens(q.get("evidence_refs", []))]


def _open(questions):
    return [q for q in questions if q.get("status", q.get("state"))
            in ("open", "pending", "reopened", "unknown")]


def derive(cell, witness, before, after):
    """Return an evidence row, including raw public fields for audit.

    Scope is the adapter and the changed/removed native identities in this step.
    No evidence from a different adapter can license a missing observation.
    """
    prior = observations(before, cell.adapter)
    seen = observations(after, cell.adapter)
    prior_by_id = {r.get("observation_id"): r for r in prior}
    changed = [r for r in seen if prior_by_id.get(r.get("observation_id")) != r]
    # A replay legitimately has no changed observation, but must retain the
    # records established by the previous ingest, not just a source count.
    targets = changed or seen
    old_facts, facts = _facts(before, prior), _facts(after, seen)
    affected_facts = _facts(after, targets)
    identities = {o.get("source_identity") for o in targets} - {None}
    relevant_prior = [o for o in prior if o.get("source_identity") in identities]
    prior_affected_facts = _facts(before, relevant_prior)
    questions = _questions(after, affected_facts + prior_affected_facts,
                           relevant_prior + targets)
    old_questions = _questions(before, prior_affected_facts, relevant_prior)
    states = [o.get("state") for o in targets]
    dispositions = [o.get("disposition") for o in targets]
    observation_ok = bool(targets) and all(s in STATES for s in states) \
        and all(isinstance(d, str) and d for d in dispositions)
    if cell.observation in ("removed_observation", "absent_source_recorded",
                            "retracted_observation", "revoked_observation"):
        observation_ok = observation_ok and bool(changed) and any(s in RETIRED for s in states)
    elif cell.observation == "superseded_observation":
        observation_ok = observation_ok and bool(changed) and any(
            r.get("state") in RETIRED or r.get("disposition") == "superseded" for r in seen)
    elif cell.observation == "amended_new_observation":
        observation_ok = observation_ok and bool(changed)
    elif cell.observation == "expired_raw_withheld" and cell.fact != "current":
        observation_ok = observation_ok and any(s in RETIRED for s in states)
    elif cell.observation == "conflicting_observations":
        observation_ok = observation_ok and len(seen) >= 2

    # A surviving fact from a previous native source cannot license an ignored
    # new source. Terminal/retention transitions intentionally preserve facts.
    current = _current(affected_facts)
    if cell.observation in ("terminal", "expired_raw_withheld") and cell.fact == "current":
        current = _current(facts)
    if cell.fact == "current":
        fact_ok = bool(current)
    elif cell.fact == "conflict":
        fact_ok = bool(affected_facts) and any(f.get("state") == "conflict" for f in affected_facts)
    elif cell.fact == "unchanged":
        fact_ok = _projection(facts) == _projection(old_facts)
    elif cell.fact == "recomputed":
        fact_ok = bool(affected_facts) and bool(changed or witness.get("rebuild_digest"))
    else:
        affected_ids = {o.get("observation_id") for o in targets} - {None}
        affected = [f for f in facts if affected_ids & _tokens(f.get("evidence_refs", []))]
        fact_ok = bool(affected) and not _current(affected)
        if cell.fact == "absent":
            fact_ok = not affected

    opened = _open(questions)
    previously_open = _open(old_questions)
    if cell.unknown in ("opened", "reopened"):
        unknown_ok = bool(opened)
    elif cell.unknown == "owner_scoped":
        unknown_ok = bool(opened) and all(q.get("owner") for q in opened)
    elif cell.unknown == "closed":
        unknown_ok = not opened
    else:
        old_ids = {q.get("question_id", q.get("event_id")) for q in previously_open}
        unknown_ok = all(q.get("question_id", q.get("event_id")) in old_ids for q in opened)

    count = receipt_count(after, cell.adapter)
    replay = witness.get("replay_status")
    replay_ok = True
    if witness.get("repeat_ingest"):
        replay_ok = isinstance(replay, dict) and observations(replay, cell.adapter) == seen \
            and _projection(_facts(replay, seen)) == _projection(facts)
    return {
        "adapter": cell.adapter, "cell": cell.cell, "native_format": cell.native_format,
        "expected_observation_state": cell.observation,
        "expected_fact_state": cell.fact, "expected_unknown_state": cell.unknown,
        "observed_observation_state": {"states": states, "dispositions": dispositions},
        "observed_fact_state": [f.get("state") for f in facts],
        "observed_unknown_state": [q.get("status", q.get("state")) for q in questions],
        "states_match": bool(observation_ok and fact_ok and unknown_ok and replay_ok),
        "adapter_receipts_present": isinstance(count, int) and count > 0,
        "observations": targets, "facts": facts, "unknowns": questions,
        "transition_executed_natively": witness["source_tree_before"] != witness["source_tree_after"]
            or witness.get("tree_unchanged_is_the_point", False),
        "source_tree_before": witness["source_tree_before"],
        "source_tree_after": witness["source_tree_after"],
        "negative_mutation": cell.mutation_id,
    }
