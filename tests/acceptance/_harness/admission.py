"""Read the automatic-admission audit trail without restoring an approval API.

Receipt counts are recomputed from durable event bytes. Missing records are a
product failure, and an empty fixture cannot manufacture a successful receipt.
"""
from collections import Counter
import json
from pathlib import Path
import tomllib

from .requirements import ProductFailure


def personal_root(driver):
    config = driver.xdg_config_home / "kinbase/config.toml"
    if config.is_file():
        return Path(tomllib.loads(config.read_text())["personal"]["data_root"])
    return driver.home / ".local/state/kinbase/codebase-personal"


def records(path, *, required=False):
    if not path.is_file():
        if required:
            raise ProductFailure(f"required durable admission ledger is missing: {path}")
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def audit(driver, repo, session):
    root = personal_root(driver)
    observations = [r for r in records(root / "observations.jsonl", required=True)
                    if r.get("source_identity") == f"session:{session}"]
    by_id = {r["observation_id"]: r for r in observations}
    atoms = [a for a in records(root / "atoms.jsonl", required=True)
             if a.get("observation_id") in by_id]
    candidates = [c for c in records(root / "candidates.jsonl") if c.get("session_id") == session]
    ids = {c["candidate_id"] for c in candidates}
    latest = {}
    for receipt in records(root / "proposal-decisions.jsonl"):
        if receipt.get("candidate_id") in ids:
            latest[receipt["candidate_id"]] = receipt
    apologies = {}
    for row in records(root / "apologies.jsonl"):
        # Apology transitions are partial append-only updates.
        key = row.get("apology_id")
        if key:
            apologies.setdefault(key, {}).update(row)
    event_docs = [json.loads(p.read_bytes()) for p in (Path(repo) / ".kin/events").rglob("*.json")]
    counts = Counter(d.get("event_id") for d in event_docs)
    predictions = []
    for observation in by_id.values():
        selected = [a for a in atoms if a.get("observation_id") == observation["observation_id"]]
        predictions.append({"id": observation["native_id"],
                            "confidence": "low" if selected and min(a["confidence"] for a in selected) < 4000 else "high",
                            "atoms": [{**a, "text": a["statement"], "proposed_destinations": [d.split(":")[0] for d in a["proposed_destinations"]] or ["none"]} for a in selected]})
    fanout = {}
    for receipt in latest.values():
        destination = receipt.get("destination", "").split(":")[0]
        fanout[destination] = receipt
    reported_atoms = [{**a, "confidence": "low" if a["confidence"] < 4000 else "medium" if a["confidence"] < 7500 else "high",
                       "destination": destination}
                      for a in atoms for destination in (a["proposed_destinations"] or ["none"])]
    return {"candidates": candidates, "atoms": reported_atoms, "predictions": predictions,
            "receipts": list(latest.values()), "fanout_receipts": fanout,
            "apologies": list(apologies.values()),
            "duplicate_events": sum(n - 1 for n in counts.values()),
            "committed_event_count": len(event_docs),
            "recursive_apologies": sum(a.get("failed_receipt_id") in apologies for a in apologies.values()),
            "deidentify_retains_taint": bool(atoms) and all(
                a.get("hard_blocked") and bool(a.get("taints")) and not a.get("eligible_destinations")
                for a in atoms)}


def required_rows(payload, key):
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ProductFailure(f"required product array {key!r} is missing or malformed")
    return value
