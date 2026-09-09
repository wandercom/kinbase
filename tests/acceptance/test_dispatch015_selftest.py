"""Dispatch 015 regressions: synthetic harness evidence, never an operator run."""
import copy
import hashlib
import json
import shutil
import subprocess
import sys

import pytest

from ._harness import auxsel, consumption, corpora
from ._harness.requirements import HarnessInvalid, VERIFY, spec_ref
from ._harness.roots import ProofRoots
from . import test_v9_fatigue as fatigue

pytestmark = pytest.mark.selftest
REFERENCE = VERIFY("INSTRUMENT", "fail-closed", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.")


@spec_ref(REFERENCE)
def test_pool_projection_and_byte_framing_are_reproducible(tmp_path):
    pool = json.loads((auxsel.AUXILIARY / "pool.json").read_bytes())
    projected = auxsel.project(pool)
    # Independent framing assembly, including a CRLF byte distinction.
    raw = json.dumps(projected, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("utf-8")
    blocks = [raw] + [(auxsel.AUXILIARY / name).read_bytes() for name in auxsel.DOCUMENTS]
    expected = hashlib.sha256(b"guildhall-auxiliary-pool-digest/1\0" + b"".join(
        len(block).to_bytes(8, "big") + block for block in blocks)).hexdigest()
    assert auxsel.verify() == expected
    mutable = copy.deepcopy(pool)
    for key in ("rights_basis", "selectable", "status", "blocking", "selection_record",
                "pool_digest_sha256", "digest_binds", "superseded_pool_digests"):
        mutable[key] = "changed"
    assert auxsel.compute(mutable) == expected
    for section, field in (("candidates", "version"), ("candidates", "sha256"),
                           ("generated_components", "seed"), ("generated_components", "sha256")):
        changed = copy.deepcopy(pool)
        changed[section][0][field] = "changed"
        assert auxsel.compute(changed) != expected
    changed = copy.deepcopy(pool)
    changed["candidates"].reverse()
    assert auxsel.compute(changed) != expected
    changed = copy.deepcopy(pool)
    changed["generation"]["algorithms"]["decoys"] += "changed"
    assert auxsel.compute(changed) != expected
    shutil.copytree(auxsel.AUXILIARY, tmp_path / "aux")
    rights = tmp_path / "aux/RIGHTS.md"
    rights.write_bytes(rights.read_bytes().replace(b"\n", b"\r\n"))
    assert auxsel.compute(pool, tmp_path / "aux") != expected


@spec_ref(REFERENCE)
@pytest.mark.parametrize("target", ["POOL-DIGEST", "pool.json", "sources/encoding-practice.txt", "decoys.json", "RIGHTS.md", "GRANT-TEMPLATE.md", "SELECTION-PROTOCOL.md"])
def test_auxsel_cli_refuses_tampering(tmp_path, target):
    directory = tmp_path / "tests/fixtures/auxiliary"
    shutil.copytree(auxsel.AUXILIARY, directory)
    path = directory / target
    if target == "pool.json":
        pool = json.loads(path.read_bytes())
        pool["pool_digest_sha256"] = "0" * 64
        path.write_text(json.dumps(pool))
    else:
        path.write_bytes(path.read_bytes() + b"tampered")
    result = subprocess.run([sys.executable, "-m", "acceptance._harness.auxsel",
                             "--verify", "--pool-dir", str(directory), "--root", str(tmp_path)],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "mismatch" in result.stderr


@spec_ref(REFERENCE)
def test_current_grant_and_selection_remain_required(tmp_path):
    shutil.copytree(auxsel.AUXILIARY, tmp_path / "aux")
    directory = tmp_path / "aux"
    for name in ("RE-ATTESTATION.md", "SELECTION.json"):
        (directory / name).unlink(missing_ok=True)
    pool = json.loads((auxsel.AUXILIARY / "pool.json").read_bytes())
    with pytest.raises(HarnessInvalid, match="RE-ATTESTATION.md.*steps 4-6"):
        auxsel.require_review(directory, pool, "0" * 64)


@spec_ref(REFERENCE)
def test_prior_process_operator_recording_joins_and_fanout_is_not_penalized(tmp_path, monkeypatch):
    # Exercise real scoring without crediting synthetic evidence to a V-9 run.
    monkeypatch.setattr(consumption, "record", lambda *args, **kwargs: None)
    # Synthetic responses intentionally read gold in the producer process. They
    # prove harness mechanics only and must never be reported as a human run.
    producer = r'''
import json, sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from acceptance._harness import corpora
exercise = corpora.load_gold("operator_exercise.json")
bound = corpora.bind_operator_exercise(exercise, Path(sys.argv[1]))
start = datetime(2026, 9, 9, tzinfo=timezone.utc)
rows = [{"item_id": bound.ids.token(item["item_id"]), "decision": item["gold_decision"],
         "also_belongs_in": ["company"] if item["proposed_destination"] == "codebase" else [],
         "decided_at": (start + timedelta(seconds=20*i)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        for i, item in enumerate(exercise["items"])]
Path(sys.argv[2]).write_text("\n".join(json.dumps(row) for row in rows) + "\n")
'''
    presentation = tmp_path / "presentation.jsonl"
    responses = tmp_path / "synthetic-responses.jsonl"
    subprocess.run([sys.executable, "-c", producer, str(presentation), str(responses)], check=True)
    monkeypatch.setenv(fatigue.OPERATOR_RESPONSES_ENV, str(responses))
    captured = []
    real_check = fatigue.O.check

    def checked(oid, observation, **kwargs):
        captured.append(observation)
        return real_check(oid, observation, **kwargs)

    monkeypatch.setattr(fatigue.O, "check", checked)
    roots = ProofRoots.create(tmp_path / "proof", company_port=0)
    fatigue.test_blinded_operator_exercise_accuracy_and_median_time(roots)
    assert captured[0]["decisions_recorded"] == 20
    assert captured[0]["accuracy"] == 1.0
    assert captured[0]["median_decision_seconds"] == 20.0
    raw = presentation.read_text()
    assert "gold_decision" not in raw and "gold_reason" not in raw
    assert "Proposed destination:" in raw
    exercise = corpora.load_gold("operator_exercise.json")
    changed = copy.deepcopy(exercise)
    changed["items"][0]["rendered_statement"] += " changed"
    rebound = corpora.bind_operator_exercise(changed, tmp_path / "changed.jsonl")
    recorded_ids = {json.loads(line)["item_id"] for line in responses.read_text().splitlines()}
    assert not recorded_ids.intersection(rebound.gold)
