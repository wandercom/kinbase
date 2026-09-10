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
    expected = hashlib.sha256(b"kinbase-auxiliary-pool-digest/1\0" + b"".join(
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
