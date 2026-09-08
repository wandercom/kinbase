"""Product-independent regression guards for Validator dispatch 007.

These test the instrument, never a product snapshot. Authority references are
resolved by the ordinary signed-artifact backreference checker.
"""
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from ._harness import lifecycle as L
from ._harness import lifecycle_observations as LO
from ._harness.requirements import ProductFailure, VERIFY, spec_ref
from ._harness.worldbuilder import SignedWorld, start_session

pytestmark = pytest.mark.selftest


@spec_ref(VERIFY("INSTRUMENT", "v1", "Every declared cell has an expected observation/current-fact/Unknown state and at least one negative mutation."))
def test_all_native_lifecycle_transitions_execute_without_product(tmp_path: Path):
    world = SignedWorld.create(tmp_path / "repo")
    ctx = L.LifecycleContext(world, world.repo.path / "sources", tmp_path / "external")
    ctx.sources.mkdir(parents=True)
    ctx.external.mkdir()
    witnesses = {cell.key: cell.run(ctx) for cell in L.verify_table()}
    assert len(witnesses) == 64
    assert all(w["source_tree_before"] != w["source_tree_after"]
               or w.get("tree_unchanged_is_the_point") for w in witnesses.values())
    import json
    from ._harness import synth
    for path in (ctx.sources / "answers").glob("*.json"):
        assert synth.verify_document("answer", json.loads(path.read_bytes()))
    with sqlite3.connect(ctx.sources / "kindex" / "kindex.sqlite3") as conn:
        assert [r[1] for r in conn.execute("PRAGMA table_info(nodes)")] == [
            "id", "node_type", "title", "content", "payload", "created_at"]
        assert conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0] >= 2
        assert conn.execute("SELECT COUNT(*) FROM nodes WHERE id = 'kx-1'").fetchone()[0] == 1


def _snapshot(state="current", disposition="accepted"):
    return {"receipt_counts": {"repo_code": 1}, "observations": [
        {"observation_id": "obs-1", "source_kind": "repo_code",
         "source_identity": "src/window.py", "content_digest": "a" * 64,
         "state": state, "disposition": disposition}],
        "facts": [{"logical_key": "window", "state": state,
                   "statement": "four retries", "disposition": disposition,
                   "evidence_refs": ["obs-1"]}], "unknowns": []}


@spec_ref(VERIFY("INSTRUMENT", "v1", "Every declared cell has an expected observation/current-fact/Unknown state and at least one negative mutation."))
def test_lifecycle_oracle_uses_public_records_and_rejects_count_only_evidence():
    cell = next(c for c in L.CELLS if c.key == "repo_code::create")
    witness = {"source_tree_before": "a", "source_tree_after": "b"}
    positive = _snapshot()
    result = LO.derive(cell, witness, {}, positive)
    assert result["states_match"] and result["adapter_receipts_present"]
    assert "negative_mutation_killed" not in result
    assert not LO.derive(cell, witness, {}, {"receipt_counts": {"repo_code": 1}})["states_match"]
    wrong_adapter = _snapshot()
    wrong_adapter["observations"][0]["source_kind"] = "docs_adr"
    assert not LO.derive(cell, witness, {}, wrong_adapter)["states_match"]
    unlinked = _snapshot()
    unlinked["facts"][0]["evidence_refs"] = ["someone-else"]
    assert not LO.derive(cell, witness, {}, unlinked)["states_match"]
    # A previously captured source cannot conceal a missing derivation for a
    # newly appended source from the same adapter.
    appended = _snapshot()
    appended["observations"].append({**appended["observations"][0],
                                     "observation_id": "new-obs",
                                     "source_identity": "src/new.py"})
    assert not LO.derive(cell, witness, _snapshot(), appended)["states_match"]
    # Harness labels and claimed mutation outcomes have no influence.
    positive["lifecycle_cells"] = [{"cell": cell.cell, "negative_mutation_killed": True}]
    assert LO.derive(cell, witness, {}, positive) == result


@spec_ref(VERIFY("INSTRUMENT", "v1", "Every declared cell has an expected observation/current-fact/Unknown state and at least one negative mutation."))
def test_lifecycle_delete_rejects_current_fact_and_missing_unknown():
    cell = next(c for c in L.CELLS if c.key == "repo_code::delete")
    witness = {"source_tree_before": "a", "source_tree_after": "b"}
    before = _snapshot()
    after = _snapshot("retracted", "retracted")
    after["unknowns"] = [{"question_id": "q-1", "logical_key": "window", "status": "open"}]
    assert LO.derive(cell, witness, before, after)["states_match"]
    after["facts"][0]["state"] = "current"
    assert not LO.derive(cell, witness, before, after)["states_match"]
    after["facts"][0]["state"] = "retracted"
    after["unknowns"] = []
    assert not LO.derive(cell, witness, before, after)["states_match"]


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_session_id_is_read_from_start_response():
    calls = []
    class Driver:
        payload = {"session_id": "product-issued-42"}
        def run(self, *args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0, json=self.payload)
    driver = Driver()
    assert start_session(driver, Path("/repo")) == "product-issued-42"
    assert calls[0][:2] == ("session", "start")
    driver.payload = {}
    with pytest.raises(ProductFailure, match="no session identifier"):
        start_session(driver, Path("/repo"))


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_host_diff_oracle_checks_bytes_and_rejects_unplanned_content():
    from ._harness import hosts
    patch = "--- a/config\n+++ b/config\n@@ -1 +1 @@\n-old\n+new\n"
    plan = {"files": [{"path": ".host/config", "diff": patch}]}
    before = {".host/config": "old\n"}
    assert hosts.installed_files_match_plan(plan, before, {".host/config": "new\n"})
    assert not hosts.installed_files_match_plan(plan, before, {".host/config": "wrong\n"})
    assert not hosts.installed_files_match_plan(plan, {}, {".host/config": "new\n"})
    plan["files"][0]["path"] = "../project/settings.json"
    assert not hosts.installed_files_match_plan(plan, before, {})


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_cache_clear_retains_installed_certificate(roots):
    from ._harness import trust
    original = roots.client_root / trust.CERTIFICATE_DIR / "uuid.json"
    original.parent.mkdir()
    original.write_bytes(b"certificate fixture")
    cached = roots.company_cache / "uuid" / "certificate.json"
    cached.parent.mkdir()
    cached.write_bytes(original.read_bytes())
    derived = roots.company_cache / "facts.sqlite3"
    derived.write_bytes(b"derived cache")
    assert trust.remove_cache(roots) == 1
    assert cached.read_bytes() == original.read_bytes()
    assert not derived.exists()


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_host_recorder_precedes_even_an_explicit_path(roots, monkeypatch):
    from ._harness import cli, hosts
    import os
    monkeypatch.setattr(cli, "_resolve_entrypoint", lambda: ("unused-product",))
    directory = roots.run_root / "hostbin" / "codex"
    wrapper = hosts.install_invocation_recorder(directory, "codex", Path("/bin/echo"))
    assert wrapper == directory / "codex"
    assert os.access(wrapper, os.X_OK)
    driver = cli.Guildhall(home=roots.home, xdg_config_home=roots.xdg_config_home,
                          cwd=roots.repo_root, path_prefix=[directory])
    env = driver.base_env({"PATH": "/usr/bin:/bin"})
    assert env["PATH"].split(os.pathsep)[0] == str(directory)
    assert driver.base_env(env)["PATH"] == env["PATH"]
