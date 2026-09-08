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
    witnesses = {cell.key: cell.run(ctx) for cell in L.execution_cells(reversed(L.verify_table()))}
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


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_privacy_runner_forwards_stdin_and_environment(tmp_path):
    from . import test_v3_privacy as privacy
    calls = []
    class Driver:
        def run(self, *args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0)
    privacy._run(Driver(), "hooks", "dispatch", cwd=tmp_path,
                 stdin='{"cwd":"/fixture"}', env={"PATH": "/fixture/bin"})
    assert calls[0][1]["stdin"] == '{"cwd":"/fixture"}'
    assert calls[0][1]["env"] == {"PATH": "/fixture/bin"}
    assert calls[0][1]["check"] is False


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_reconstructor_reads_pool_digest_without_a_product(roots, vault, monkeypatch):
    from . import test_v3_privacy as privacy
    from ._harness import auxgen, matrix
    captured = []
    # Only the terminal obligation sink is replaced. Real surface planting,
    # scanning, vault sealing and frozen-pool lookup execute normally.
    monkeypatch.setattr(privacy.O, "check", lambda oid, payload, **kw: captured.append(payload))
    privacy.test_reconstructor_findings_are_independent_and_content_addressed(
        roots, matrix.SurfaceRoots.create(roots), vault)
    assert captured[0]["auxiliary_corpus_digest"] == auxgen.pool_digest()
    assert len(captured[0]["auxiliary_corpus_digest"]) == 64
    assert captured[0]["exact_recovery"]["cells"] > 0


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_temporal_branch_preserves_plants_on_reducer_revision(tmp_path):
    import json
    from ._harness import worldbuilder as W
    world = SignedWorld.create(tmp_path / "repo")
    # The double is a transport acknowledgement only, not an authority oracle.
    world.company = SimpleNamespace(
        registry=SimpleNamespace(is_registered=lambda authority: True),
        admit_fact=lambda document: {"admitted": True})
    for case in W.TEMPORAL_CASES:
        W.plant_temporal_history(world, case)
    world.verify_planted()
    assert world.repo.run("branch", "--show-current").strip() == world.repo.default_branch
    event = next(r for r in world.codebase_records() if r["logical_key"].endswith("branch-adr"))
    assert json.loads((world.repo.path / event["path"]).read_bytes())["disposition"] == "proposed"
    assert world.repo.run("ls-tree", "attacker/plant-adr", "--", event["path"]).strip()
    assert world.repo.run("ls-tree", "HEAD", "--", event["path"]).strip()
    # The loss detector still rejects a genuinely missing event.
    (world.repo.path / event["path"]).unlink()
    with pytest.raises(ProductFailure, match="missing"):
        world.verify_planted()


@spec_ref(VERIFY("INSTRUMENT", "v1", "Every declared cell has an expected observation/current-fact/Unknown state and at least one negative mutation."))
def test_dispatch008_transcript_dependencies_survive_destructive_expiry(tmp_path):
    world = SignedWorld.create(tmp_path / "repo")
    ctx = L.LifecycleContext(world, world.repo.path / "sources", tmp_path / "external")
    ctx.sources.mkdir()
    ctx.external.mkdir()
    cells = L.execution_cells(reversed(L.verify_table()))
    for adapter in ("codex_jsonl", "claude_jsonl"):
        selected = [c for c in cells if c.adapter == adapter]
        assert selected[0].cell == "create"
        assert [c.cell for c in selected][-3:] == ["missing source", "restart", "raw expiry"]
        for cell in selected:
            witness = cell.run(ctx)
            if cell.cell == "raw expiry":
                # Simulate only the documented deletion side effect, not a host.
                Path(witness["native_path"]).unlink()
    assert len(cells) == 64


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_classifier_config_pins_product_and_uses_ruling_fields(roots, tmp_path):
    import hashlib
    import tomllib
    from ._harness import trust
    executable = tmp_path / "guildhall-fixture"
    executable.write_text("#!/bin/sh\nexit 99\n")
    executable.chmod(0o700)
    driver = SimpleNamespace(entrypoint=(str(executable),))
    classifier = trust.resolve_classifier(roots, driver, model="ollama:fixture-model")
    assert classifier.args == ("classifier", "--json")
    assert classifier.source == "product"
    assert classifier.sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()
    config = roots.write_user_config(
        classifier_path=classifier.path, classifier_sha256=classifier.sha256,
        classifier_args=classifier.args, classifier_model=classifier.model,
        facts_token_file=tmp_path / "facts.token", root_public_key_file=tmp_path / "root.pub")
    table = tomllib.loads(config.read_text())["classifier"]
    assert table["model"] == "ollama:fixture-model"
    assert table["args"] == ["classifier", "--json"]
    assert table["executable_sha256"] == classifier.sha256
    response = {"classifier_pinned": True, "classifier": {
        "provider": "ollama", "executable_sha256": classifier.sha256}}
    doctor = SimpleNamespace(xdg_config_home=roots.xdg_config_home,
                             run=lambda *a, **kw: SimpleNamespace(json=response))
    trust.verify_classifier_spawn(doctor, roots.repo_root)
    response["classifier_pinned"] = False
    with pytest.raises(ProductFailure, match="after spawn"):
        trust.verify_classifier_spawn(doctor, roots.repo_root)
    # Absence of model selects structural rule/replay operation.
    roots.rewrite_user_config(classifier_model=None)
    assert "model" not in tomllib.loads(config.read_text())["classifier"]


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_hook_json_requires_one_base64_envelope():
    import base64
    import json
    from ._harness import canonical, hosts
    body = canonical.jcs({"facts": []})
    framed = str(len(body)).encode() + b"\n" + body
    response = json.dumps({"envelope": base64.b64encode(framed).decode()})
    assert hosts.decode_dispatch_json(response) == [{"facts": []}]
    for malformed in (response + "\n{}", "{}", '{"envelope":"not base64"}',
                      json.dumps({"envelope": base64.b64encode(framed + b"tail").decode()}),
                      json.dumps({"envelope": base64.b64encode(framed[:-1]).decode()})):
        with pytest.raises(ProductFailure):
            hosts.decode_dispatch_json(malformed)


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_receipt_clock_does_not_rewrite_historical_validity(monkeypatch):
    import datetime
    from ._harness import synth
    monkeypatch.setattr("time.time", lambda: 1800000000)
    monkeypatch.setenv("GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS", "60")
    timestamp = datetime.datetime.fromisoformat(synth.receipt_stamp(-240).replace("Z", "+00:00"))
    assert timestamp.timestamp() == 1800000000 + 60 - 240
    event = synth.fact_event(store_kind="codebase", authority_id="a", authority_scope="codebase:r",
                             logical_key="historical", statement="a historical claim",
                             asserted_at="1990-01-01T00:00:00.000Z",
                             effective_from="1990-01-01T00:00:00.000Z")
    assert event["asserted_at"] == "1990-01-01T00:00:00.000Z"
    assert event["effective_from"] == event["asserted_at"]


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_revocation_is_a_new_signed_registry_publication(tmp_path, monkeypatch):
    from ._harness import synth, trust
    world = SignedWorld.create(tmp_path / "repo")
    registry = trust.AuthorityRegistry(steward=world.steward)
    registry.register(world.architect, channel="architecture:scheduling")
    documents = []
    def publish(registry, client, roots, *, cursor):
        documents.append(registry.document(cursor=cursor))
    monkeypatch.setattr(trust, "publish_registry", publish)
    anchors = SimpleNamespace(registry=registry, client=None, roots=None)
    anchors.republish_registry = lambda **kw: trust.TrustAnchors.republish_registry(anchors, **kw)
    trust.TrustAnchors.revoke(anchors, world.architect, cursor=str(int(registry.cursor) + 1))
    assert len(documents) == 1
    assert not documents[0]["entries"]
    assert synth.verify_document("authority-registry-entry", documents[0])
    assert int(documents[0]["authority_cursor"]) > 1000


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_normalisation_plants_a_codebase_alias_in_git(tmp_path, monkeypatch):
    import json
    from . import test_v4_maintenance as maintenance
    world = SignedWorld.create(tmp_path / "repo")
    captured = []
    class Driver:
        def run(self, *args, **kwargs):
            assert args[:2] == ("fsck", "--repo")
            return SimpleNamespace(returncode=0, json={"admitted_paths": []})
    monkeypatch.setattr(maintenance.O, "check", lambda oid, payload, **kw: captured.append(payload))
    maintenance.test_case_crlf_normalisation_and_uppercase_alias_are_refused(Driver(), (world, None))
    event = world.codebase_records()[0]
    assert event["path"] is not None
    original = (world.repo.path / event["path"]).read_bytes()
    assert json.loads(original)["store_kind"] == "codebase"
    paths = world.repo.run("ls-tree", "-r", "--name-only", "HEAD").splitlines()
    aliases = [p for p in paths if p.startswith(".kin/events/") and p != p.lower()]
    assert len(aliases) == 1
    assert aliases[0].endswith(".json")
    assert captured[0]["canonical_bytes_identical"]
    # The index and object database carry the alias even on case-insensitive disks.
    assert world.repo.run("show", "HEAD:" + aliases[0]).encode().strip() == original


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch008_company_criticality_and_prediction_fields_follow_rulings():
    from ._harness import metrics, synth
    event = synth.fact_event(store_kind="company", authority_id="architect",
                             authority_scope="architecture:scheduling",
                             logical_key="window", statement="preserve the wire format")
    assert event["distortion"]["loss_if_absent"] == "safety_critical"
    predictions = metrics.parse_predictions([{"id": "opaque-1", "atoms": [{
        "text": "preserve the wire format", "atom_kind": "constraint",
        "proposed_destinations": ["company"], "confidence": "high"}]}])
    assert predictions["opaque-1"].destinations == frozenset({"company"})
    assert predictions["opaque-1"].atoms[0][0] == "constraint"
