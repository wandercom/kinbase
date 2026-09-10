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
    for cell in L.CELLS:
        witness = witnesses[cell.key]
        assert LO.derive(cell, witness, {}, {})["transition_executed_natively"] is True
        if "registry_revoke" in witness:
            assert witness["source_tree_before"] == witness["source_tree_after"]
            assert witness["tree_unchanged_is_the_point"] is True
            assert witness["tree_unchanged_reason"] == "revocation occurs in the external registry"
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
    unchanged = {"source_tree_before": "a", "source_tree_after": "a"}
    assert LO.derive(cell, unchanged, {}, positive)["transition_executed_natively"] is False
    unchanged["tree_unchanged_is_the_point"] = True
    assert LO.derive(cell, unchanged, {}, positive)["transition_executed_natively"] is True


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
    driver = cli.Kinbase(home=roots.home, xdg_config_home=roots.xdg_config_home,
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
        events = W.plant_temporal_history(world, case)
        assert len(events) >= 2, case.case_id
        if case.case_id in {"expired_incident_workaround", "runtime_freshness_lapsed",
                            "unregistered_environment"}:
            documents = [json.loads((world.repo.path / event["path"]).read_bytes())
                         for event in events]
            assert documents[0]["event_id"] in documents[1]["supersedes"]
            assert documents[0]["event_id"] in documents[1]["parents"]
            assert documents[0]["authority_scope"] == documents[1]["authority_scope"]
        world.verify_planted()
        # Every intermediate reducer revision must carry all previous plants.
        assert all(world._tracked(r["path"]) for r in world.codebase_records())
    world.verify_planted()
    assert world.repo.run("branch", "--show-current").strip() == world.repo.default_branch
    event = next(r for r in world.codebase_records() if r["logical_key"].endswith("branch-adr"))
    assert json.loads((world.repo.path / event["path"]).read_bytes())["disposition"] == "proposed"
    assert world.repo.run("ls-tree", "attacker/plant-adr", "--", event["path"]).strip()
    assert world.repo.run("ls-tree", "HEAD", "--", event["path"]).strip()
    assert "attacker/plant-adr" not in world.repo.run("branch", "--merged", "HEAD")
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
def test_dispatch008_classifier_config_pins_product_and_uses_ruling_fields(roots, tmp_path, monkeypatch):
    import hashlib
    import tomllib
    from ._harness import trust
    monkeypatch.delenv("KINBASE_CLASSIFIER_MODEL", raising=False)
    executable = tmp_path / "kinbase-fixture"
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
    monkeypatch.setenv("KINBASE_PROOF_CLOCK_OFFSET_SECONDS", "60")
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
            return SimpleNamespace(returncode=0, json={"admitted_paths": [
                {"path": world.codebase_records()[0]["path"]}]})
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


@pytest.mark.parametrize("day,expected", [
    (1, "2026-03-01"), (30, "2026-03-30"), (32, "2026-04-01"),
    (60, "2026-04-29"), (307, "2027-01-01"),
])
@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch009_synthetic_dates_use_calendar_arithmetic(day, expected):
    from datetime import datetime
    from ._harness import synth
    stamp = synth._stamp(day=day)
    assert stamp == expected + "T00:00:00.000Z"
    assert datetime.fromisoformat(stamp.replace("Z", "+00:00")).isoformat().startswith(expected)
    # Transcript generators also pass unbounded minute offsets.
    assert synth._stamp(day=31, hour=23, minute=61) == "2026-04-01T00:01:00.000Z"


@pytest.mark.parametrize("host", ["codex", "claude"])
@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch009_latency_gates_read_numeric_percentiles(roots, monkeypatch, host):
    from contextlib import contextmanager
    from . import test_v9_host_lifecycle as gates
    from ._harness import hosts
    from ._harness.worldbuilder import OpaqueIds
    world = SignedWorld.create(roots.repo_root)
    captured = {}
    configured = []

    @contextmanager
    def blackhole(port):
        assert port == 0
        yield SimpleNamespace(port=43123)

    @contextmanager
    def endpoint(url):
        configured.append(url)
        yield

    class Driver:
        def run(self, *args, **kwargs):
            return SimpleNamespace(returncode=0, duration_s=0.25,
                                   json={"company_connect_seconds": 0.1,
                                         "degraded": True})

    # Transport and listener doubles only; actual gate loops, state construction,
    # envelope construction and percentile implementation execute.
    monkeypatch.setattr(gates, "Blackhole", blackhole)
    monkeypatch.setattr(gates.O, "check", lambda oid, payload, **kw: captured.update({oid: payload}))
    anchors = SimpleNamespace(company_endpoint=endpoint)
    driver = Driver()
    gates.test_session_start_p95_under_two_seconds_in_every_state(
        driver, roots, (world, anchors), host, None, OpaqueIds(seed=b"latency-009"))
    latency = captured["V-9.latency"]
    assert {s["state"] for s in latency["states"]} == set(gates.START_STATES)
    assert all(s["state_constructed"] and s["invocations"] == hosts.INVOCATIONS_PER_HOST_STATE
               and s["p95_seconds"] == 0.25 for s in latency["states"])
    gates.test_blackholed_company_endpoint_degrades_loudly_inside_the_budget(
        driver, roots, (world, anchors), host, None, OpaqueIds(seed=b"blackhole-009"))
    observed = captured["V-9.blackhole"]
    assert isinstance(observed["p95_seconds"], float)
    assert observed["payload_count"] == 20
    assert configured == ["http://127.0.0.1:43123"]


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch009_claim_rejects_bad_strings_and_quotes_observation(roots):
    from . import test_v3_privacy as privacy
    valid = privacy.V3_CLAIM_FRAGMENT + " kinbase-atm/1"
    manifest = SimpleNamespace(artifact_digests={"spec/threat-model.md": "a" * 64})

    class Driver:
        claim = valid
        def run(self, *args, **kwargs):
            return SimpleNamespace(returncode=0, json={
                "privacy_claim": self.claim, "execution_census_digest": "b" * 64})

    driver = Driver()
    world = SimpleNamespace(repo=SimpleNamespace(path=roots.repo_root))
    privacy.test_v3_claim_is_digest_qualified_and_never_unqualified(
        driver, roots, (world, None), manifest)
    for claim in (valid + " Privacy Proved", valid + " ZERO LEAKAGE",
                  privacy.V3_CLAIM_FRAGMENT, "", None):
        driver.claim = claim
        with pytest.raises(ProductFailure) as failure:
            privacy.test_v3_claim_is_digest_qualified_and_never_unqualified(
                driver, roots, (world, None), manifest)
        assert repr(claim) in str(failure.value)
        assert "problems=" in str(failure.value)
        if claim and ("Privacy Proved" in claim or "ZERO LEAKAGE" in claim):
            assert "forbidden_phrases_found" in str(failure.value)
            assert "forbidden phrase" in str(failure.value)


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch009_restart_diagnostic_failure_quotes_product_output(roots, monkeypatch):
    from . import test_nonfunctional as nf
    world = SimpleNamespace(repo=SimpleNamespace(path=roots.repo_root),
                            architect=None, maintainer=None,
                            plant_event=lambda *args, **kwargs: None)

    class Driver:
        def run(self, *args, **kwargs):
            if args[0] == "questions":
                return SimpleNamespace(returncode=0, json=[], stdout="[]\n",
                                       stderr="fixture diagnostic string\n")
            return SimpleNamespace(returncode=0, json={"ok": True},
                                   stdout='{"ok":true}\n', stderr="")

    driver = Driver()
    monkeypatch.setattr(nf, "Kinbase", lambda **kwargs: driver)
    with pytest.raises(ProductFailure) as failure:
        nf.test_diagnostics_are_executable_and_useful_after_restart(
            driver, roots, (world, None))
    text = str(failure.value)
    assert "[3]" in text and "useful" in text
    assert '"stdout": "[]\\n"' in text
    assert '"stderr": "fixture diagnostic string\\n"' in text
    assert '"argv": ["questions", "list", "--json"]' in text
    assert '"returncode": 0' in text


@spec_ref(VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS."))
def test_dispatch009_partial_fanout_binds_before_redirecting_company(roots, monkeypatch):
    from contextlib import contextmanager
    from . import test_v2_classification as gates
    from ._harness import service
    events = []
    captured = []
    world = SimpleNamespace(repo=SimpleNamespace(path=roots.repo_root))

    class Socket:
        def __init__(self, *args):
            self.bound = False
        def setsockopt(self, *args):
            pass
        def bind(self, address):
            # Treat all explicit ports as already occupied, including Company.
            assert address == ("127.0.0.1", 0)
            self.bound = True
            events.append("bind")
        def getsockname(self):
            assert self.bound
            return ("127.0.0.1", 43124)
        def listen(self, backlog):
            events.append("listen")
        def close(self):
            events.append("close")

    @contextmanager
    def endpoint(url):
        assert events == ["bind", "listen"]
        assert url == "http://127.0.0.1:43124"
        events.append("redirect")
        yield
        events.append("restore")

    def observe(*args):
        assert events[-1] == "redirect"
        return {"status": "observed"}

    monkeypatch.setattr(service.socket, "socket", Socket)
    monkeypatch.setattr(gates, "start_session", lambda *args: "session-issued")
    monkeypatch.setattr(gates, "_observe", observe)
    monkeypatch.setattr(gates, "_admissions", lambda *args: {})
    monkeypatch.setattr(gates, "_fanout_pair", lambda *args: ("local-issued", "company-issued"))
    monkeypatch.setattr(gates.O, "check", lambda oid, payload, **kw: captured.append(oid))
    anchors = SimpleNamespace(company_endpoint=endpoint, repository_uuid="uuid")
    gates.test_partial_fanout_failure_does_not_roll_back_committed_destination(
        None, (world, anchors), SimpleNamespace(path=roots.run_root / "corpus"), roots)
    assert events == ["bind", "listen", "redirect", "restore", "close"]
    assert captured == ["V-2.partial-fanout"]


_REMEDIATION_010 = VERIFY("INSTRUMENT", "positive-controls", "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.")


@spec_ref(_REMEDIATION_010)
def test_dispatch010_control_removal_restores_native_bytes_and_keeps_detector_armed(roots):
    from ._harness import matrix as MX
    from ._harness.gitfix import GitRepo
    surfaces = MX.SurfaceRoots.create(roots)
    repo = GitRepo.init(surfaces.repo)
    repo.write("baseline.md", "baseline must survive\n")
    head = repo.commit("baseline")
    log = surfaces.state / "kinbase.log"
    log.write_text("original log\n")
    planted = MX.Matrix.plant(surfaces, seed=20260907)
    receipts = planted.receipts(planted.detector())
    assert len(receipts) == planted.expected_cells
    assert all(row["detected"] for row in receipts)
    registry = dict(planted.registry)
    # An unexpected copy is not a control location and must survive cleanup.
    residual = surfaces.state / "unexpected-copy.log"
    residual.write_text(planted.cells[0].raw_value)
    assert planted.remove() == len(planted.cells)
    assert planted.registry == registry
    assert repo.head() == head
    assert repo.run("status", "--porcelain") == ""
    assert log.read_text() == "original log\n"
    assert any(planted.sweep(planted.detector()).values())
    residual.unlink()
    assert not any(planted.sweep(planted.detector()).values())


@spec_ref(_REMEDIATION_010)
def test_dispatch010_positive_control_gate_reaches_real_clean_assertion(roots, vault):
    from . import test_v3_privacy as gate
    from ._harness.matrix import SurfaceRoots
    gate.test_positive_control_precedes_and_licenses_the_clean_assertion(
        SurfaceRoots.create(roots), vault)


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("destination", ["personal", "company", "codebase"])
@pytest.mark.parametrize("pooled", [False, True])
def test_dispatch010_zero_shared_predictions_are_product_failures(destination, pooled):
    from ._harness import metrics
    gold = {"m": metrics.GoldRecord("m", (("fact", "message", ("company", "codebase")),), False, "one")}
    prediction = metrics.Prediction("m", (("fact", "message", (destination,)),))
    joined = metrics.joined({"m": prediction}, gold, name="synthetic-empty-destination")
    with pytest.raises(ProductFailure, match="empty predictions.*trials=0"):
        if pooled:
            metrics.pooled_shared_precision([joined] * 5)
        else:
            joined.shared_precision_lower_bounds()


@spec_ref(_REMEDIATION_010)
def test_dispatch010_empty_prediction_map_and_missing_instrument_pool_are_distinct():
    from ._harness import metrics, stats
    from ._harness.requirements import HarnessInvalid
    gold = {"m": metrics.GoldRecord("m", (), False, "one")}
    with pytest.raises(ProductFailure, match="empty predictions; predictions=0, gold=1"):
        metrics.joined({}, gold, name="empty-product-response")
    with pytest.raises(HarnessInvalid, match="at least one frozen run"):
        metrics.pooled_shared_precision([])
    with pytest.raises(ValueError, match="trials > 0"):
        stats.wilson(0, 0)
    gold["m"] = metrics.GoldRecord("m", (("fact", "message", ("company", "codebase")),), False, "one")
    good = metrics.Joined(("m",), {"m": metrics.Prediction("m", gold["m"].atoms)}, gold)
    bounds = metrics.pooled_shared_precision([good] * 100)
    assert all(row["trials"] == 100 and row["value"] > .95 for row in bounds)


@spec_ref(_REMEDIATION_010)
def test_dispatch010_normalisation_reports_product_refusals_before_universal_claim(roots):
    from . import test_v4_maintenance as gate
    world = SignedWorld.create(roots.repo_root)
    status = {"admitted_paths": [], "refusal_counts": {"INEFFECTIVE_ATTRIBUTES": 2},
              "ineffective_git_attributes": True}
    driver = SimpleNamespace(run=lambda *a, **kw: SimpleNamespace(returncode=3, json=status))
    with pytest.raises(ProductFailure, match='"refusal_counts": {"INEFFECTIVE_ATTRIBUTES": 2}') as error:
        gate.test_case_crlf_normalisation_and_uppercase_alias_are_refused(driver, (world, None))
    assert "normalisation remains unmeasured" in str(error.value)
    assert "[V-4.normalisation]" not in str(error.value)


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("path", [".kin/observations.jsonl", ".kin/atoms.jsonl", "ordinary.txt"])
def test_dispatch010_merge_private_store_overwrite_is_typed_product_observation(tmp_path, path):
    from ._harness.gitfix import GitRepo
    from ._harness.requirements import HarnessInvalid
    repo = GitRepo.init(tmp_path / "merge")
    repo.write(path, "base\n")
    repo.commit("base")
    repo.branch("topic")
    repo.write(path, "branch\n")
    repo.commit("branch")
    repo.checkout("main")
    repo.write(path, "uncommitted product write\n")
    expected = HarnessInvalid if path == "ordinary.txt" else ProductFailure
    with pytest.raises(expected, match="would be overwritten") as error:
        repo.merge("topic")
    assert (repo.path / path).read_text() == "uncommitted product write\n"
    if expected is ProductFailure:
        assert "[P-3] private-store surface violation" in str(error.value)


@spec_ref(_REMEDIATION_010)
def test_dispatch010_classifier_override_is_config_only(roots, tmp_path, monkeypatch):
    import tomllib
    from ._harness import cli, trust
    from ._harness.controls import HARNESS_ONLY
    from ._harness.requirements import HarnessInvalid
    executable = tmp_path / "fixture-classifier"
    executable.write_text("#!/bin/sh\nexit 99\n")
    executable.chmod(0o700)
    monkeypatch.setattr(cli, "_resolve_entrypoint", lambda: (str(executable),))
    driver = cli.Kinbase(home=roots.home, xdg_config_home=roots.xdg_config_home, cwd=roots.repo_root)
    monkeypatch.setenv("KINBASE_CLASSIFIER_MODEL", "ollama:glm-5.3:cloud")
    for default in (None, "ollama:qwen2.5:7b"):
        pin = trust.resolve_classifier(roots, driver, model=default)
        config, _ = trust.write_user_config(roots, company_url="http://127.0.0.1:1",
                                          facts_token="fixture-token", root_key=tmp_path / "root.pub",
                                          classifier=pin)
        assert tomllib.loads(config.read_text())["classifier"]["model"] == "ollama:glm-5.3:cloud"
        assert "KINBASE_CLASSIFIER_MODEL" not in driver.base_env()
    assert "KINBASE_CLASSIFIER_MODEL" in HARNESS_ONLY
    monkeypatch.setenv("KINBASE_CLASSIFIER_MODEL", "")
    with pytest.raises(HarnessInvalid, match="live model"):
        trust.resolve_classifier(roots, driver)
    monkeypatch.delenv("KINBASE_CLASSIFIER_MODEL")
    assert trust.resolve_classifier(roots, driver).model is None


@spec_ref(_REMEDIATION_010)
def test_dispatch010_popen_explicit_stdin_pipe_with_fixture_process(roots, monkeypatch):
    import subprocess
    import sys
    from ._harness import cli
    monkeypatch.setattr(cli, "_resolve_entrypoint", lambda: (sys.executable,))
    driver = cli.Kinbase(home=roots.home, xdg_config_home=roots.xdg_config_home, cwd=roots.repo_root)
    # A tester-owned Python echo process, never the product or a host executable.
    child = driver.popen("-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())", stdin=subprocess.PIPE)
    stdout, stderr = child.communicate(b'{"fixture":"envelope"}', timeout=10)
    assert child.returncode == 0 and not stderr
    assert stdout == b'{"fixture":"envelope"}'


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("transition", ["nonce_reservation", "event_append_rename", "manifest", "receipt", "apology"])
@pytest.mark.parametrize("source", ["repo", "private", "status"])
def test_dispatch010_kill_witness_uses_journal_and_reaps_sigkill(roots, monkeypatch, transition, source):
    import json
    import signal
    from . import test_v2_classification as gate
    candidate = {"candidate_id": "fixture-candidate", "session_id": "fixture-session", "corpus": "native.jsonl"}
    roots.user_config_path.parent.mkdir(parents=True, exist_ok=True)
    roots.user_config_path.write_text('[personal]\ndata_root = ' + json.dumps(str(roots.personal_root)) + '\n')
    marker_root = roots.repo_root / ".kin/local/journal" if source == "repo" else roots.personal_root / "journal"
    marker_root.mkdir(parents=True, exist_ok=True)
    marker = marker_root / "transaction.json"
    marker.write_text(json.dumps({"candidate_id": "someone-else", "journal_state": transition}))
    calls = []
    class Process:
        returncode = None
        pid = 123
        def poll(self):
            return self.returncode
        def send_signal(self, sig):
            assert sig == signal.SIGKILL
            calls.append("kill")
        def communicate(self, timeout):
            calls.append("reap")
            self.returncode = -signal.SIGKILL
            return b"", b""
    process = Process()
    running = False
    def launch(*args, **kwargs):
        nonlocal running
        running = True
        if source != "status":
            marker.write_text(json.dumps({**candidate, "journal_state": transition}))
        return process
    def run(*args, **kwargs):
        assert args[0] == "status"
        return SimpleNamespace(json={"journal_state": {**candidate, "transition": transition} if running and source == "status" else None})
    monkeypatch.setattr(gate, "_checkpoint_async", launch)
    driver = SimpleNamespace(xdg_config_home=roots.xdg_config_home, run=run, popen=launch)
    result = gate._kill_at_transition(driver, SimpleNamespace(repo=SimpleNamespace(path=roots.repo_root)), candidate, "codebase:fixture", transition)
    assert result["crash_witnessed"]
    assert calls == ["kill", "reap"]
    assert result["exit_witness"]["observations"][0]["exit_code"] == -signal.SIGKILL


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("ending", ["normal", "failure", "stale"])
def test_dispatch010_completed_or_stale_journal_never_licenses_crash(roots, monkeypatch, ending):
    from . import test_v2_classification as gate
    marker = roots.repo_root / ".kin/local/journal/receipt"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("receipt")
    class Process:
        returncode = 0 if ending != "failure" else 3
        pid = 123
        def poll(self):
            return self.returncode
        def communicate(self, timeout):
            return b"", b""
    def launch(*args, **kwargs):
        if ending != "stale":
            marker.write_text("receipt\n")
        return Process()
    monkeypatch.setattr(gate, "_checkpoint_async", launch)
    driver = SimpleNamespace(xdg_config_home=roots.xdg_config_home, popen=launch,
                             run=lambda *a, **kw: SimpleNamespace(json={"journal_state": "receipt"}))
    result = gate._kill_at_transition(driver, SimpleNamespace(repo=SimpleNamespace(path=roots.repo_root)), {"candidate_id": "fixture", "session_id": "fixture-session", "corpus": "native.jsonl"}, "codebase:fixture", "receipt")
    assert not result["crash_witnessed"]


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("event_count", [1, 2])
def test_dispatch010_crash_gate_uses_five_fresh_worlds_and_checks_each_recovery(roots, monkeypatch, event_count):
    from . import test_v2_classification as gate
    from ._harness import service
    from contextlib import nullcontext
    seen = []
    stopped = []
    actions = []
    original_create = gate.ProofRoots.create
    monkeypatch.setattr(gate.ProofRoots, "create", lambda base: original_create(base, company_port=0))
    def driver(**kw):
        seen.append(kw["cwd"])
        return SimpleNamespace(**kw)
    monkeypatch.setattr(gate, "Kinbase", driver)
    monkeypatch.setattr(gate, "start_company", lambda driver, layout: SimpleNamespace(stop=lambda: stopped.append(layout.repo_root)))
    monkeypatch.setattr(gate.trust, "establish", lambda *a, **kw: SimpleNamespace(repository_uuid="fixture", company_endpoint=lambda *a: nullcontext()))
    monkeypatch.setattr(gate.trust, "classifier_pinned", lambda *a, **kw: None)
    monkeypatch.setattr(gate, "start_session", lambda *a: "fixture-session")
    monkeypatch.setattr(gate, "_observe", lambda *a: None)
    monkeypatch.setattr(gate, "_one_fanout_source", lambda corpus, repo: repo / "one.jsonl")
    monkeypatch.setattr(gate, "_checkpoint", lambda *a: None)
    monkeypatch.setattr(service, "Blackhole", lambda *a: nullcontext(SimpleNamespace(port=0)))
    def listing(*args):
        return {"candidates": [{"candidate_id": "fixture", "payload_digest": "f" * 64, "destination": "codebase:fixture", "message_id": "source"},
                               {"candidate_id": "company", "payload_digest": "e" * 64, "destination": "company:root", "message_id": "source"}],
                "duplicate_events": 0, "recursive_apologies": 0,
                "fanout_receipts": {"codebase": {"state": "committed"}},
                "committed_event_count": event_count if len(seen) == 1 else 1}
    monkeypatch.setattr(gate, "_admissions", listing)
    def killed(*args):
        actions.clear()
        return {"transition": args[-1], "crash_witnessed": True}
    monkeypatch.setattr(gate, "_kill_at_transition", killed)
    def retry(*args):
        actions.append("launch")
        def communicate(timeout):
            assert actions[:2] == ["launch", "launch"]
            actions.append("reap")
        return SimpleNamespace(communicate=communicate)
    monkeypatch.setattr(gate, "_checkpoint_async", retry)
    args = (SimpleNamespace(path_prefix=[]), roots, SimpleNamespace(path=roots.run_root / "held-out"))
    if event_count == 1:
        gate.test_kill_at_every_transition_then_concurrent_retry(*args)
    else:
        with pytest.raises(ProductFailure, match="exactly one event"):
            gate.test_kill_at_every_transition_then_concurrent_retry(*args)
    assert len(set(seen)) == 5
    assert stopped == seen




@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("source,second_digest,missing,passes", [
    ("recorded-proof-clock", "a" * 64, False, True),
    ("proof-clock:wall", "a" * 64, False, False),
    ("recorded-proof-clock", "b" * 64, False, False),
    ("recorded-proof-clock", "a" * 64, True, False),
    (None, "a" * 64, False, False),
])
def test_dispatch011_omitted_as_of_requires_recorded_source_and_stability(
        tmp_path, source, second_digest, missing, passes):
    from . import test_v4_maintenance as gate
    calls = []
    def run(*argv, **kwargs):
        calls.append(argv)
        explicit = "--as-of" in argv
        stamp = argv[argv.index("--as-of") + 1] if explicit else "2026-09-08T19:00:00.000Z"
        body = {"inputs": {"as_of": stamp}, "as_of_source": source,
                "current_view_digest": second_digest if len(calls) == 3 else "a" * 64}
        if missing and not explicit:
            body.pop("current_view_digest")
        return SimpleNamespace(returncode=0, json=body)
    args = (SimpleNamespace(run=run), (SimpleNamespace(repo=SimpleNamespace(path=tmp_path)), None))
    if passes:
        gate.test_omitting_as_of_breaks_determinism_and_is_refused(*args)
    else:
        with pytest.raises(ProductFailure):
            gate.test_omitting_as_of_breaks_determinism_and_is_refused(*args)
    assert len(calls) == 3
    assert "--as-of" not in calls[1] and "--as-of" not in calls[2]


@spec_ref(_REMEDIATION_010)
def test_dispatch011_fanout_pairs_destination_bound_candidates_by_message():
    from . import test_v2_classification as gate
    local = {"candidate_id": "local", "destination": "codebase:uuid",
             "message_id": "same", "payload_digest": "a" * 64}
    company = {"candidate_id": "company", "destination": "company:root",
               "message_id": "same", "payload_digest": "b" * 64}
    unrelated = {**company, "message_id": "other", "candidate_id": "other"}
    listing = {"candidates": [unrelated, company, local]}
    assert gate._first_candidate(listing, "codebase:uuid") == local
    assert gate._fanout_pair(listing, "codebase:uuid") == (local, company)
    with pytest.raises(ProductFailure):
        gate._fanout_pair({"candidates": [unrelated, local]}, "codebase:uuid")




@spec_ref(_REMEDIATION_010)
def test_dispatch011_public_adapter_receipts_never_replace_lifecycle_evidence():
    cell = next(c for c in L.CELLS if c.key == "repo_code::create")
    witness = {"source_tree_before": "a", "source_tree_after": "b"}
    snapshot = _snapshot()
    snapshot["adapter_receipts"] = snapshot.pop("receipt_counts")
    observed = LO.derive(cell, witness, {}, snapshot)
    assert observed["states_match"] and observed["adapter_receipts_present"]
    snapshot["facts"] = []
    assert not LO.derive(cell, witness, {}, snapshot)["states_match"]


@spec_ref(_REMEDIATION_010)
def test_dispatch011_ceiling_does_not_credit_a_path_escape(tmp_path):
    from . import test_nonfunctional as gate
    roots = SimpleNamespace(repo_root=tmp_path)
    for code, expected in (("CONFIG_INVARIANT", False), ("LIMIT_EXCEEDED", True)):
        result = SimpleNamespace(returncode=4, json={"error": {"code": code}, "omitted_count": 1})
        driver = SimpleNamespace(run=lambda *a, **kw: result)
        row = gate._ceiling_probe(driver, roots, "source_body", ("ingest",), constructed=True)
        assert row["refused"] is expected


@spec_ref(_REMEDIATION_010)
def test_dispatch011_empty_rejected_alias_cannot_hide_negative_evidence():
    from . import test_v5_temporal as gate
    assert gate._list({"rejected_events": [], "negative_evidence": ["rejected-id"]},
                      "rejected_events", "negative_evidence") == ["rejected-id"]
    assert gate._list({"rejected_events": [], "negative_evidence": []},
                      "rejected_events", "negative_evidence") == []


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("count,omitted,accepted", [(32, 1, True), (33, 1, False), (32, 0, False)])
def test_dispatch011_projection_ceiling_accepts_only_bounded_omission(tmp_path, count, omitted, accepted):
    from . import test_nonfunctional as gate
    payload = {"selected": list(range(count)), "projection_bytes": 1000, "omitted_count": omitted}
    driver = SimpleNamespace(run=lambda *a, **kw: SimpleNamespace(returncode=0, json=payload))
    result = gate._ceiling_probe(driver, SimpleNamespace(repo_root=tmp_path),
                                 "projection_call", ("project",), constructed=True)
    assert result["refused"] is accepted


@spec_ref(_REMEDIATION_010)
def test_dispatch011_conflict_fixture_resolves_both_heads_in_their_own_scope(tmp_path):
    import json
    from . import test_v4_maintenance as gate
    from ._harness.worldbuilder import OpaqueIds
    world = SignedWorld.create(tmp_path / "repo")
    world.company = SimpleNamespace(
        registry=SimpleNamespace(is_registered=lambda identity: True),
        admit_fact=lambda doc: {"admitted": True, "receipt": {"event_id": doc["event_id"]}})
    states = iter(("conflict", "conflict", "current"))
    driver = SimpleNamespace(run=lambda *a, **kw: SimpleNamespace(returncode=0, json={"state": next(states)}),
                             base_env=lambda env: env)
    gate.test_incompatible_heads_remain_conflict_until_authorized_parent_bound_event(
        driver, (world, world.company), OpaqueIds(), tmp_path)
    events = [json.loads(p.read_bytes()) for p in (world.repo.path / ".kin/events").rglob("*.json")]
    resolution = next(e for e in events if len(e["supersedes"]) == 2)
    heads = {e["event_id"] for e in events if e is not resolution}
    assert set(resolution["supersedes"]) == heads
    assert heads <= set(resolution["parents"])
    assert resolution["authority_scope"] == world.maintainer.scope
    assert resolution["statement"] == "the drain order is oldest first"


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("body,expected", [
    ({"checks": [{"code": "HOOK_APPROVAL_REQUIRED"}]}, "HOOK_APPROVAL_REQUIRED"),
    ({"checks": [{"status": "ok"}]}, None),
])
def test_dispatch011_doctor_success_diagnostic_is_not_a_typed_error(body, expected):
    from . import test_v9_host_lifecycle as gate
    assert gate._doctor_approval_code(body) == expected


@spec_ref(_REMEDIATION_010)
def test_dispatch011_native_corpus_survives_without_lifecycle_teardown(tmp_path, monkeypatch):
    import json
    from . import test_v1_ingestion as gate
    world = SignedWorld.create(tmp_path / "repo")
    ctx = L.LifecycleContext(world, world.repo.path / "sources", tmp_path / "external")
    ctx.sources.mkdir(parents=True)
    ctx.external.mkdir()
    monkeypatch.setattr(gate.trust, "classifier_pinned", lambda *a, **kw: None)
    result = gate.native_corpus.__wrapped__((world, None, ctx))
    assert set(result[3]) == set(gate.ADAPTERS)
    envelopes = list((ctx.sources / "tests").glob("*.json"))
    assert envelopes
    assert all(json.loads(p.read_bytes())["schema"] == "kinbase-command-result/1" for p in envelopes)
    assert (world.repo.path / "src").is_dir()
    assert (ctx.sources / "answers").is_dir()


@spec_ref(_REMEDIATION_010)
def test_dispatch012_incremental_snapshot_uses_real_git_result(tmp_path):
    import ast
    import hashlib
    from . import test_v4_maintenance as gate
    from ._harness import canonical
    # Execute the actual nested snapshot against GitRepo, without running any
    # product stage or replacing GitRepo.run with a differently shaped double.
    module = ast.parse(Path(gate.__file__).read_text())
    cycle = next(n for n in module.body if isinstance(n, ast.FunctionDef)
                 and n.name == "test_repeated_incremental_cycle_is_restart_safe_and_bounded")
    snapshot = next(n for n in cycle.body if isinstance(n, ast.FunctionDef)
                    and n.name == "snapshot")
    world = SignedWorld.create(tmp_path / "repo")
    namespace = dict(world=world, repo=world.repo.path, hashlib=hashlib,
                     canonical=canonical, rows=gate.rows, _store_digest=gate._store_digest,
                     anchors=SimpleNamespace(
                         client=SimpleNamespace(get=lambda path: SimpleNamespace(json={"facts": []})),
                         registry=SimpleNamespace(document=lambda: {})))
    exec(compile(ast.Module(body=[snapshot], type_ignores=[]), gate.__file__, "exec"), namespace)
    initial = namespace["snapshot"]()
    assert len(initial) == 64 and initial == namespace["snapshot"]()
    world.repo.branch("maintenance/snapshot")
    world.repo.checkout("maintenance/snapshot")
    assert namespace["snapshot"]() != initial


@spec_ref(_REMEDIATION_010)
def test_dispatch012_late_test_result_preserves_earlier_receipt(tmp_path, monkeypatch):
    import json
    import time
    from datetime import datetime
    clock = [1790000000]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    monkeypatch.setenv("KINBASE_PROOF_CLOCK_OFFSET_SECONDS", "60")
    ctx = L.LifecycleContext(None, tmp_path / "sources", tmp_path / "external")
    receipts = []
    for hour in range(1, 5):
        path = L._test_envelope(ctx, exit_code=0, stdout="passed", hour=hour,
                                name=f"run-{hour}")
        stamp = json.loads(path.read_bytes())["observed_at"]
        receipts.append(stamp)
        assert abs(datetime.fromisoformat(stamp).timestamp() - (clock[0] + 60)) <= 30
        clock[0] += 120
    # Long delivery delay must not turn the older failure into a newer result.
    clock[0] += 3600
    late = L._tests_out_of_order(ctx)
    document = json.loads(Path(late["native_path"]).read_bytes())
    assert document["exit_code"] == 1
    assert receipts == sorted(set(receipts))
    assert document["observed_at"] == receipts[1] < receipts[3]


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("now,offset", [(1790000000, 0), (1925000000, 604800),
                                        (1925000000, -604800)])
def test_dispatch012_runtime_freshness_tracks_proof_clock(tmp_path, monkeypatch, now, offset):
    import json
    import time
    from datetime import datetime
    monkeypatch.setattr(time, "time", lambda: now)
    monkeypatch.setenv("KINBASE_PROOF_CLOCK_OFFSET_SECONDS", str(offset))
    ctx = L.LifecycleContext(None, tmp_path / "sources", tmp_path / "external")
    for transition in (L._runtime_create, L._runtime_changed_value,
                       L._runtime_owner_change, L._runtime_late_arrival,
                       L._runtime_bounded_skew):
        witness = transition(ctx)
        doc = json.loads(Path(witness["native_path"]).read_bytes())
        assert datetime.fromisoformat(doc["effective_until"]).timestamp() == now + offset + 604800
        assert doc["environment_owner"] in ("sre-owner-1", "sre-owner-2")
    expired = L._runtime_expiry(ctx)
    doc = json.loads(Path(expired["native_path"]).read_bytes())
    assert doc["effective_until"] == expired["effective_until"]
    assert datetime.fromisoformat(doc["effective_until"]).timestamp() == now + offset - 60


@spec_ref(_REMEDIATION_010)
def test_dispatch012_maintainer_key_matches_registry_and_survives_config_rewrite(roots):
    import tomllib
    from ._harness import ed25519_pure, trust
    world = SignedWorld.create(roots.repo_root)
    classifier = trust.Classifier(roots.client_root / "unspawned", "a" * 64,
                                  ("classifier", "--json"), "product")
    config, _ = trust.write_user_config(
        roots, company_url="http://127.0.0.1:1", facts_token="selftest",
        root_key=roots.client_root / "root.pub", classifier=classifier,
        maintainer=world.maintainer)
    key = Path(tomllib.loads(config.read_text())["identity"]["maintainer_key_file"])
    assert key.is_absolute() and not key.is_relative_to(world.repo.path)
    assert key.read_bytes() == world.maintainer.seed == bytes([13]) * 32
    assert key.stat().st_mode & 0o777 == 0o600
    registry = trust.AuthorityRegistry(world.steward)
    registry.register(world.maintainer, channel=world.maintainer.scope,
                      capabilities=("request", "publish-manifest"))
    assert ed25519_pure.public_key(key.read_bytes()).hex() == registry.entry_for(
        world.maintainer.authority_id).public_key
    roots.rewrite_user_config(company_url="http://127.0.0.1:2")
    assert tomllib.loads(config.read_text())["identity"]["maintainer_key_file"] == str(key)
    assert config.stat().st_mode & 0o777 == 0o600


@spec_ref(_REMEDIATION_010)
@pytest.mark.parametrize("behavior,expected", [("detect", True), ("ignore", False),
                                               ("internal-error", False), ("sticky", False)])
def test_dispatch012_duplicate_certificate_fsck_observation(roots, behavior, expected):
    import json
    from . import test_v8_company_refs as gate
    from ._harness import synth, trust
    from ._harness.worldbuilder import REPO_UUID
    world = SignedWorld.create(roots.repo_root)
    original = trust.write_certificate_file(roots, world.steward, repository_uuid=REPO_UUID)
    installed = roots.company_cache / REPO_UUID / "certificate.json"
    installed.parent.mkdir(parents=True)
    installed.write_bytes(original.read_bytes())
    calls = []

    def run(*args, **kwargs):
        assert args[:2] == ("fsck", "--repo")
        docs = [json.loads(p.read_bytes()) for p in installed.parent.glob("*.json")]
        calls.append(len(docs))
        assert all(d["repository_uuid"] == REPO_UUID for d in docs)
        assert all(synth.verify_document("repo-certificate", d) for d in docs)
        if len(docs) == 2:
            assert docs[0]["issued_at"] != docs[1]["issued_at"]
            code = {"detect": 5, "ignore": 0, "internal-error": 70, "sticky": 5}[behavior]
        else:
            code = 5 if behavior == "sticky" and len(calls) == 3 else 0
        return SimpleNamespace(returncode=code, json={"checks": []})

    observed = gate._two_certificates_fail_fsck(
        SimpleNamespace(run=run), world, SimpleNamespace(roots=roots))
    assert observed is expected
    assert calls == [1, 2, 1]
    assert installed.read_bytes() == original.read_bytes()


@pytest.mark.parametrize("fault", [
    None, "create", "duplicate", "edit", "supersede", "retract", "revoke",
    "expire", "branch", "merge", "conflict", "resolve", "rebuild", "restart",
    "rebuild-view", "restart-view", "revisited-state",
])
@spec_ref(_REMEDIATION_010)
def test_dispatch013_cycle_accepts_preservation_and_rejects_idle_mutations(fault):
    import ast
    import hashlib
    from . import test_v4_maintenance as gate
    from ._harness.catalog import BY_ID
    from ._harness.evidence_model import Evidence, Origin

    # Execute the actual stage recorder and final evidence expression, as in
    # the snapshot guard above. No action here invokes the product.
    module = ast.parse(Path(gate.__file__).read_text())
    cycle = next(n for n in module.body if isinstance(n, ast.FunctionDef)
                 and n.name == "test_repeated_incremental_cycle_is_restart_safe_and_bounded")
    recorder = next(n for n in cycle.body if isinstance(n, ast.FunctionDef)
                    and n.name == "stage")
    check = next(n.value for n in cycle.body if isinstance(n, ast.Expr)
                 and isinstance(n.value, ast.Call)
                 and isinstance(n.value.func, ast.Attribute)
                 and isinstance(n.value.func.value, ast.Name)
                 and n.value.func.value.id == "O" and n.value.func.attr == "check")
    names = [n.value.args[0].value for n in cycle.body if isinstance(n, ast.Expr)
             and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
             and n.value.func.id == "stage"]
    assert names == ["create", "duplicate", "edit", "supersede", "retract", "revoke",
                     "expire", "branch", "merge", "conflict", "resolve", "rebuild", "restart"]
    preserving = {"duplicate", "rebuild", "restart"}
    state = [0]

    def snapshot():
        return hashlib.sha256(str(state[0]).encode()).hexdigest()

    namespace = dict(snapshot=snapshot, stages=[], cycle_digests=[], field=gate.field,
                     final={"view_stabilises": True, "growth_bounded": True})
    exec(compile(ast.Module(body=[recorder], type_ignores=[]), gate.__file__, "exec"), namespace)
    for name in names:
        def action():
            if (name not in preserving) != (fault == name):
                state[0] += 1
            if fault == "revisited-state" and name == "resolve":
                state[0] = 1  # Advances locally but revisits create's state.
            if name in ("rebuild", "restart"):
                namespace["cycle_digests"].append("" if fault == name + "-view" else "stable-view")
        namespace["stage"](name, action)

    payload = eval(compile(ast.Expression(check.args[1]), gate.__file__, "eval"), namespace)
    assert len(payload["stages"]) == 13
    assert len(payload["cycle_state_digests"]) == 10
    ev = Evidence(obligation="V-4.incremental-cycle", origin=Origin.PRODUCT,
                  label="synthetic mutation/preservation sequence", payload=payload)
    clauses = BY_ID[ev.obligation].clause_set
    if fault is None:
        assert all(s["stage_verified"] is True for s in payload["stages"])
        assert len({s["post_state_digest"] for s in payload["stages"]}) == 10
        clauses.check(ev)
    else:
        tag = "cycle_state_digests" if fault == "revisited-state" else "stages"
        with pytest.raises(ProductFailure, match=tag):
            clauses.check(ev)
