"""Fixtures, census and two-channel gate reporting for the acceptance suite.

Responsibilities:

1. Build fully isolated proof environments (temporary ``HOME``, config,
   repository and Personal roots plus a mode-0700 Tester vault) so no run can
   touch a real Personal store, a real Company service, or the operator's own
   configuration.
2. Maintain the execution census defined in :mod:`acceptance._harness.census`.
   Every gate begins ``NOT_RUN``; only a gate whose every catalogued node was
   collected, executed and passed becomes green.
3. Keep instrument invalidity and product failure as two independent channels,
   and record a content address for any product observation so the ratified
   composition step can check independence rather than assume it.

This file computes no verdict. ``spec/verification.md`` "Role separation"
reserves that to the Validator; the suite owns only the observations a verdict
is composed from.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator, Sequence

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acceptance._harness import catalog as catalog_module  # noqa: E402
from acceptance._harness import mutations as mutation_catalog  # noqa: E402
from acceptance._harness.census import GROUPS, Census  # noqa: E402
from acceptance._harness.cli import Guildhall  # noqa: E402
from acceptance._harness.evidence_model import Outcome, content_address  # noqa: E402
from acceptance._harness.requirements import (  # noqa: E402
    HarnessInvalid,
    ProductFailure,
    refs_of,
    repo_root,
    verify_manifest,
)
from acceptance._harness.roots import ProofRoots  # noqa: E402
from acceptance._harness.vault import CanaryVault  # noqa: E402

MANIFEST_KEY: pytest.StashKey[Any] = pytest.StashKey()
CENSUS_KEY: pytest.StashKey[Census] = pytest.StashKey()

GATE_MARKERS: dict[str, str] = {
    "v1": "V-1", "v2": "V-2", "v3": "V-3", "v4": "V-4", "v5": "V-5",
    "v6": "V-6", "v7": "V-7", "v8": "V-8", "v9": "V-9", "v10": "V-10",
    "nonfunctional": "NONFUNCTIONAL",
    "evidence": "EVIDENCE",
    "verdict": "VERDICT",
    "selftest": "INSTRUMENT",
}


# --------------------------------------------------------------------------
# Session integrity
# --------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Verify the ratified manifest and initialise the census as NOT_RUN.

    ``GUILDHALL_REVIEWER_MODE=1`` restricts verification to the six ratified
    authority artifacts, omitting the receipt and review-evidence paths that lie
    outside an implementation-blind Detector Reviewer's permitted surface.
    """
    reviewer = os.environ.get("GUILDHALL_REVIEWER_MODE", "") == "1"
    try:
        verification = verify_manifest(reviewer_mode=reviewer)
    except HarnessInvalid as exc:
        raise pytest.UsageError(f"INVALID_HARNESS: {exc}") from exc
    config.stash[MANIFEST_KEY] = verification

    census = Census.build()
    census.catalog_digest = catalog_module.catalog_digest()
    census.mutation = mutation_catalog.active_mutation() or ""
    census.detector_mutation = os.environ.get("GUILDHALL_ACCEPT_DETECTOR_MUTATION", "")
    config.stash[CENSUS_KEY] = census


def pytest_report_header(config: pytest.Config) -> list[str]:
    verification = config.stash[MANIFEST_KEY]
    census = config.stash[CENSUS_KEY]
    lines = [
        f"guildhall acceptance: manifest {verification.manifest_sha256}",
        f"guildhall acceptance: obligation catalog {census.catalog_digest[:16]} "
        f"({len(catalog_module.OBLIGATIONS)} obligations, "
        f"{sum(len(o.thresholds) for o in catalog_module.OBLIGATIONS)} thresholds)",
        "guildhall acceptance: every gate initialised NOT_RUN; only a gate whose "
        "catalogued nodes all executed and passed becomes green",
    ]
    if census.mutation:
        entry = mutation_catalog.CATALOG[census.mutation]
        lines.append(
            f"guildhall acceptance: MUTATION RUN {census.mutation} ({entry.gate}) -- "
            f"{len(entry.must_fail_nodes)} node(s) must fail"
        )
    if census.detector_mutation:
        lines.append(
            f"guildhall acceptance: DETECTOR MUTATION RUN {census.detector_mutation}"
        )
    if os.environ.get("GUILDHALL_REVIEWER_MODE", "") == "1":
        lines.append(
            "guildhall acceptance: REVIEWER MODE -- ratified spec/** and tests/** only"
        )
    return lines


def _gate_of(item: pytest.Item) -> str:
    for marker, gate in GATE_MARKERS.items():
        if item.get_closest_marker(marker) is not None:
            return gate
    return "INSTRUMENT"


def pytest_collection_modifyitems(
    session: pytest.Session, config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Record collection, including nodes that selection will deselect."""
    census = config.stash[CENSUS_KEY]
    for item in items:
        record = census.record(item.nodeid, _gate_of(item))
        record.collected = True


def pytest_deselected(items: Sequence[pytest.Item]) -> None:
    """Deselection is not a pass. The node stays NOT_RUN."""
    for item in items:
        census = item.config.stash[CENSUS_KEY]
        record = census.record(item.nodeid, _gate_of(item))
        record.collected = True
        record.reason = "deselected by marker/name selection"


def _classify(item: pytest.Item, call: pytest.CallInfo) -> tuple[Outcome, str]:
    """Instrument defect or product finding? Ordered, total, fail-closed."""
    if call.when != "call":
        return Outcome.INVALID_HARNESS, f"failure during {call.when}"
    if item.get_closest_marker("selftest") is not None:
        return Outcome.INVALID_HARNESS, "selftest failure (no product involved)"
    exc = call.excinfo.value if call.excinfo is not None else None
    if isinstance(exc, HarnessInvalid):
        return Outcome.INVALID_HARNESS, "HarnessInvalid"
    if isinstance(exc, ProductFailure):
        return Outcome.PRODUCT_FAILURE, "ProductFailure"
    if isinstance(exc, AssertionError):
        return Outcome.PRODUCT_FAILURE, "assertion"
    return Outcome.INVALID_HARNESS, f"unexpected {type(exc).__name__}"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Iterator[None]:
    outcome = yield
    report = outcome.get_result()
    census: Census = item.config.stash[CENSUS_KEY]
    gate = _gate_of(item)
    record = census.record(item.nodeid, gate)
    record.collected = True
    record.phases[report.when] = report.outcome

    if report.outcome == "failed":
        classification, reason = _classify(item, call)
        if gate == "INSTRUMENT":
            classification = Outcome.INVALID_HARNESS
        record.outcome = classification
        record.reason = reason
        if classification is Outcome.PRODUCT_FAILURE:
            # Content-address the observation so the ratified composition can
            # check independence instead of assuming it.
            record.product_digest = content_address(
                {
                    "node": item.nodeid,
                    "gate": gate,
                    "reason": reason,
                    "longrepr": str(report.longrepr)[:4000],
                    "refs": [r.render() for r in refs_of(getattr(item, "function", None))]
                    if getattr(item, "function", None) is not None
                    else [],
                }
            )
        record.channel = classification.value
        census.gates[gate].observe(record)
    elif report.outcome == "skipped":
        # A skip is not a pass. It leaves the node NOT_RUN, so any gate whose
        # catalogued node was skipped cannot be green.
        record.outcome = Outcome.NOT_RUN
        record.reason = f"skipped during {report.when}"
    elif report.when == "call" and report.outcome == "passed":
        if record.outcome is Outcome.NOT_RUN:
            record.outcome = Outcome.PASS


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ANN001
    census: Census | None = config.stash.get(CENSUS_KEY, None)
    if census is None:
        return
    census.resolve()

    terminalreporter.write_sep("=", "guildhall gate vector (observation, not a verdict)")
    vector = census.gate_vector()
    for gate in GROUPS:
        state = census.gates[gate]
        executed = sum(
            1
            for n in state.expected_nodes
            if any(
                _tail(r.node) == n and r.outcome is not Outcome.NOT_RUN
                for r in census.records.values()
            )
        )
        terminalreporter.write_line(
            f"{gate:<14} {vector[gate]:<16} "
            f"instrument={state.instrument.value:<16} product={state.product.value:<16} "
            f"nodes={executed}/{len(state.expected_nodes)}"
        )
    terminalreporter.write_line(
        "NOT_RUN is non-green: an unexecuted, deselected, skipped or uncollected "
        "obligation never reports as satisfied."
    )
    terminalreporter.write_line(
        "spec/verification.md reserves verdict composition to the Validator."
    )

    artifact = os.environ.get("GUILDHALL_ACCEPT_GATE_VECTOR")
    if artifact:
        target = Path(artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = census.as_json()
        payload["census_digest"] = census.digest
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        terminalreporter.write_line(f"census written to {target} ({census.digest[:16]})")


def _tail(node_id: str) -> str:
    tail = node_id.split("/")[-1]
    return tail.split("[", 1)[0]


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def manifest():
    return verify_manifest(
        reviewer_mode=os.environ.get("GUILDHALL_REVIEWER_MODE", "") == "1"
    )


@pytest.fixture(scope="session")
def spec_root() -> Path:
    return repo_root()


@pytest.fixture()
def roots(tmp_path: Path) -> Iterator[ProofRoots]:
    layout = ProofRoots.create(tmp_path / "proof")
    layout.assert_personal_is_not_a_shared_root()
    yield layout


@pytest.fixture()
def vault(tmp_path: Path, roots: ProofRoots) -> Iterator[CanaryVault]:
    box = CanaryVault(
        root=tmp_path / "vault",
        forbidden_roots=(roots.repo_root, roots.home, roots.evidence_root),
    )
    try:
        yield box
    finally:
        box.destroy()


@pytest.fixture()
def guildhall(roots: ProofRoots) -> Guildhall:
    """The black-box CLI driver bound to the isolated roots."""
    return Guildhall(
        home=roots.home,
        xdg_config_home=roots.xdg_config_home,
        cwd=roots.repo_root,
    )
