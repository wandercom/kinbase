"""Shared fixtures and gate reporting for the Guildhall acceptance suite.

Two responsibilities:

1. Build fully isolated proof environments (temporary ``HOME``, config,
   repository and Personal roots plus a mode-0700 Tester vault) so no acceptance
   run can touch a real Personal store, a real Company service, or the
   operator's own configuration.
2. Classify every failure as ``PRODUCT_FAILURE`` or ``INVALID_HARNESS`` and emit
   the gate vector, because ``spec/verification.md`` "Verdict semantics" makes
   that distinction load bearing:

       ``gate_result`` over V-1 through V-9 is ``PASS``, ``PRODUCT_FAILURE``, or
       ``INVALID_HARNESS``

This file does not compute a verdict. ``spec/verification.md`` "Role separation"
reserves the verdict to the Validator; the suite owns only the observations a
verdict is composed from.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acceptance._harness import mutations as mutation_catalog  # noqa: E402
from acceptance._harness.cli import Guildhall  # noqa: E402
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

GATE_MARKERS: dict[str, str] = {
    "v1": "V-1",
    "v2": "V-2",
    "v3": "V-3",
    "v4": "V-4",
    "v5": "V-5",
    "v6": "V-6",
    "v7": "V-7",
    "v8": "V-8",
    "v9": "V-9",
    "v10": "V-10",
    "nonfunctional": "NONFUNCTIONAL",
    "evidence": "EVIDENCE",
    "verdict": "VERDICT",
    "selftest": "INSTRUMENT",
}

GATE_ORDER: tuple[str, ...] = (
    "V-1",
    "V-2",
    "V-3",
    "V-4",
    "V-5",
    "V-6",
    "V-7",
    "V-8",
    "V-9",
    "V-10",
    "NONFUNCTIONAL",
    "EVIDENCE",
    "VERDICT",
    "INSTRUMENT",
)


# --------------------------------------------------------------------------
# Session-level integrity
# --------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Verify the ratified manifest before any test is collected.

    A digest disagreement means the instrument is not measuring the ratified
    specification. ``spec/verification.md`` treats that as an instrument
    condition, so the run stops rather than reporting product results against
    unratified bytes.
    """
    try:
        verification = verify_manifest()
    except HarnessInvalid as exc:
        raise pytest.UsageError(f"INVALID_HARNESS: {exc}") from exc
    config.stash[MANIFEST_KEY] = verification
    config._guildhall_gate_state = {gate: "PASS" for gate in GATE_ORDER}
    config._guildhall_records = []


def pytest_report_header(config: pytest.Config) -> list[str]:
    verification = config.stash[MANIFEST_KEY]
    lines = [
        f"guildhall acceptance: manifest {verification.manifest_sha256}",
        "guildhall acceptance: authority precedence "
        + " > ".join(Path(p).name for p in verification.precedence),
    ]
    mutation = mutation_catalog.active_mutation()
    if mutation:
        entry = mutation_catalog.CATALOG[mutation]
        lines.append(
            f"guildhall acceptance: MUTATION RUN {mutation} ({entry.gate}) -- "
            f"{len(entry.must_fail_nodes)} node(s) must fail"
        )
    detector_mutation = os.environ.get("GUILDHALL_ACCEPT_DETECTOR_MUTATION", "")
    if detector_mutation:
        lines.append(f"guildhall acceptance: DETECTOR MUTATION RUN {detector_mutation}")
    return lines


def _gate_of(item: pytest.Item) -> str:
    for marker, gate in GATE_MARKERS.items():
        if item.get_closest_marker(marker) is not None:
            return gate
    return "INSTRUMENT"


def _refs_for(item: pytest.Item) -> list[str]:
    function = getattr(item, "function", None)
    if function is None:
        return []
    return [ref.render() for ref in refs_of(function)]


def _classify(item: pytest.Item, call: pytest.CallInfo) -> tuple[str, str]:
    """Decide whether a failure is an instrument defect or a product finding.

    ``spec/verification.md`` "Verdict semantics" separates ``INVALID_HARNESS``
    from ``PRODUCT_FAILURE``, and "Instrument validity" makes the instrument's
    own soundness a precondition for believing any gate observation. A defect in
    the measuring device is therefore never reported as a product defect. The
    ordered rules:

    * a failure outside the call phase is a fixture/collection defect;
    * a ``selftest``-marked test never touches the product, so any failure in it
      is an instrument condition by construction;
    * an explicit :class:`HarnessInvalid` is an instrument condition;
    * an unexpected exception type -- anything that is not the deliberate
      :class:`ProductFailure` or a plain assertion -- means the instrument
      itself misbehaved rather than that it observed a product violation;
    * only a deliberate product assertion is ``PRODUCT_FAILURE``.
    """
    if call.when != "call":
        return "INVALID_HARNESS", f"failure during {call.when}"
    if item.get_closest_marker("selftest") is not None:
        return "INVALID_HARNESS", "selftest failure (no product involved)"
    exc = call.excinfo.value if call.excinfo is not None else None
    if isinstance(exc, HarnessInvalid):
        return "INVALID_HARNESS", "HarnessInvalid"
    if isinstance(exc, ProductFailure):
        return "PRODUCT_FAILURE", "ProductFailure"
    if isinstance(exc, AssertionError):
        return "PRODUCT_FAILURE", "assertion"
    return "INVALID_HARNESS", f"unexpected {type(exc).__name__}"


def _record(item: pytest.Item, call: pytest.CallInfo) -> None:
    gate = _gate_of(item)
    state = getattr(item.config, "_guildhall_gate_state", None)
    if state is None:
        return
    classification, reason = _classify(item, call)
    # The INSTRUMENT gate is definitionally an instrument observation.
    if gate == "INSTRUMENT":
        classification = "INVALID_HARNESS"
    # PRODUCT_FAILURE dominates INVALID_HARNESS inside a gate, matching
    # spec/verification.md: an independently valid product-failure observation
    # is retained alongside an invalid detector.
    if state.get(gate) != "PRODUCT_FAILURE":
        state[gate] = classification
    item.config._guildhall_records.append(
        {
            "node": item.nodeid,
            "gate": gate,
            "outcome": classification,
            "reason": reason,
            "phase": call.when,
            "refs": _refs_for(item),
        }
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Iterator[None]:
    outcome = yield
    report = outcome.get_result()
    # Setup and teardown errors are instrument conditions and must not be
    # dropped: an unreported fixture failure would leave the gate reading PASS.
    if report.failed or (report.outcome == "failed"):
        _record(item, call)


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ANN001
    state = getattr(config, "_guildhall_gate_state", {})
    if not state:
        return
    terminalreporter.write_sep("=", "guildhall gate vector")
    for gate in GATE_ORDER:
        terminalreporter.write_line(f"{gate:<14} {state.get(gate, 'PASS')}")
    terminalreporter.write_line(
        "note: this vector is an observation set, not a verdict. "
        "spec/verification.md reserves verdict composition to the Validator."
    )
    artifact = os.environ.get("GUILDHALL_ACCEPT_GATE_VECTOR")
    if artifact:
        target = Path(artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "gate_vector": state,
                    "records": getattr(config, "_guildhall_records", []),
                    "mutation": mutation_catalog.active_mutation(),
                    "detector_mutation": os.environ.get(
                        "GUILDHALL_ACCEPT_DETECTOR_MUTATION"
                    ),
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def manifest():
    """The verified ratification manifest."""
    return verify_manifest()


@pytest.fixture(scope="session")
def spec_root() -> Path:
    return repo_root()


@pytest.fixture()
def roots(tmp_path: Path) -> Iterator[ProofRoots]:
    """A fully isolated proof environment for one test."""
    layout = ProofRoots.create(tmp_path / "proof")
    layout.assert_personal_is_not_a_shared_root()
    yield layout


@pytest.fixture()
def vault(tmp_path: Path, roots: ProofRoots) -> Iterator[CanaryVault]:
    """A per-test mode-0700 canary vault outside every repository and home."""
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
    """The black-box CLI driver bound to the isolated roots.

    If the combined snapshot exposes no ratified entry point the resulting
    :class:`ProductEntryPointMissing` surfaces as a product failure, because
    ``spec/cli.md`` freezes that command surface as part of the deliverable.
    """
    return Guildhall(
        home=roots.home,
        xdg_config_home=roots.xdg_config_home,
        cwd=roots.repo_root,
    )
