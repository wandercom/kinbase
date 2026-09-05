"""Oracle privacy: nothing semantic may reach the system under test.

Detector Reviewer finding 7 and the complete out-of-band control inventory. This
module enforces the closed policy in :mod:`acceptance._harness.controls` by
static inspection of the whole suite, so a selector cannot be reintroduced
without failing the instrument.

It also enforces the two positive rules the dispatch states: gold, expected
answers, case identities and semantic outcome selectors stay outside every
product command, environment, prompt and fixture payload; and the only controls
that may reach the product are narrowly scheduled, independently witnessed
timing, ordering and failure perturbations.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from ._harness.controls import HARNESS_ONLY, PERMITTED, violations
from ._harness.requirements import THREAT, VERIFY, HarnessInvalid, spec_ref

pytestmark = pytest.mark.selftest

_SUITE = Path(__file__).resolve().parent
_LANE = _SUITE.parent


#: The policy module and this guard must name the forbidden shapes in order to
#: forbid them, so they are excluded from their own scan.
_POLICY_MODULES = {"controls.py", "test_control_policy.py"}


def _modules() -> list[Path]:
    return sorted(p for p in _SUITE.rglob("*.py") if p.name not in _POLICY_MODULES)


def _env_names_passed_to_product() -> dict[str, list[str]]:
    """Every string literal used as an env key in an ``env=`` mapping.

    The driver merges ``env=`` overrides into the child process environment, so
    each such key is physically visible to the product.
    """
    found: dict[str, list[str]] = {}
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "env" or not isinstance(keyword.value, ast.Dict):
                    continue
                for key in keyword.value.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        found.setdefault(key.value, []).append(path.name)
    return found


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "role-separation",
        "**Tester (Claude):** reads ratified product, architecture, verification strategy, and a "
        "clean test lane; authors acceptance/benchmark tests and fixtures only; cannot read "
        "implementation or Coder work or issue a verdict.",
    ),
    THREAT(
        "INSTRUMENT",
        "canary-custody",
        "Committed fixtures contain generators, structural labels, and placeholder IDs only.",
    ),
)
def test_no_semantic_control_reaches_the_product() -> None:
    """Every environment key passed to the product is on the closed allowlist."""
    passed = _env_names_passed_to_product()
    bad = violations(passed)
    assert not bad, (
        "these environment names reach the system under test but are not permitted "
        "controls; a product can branch on them instead of doing the work:\n"
        + "\n".join(
            f"  {name}: {reason} (in {', '.join(sorted(set(passed[name])))})"
            for name, reason in bad
        )
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "role-separation",
        "authors acceptance/benchmark tests and fixtures only; cannot read implementation or Coder "
        "work or issue a verdict.",
    )
)
def test_no_acceptance_prefixed_name_survives_anywhere_in_test_bodies() -> None:
    """The ``GUILDHALL_ACCEPTANCE_`` prefix itself is forbidden.

    Its mere presence disclosed acceptance-run identity to the product, which
    let an implementation branch on being under test even when the value carried
    no answer.
    """
    offenders: list[str] = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "GUILDHALL_ACCEPTANCE_" in node.value:
                    offenders.append(f"{path.name}:{node.lineno} {node.value[:60]!r}")
    assert not offenders, (
        "acceptance-run identity must not be disclosed to the product:\n  "
        + "\n  ".join(offenders)
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "role-separation",
        "cannot read implementation or Coder work or issue a verdict.",
    )
)
def test_harness_only_variables_never_reach_the_product() -> None:
    passed = set(_env_names_passed_to_product())
    leaked = sorted(passed & HARNESS_ONLY)
    assert not leaked, (
        f"these instrument-only variables were passed to the product: {leaked}"
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fault-schedule",
        "Capture full context provenance and query traces; preserve failures and timeouts.",
    )
)
def test_every_permitted_fault_schedule_declares_a_witness() -> None:
    unwitnessed = [
        control.name
        for control in PERMITTED.values()
        if control.classification == "fault_schedule" and not control.witness_required
    ]
    assert not unwitnessed, (
        "a fault schedule the instrument cannot independently witness is a work "
        f"substitute, not a perturbation: {unwitnessed}"
    )


@spec_ref(
    THREAT(
        "INSTRUMENT",
        "canary-custody",
        "Committed fixtures contain generators, structural labels, and placeholder IDs only.",
    )
)
def test_no_committed_fixture_that_reaches_the_product_carries_gold() -> None:
    """Gold labels may exist in the lane, but never in a product-bound payload.

    The Reviewer found the full gold maintenance file and the routing corpus's
    ``gold_atoms`` being handed to ``session observe``. Fixtures under
    ``fixtures/gold/`` are tester-held; the guard here is that no module passes
    one of those paths to the product, and that the builders that *do* construct
    product input strip every gold key.
    """
    gold_keys = {
        "gold_atoms", "gold_label", "gold_correct_admission", "gold_decision",
        "gold_atom_label", "gold_destination_labels", "durable_shared_fact",
        "expected_state", "expected_fragment", "mixed", "stratum",
        "distortion_severity_rank", "origin_trust_class",
    }
    builders = _LANE / "acceptance" / "_harness" / "corpora.py"
    assert builders.is_file(), (
        "product-bound corpora must be built by a dedicated module that strips gold"
    )
    source = builders.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(builders))
    declared: set[str] = set()
    for node in ast.walk(tree):
        targets: list = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if not (isinstance(target, ast.Name)
                    and target.id == "PRODUCT_VISIBLE_KEYS"):
                continue
            value = node.value
            if isinstance(value, ast.Call) and value.args:
                value = value.args[0]
            if isinstance(value, (ast.Set, ast.Tuple, ast.List)):
                declared = {
                    e.value for e in value.elts if isinstance(e, ast.Constant)
                }
    assert declared, (
        "corpora.py must declare PRODUCT_VISIBLE_KEYS, the closed set of keys a "
        "product-bound record may carry"
    )
    leaked = sorted(declared & gold_keys)
    assert not leaked, (
        f"these gold keys are declared product-visible: {leaked}"
    )
