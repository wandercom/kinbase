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

#: Modules that *are* the child-process mechanism. They construct the
#: environment the policy governs, so scanning them for "controls" would flag
#: the allowlist itself. Their contents are governed by ``ENV_ALLOWLIST``.
_MECHANISM_MODULES = {"cli.py", "gitfix.py", "worldbuilder.py", "planters.py"}

#: Modules that start a *Tester-owned* child process rather than the system
#: under test. The frozen answer service in ``authority.py`` is an instrument:
#: its environment configures the harness's own answering helper and never
#: reaches the product, so scanning it against the product allowlist would
#: report the instrument's own configuration as a product control. Its variable
#: names are listed in ``HARNESS_ONLY`` so the separate leak test still covers
#: them.
_NON_PRODUCT_CHILD_MODULES = {"authority.py"}


def _subscript_keys(tree: ast.Module, mapping: ast.expr) -> list[str]:
    """Literal keys assigned into a named mapping anywhere in the module."""
    if not isinstance(mapping, ast.Name):
        return []
    keys: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == mapping.id
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)
            ):
                keys.append(target.slice.value)
    return keys


def _modules() -> list[Path]:
    return sorted(p for p in _SUITE.rglob("*.py") if p.name not in _POLICY_MODULES)


def _env_names_passed_to_product() -> dict[str, list[str]]:
    """Every environment key the suite can place in a child process.

    Detector Reviewer finding 20: the previous scan read only literal keys inside
    a literal ``env={...}`` argument, so a variable mapping or a constructor
    ``extra_env`` was invisible. Both are inspected now, and a non-literal
    mapping is itself reported, because an unreadable channel cannot be cleared.
    """
    found: dict[str, list[str]] = {}
    for path in _modules():
        if path.name in _NON_PRODUCT_CHILD_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg not in ("env", "extra_env"):
                    continue
                value = keyword.value
                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and value.func.attr == "base_env"
                    and value.args
                    and isinstance(value.args[0], ast.Dict)
                ):
                    # `guildhall.base_env({...})` is the driver's own allowlisted
                    # constructor; the literal overrides are the test-supplied
                    # controls and are exactly what must be inspected.
                    keyword = ast.keyword(arg=keyword.arg, value=value.args[0])
                if not isinstance(keyword.value, ast.Dict):
                    # A mapping built by name is readable when every key
                    # assigned into it in this module is a literal string; the
                    # driver's own base_env and the git fixture env are
                    # mechanism, not test-supplied controls.
                    if path.name in _MECHANISM_MODULES:
                        continue
                    literal_keys = _subscript_keys(tree, keyword.value)
                    if literal_keys:
                        for key in literal_keys:
                            found.setdefault(key, []).append(path.name)
                        continue
                    found.setdefault(
                        f"<non-literal {keyword.arg} mapping>", []
                    ).append(f"{path.name}:{node.lineno}")
                    continue
                for key in keyword.value.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        found.setdefault(key.value, []).append(path.name)
                    else:
                        found.setdefault(
                            f"<computed {keyword.arg} key>", []
                        ).append(f"{path.name}:{node.lineno}")
    return found


#: Words that name a semantic case, scenario or expected outcome. None of these
#: may appear in any value the product can read on any channel: argv, cwd,
#: session identifiers, committed paths, stdin payloads or service requests.
SEMANTIC_TOKENS: tuple[str, ...] = (
    "scenario", "expected", "historical_digest_differs", "historical_digest_matches",
    "historical_version_missing", "company_unavailable", "local_superset_fresh",
    "missing_expected_head", "expired_observation", "full-fsck-required",
    "invalid-cache", "newest_wins", "highest_authority", "repetition_as",
    "acceptance-v", "acceptance-",
)


def _product_readable_string_literals() -> list[tuple[str, int, str]]:
    """String literals that flow into argv, cwd, stdin or a committed path.

    Any literal passed positionally to a ``guildhall.run``/``popen`` call, used
    as a commit message, or written into a repository path is readable by the
    product. The scan is deliberately broad: a literal that never reaches the
    product costs nothing to rename, while one that does is a leak.
    """
    out: list[tuple[str, int, str]] = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            name = (
                target.attr if isinstance(target, ast.Attribute)
                else getattr(target, "id", "")
            )
            if name not in ("run", "popen", "commit", "write", "write_text",
                            "write_bytes", "mkdir", "create", "plant_event"):
                continue
            for argument in list(node.args) + [k.value for k in node.keywords]:
                for literal in ast.walk(argument):
                    if isinstance(literal, ast.Constant) and isinstance(
                        literal.value, str
                    ):
                        out.append((path.name, literal.lineno, literal.value))
    return out


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
    VERIFY(
        "INSTRUMENT",
        "oracle-privacy",
        "**Tester (Claude):** reads ratified product, architecture, verification strategy, and a "
        "clean test lane; authors acceptance/benchmark tests and fixtures only; cannot read "
        "implementation or Coder work or issue a verdict.",
    )
)
def test_no_semantic_case_identity_reaches_the_product_on_any_channel() -> None:
    """argv, cwd, session IDs, committed paths and messages carry no case name.

    Detector Reviewer finding 20 named three concrete leaks: V-4 committed the
    manifest scenario into Git history, V-8 embedded the digest-attribution case
    in a repository path, and V-9 embedded the expected start state in a session
    ID. Fixed acceptance-prefixed session identifiers disclosed run identity too.
    """
    offenders: list[str] = []
    for module, line, value in _product_readable_string_literals():
        lowered = value.lower()
        for token in SEMANTIC_TOKENS:
            if token in lowered:
                offenders.append(f"{module}:{line} {value[:70]!r} contains {token!r}")
                break
    assert not offenders, (
        "these product-readable strings disclose a case identity, scenario or "
        "expected outcome; use an opaque harness-mapped identifier:\n  "
        + "\n  ".join(sorted(set(offenders)))
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
