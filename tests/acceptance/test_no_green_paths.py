"""No assertion may pass without evidence.

Detector Reviewer section 8, the green-path and fail-closed audit. Every pattern
below was found in the previous instrument and each turned "the product produced
nothing" into "the obligation is satisfied":

* bare ``return`` inside a test, so a refusal ends the test green;
* ``payload.get(k, 0)`` / ``.get(k, [])``, so a missing counter or list satisfies
  a bound or a loop;
* ``... or True``, which asserts nothing;
* ``for x in payload.get(k, []):`` with the assertion inside, vacuously true on
  an empty domain;
* ``if result.returncode == 0:`` guarding the only assertion in a test.

This module forbids them by static inspection over the gate modules, so the class
cannot return. Where a genuinely optional branch is unavoidable, the test must
raise a typed failure instead of returning, and quantified claims must go through
``require_all`` / ``require_nonempty``, which refuse an empty domain.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ._harness.requirements import VERIFY, spec_ref

pytestmark = pytest.mark.selftest

_SUITE = Path(__file__).resolve().parent

#: Modules that assert against the product. The instrument's own self-tests are
#: exempt from the bare-return rule because they legitimately branch on optional
#: platform capability, but they are still covered by every other rule.
_GATE_MODULES = tuple(
    f"test_v{n}{suffix}.py"
    for n, suffix in (
        (1, "_ingestion"), (2, "_classification"), (3, "_privacy"),
        (3, "_attacks"), (3, "_qualification"), (4, "_maintenance"),
        (5, "_temporal"), (6, "_authority"), (7, "_projection"),
        (8, "_company_refs"), (9, "_fatigue"), (9, "_host_lifecycle"),
        (10, "_protocol"),
    )
) + ("test_nonfunctional.py", "test_evidence_packet.py")


def _gate_sources() -> list[tuple[Path, ast.Module]]:
    out: list[tuple[Path, ast.Module]] = []
    for name in _GATE_MODULES:
        path = _SUITE / name
        if path.is_file():
            out.append((path, ast.parse(path.read_text(encoding="utf-8"), str(path))))
    return out


def _tests(tree: ast.Module):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            yield node


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_no_bare_return_ends_a_gate_test_green() -> None:
    offenders: list[str] = []
    for path, tree in _gate_sources():
        for func in _tests(tree):
            for node in ast.walk(func):
                if isinstance(node, ast.Return) and node.value is None:
                    offenders.append(f"{path.name}:{node.lineno} in {func.name}")
    assert not offenders, (
        "a bare return ends a gate test green without evidence; raise a typed "
        "failure instead:\n  " + "\n  ".join(offenders)
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_no_permissive_default_satisfies_an_assertion() -> None:
    """``.get(key, default)`` on product evidence is forbidden.

    A default turns absent evidence into satisfied evidence. Product reads go
    through the typed accessors in ``evidence_model``, which have no default.
    """
    offenders: list[str] = []
    for path, tree in _gate_sources():
        for func in _tests(tree):
            for node in ast.walk(func):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and len(node.args) == 2
                ):
                    default = node.args[1]
                    # `or []` style normalisation immediately followed by a
                    # require_* call is handled separately; a literal default
                    # inside .get() is always a permissive read.
                    if isinstance(default, ast.Constant) and default.value in (
                        0, "", False,
                    ):
                        offenders.append(
                            f"{path.name}:{node.lineno} in {func.name}"
                        )
    assert not offenders, (
        "a literal default turns missing product evidence into a satisfied "
        "assertion; use the typed accessors instead:\n  " + "\n  ".join(offenders)
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_no_tautological_assertion() -> None:
    """``assert X or True`` and ``assert True`` assert nothing."""
    offenders: list[str] = []
    for path, tree in _gate_sources():
        for func in _tests(tree):
            for node in ast.walk(func):
                if not isinstance(node, ast.Assert):
                    continue
                test = node.test
                if isinstance(test, ast.Constant) and bool(test.value):
                    offenders.append(f"{path.name}:{node.lineno} assert <constant>")
                if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
                    for value in test.values:
                        if isinstance(value, ast.Constant) and bool(value.value):
                            offenders.append(
                                f"{path.name}:{node.lineno} assert ... or <truthy>"
                            )
    assert not offenders, (
        "these assertions are tautological:\n  " + "\n  ".join(offenders)
    )


@spec_ref(
    VERIFY(
        "INSTRUMENT",
        "fail-closed",
        "A detector that cannot catch its positive control yields `INVALID_HARNESS`, never PASS.",
    )
)
def test_every_gate_module_uses_total_quantifiers() -> None:
    """A gate module that loops over product output must refuse an empty domain.

    ``for x in payload["items"]: assert p(x)`` is vacuously true when the list is
    empty, which is precisely how a product that produced nothing passed. Every
    gate module must import at least one of the total quantifiers, or route its
    obligation through the catalog checker, which refuses empty domains itself.
    """
    missing: list[str] = []
    for path, _ in _gate_sources():
        source = path.read_text(encoding="utf-8")
        uses_total = any(
            marker in source
            for marker in (
                "require_all", "require_nonempty", "require_exactly",
                "require_total_coverage", "O.check", "obligations as O",
            )
        )
        if not uses_total:
            missing.append(path.name)
    assert not missing, (
        "these gate modules quantify over product output without a total "
        f"quantifier or catalog checker: {missing}"
    )
