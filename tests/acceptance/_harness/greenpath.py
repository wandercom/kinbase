"""Per-test analysis of every branch on which a gate test could pass.

Detector Reviewer finding 6. The previous linter checked three literal defaults
(``0``, ``""``, ``False``) and accepted a whole module if any one total-quantifier
name appeared anywhere in it. The Reviewer then found, in the modules it had
already approved, 24 collection defaults, 17 optional loops and 41 assertion
blocks nested inside a guard on product output --- every one of which is a path
where the product produces nothing and the test still ends green.

This module replaces the module-level heuristic with a per-test control-flow
analysis. For every test function in every gate module it asks one question:

    is there a path through this function that reaches ``return`` without
    evaluating a typed claim over a non-empty domain?

and reports each way the answer is yes. The rules are deliberately syntactic and
total: a construct is rejected unless the function *proves* the domain, because
"probably non-empty" is exactly the assumption that produced the finding.

Nothing here is exemptable. A gate test that genuinely has an optional branch
must raise a typed failure on it, which is a claim, not a green path.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

#: Calls that constitute a typed claim: they either evaluate a catalogued
#: obligation or refuse an empty/absent domain in a declared channel.
CLAIM_CALLS: frozenset[str] = frozenset({
    "check",                  # obligations.check / O.check
    "require_all",
    "require_nonempty",
    "require_exactly",
    "require_total_coverage",
    "forbid",
    "expect_refusal",
    "expect_typed_refusal",
    "assert_killed",
    "raises",                 # pytest.raises(...) as a context manager
})

#: Evidence accessors are claims too; all of them are total and typed.
CLAIM_PREFIXES: tuple[str, ...] = ("need",)

#: Prerequisite helpers establish instrument-owned state. They are typed and
#: fail closed, so they prove a domain, but they are not by themselves a claim
#: about the product.
PREREQ_CALLS: frozenset[str] = frozenset({
    "fixture_file", "gold_records", "gold_join", "isolated_root", "private_mode",
    "executable", "env_var", "listening", "service_ready", "certificate_installed",
    "registered", "corpus_at_scale", "collected", "witnessed", "rights_granted",
})

#: Wrappers that preserve the emptiness of their argument.
TRANSPARENT_WRAPPERS: frozenset[str] = frozenset({
    "sorted", "list", "tuple", "set", "reversed", "enumerate", "frozenset",
})

#: Literal defaults that turn absent product evidence into satisfied evidence.
FALSY_LITERALS = (0, 0.0, "", False)


@dataclass(frozen=True)
class Finding:
    module: str
    line: int
    func: str
    rule: str
    detail: str

    def render(self) -> str:
        return f"{self.module}:{self.line} {self.func}: [{self.rule}] {self.detail}"


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_claim(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node)
    if name in CLAIM_CALLS:
        return True
    return any(name.startswith(p) for p in CLAIM_PREFIXES)


def _is_prereq(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node) in PREREQ_CALLS


def _contains_claim(node: ast.AST) -> bool:
    return any(_is_claim(child) for child in ast.walk(node))


def _contains_raise(node: ast.AST) -> bool:
    return any(isinstance(child, ast.Raise) for child in ast.walk(node))


def _module_constants(tree: ast.Module) -> set[str]:
    """Module-level names bound to a frozen literal collection.

    Iterating one of those is safe: its size is fixed in the committed bytes and
    a selftest can assert it. Iterating anything else must be proved.
    """
    names: set[str] = set()
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if value is None:
            continue
        literal = value
        if isinstance(literal, ast.Call) and _call_name(literal) in TRANSPARENT_WRAPPERS:
            literal = literal.args[0] if literal.args else literal
        if isinstance(literal, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            for target in targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _proved_names(func: ast.FunctionDef) -> set[str]:
    """Names whose non-emptiness this function established before iterating.

    A name is proved when it is the subject of a total quantifier or a typed
    prerequisite, or when it is bound to the *result* of one.
    """
    proved: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and (
            _call_name(node) in {"require_nonempty", "require_all", "require_exactly",
                                 "require_total_coverage"}
            or _is_prereq(node)
        ):
            if node.args:
                first = node.args[0]
                if isinstance(first, ast.Name):
                    proved.add(first.id)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if (
                _call_name(node.value) in {"require_nonempty", "require_all",
                                           "require_exactly"}
                or _is_prereq(node.value)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        proved.add(target.id)
    return proved


def _iter_subject(node: ast.expr) -> str:
    """Reduce a loop iterable to the name whose emptiness governs the loop."""
    current = node
    while True:
        if isinstance(current, ast.Call) and _call_name(current) in TRANSPARENT_WRAPPERS:
            if not current.args:
                return ""
            current = current.args[0]
            continue
        if isinstance(current, ast.Attribute):
            # `mapping.items()` style is reached through the Call branch; a bare
            # attribute is governed by its root name.
            current = current.value
            continue
        if isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute):
            current = current.func.value
            continue
        break
    if isinstance(current, ast.Name):
        return current.id
    return ""


_GUARD_NODES = (ast.If, ast.Try, ast.While, ast.ExceptHandler)


def _unconditional_statements(func: ast.FunctionDef) -> list[ast.stmt]:
    """Statements reachable without passing through a guard.

    ``With`` (including ``pytest.raises``) and ``For`` are containers, not
    guards; a ``For`` is separately required to prove its domain.
    """
    out: list[ast.stmt] = []

    def walk(body: Sequence[ast.stmt]) -> None:
        for statement in body:
            if isinstance(statement, _GUARD_NODES):
                continue
            out.append(statement)
            for field_name in ("body", "orelse", "finalbody"):
                nested = getattr(statement, field_name, None)
                if isinstance(nested, list):
                    walk([s for s in nested if isinstance(s, ast.stmt)])

    walk(func.body)
    return out


#: Rules that only govern *product-facing* tests. A ``selftest``-marked node is
#: instrument-only: ``census.py`` forbids it from resolving the product channel
#: at all, so requiring it to declare a product channel or consume a catalog row
#: would describe a claim it is structurally incapable of making. Every other
#: rule --- bare return, permissive default, collection fallback, tautology,
#: swallowed failure, unproved loop --- applies to every test without exception.
PRODUCT_FACING_RULES: frozenset[str] = frozenset({
    "bare-assert", "no-catalog-consumption", "optional-guard",
})


def _module_is_selftest(tree: ast.Module) -> bool:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "pytestmark":
                if "selftest" in ast.unparse(node.value):
                    return True
    return False


def _is_selftest(func: ast.FunctionDef) -> bool:
    return any(
        "selftest" in ast.unparse(decorator) for decorator in func.decorator_list
    )


def analyse_module(path: Path) -> list[Finding]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    constants = _module_constants(tree)
    module_selftest = _module_is_selftest(tree)
    findings: list[Finding] = []

    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef) or not func.name.startswith("test_"):
            continue
        results = _analyse_test(path.name, func, constants)
        if module_selftest or _is_selftest(func):
            results = [f for f in results if f.rule not in PRODUCT_FACING_RULES]
        findings.extend(results)
    return findings


def _analyse_test(
    module: str, func: ast.FunctionDef, constants: set[str]
) -> list[Finding]:
    out: list[Finding] = []
    add = lambda line, rule, detail: out.append(  # noqa: E731
        Finding(module, line, func.name, rule, detail)
    )

    # -- bare return -------------------------------------------------------
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and node.value is None:
            add(node.lineno, "bare-return",
                "a bare return ends the test green; raise a typed failure")

    # -- bare assert -------------------------------------------------------
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            add(node.lineno, "bare-assert",
                "an untyped assert cannot declare its channel; route the claim "
                "through O.check, require_*, forbid or a typed prerequisite")

    # -- permissive defaults and collection fallbacks ----------------------
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and len(node.args) == 2
        ):
            add(node.lineno, "permissive-default",
                "`.get(key, default)` turns absent evidence into satisfied "
                "evidence; use a typed accessor")
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            for value in node.values[1:]:
                if isinstance(value, (ast.List, ast.Tuple, ast.Dict, ast.Set)) and not (
                    getattr(value, "elts", None) or getattr(value, "keys", None)
                ):
                    add(node.lineno, "collection-fallback",
                        "`... or <empty collection>` silently substitutes an "
                        "empty domain for missing product output")
                if isinstance(value, ast.Constant) and value.value in FALSY_LITERALS:
                    add(node.lineno, "collection-fallback",
                        f"`... or {value.value!r}` substitutes a falsy default")
                if isinstance(value, ast.Call) and _call_name(value) in {
                    "list", "dict", "set", "tuple"
                } and not value.args:
                    add(node.lineno, "collection-fallback",
                        "`... or <empty constructor>` substitutes an empty domain")

    # -- tautologies -------------------------------------------------------
    for node in ast.walk(func):
        if isinstance(node, ast.Assert) and isinstance(node.test, ast.Constant):
            if bool(node.test.value):
                add(node.lineno, "tautology", "assert over a truthy constant")

    # -- swallowed typed failures -----------------------------------------
    for node in ast.walk(func):
        if isinstance(node, ast.ExceptHandler) and not _contains_raise(node):
            add(node.lineno, "swallowed-failure",
                "an except handler that does not re-raise converts a typed "
                "failure into a green path")

    # -- unproved loop domains --------------------------------------------
    proved = _proved_names(func) | constants
    for node in ast.walk(func):
        if not isinstance(node, ast.For):
            continue
        if not any(_contains_claim(child) for child in node.body):
            continue
        subject = _iter_subject(node.iter)
        if subject and subject in proved:
            continue
        if isinstance(node.iter, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            continue
        add(node.lineno, "unproved-loop",
            f"the claim inside this loop is vacuous when {subject or 'the domain'} "
            "is empty; prove the domain with require_nonempty/require_all or a "
            "typed prerequisite first")

    # -- optional assertion guard -----------------------------------------
    unconditional = _unconditional_statements(func)
    if not any(_contains_claim(s) for s in unconditional):
        guarded = [n.lineno for n in ast.walk(func)
                   if isinstance(n, _GUARD_NODES) and _contains_claim(n)]
        add(func.lineno, "optional-guard",
            "every claim in this test is nested inside a guard, so a product "
            "that produces nothing takes a path with no claim at all"
            + (f" (guarded claims at line(s) {guarded})" if guarded else ""))

    # -- catalog consumption ----------------------------------------------
    consumes = [
        n for n in ast.walk(func)
        if isinstance(n, ast.Call) and _call_name(n) == "check"
        and n.args and isinstance(n.args[0], ast.Constant)
        and isinstance(n.args[0].value, str)
    ]
    if not consumes:
        add(func.lineno, "no-catalog-consumption",
            "the test evaluates no catalogued obligation, so the census would "
            "credit a row this node never checked")
    return out


def consumed_oids(path: Path) -> dict[str, set[str]]:
    """``{test_function: {oid, ...}}`` literally consumed in this module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out: dict[str, set[str]] = {}
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef) or not func.name.startswith("test_"):
            continue
        oids: set[str] = set()
        for node in ast.walk(func):
            if (
                isinstance(node, ast.Call)
                and _call_name(node) == "check"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                oids.add(node.args[0].value)
        out[func.name] = oids
    return out
