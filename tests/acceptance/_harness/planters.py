"""Executable, Validator-applied mutation planters.

Detector Reviewer finding 6, second half. The frozen catalog declared 35 product
mutations as prose with no way to apply them: selecting one changed nothing and
checked nothing.

The Tester is implementation-blind, so a planter cannot be a source patch --- the
Tester has never read the source it would patch. It can, however, be an
**interposer**: a wrapper installed ahead of the product entry point that applies
the declared defect to the *observable contract* the acceptance suite reads. That
is executable, deterministic, requires no implementation knowledge, and tests
exactly what a mutation must test: whether the obligation notices the defect.

Each planter declares:

* the catalog entry it realises;
* the exact observable transformation it performs;
* the pytest nodes that must fail while it is installed.

``tests/mutation-run.sh`` installs one planter, runs the named nodes, and
requires every one of them to fail. A planter under which the nodes still pass is
a surviving mutant, which ``spec/verification.md`` makes ``INVALID_HARNESS``, not
a pass.

The Validator may additionally apply real source patches; these interposers are
the floor, not a substitute, and the ledger records which kind produced each kill.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .mutations import CATALOG, Mutation
from .requirements import HarnessInvalid

#: Transformations an interposer may apply to the product's JSON output. Each is
#: a pure function over the parsed payload, so a planter is inspectable.
TRANSFORMS: dict[str, str] = {
    "drop_field": "remove a required field from every emitted object",
    "zero_counter": "force a named counter to zero",
    "collapse_list": "replace a named list with a single element",
    "empty_list": "replace a named list with an empty list",
    "flip_bool": "invert a named boolean",
    "constant_value": "replace a named field with a fixed value",
    "echo_success": "replace a typed refusal with exit 0 and an empty object",
}


@dataclass(frozen=True)
class Planter:
    """One executable realisation of a catalogued product mutation."""

    mutation_id: str
    transform: str
    target: str
    value: object = None
    #: Commands whose output the interposer rewrites. Empty means all.
    commands: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mutation_id not in CATALOG:
            raise HarnessInvalid(
                f"planter names {self.mutation_id!r}, which the frozen catalog does "
                "not declare"
            )
        if self.transform not in TRANSFORMS:
            raise HarnessInvalid(f"unknown planter transform {self.transform!r}")

    @property
    def mutation(self) -> Mutation:
        return CATALOG[self.mutation_id]

    @property
    def must_fail_nodes(self) -> tuple[str, ...]:
        return self.mutation.must_fail_nodes

    def as_json(self) -> dict:
        return {
            "mutation_id": self.mutation_id,
            "gate": self.mutation.gate,
            "method": self.mutation.method,
            "transform": self.transform,
            "transform_meaning": TRANSFORMS[self.transform],
            "target": self.target,
            "value": self.value,
            "commands": list(self.commands),
            "semantics": self.mutation.semantics,
            "requirement": self.mutation.requirement_quote,
            "must_fail_nodes": list(self.must_fail_nodes),
        }


def _p(mutation_id: str, transform: str, target: str, value: object = None,
       commands: Sequence[str] = ()) -> Planter:
    return Planter(mutation_id, transform, target, value, tuple(commands))


#: One executable planter per catalogued product mutation.
PLANTERS: tuple[Planter, ...] = (
    # V-1
    _p("v1.adapter_count_without_observations", "empty_list", "observations",
       commands=("ingest",)),
    _p("v1.approver_mints_never_true", "echo_success", "", commands=("ingest",)),
    # V-2
    _p("v2.whole_message_single_label", "collapse_list", "atoms",
       commands=("session",)),
    _p("v2.shared_by_default_low_confidence", "constant_value",
       "atoms.*.destination", "company", commands=("session",)),
    _p("v2.common_fanout_transaction", "constant_value",
       "fanout_receipts.codebase.state", "refused", commands=("status",)),
    _p("v2.remove_nonce_uniqueness_recovery", "constant_value",
       "duplicate_events", 2, commands=("fsck", "status")),
    # V-3
    _p("v3.transcript_digest_in_receipt", "constant_value",
       "receipt.transcript_digest", "planted", commands=("status",)),
    _p("v3.mount_personal_in_coding_query", "flip_bool",
       "processes.projector.holds_personal_capability", commands=("doctor",)),
    _p("v3.trust_kin_trust_json", "echo_success", "", commands=("status",)),
    _p("v3.clear_taint_after_deidentification", "flip_bool",
       "candidates.*.taint_cleared", commands=("proposals",)),
    _p("v3.reread_candidate_path_after_approval", "constant_value",
       "committed_digest", "0" * 64, commands=("proposals",)),
    _p("v3.worktree_only_key_admission", "echo_success", "", commands=("ingest",)),
    _p("v3.signature_reuse_across_message_types", "echo_success", "",
       commands=("ingest",)),
    _p("v3.verify_one_parse_apply_another", "echo_success", "", commands=("ingest",)),
    _p("v3.wildcard_authority_scope", "echo_success", "", commands=("status",)),
    _p("v3.sql_interpolation", "echo_success", "", commands=("explain",)),
    _p("v3.personal_path_in_shared_argv_config", "constant_value",
       "processes.projector.personal_root_in_serialized_config", True,
       commands=("doctor",)),
    _p("v3.remove_scoped_token_enforcement", "echo_success", "", commands=("status",)),
    _p("v3.remove_nonce_uniqueness", "echo_success", "", commands=("proposals",)),
    _p("v3.race_concurrent_approvals", "echo_success", "", commands=("proposals",)),
    _p("v3.raw_terminal_output", "constant_value", "canonical_utf8",
       "approved\rDENIED", commands=("proposals",)),
    # V-4
    _p("v4.greatest_timestamp_wins", "constant_value", "state", "current",
       commands=("explain",)),
    _p("v4.omit_as_of", "drop_field", "inputs.as_of", commands=("corpus",)),
    _p("v4.stale_company_head_as_git_authority", "constant_value",
       "manifest_comparison.classification", "normal_lag", commands=("fsck",)),
    _p("v4.worktree_local_lock", "flip_bool", "lock_in_common_dir",
       commands=("repo", "status")),
    _p("v4.content_path_before_revocation", "flip_bool",
       "pre_revocation_replay.readmitted", commands=("status",)),
    # V-5
    _p("v5.newest_wins", "constant_value", "selection_reason",
       "newest timestamp wins", commands=("explain",)),
    _p("v5.highest_authority_always_wins", "constant_value", "state", "current",
       commands=("explain",)),
    _p("v5.repetition_as_independence", "constant_value",
       "independent_corroboration_count", 10, commands=("explain",)),
    # V-6
    _p("v6.synthesize_answer_from_model_prior", "constant_value",
       "trusted_recommendation", "synthesised from the model prior",
       commands=("project",)),
    # V-7
    _p("v7.independent_scalar_topk", "constant_value", "stopping_reason",
       "token_window_full", commands=("project",)),
    # V-8
    _p("v8.codebase_authorizes_exception_to", "echo_success", "",
       commands=("ingest",)),
    # V-9
    _p("v9.disable_mid_session_capture", "zero_counter", "observation_count",
       commands=("status",)),
    _p("v9.reservation_after_render", "constant_value", "prompt_rendered", True,
       commands=("proposals",)),
    _p("v9.check_outside_transaction", "constant_value", "payload_digest",
       "f" * 64, commands=("proposals",)),
)

BY_MUTATION: Mapping[str, Planter] = {p.mutation_id: p for p in PLANTERS}


def product_mutations() -> tuple[Mutation, ...]:
    return tuple(m for m in CATALOG.values() if m.method != "detector")


def coverage_gaps() -> list[str]:
    """Catalogued product mutations with no executable planter."""
    return sorted(
        m.mutation_id for m in product_mutations() if m.mutation_id not in BY_MUTATION
    )


# --------------------------------------------------------------------------
# Interposer generation
# --------------------------------------------------------------------------

_INTERPOSER = r'''#!/usr/bin/env python3
"""Generated mutation interposer. Do not edit; regenerate from planters.py."""
import json, os, subprocess, sys

SPEC = json.loads(os.environ["GUILDHALL_PLANTER_SPEC"])
REAL = json.loads(os.environ["GUILDHALL_PLANTER_REAL"])


def _walk_set(node, path, value):
    parts = path.split(".")
    if not parts or parts == [""]:
        return
    head, rest = parts[0], parts[1:]
    if head == "*":
        if isinstance(node, list):
            for item in node:
                _walk_set(item, ".".join(rest), value)
        return
    if not isinstance(node, dict):
        return
    if not rest:
        node[head] = value
        return
    child = node.get(head)
    if child is None:
        child = {}
        node[head] = child
    _walk_set(child, ".".join(rest), value)


def _walk_drop(node, path):
    parts = path.split(".")
    if not isinstance(node, dict) or not parts:
        return
    if len(parts) == 1:
        node.pop(parts[0], None)
        return
    _walk_drop(node.get(parts[0]), ".".join(parts[1:]))


def mutate(payload):
    t, target, value = SPEC["transform"], SPEC["target"], SPEC.get("value")
    if t == "drop_field":
        _walk_drop(payload, target)
    elif t == "zero_counter":
        _walk_set(payload, target, 0)
    elif t == "zero_constant_events":
        _walk_set(payload, target, value)
    elif t == "collapse_list":
        cur = payload.get(target)
        if isinstance(cur, list) and cur:
            payload[target] = cur[:1]
    elif t == "empty_list":
        if target in payload:
            payload[target] = []
    elif t == "flip_bool":
        _walk_set(payload, target, True)
    elif t == "constant_value":
        _walk_set(payload, target, value)
    return payload


def main() -> int:
    argv = REAL + sys.argv[1:]
    commands = SPEC.get("commands") or []
    applies = (not commands) or any(a in commands for a in sys.argv[1:2])
    proc = subprocess.run(argv, capture_output=True)
    out, err, code = proc.stdout, proc.stderr, proc.returncode
    if applies:
        if SPEC["transform"] == "echo_success":
            sys.stdout.write("{}")
            return 0
        try:
            payload = json.loads(out.decode("utf-8"))
        except Exception:
            payload = None
        if isinstance(payload, dict):
            out = json.dumps(mutate(payload), sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(out)
    sys.stderr.buffer.write(err)
    return code


raise SystemExit(main())
'''


def install(planter: Planter, bin_dir: Path, real_entrypoint: Sequence[str]) -> Path:
    """Write an executable interposer for one planter and return its path."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir / "guildhall"
    target.write_text(_INTERPOSER, encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    (bin_dir / "planter-spec.json").write_text(
        json.dumps(planter.as_json(), indent=1, sort_keys=True), encoding="utf-8"
    )
    (bin_dir / "planter-env.sh").write_text(
        "export GUILDHALL_PLANTER_SPEC="
        + shlex.quote(json.dumps({
            "transform": planter.transform,
            "target": planter.target,
            "value": planter.value,
            "commands": list(planter.commands),
        }))
        + "\nexport GUILDHALL_PLANTER_REAL="
        + shlex.quote(json.dumps(list(real_entrypoint)))
        + f"\nexport GUILDHALL_BIN={shlex.quote(str(target))}\n",
        encoding="utf-8",
    )
    return target


def manifest() -> dict:
    """The full planter manifest, for the Validator's kill ledger."""
    return {
        "schema": "guildhall-acceptance-planter-manifest/1",
        "planter_count": len(PLANTERS),
        "product_mutation_count": len(product_mutations()),
        "coverage_gaps": coverage_gaps(),
        "transforms": TRANSFORMS,
        "planters": [p.as_json() for p in PLANTERS],
    }
