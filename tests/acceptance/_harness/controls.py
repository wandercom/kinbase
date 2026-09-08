"""The closed policy for what may reach the system under test.

Detector Reviewer finding 7 and the out-of-band control inventory. The previous
instrument passed forty ``GUILDHALL_ACCEPTANCE_*`` variables into the product
process. Most were ``result_selector`` or ``work_substitute`` class: a product
could branch on ``DIGEST_SCENARIO``, ``TEMPORAL_CASE`` or ``V7_FIXTURE`` and emit
the expected JSON without doing the work, and every name disclosed acceptance-run
identity regardless of its value.

This module fixes the policy and makes it enforceable:

* **Raw state only.** Everything semantic must reach the product as real input
  through a ratified surface --- planted signed events, ingested corpora, a live
  Company service, real repository topology.
* **No semantic controls.** No environment variable may carry an expected
  outcome, a scenario name, a case identity or a fixture mode.
* **Witnessed perturbations only.** Timing, ordering and failure schedules are
  permitted, but each must be paired with an independent witness that observed
  the perturbation actually occurring.

``test_control_policy.py`` enforces this over the whole suite by static
inspection, so a future selector cannot creep back in unnoticed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from .requirements import HarnessInvalid


@dataclass(frozen=True)
class PermittedControl:
    """One environment name the suite may pass to the product."""

    name: str
    classification: str          # "environment" | "fault_schedule" | "attack_input"
    rationale: str
    witness_required: bool

    def __post_init__(self) -> None:
        if self.classification not in ("environment", "fault_schedule", "attack_input"):
            raise HarnessInvalid(
                f"{self.name}: classification must be environment, fault_schedule "
                "or attack_input; result_selector and work_substitute are "
                "forbidden outright"
            )


#: Ordinary configuration and isolation. These carry no semantic answer and
#: correspond to real deployment inputs the ratified CLI contract already names.
_ENVIRONMENT = (
    ("HOME", "isolated temporary home, spec/verification.md V-9"),
    ("XDG_CONFIG_HOME", "isolated config root, spec/cli.md configuration"),
    ("XDG_DATA_HOME", "isolated data root"),
    ("XDG_STATE_HOME", "isolated state root"),
    ("XDG_CACHE_HOME", "isolated cache root"),
    ("PATH", "executable resolution for real host binaries"),
    ("LANG", "ambient locale"),
    ("LC_ALL", "ambient locale"),
    ("TZ", "deterministic UTC"),
    ("TMPDIR", "isolated temporary directory"),
    ("SYSTEMROOT", "platform requirement"),
    ("PYTHONHASHSEED", "determinism"),
    ("PYTHONIOENCODING", "deterministic encoding"),
    ("NO_COLOR", "machine-readable output"),
    ("TERM", "non-interactive terminal"),
    ("GIT_CONFIG_GLOBAL", "isolation from operator git configuration"),
    ("GIT_CONFIG_SYSTEM", "isolation from system git configuration"),
    ("GIT_TERMINAL_PROMPT", "non-interactive git"),
    ("GIT_AUTHOR_NAME", "deterministic fixture identity"),
    ("GIT_AUTHOR_EMAIL", "deterministic fixture identity"),
    ("GIT_COMMITTER_NAME", "deterministic fixture identity"),
    ("GIT_COMMITTER_EMAIL", "deterministic fixture identity"),
    ("GIT_AUTHOR_DATE",
     "deterministic fixture commit time; consumed by git when the instrument\n      builds repository topology, carries no expected outcome"),
    ("GIT_COMMITTER_DATE", "deterministic fixture commit time"),
)

#: Hostile inputs the instrument deliberately injects. They are not controls:
#: the product must *refuse* them, and the refusal is witnessed independently
#: (an observed connection count). Validator ruling C28: the product never
#: reads a Company endpoint from the environment; an env-supplied endpoint
#: yields ``PROCESSOR_UNAUTHORIZED`` with zero connections.
_ATTACK_INPUT = (
    ("GUILDHALL_COMPANY_URL",
     "an environment-supplied Company endpoint, threat-model family 14; the "
     "product must refuse it without connecting, witnessed by the listener's "
     "observed connection count"),
)

#: Perturbation schedules. Permitted only with an independent witness proving the
#: perturbation happened, so a product cannot satisfy the obligation by
#: recognising the request rather than surviving the event.
_FAULT_SCHEDULE = (
    ("GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS",
     "advances the proof clock; witnessed by an observed elapsed interval and by "
     "the expiry state the instrument reads back"),
)

PERMITTED: Mapping[str, PermittedControl] = {
    name: PermittedControl(name, "environment", why, witness_required=False)
    for name, why in _ENVIRONMENT
} | {
    name: PermittedControl(name, "fault_schedule", why, witness_required=True)
    for name, why in _FAULT_SCHEDULE
} | {
    name: PermittedControl(name, "attack_input", why, witness_required=True)
    for name, why in _ATTACK_INPUT
}

#: Name shapes that always indicate a semantic control, whatever the value.
FORBIDDEN_SHAPES: tuple[tuple[str, str], ...] = (
    (r"_SCENARIO$", "names a scenario the product can branch on"),
    (r"_CASE$", "names a frozen case identity"),
    (r"_FIXTURE$", "selects a fixture mode instead of ingesting state"),
    (r"_STATE$", "selects a state instead of constructing it"),
    (r"_CRITICALITY$", "supplies a class the product should read from signed state"),
    (r"_VALIDITY$", "supplies validity the product should read from signed state"),
    (r"_DEPENDENCE$", "supplies a class the product should read from a Codebase fact"),
    (r"_TRUST$", "supplies a trust class the product should derive"),
    (r"_SNAPSHOT$", "supplies a snapshot state instead of changing it"),
    (r"_OVERRIDE$", "overrides a value the product should compute"),
    (r"_APPROVAL$", "supplies an approval outcome"),
    (r"_PRINCIPAL$", "supplies an identity that must be authenticated"),
    (r"_ALG_VERSION$", "supplies a value that belongs in the reference"),
    (r"RESOLVES_TO", "supplies a resolution result"),
    (r"^GUILDHALL_ACCEPTANCE_", "discloses acceptance-run identity to the product"),
)


def classify(name: str) -> str:
    """Classify an environment name against the frozen policy."""
    if name in PERMITTED:
        return PERMITTED[name].classification
    for pattern, _ in FORBIDDEN_SHAPES:
        if re.search(pattern, name):
            return "forbidden"
    return "unknown"


def violations(names: Iterable[str]) -> list[tuple[str, str]]:
    """Return ``(name, reason)`` for every name the policy forbids."""
    out: list[tuple[str, str]] = []
    for name in sorted(set(names)):
        if name in PERMITTED:
            continue
        matched = False
        for pattern, reason in FORBIDDEN_SHAPES:
            if re.search(pattern, name):
                out.append((name, reason))
                matched = True
                break
        if not matched:
            out.append(
                (name, "not on the closed permitted-control allowlist")
            )
    return out


#: Harness-only variables. These never reach the product process; they configure
#: the instrument itself and are asserted to be absent from the child environment.
HARNESS_ONLY: frozenset[str] = frozenset({
    "GUILDHALL_BIN",
    "GUILDHALL_CLASSIFIER_MODEL",
    "GUILDHALL_SPEC_ROOT",
    "GUILDHALL_TESTER_VAULT",
    "GUILDHALL_HOST_CODEX",
    "GUILDHALL_HOST_CLAUDE",
    "GUILDHALL_ACCEPT_GATE_VECTOR",
    "GUILDHALL_ACCEPT_MUTATION",
    "GUILDHALL_ACCEPT_DETECTOR_MUTATION",
    "GUILDHALL_REVIEWER_MODE",
    "AUTHORITY_SEED_HEX",
    "AUTHORITY_LOG",
    "AUTHORITY_CALL_CEILING",
    "AUTHORITY_HARNESS_PATH",
    "GUILDHALL_OPERATOR_RESPONSES",
    "GUILDHALL_KILL_LEDGER",
    "GUILDHALL_DETECTOR_LEDGER",
    "ACCEPT_PYTHON",
    "ACCEPT_NO_VENV",
})
