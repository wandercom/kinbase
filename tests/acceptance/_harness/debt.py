"""The instrument's own outstanding-validity ledger.

Detector Reviewer dispatch 003 found 22 blocking defects. Several are deep
causal rework --- 64 natively executed lifecycle cells, a complete surface ×
encoding × attack-family matrix, live Company registries and fact history, real
host installation and invocation, pre-execution causal mutation. Those are not
closed yet.

An instrument with known validity debt must not report green. ``spec/verification.md``
"Instrument validity" makes an instrument that cannot substantiate its own
controls ``INVALID_HARNESS``, and "Verdict semantics" forbids an unperformed
measurement from becoming proof. So the debt is enumerated here, machine
readable and content addressed, and the suite *fails* while any blocking entry
remains open.

This is deliberately not a suppression list. Nothing here is skipped, xfailed or
tolerated: the entries are the reason the instrument currently reports
``INVALID_HARNESS`` instead of a green wrapper.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable, Sequence

OPEN = "OPEN"
CLOSED = "CLOSED"


@dataclass(frozen=True)
class DebtEntry:
    """One outstanding instrument-validity defect."""

    finding: int
    title: str
    status: str
    gates: tuple[str, ...]
    why_blocking: str
    required_work: str
    #: What the instrument currently reports because of this entry.
    current_effect: str = "gate instrument channel reports INVALID_HARNESS"

    def as_json(self) -> dict:
        return {
            "finding": self.finding,
            "title": self.title,
            "status": self.status,
            "gates": list(self.gates),
            "why_blocking": self.why_blocking,
            "required_work": self.required_work,
            "current_effect": self.current_effect,
        }


_ALL = tuple(f"V-{i}" for i in range(1, 10))

LEDGER: tuple[DebtEntry, ...] = (
    DebtEntry(
        1, "Full clean-worktree attestation unavailable", CLOSED, ("INSTRUMENT",),
        "Git cannot stat tracked paths under .kin/** and evidence/**, so untracked "
        "or modified material there cannot be excluded.",
        "tools/attest-clean.sh now enumerates untracked paths, records the exact "
        "commit/tree, and names each inaccessible path explicitly rather than "
        "silently scoping it away.",
        "attestation states its own scope and unreadable paths",
    ),
    DebtEntry(
        2, "V-10 reported product PASS with no product", CLOSED, ("V-10",),
        "Two static selftest assertions resolved both channels to PASS.",
        "Nodes now carry an origin; a selftest-marked node is instrument-only and "
        "can never resolve the product channel.",
        "V-10 reports instrument=PASS product=NOT_RUN",
    ),
    DebtEntry(
        3, "Parameterised nodes collapsed into one census record", CLOSED, ("V-9",),
        "f[codex] skipped and f[claude] passing folded to one key; the later "
        "record overwrote the earlier.",
        "Census now folds every collected parameter instance, keeping the worst "
        "outcome, and never discards an instance.",
        "a skipped parameter keeps its function NOT_RUN",
    ),
    DebtEntry(
        4, "Controls and mutations are circular synthetic artifacts", OPEN, _ALL,
        "conforming(), violating(), the blinded checker and the judge all derive "
        "from one clause object, so the 401-row ledger cannot establish semantic "
        "sensitivity to product behaviour.",
        "Freeze separate raw positive and negative fixtures per obligation, drive "
        "them through shipping surfaces, and bind each result to independently "
        "captured raw evidence rather than a synthesised payload.",
    ),
    DebtEntry(
        5, "Obligations lack executable checker coupling", OPEN, _ALL,
        "66 of 92 obligations are named by a test that never calls their checker, "
        "so a weak test satisfies the census without consuming its row.",
        "Every catalog node must emit a content-addressed evidence record for its "
        "exact OID at runtime; rows with no exact consumption must be rejected.",
    ),
    DebtEntry(
        6, "Static green-path audit missed the patterns it forbids", OPEN, _ALL,
        "The linter checked only 0/\"\"/False defaults and accepted a module if one "
        "total-quantifier name appeared anywhere; 24 collection defaults, 17 "
        "optional loops and 41 guarded assertion blocks remain.",
        "Per-test analysis of every product-derived branch, rejecting collection "
        "fallbacks, optional assertion guards and unproved loop non-emptiness.",
    ),
    DebtEntry(
        7, "Planters rewrite the result after execution", OPEN, _ALL,
        "The interposer runs the real product first and then edits stdout and exit "
        "status, mutating observation rather than causal behaviour.",
        "Apply source, fixture, config, filesystem, authority or fault mutations "
        "before product execution and independently witness the mutated state.",
    ),
    DebtEntry(
        8, "Mutation runner counts infrastructure failure as a kill", CLOSED, _ALL,
        "Any nonzero pytest status marked the whole mutation KILLED, and the "
        "interposer's own configuration was dropped by the driver's env scrub.",
        "The runner now parses per-node call-phase reports, requires every named "
        "node to fail in its expected channel, and classifies collection, setup "
        "and environment failure as INVALID_HARNESS.",
        "a partial or infrastructure failure is no longer a kill",
    ),
    DebtEntry(
        9, "Detector mutations never demonstrate gate invalidation", OPEN, ("V-3",),
        "One unit selftest confirms local blindness; no runner activates a "
        "mutation, executes its gate and requires INVALID_HARNESS.",
        "One isolated run per detector mutation, requiring the exact positive "
        "control to escape and the affected gate's instrument channel to become "
        "INVALID_HARNESS.",
    ),
    DebtEntry(
        10, "Assertion classification conflates instrument and product", OPEN, _ALL,
        "Every non-selftest AssertionError becomes PRODUCT_FAILURE, including "
        "assertions about Tester fixture counts and absent prerequisites.",
        "Type every prerequisite by origin so fixture, gold, environment, rights "
        "and collection failures raise HarnessInvalid.",
    ),
    DebtEntry(
        11, "V-1 lifecycle matrix is neither exact nor natively executed", OPEN, ("V-1",),
        "The ratified table sums to 64 cells; the catalog requires 61. Transitions "
        "write generic JSON outside the adapter's native source and all cells "
        "share one generic receipt mutation.",
        "Enumerate all 64 exact cells with held expected pre/post native source, "
        "observation and fact/Unknown state, and a cell-specific mutation driven "
        "in the adapter's actual native format.",
    ),
    DebtEntry(
        12, "V-2 lacks calibration, gold-derived metrics and real sagas", OPEN, ("V-2",),
        "The calibration manifest is absent yet a refusal passes; metrics are "
        "product-reported; mixed-message lookups use pre-opaque IDs; crash seams "
        "are sleep-duration labels with a hardcoded recovery flag.",
        "Add the frozen calibration corpus, join opaque IDs to Tester gold, compute "
        "metrics in the harness from raw predictions, and witness every named "
        "transition before killing it.",
    ),
    DebtEntry(
        13, "V-3 coverage is not total over surfaces and encodings", OPEN, ("V-3",),
        "Family coverage checks anchor names; qualification labels in-memory "
        "payloads with surface names without planting through them; the lifecycle "
        "stage list is reported rather than executed.",
        "Build the complete surface × encoding × family matrix, place native bytes "
        "on each actual surface, and require exact detector/location receipts.",
    ),
    DebtEntry(
        14, "Signed worlds lack the ratified external trust prerequisites", OPEN,
        ("V-4", "V-5", "V-7", "V-8", "V-9"),
        "SignedWorld writes a worktree hint and local signers with no external "
        "Company root, repository certificate or signed AuthorityRegistry, so a "
        "conforming product should refuse the intended positive fixtures.",
        "Start and populate Company, configure the external root outside the "
        "worktree, install a repository certificate, publish registry keys and "
        "scopes, then ingest.",
    ),
    DebtEntry(
        15, "V-4 substitutes labels for transitions, scale, replay and locking", OPEN,
        ("V-4",),
        "Rebuild/restart mark themselves changed; conflict plants no authorized "
        "resolution; three of four manifest relations; no 10x corpus, no "
        "10,000-event revocation graph, no replay, no lock witness.",
        "Construct and digest every pre/post state, all four relations, the 10x "
        "corpus, the revocation graph, the replay and a concurrent lock witness.",
    ),
    DebtEntry(
        16, "V-6 has no registered live authority round trip", OPEN, ("V-6",),
        "The fixture never registers the helper key, scope or channel; the test "
        "invokes the helper directly, so the product never delivers a question "
        "through a registered channel.",
        "Register the separate process through the live AuthorityRegistry and "
        "require a product-originated delivery receipt and invocation digest.",
    ),
    DebtEntry(
        17, "V-8's live service holds no fact history, cache or revocation", OPEN,
        ("V-8",),
        "Company starts but no referenced fact version is inserted, the "
        "certificate is not installed, and cache rows hardcode state_constructed.",
        "Populate Company through its admission API, install the certificate, "
        "retain historical versions and trigger real expiry and revocation.",
    ),
    DebtEntry(
        18, "V-9 performs no approved install or native host invocation", OPEN, ("V-9",),
        "Setup tests only dry-run and refusal; envelopes are synthetic; the "
        "invocation assertion is conditional; the 250 ms bound is asserted as 5 s; "
        "fsck uses eight events; no submodule is created.",
        "Exercise the host's real approval and install flow, invoke Codex and "
        "Claude themselves, enforce 250 ms, build the 10,000-event ceiling and a "
        "real submodule.",
    ),
    DebtEntry(
        19, "V-9 permits zero operator work and trusts reported adequacy", OPEN, ("V-9",),
        "The blinded file is never driven; absence of a result passes; adequacy "
        "sends the same file five times and trusts product-reported slots.",
        "Drive a real blinded operator, time and score all 20 decisions, send "
        "distinct per-window arrivals and compute adequacy in the harness.",
    ),
    DebtEntry(
        20, "Control inspection incomplete; case identity leaks", CLOSED, _ALL,
        "The policy read only literal env= keys, missing argv, cwd, stdin, "
        "extra_env and committed history; the V-4 scenario, V-8 digest case and "
        "V-9 start state crossed those channels.",
        "The policy now inspects argv, cwd, stdin, extra_env and committed paths, "
        "and the three named leaks use opaque harness-mapped identifiers.",
        "semantic identity no longer reaches the product on any inspected channel",
    ),
    DebtEntry(
        21, "Auxiliary rights, provenance and freeze unresolved", OPEN, ("V-3",),
        "A Tester assertion of authorship cannot independently prove authority to "
        "grant CC0; the digest omits rights and manifest bytes; generated "
        "components had no derivation recipe.",
        "Deterministic generation, a digest binding every byte and the selection "
        "protocol are now in place. A named human rightsholder grant remains "
        "outstanding and cannot be authored by the Tester.",
    ),
    DebtEntry(
        22, "Reviewer environment did not enforce pytest timeouts", CLOSED,
        ("INSTRUMENT",),
        "pytest_timeout was unavailable and the strict run still exited zero.",
        "The suite now refuses to start when a declared plugin is missing unless "
        "an explicitly recorded untimed run is requested.",
        "a missing timeout plugin stops the run",
    ),
)


def open_entries() -> tuple[DebtEntry, ...]:
    return tuple(e for e in LEDGER if e.status == OPEN)


def closed_entries() -> tuple[DebtEntry, ...]:
    return tuple(e for e in LEDGER if e.status == CLOSED)


def gates_with_open_debt() -> frozenset[str]:
    out: set[str] = set()
    for entry in open_entries():
        out.update(entry.gates)
    return frozenset(out)


def as_json() -> dict:
    return {
        "schema": "guildhall-acceptance-instrument-debt/1",
        "review": "detector-reviewer dispatch 003",
        "total_findings": len(LEDGER),
        "closed": len(closed_entries()),
        "open": len(open_entries()),
        "gates_with_open_debt": sorted(gates_with_open_debt()),
        "entries": [e.as_json() for e in LEDGER],
    }


def digest() -> str:
    return hashlib.sha256(
        json.dumps(as_json(), sort_keys=True).encode("utf-8")
    ).hexdigest()
