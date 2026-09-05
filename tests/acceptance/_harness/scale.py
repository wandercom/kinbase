"""Corpora at the ratified ceilings, built fast enough to actually run.

Detector Reviewer finding 15. V-4 requires a corpus at **10x the admission
ceiling** and a dense derivation graph at the **10,000-event ceiling**; the
previous instrument constructed neither, so the ceiling and cascade obligations
were asserted over a handful of events.

Building them means signing 110,000 events. The Tester's reference signer is the
pure-Python RFC 8032 implementation in :mod:`acceptance._harness.ed25519_pure`,
which costs about 3.5 ms per signature --- six minutes for the ceiling corpus
alone. This module therefore signs in bulk with the platform Ed25519 primitive
when it is available and **verifies a random sample against the pure reference**,
so the fast path can never diverge from the ratified algorithm without the
instrument noticing.

Ed25519 is deterministic: for one key and one message both implementations must
emit the same 64 bytes. The sample check is an equality check, not a statistical
one.

Without a platform primitive the corpus cannot be built in a usable time. That
is an *environment* prerequisite, so it raises
:class:`~acceptance._harness.prereq.PrerequisiteMissing` --- ``INVALID_HARNESS``
--- rather than shrinking the corpus and reporting a ceiling that was never
reached.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import canonical, ed25519_pure, prereq, synth

#: How many signatures are re-verified against the pure reference.
CROSS_CHECK_SAMPLE = 24


def _fast_signer(seed: bytes):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except Exception as exc:  # noqa: BLE001 - reported as a prerequisite
        raise prereq.missing(
            "environment", "bulk Ed25519 signer",
            "no platform Ed25519 primitive is available, so a corpus at the "
            "ratified ceiling would take minutes per gate to sign; install the "
            "pinned tests/requirements.txt. The instrument will not report a "
            "ceiling it did not construct",
        ) from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


@dataclass
class CorpusBuild:
    """What was actually written, with an independent cross-check."""

    root: Path
    event_count: int
    signer_authority: str
    head_event_id: str
    depth: int
    cross_checked: int
    cross_check_agreed: bool
    digest: str

    def as_json(self) -> dict:
        return {
            "root": str(self.root),
            "event_count": self.event_count,
            "signer_authority": self.signer_authority,
            "head_event_id": self.head_event_id,
            "derivation_depth": self.depth,
            "cross_checked_signatures": self.cross_checked,
            "fast_path_matches_pure_reference": self.cross_check_agreed,
            "digest": self.digest,
        }


def build_event_corpus(
    repo_root: Path,
    signer: synth.Signer,
    count: int,
    *,
    logical_prefix: str,
    dense: bool = False,
    seed: int = 20260907,
) -> CorpusBuild:
    """Write ``count`` genuinely signed events at their content paths.

    ``dense=True`` chains each event to the previous one and to a second earlier
    parent, producing the dense derivation graph a revocation cascade must walk
    rather than a flat list.
    """
    key = _fast_signer(signer.seed)
    public = signer.public_hex
    rng = random.Random(seed)
    events_root = repo_root / ".kin" / "events"
    events_root.mkdir(parents=True, exist_ok=True)

    sample_indices = set(rng.sample(range(count), min(CROSS_CHECK_SAMPLE, count)))
    agreed = True
    checked = 0
    previous: list[str] = []
    head = ""
    running = hashlib.sha256()

    for index in range(count):
        parents: tuple[str, ...] = ()
        if dense and previous:
            first = previous[-1]
            second = previous[max(0, len(previous) - 1 - rng.randrange(1, 8))] \
                if len(previous) > 8 else previous[0]
            parents = (first, second)
        body = synth.fact_event(
            store_kind="company",
            authority_id=signer.authority_id,
            authority_scope=signer.scope,
            logical_key=logical_prefix + "/" + format(index, "06d"),
            statement="bulk corpus entry " + format(index, "06d"),
            parents=parents,
        )
        body["signer"] = public
        body["message_type"] = "fact-event"
        raw_body = canonical.jcs({k: v for k, v in body.items() if k != "signature"})
        digest = canonical.signing_digest("fact-event", raw_body)
        signature = key.sign(digest)
        if index in sample_indices:
            checked += 1
            reference = ed25519_pure.sign(signer.seed, digest)
            if reference != signature:
                agreed = False
        signed = dict(body)
        signed["signature"] = signature.hex()
        raw = canonical.jcs(signed)
        content = canonical.content_digest_hex(raw)
        path = events_root / canonical.event_shard_path(content)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        running.update(content.encode("ascii"))
        head = signed["event_id"]
        previous.append(head)
        if len(previous) > 4096:
            del previous[:2048]

    return CorpusBuild(
        root=events_root,
        event_count=count,
        signer_authority=signer.authority_id,
        head_event_id=head,
        depth=count if dense else 1,
        cross_checked=checked,
        cross_check_agreed=agreed,
        digest=running.hexdigest(),
    )


def count_events(repo_root: Path) -> int:
    root = repo_root / ".kin" / "events"
    if not root.exists():
        return 0
    return sum(1 for _ in root.rglob("*.json"))
