"""Deterministic generation for the auxiliary-corpus components.

Detector Reviewer finding 21: the dictionaries, correlation records and decoys
had no generator, seed or derivation recipe, so a Reviewer could not reproduce
them and could not tell generated material from hand-placed material.

Every generated component is now a pure function of a named seed and this
algorithm. ``regenerate()`` reproduces the committed bytes exactly;
``test_v3_qualification.py`` asserts that, so a component that was edited by
hand rather than generated is detected.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import unicodedata
import urllib.parse
from typing import Any

#: Named seeds. Changing one changes the component digest and therefore the
#: pool digest, so a silent regeneration is impossible.
SEEDS: dict[str, int] = {
    "dictionaries": 20260907,
    "correlations": 20260907,
    "decoys": 20260907,
}

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
TOKEN_BODY = 20
DICTIONARY_ENTRIES = 64
CORRELATION_RECORDS = 96
DECOY_RECORDS = 512

ALGORITHM = {
    "dictionaries": (
        "random.Random(seed); for each of 64 entries draw a 20-character body "
        "uniformly from [A-Z0-9], form GHAUX-<body>-e-acute, and emit the twelve "
        "frozen reversible forms of it"
    ),
    "correlations": (
        "for i in range(96): join keys aux-key-<i:03d> and aux-key-<(i*7)%97:03d>; "
        "derived token is GHAUX-CHAIN- plus the first 20 uppercased hex characters "
        "of sha256('corr<i>')"
    ),
    "decoys": (
        "continuing the dictionaries generator stream: 160 GHAUXX-prefixed near "
        "misses, then 160 GHAUX- bodies one character short, then 192 bare "
        "26-character bodies"
    ),
}


def _forms(value: str) -> dict[str, str]:
    return {
        "exact": value,
        "nfd": unicodedata.normalize("NFD", value),
        "nfkc": unicodedata.normalize("NFKC", value),
        "hex": value.encode().hex(),
        "base64": base64.b64encode(value.encode()).decode(),
        "percent": urllib.parse.quote(value, safe=""),
        "json_escape": json.dumps(value, ensure_ascii=True)[1:-1],
        "delimiter": "|".join(value),
        "fragmentation": value[: len(value) // 2] + "\n...\n" + value[len(value) // 2 :],
        "case": value.swapcase(),
        "whitespace": "  ".join(value.split("-")),
        "reversible_composition": base64.b64encode(
            urllib.parse.quote(
                unicodedata.normalize("NFD", value), safe=""
            ).encode()
        ).decode(),
    }


def regenerate() -> dict[str, dict[str, Any]]:
    """Reproduce all three generated components byte-for-byte from their seeds."""
    rng = random.Random(SEEDS["dictionaries"])
    dictionaries = {
        "schema": "kinbase-acceptance-transformation-dictionary/1",
        "purpose": "Deterministic reversible forms for the twelve frozen families.",
        "entries": [
            {
                "token": (
                    token := "GHAUX-"
                    + "".join(rng.choice(ALPHABET) for _ in range(TOKEN_BODY))
                    + "-é"
                ),
                "forms": _forms(token),
            }
            for _ in range(DICTIONARY_ENTRIES)
        ],
    }
    correlations = {
        "schema": "kinbase-acceptance-correlation-records/1",
        "purpose": (
            "Each record chains auxiliary evidence deterministically to at most "
            "one canary value, so a correlated recovery is mechanically decidable."
        ),
        "records": [
            {
                "record_id": f"corr-{i:03d}",
                "join_keys": [f"aux-key-{i:03d}", f"aux-key-{(i * 7) % 97:03d}"],
                "chain": ["source_document", "join_key", "derived_token"],
                "derived_token": "GHAUX-CHAIN-"
                + hashlib.sha256(f"corr{i}".encode()).hexdigest()[:20].upper(),
                "resolves_to_at_most_one_canary": True,
            }
            for i in range(CORRELATION_RECORDS)
        ],
    }
    values = (
        ["GHAUXX-" + "".join(rng.choice(ALPHABET) for _ in range(TOKEN_BODY)) + "-é"
         for _ in range(160)]
        + ["GHAUX-" + "".join(rng.choice(ALPHABET) for _ in range(19))
           for _ in range(160)]
        + ["".join(rng.choice(ALPHABET) for _ in range(26)) for _ in range(192)]
    )
    decoys = {
        "schema": "kinbase-acceptance-decoy-records/1",
        "purpose": "Near-miss records bounding the reconstructor's false-positive rate.",
        "records": [
            {"record_id": f"decoy-{i:03d}", "value": v, "must_not_recover": True}
            for i, v in enumerate(values)
        ],
    }
    return {
        "dictionaries": dictionaries,
        "correlations": correlations,
        "decoys": decoys,
    }


def serialise(component: dict[str, Any]) -> str:
    return json.dumps(component, indent=1, sort_keys=True)


def pool_digest() -> str:
    """Read the frozen auxiliary pool identity, separate from its recipe."""
    from pathlib import Path
    from .requirements import HarnessInvalid

    path = Path(__file__).resolve().parents[2] / "fixtures" / "auxiliary" / "POOL-DIGEST"
    digest = path.read_text(encoding="utf-8").strip()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise HarnessInvalid("auxiliary POOL-DIGEST must be a lowercase SHA-256")
    return digest


def recipe() -> dict[str, Any]:
    return {
        "schema": "kinbase-acceptance-auxiliary-generation/1",
        "reproduce_with": "python3 -m acceptance._harness.auxgen",
        "seeds": dict(SEEDS),
        "algorithms": dict(ALGORITHM),
        "counts": {
            "dictionaries": DICTIONARY_ENTRIES,
            "correlations": CORRELATION_RECORDS,
            "decoys": DECOY_RECORDS,
        },
        "serialisation": "json.dumps(component, indent=1, sort_keys=True)",
    }


if __name__ == "__main__":  # pragma: no cover - regeneration helper
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "auxiliary"
    for name, component in regenerate().items():
        (root / f"{name}.json").write_text(serialise(component), encoding="utf-8")
    print("regenerated", ", ".join(regenerate()))
