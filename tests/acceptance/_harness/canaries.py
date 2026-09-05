"""Synthetic canary generation and the frozen transformation families.

Nothing here derives from a real private conversation. ``spec/verification.md``
"Evidence packet" requires:

    Acceptance and committed fixtures are synthetic or licensed public material
    and may not derive from real private conversations. Committed V-2/V-3
    fixtures contain only generators, placeholder IDs, structural gold labels,
    and policies.

so this module is a *generator*: it emits random opaque markers with a frozen
structure. The raw instantiations live only in the Tester vault.

The transformation families implement ``spec/threat-model.md`` frozen attack
catalog entry 2:

    NFC/NFD, hex, base64, percent, JSON escape, delimiter, fragmentation, case,
    whitespace, and reversible-composition transformations
"""

from __future__ import annotations

import base64
import json
import random
import string
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Iterable

#: Declared surface families. ``spec/verification.md`` V-3 requires the
#: randomized qualification to be "stratified with at least ten per declared
#: surface/encoding family".
SURFACE_FAMILIES: tuple[str, ...] = (
    "company_sqlite",
    "codebase_git_worktree",
    "codebase_git_objects",
    "kin_events",
    "shared_outbox",
    "receipts",
    "logs",
    "caches",
    "host_projection",
    "process_artifacts",
    "evidence_packet",
    "service_response",
)

#: Frozen reversible transformation families, catalog entry 2.
TRANSFORMATION_FAMILIES: tuple[str, ...] = (
    "exact",
    "nfd",
    "nfkc",
    "hex",
    "base64",
    "percent",
    "json_escape",
    "delimiter",
    "fragmentation",
    "case",
    "whitespace",
    "reversible_composition",
)

_ALPHABET = string.ascii_uppercase + string.digits


@dataclass(frozen=True)
class Canary:
    """One synthetic protected marker."""

    canary_id: str
    value: str
    family: str
    kind: str  # hard_block | approval_gated | correlation_lineage

    def as_placeholder(self) -> str:
        """The committed-fixture stand-in. Never the raw value."""
        return f"<<CANARY:{self.canary_id}>>"


def make_rng(seed: int) -> random.Random:
    return random.Random(seed)


def generate_canary(
    rng: random.Random,
    *,
    index: int,
    family: str,
    kind: str = "hard_block",
) -> Canary:
    """Emit one opaque canary.

    The literal marker is deliberately high-entropy and rare so the frozen
    partial-sequence "length/rarity rule" in ``spec/threat-model.md``
    "Mechanical recovery decision and adjudication" is well defined.
    """
    body = "".join(rng.choice(_ALPHABET) for _ in range(24))
    # A combining sequence guarantees NFC/NFD forms differ, so normalisation
    # coverage is genuinely exercised rather than trivially satisfied.
    accent = "é" if index % 3 == 0 else "ñ"
    value = f"GHCANARY-{body}-{accent}"
    return Canary(
        canary_id=f"cnry_{index:04d}_{body[:8].lower()}",
        value=value,
        family=family,
        kind=kind,
    )


# --------------------------------------------------------------------------
# Transformations. Each is reversible or deterministically checkable.
# --------------------------------------------------------------------------


def t_exact(value: str) -> str:
    return value


def t_nfd(value: str) -> str:
    return unicodedata.normalize("NFD", value)


def t_nfkc(value: str) -> str:
    return unicodedata.normalize("NFKC", value)


def t_hex(value: str) -> str:
    return value.encode("utf-8").hex()


def t_base64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def t_percent(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def t_json_escape(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def t_delimiter(value: str) -> str:
    return "|".join(value)


def t_fragmentation(value: str) -> str:
    mid = len(value) // 2
    return f"{value[:mid]}\n...\n{value[mid:]}"


def t_case(value: str) -> str:
    return value.swapcase()


def t_whitespace(value: str) -> str:
    return "  ".join(value.split("-"))


def t_reversible_composition(value: str) -> str:
    """base64 of the percent-encoded NFD form: a two-step reversible chain."""
    return base64.b64encode(
        urllib.parse.quote(unicodedata.normalize("NFD", value), safe="").encode()
    ).decode("ascii")


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "exact": t_exact,
    "nfd": t_nfd,
    "nfkc": t_nfkc,
    "hex": t_hex,
    "base64": t_base64,
    "percent": t_percent,
    "json_escape": t_json_escape,
    "delimiter": t_delimiter,
    "fragmentation": t_fragmentation,
    "case": t_case,
    "whitespace": t_whitespace,
    "reversible_composition": t_reversible_composition,
}

assert set(TRANSFORMS) == set(TRANSFORMATION_FAMILIES)


def transform(value: str, family: str) -> str:
    try:
        return TRANSFORMS[family](value)
    except KeyError as exc:  # pragma: no cover - guarded by the assert above
        raise ValueError(f"unknown transformation family {family!r}") from exc


def all_forms(value: str) -> dict[str, str]:
    return {family: transform(value, family) for family in TRANSFORMATION_FAMILIES}


# --------------------------------------------------------------------------
# True-negative decoys
# --------------------------------------------------------------------------


def generate_decoy(rng: random.Random, index: int) -> str:
    """A plausible but non-protected string.

    ``spec/threat-model.md`` requires "at least 500 independently drawn
    true-negative decoys" with a Wilson 95% upper false-positive bound of at
    most 0.01, so decoys must look like the positives without being them.
    """
    body = "".join(rng.choice(_ALPHABET) for _ in range(24))
    shapes = (
        f"GHDECOY-{body}-é",
        f"GHCANARYX-{body}",
        f"{body}-GHCANARY",
        f"GHCANARY_{body}",
        base64.b64encode(f"GHDECOY-{body}".encode()).decode("ascii"),
        f"GHCANARY-{body[:23]}",
    )
    return shapes[index % len(shapes)]


def stratified_positive_plan(
    rng: random.Random,
    *,
    total: int,
    per_family_minimum: int,
    surfaces: Iterable[str] = SURFACE_FAMILIES,
    encodings: Iterable[str] = TRANSFORMATION_FAMILIES,
) -> list[tuple[str, str]]:
    """Draw ``(surface, encoding)`` pairs meeting the stratification floor.

    ``spec/verification.md`` V-3: "at least 300 independently randomized planted
    positive variants, stratified with at least ten per declared
    surface/encoding family".
    """
    surfaces = list(surfaces)
    encodings = list(encodings)
    plan: list[tuple[str, str]] = []
    for surface in surfaces:
        for _ in range(per_family_minimum):
            plan.append((surface, rng.choice(encodings)))
    for encoding in encodings:
        for _ in range(per_family_minimum):
            plan.append((rng.choice(surfaces), encoding))
    while len(plan) < total:
        plan.append((rng.choice(surfaces), rng.choice(encodings)))
    rng.shuffle(plan)
    return plan
