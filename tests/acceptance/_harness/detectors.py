"""Deterministic canary detector with frozen normalisation and fail-closed error.

``spec/verification.md`` V-3 requires:

    Assert deterministic scanners normalize NFC/NFD plus hex, base64, percent,
    and JSON escape forms and fail closed on scanner error. Report semantic
    paraphrase leakage separately; do not call the seeded test a universal
    privacy bound.

``spec/verification.md`` "Instrument validity" additionally requires detector
mutations:

    Mutations target detectors as well as product code---for example, disable
    archive scanning, SQLite blob scanning, normalization decoding, or manifest
    comparison and require the planted defect to escape the detector's own
    self-test while causing the gate to reject the instrument.

Detector mutations are therefore first-class here and are selected through the
``GUILDHALL_ACCEPT_DETECTOR_MUTATION`` environment variable, which the mutation
runner sets. A mutated detector must (a) miss its planted positive control and
(b) make the gate report ``INVALID_HARNESS``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .requirements import HarnessInvalid

DETECTOR_MUTATION_ENV = "GUILDHALL_ACCEPT_DETECTOR_MUTATION"

#: Frozen detector-mutation catalog. Each entry names the capability removed.
DETECTOR_MUTATIONS: dict[str, str] = {
    "disable_archive_scan": "stop reading packed Git objects and archives",
    "disable_sqlite_blob_scan": "stop reading SQLite BLOB column values",
    "disable_normalization_decoding": "stop NFC/NFD/hex/base64/percent/JSON decoding",
    "disable_manifest_comparison": "stop comparing published and local manifests",
    "disable_partial_match": "stop applying the partial length/rarity rule",
    "disable_fail_closed": "swallow scanner errors instead of failing closed",
}


def active_detector_mutation() -> str | None:
    value = os.environ.get(DETECTOR_MUTATION_ENV, "").strip()
    if not value:
        return None
    if value not in DETECTOR_MUTATIONS:
        raise HarnessInvalid(
            f"unknown detector mutation {value!r}; frozen set is "
            f"{sorted(DETECTOR_MUTATIONS)}"
        )
    return value


class ScannerError(RuntimeError):
    """Raised when a surface cannot be read. The gate must fail closed on it."""


@dataclass(frozen=True)
class Finding:
    """One mechanically positive recovery.

    Field set matches the permanent evidence row in ``spec/verification.md``
    "Evidence packet": "canary ID, keyed-HMAC match, detector/encoding class,
    destination/location digest, offset, and times---not the canary or leaked
    bytes."
    """

    canary_id: str
    keyed_hmac: str
    detector_class: str
    encoding_class: str
    location_digest: str
    surface_family: str
    offset: int
    observed_at: str

    def sanitised(self) -> dict[str, object]:
        return {
            "canary_id": self.canary_id,
            "keyed_hmac": self.keyed_hmac,
            "detector_class": self.detector_class,
            "encoding_class": self.encoding_class,
            "location_digest": self.location_digest,
            "surface_family": self.surface_family,
            "offset": self.offset,
            "observed_at": self.observed_at,
        }


# --------------------------------------------------------------------------
# Normalisation ladder
# --------------------------------------------------------------------------

_HEXISH = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")
_B64ISH = re.compile(rb"[A-Za-z0-9+/=_-]{16,}")
_PERCENT = re.compile(rb"(?:%[0-9a-fA-F]{2})+")
_JSONESC = re.compile(rb"(?:\\u[0-9a-fA-F]{4}|\\[nrtbf\"\\/]){2,}")


def _safe_text(raw: bytes) -> str:
    return raw.decode("utf-8", "surrogateescape")


def normalised_views(raw: bytes, *, decode: bool = True) -> list[tuple[str, str]]:
    """Return ``(encoding_class, text)`` views of one byte buffer.

    Always includes the literal bytes, NFC and NFD. When ``decode`` is true the
    ladder additionally decodes hex, base64, percent and JSON-escape runs, and
    strips the delimiter/whitespace obfuscations named in the frozen catalog.
    """
    text = _safe_text(raw)
    views: list[tuple[str, str]] = [
        ("literal", text),
        ("nfc", unicodedata.normalize("NFC", text)),
        ("nfd", unicodedata.normalize("NFD", text)),
    ]
    if not decode:
        return views
    views.append(("nfkc", unicodedata.normalize("NFKC", text)))
    views.append(("case_folded", text.casefold()))
    # Delimiter and whitespace obfuscation are removed by stripping separators.
    views.append(("delimiter_stripped", re.sub(r"[|\s_]+", "", text)))
    views.append(("whitespace_collapsed", re.sub(r"\s+", "-", text).strip("-")))
    views.append(("fragment_joined", re.sub(r"\n\.\.\.\n", "", text)))

    for match in _HEXISH.findall(raw)[:512]:
        try:
            views.append(("hex", _safe_text(binascii.unhexlify(match))))
        except (binascii.Error, ValueError):
            continue
    for match in _B64ISH.findall(raw)[:512]:
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                padded = match + b"=" * (-len(match) % 4)
                decoded = decoder(padded, validate=False)
            except (binascii.Error, ValueError):
                continue
            if decoded:
                views.append(("base64", _safe_text(decoded)))
                # A composed transform (base64 of percent of NFD) needs a
                # second pass, so the decoded body re-enters the percent stage.
                try:
                    import urllib.parse

                    views.append(
                        (
                            "reversible_composition",
                            urllib.parse.unquote(_safe_text(decoded)),
                        )
                    )
                except Exception:  # pragma: no cover - defensive
                    pass
            break
    for match in _PERCENT.findall(raw)[:512]:
        import urllib.parse

        views.append(("percent", urllib.parse.unquote(_safe_text(match))))
    for match in _JSONESC.findall(raw)[:512]:
        try:
            views.append(("json_escape", json.loads(f'"{_safe_text(match)}"')))
        except json.JSONDecodeError:
            continue
    return views


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------


@dataclass
class CanaryDetector:
    """Deterministic exact / encoded / normalised / partial / lineage detector.

    ``spec/verification.md`` V-3: "Recursively scan every persistent/shared byte
    and SQLite text/blob value for exact, encoded, normalized, partial, and
    deterministic-correlation canaries."
    """

    #: canary_id -> raw value
    registry: dict[str, str]
    #: canary_id -> deterministic correlation chain values
    lineage: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: Frozen partial rule: a contiguous run of at least this many characters of
    #: the canary body is a positive. 12 of the 24-character random body has
    #: chance rarity below 36**-12 in the declared alphabet.
    partial_min_chars: int = 12
    hmac_of: object = None  # callable(str) -> str, supplied by the vault
    mutation: str | None = field(default_factory=active_detector_mutation)

    def __post_init__(self) -> None:
        if self.hmac_of is None:
            raise HarnessInvalid("CanaryDetector requires a keyed HMAC function")

    # -- capability switches (mutation targets) ---------------------------

    @property
    def decode_enabled(self) -> bool:
        return self.mutation != "disable_normalization_decoding"

    @property
    def partial_enabled(self) -> bool:
        return self.mutation != "disable_partial_match"

    @property
    def archive_enabled(self) -> bool:
        return self.mutation != "disable_archive_scan"

    @property
    def sqlite_blob_enabled(self) -> bool:
        return self.mutation != "disable_sqlite_blob_scan"

    @property
    def manifest_comparison_enabled(self) -> bool:
        return self.mutation != "disable_manifest_comparison"

    @property
    def fail_closed(self) -> bool:
        return self.mutation != "disable_fail_closed"

    # -- matching ---------------------------------------------------------

    def _partial_needles(self, value: str) -> list[str]:
        if not self.partial_enabled:
            return []
        body = value.split("-", 1)[-1]
        if len(body) < self.partial_min_chars:
            return []
        return [body[: self.partial_min_chars], body[-self.partial_min_chars :]]

    def scan_bytes(
        self,
        raw: bytes,
        *,
        surface_family: str,
        location_digest: str,
        observed_at: str,
    ) -> list[Finding]:
        views = normalised_views(raw, decode=self.decode_enabled)
        findings: list[Finding] = []
        for canary_id, value in self.registry.items():
            needles: list[tuple[str, str]] = [("exact", value)]
            needles.append(("nfd", unicodedata.normalize("NFD", value)))
            needles.append(("case", value.swapcase()))
            for needle in self._partial_needles(value):
                needles.append(("partial", needle))
            for chain in self.lineage.get(canary_id, ()):  # deterministic lineage
                needles.append(("lineage", chain))
            for detector_class, needle in needles:
                if not needle:
                    continue
                for encoding_class, text in views:
                    idx = text.find(needle)
                    if idx == -1 and detector_class in {"exact", "partial"}:
                        idx = text.casefold().find(needle.casefold())
                        if idx != -1:
                            encoding_class = f"{encoding_class}+casefold"
                    if idx != -1:
                        findings.append(
                            Finding(
                                canary_id=canary_id,
                                keyed_hmac=self.hmac_of(value),  # type: ignore[misc]
                                detector_class=detector_class,
                                encoding_class=encoding_class,
                                location_digest=location_digest,
                                surface_family=surface_family,
                                offset=idx,
                                observed_at=observed_at,
                            )
                        )
                        break
                else:
                    continue
                break
        return findings

    def detects(self, raw: bytes) -> bool:
        return bool(
            self.scan_bytes(
                raw,
                surface_family="selftest",
                location_digest="selftest",
                observed_at="1970-01-01T00:00:00.000Z",
            )
        )

    def on_scanner_error(self, surface: str, exc: BaseException) -> None:
        """Fail closed, unless the fail-closed capability is mutated away."""
        if self.fail_closed:
            raise ScannerError(
                "spec/verification.md V-3 requires deterministic scanners to "
                f"'fail closed on scanner error'; {surface} raised {exc!r}"
            ) from exc


@dataclass
class SemanticParaphraseReport:
    """Separately reported, never folded into the zero-tolerance result.

    ``spec/threat-model.md`` "Mechanical recovery decision and adjudication":
    "Semantic similarity without deterministic lineage is reported but is not
    silently promoted into or excluded from the zero-tolerance result."
    """

    inspected_surfaces: int
    paraphrase_candidates: tuple[str, ...] = ()

    def as_json(self) -> dict[str, object]:
        return {
            "kind": "semantic_paraphrase_report",
            "counts_toward_zero_tolerance": False,
            "inspected_surfaces": self.inspected_surfaces,
            "paraphrase_candidate_count": len(self.paraphrase_candidates),
        }


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054):
    """Two-sided Wilson score interval used for detector qualification bounds."""
    if trials <= 0:
        raise HarnessInvalid("Wilson interval needs a positive denominator")
    phat = successes / trials
    denom = 1.0 + z * z / trials
    centre = phat + z * z / (2 * trials)
    margin = z * ((phat * (1 - phat) / trials) + z * z / (4 * trials * trials)) ** 0.5
    return ((centre - margin) / denom, (centre + margin) / denom)


def stratification_ok(
    plan: Sequence[tuple[str, str]],
    *,
    families: Iterable[str],
    minimum: int,
) -> tuple[bool, dict[str, int]]:
    counts: dict[str, int] = {f: 0 for f in families}
    for surface, encoding in plan:
        if surface in counts:
            counts[surface] += 1
        if encoding in counts:
            counts[encoding] += 1
    return all(v >= minimum for v in counts.values()), counts
