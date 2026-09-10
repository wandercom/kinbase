"""One executable probe per detector mutation, on the surface it disables.

Detector Reviewer finding 9. ``spec/verification.md`` "Instrument validity"
requires that a detector mutation

    require the planted defect to escape the detector's own self-test while
    causing the gate to reject the instrument.

The previous instrument had one unit selftest asserting that a mutated detector
returned fewer findings on a synthetic buffer. Nothing activated a mutation,
executed the affected gate, and required ``INVALID_HARNESS``, so no detector
mutation ever demonstrated gate invalidation.

Each probe here plants a control on the *exact* surface its mutation disables ---
a real archive member, a real SQLite BLOB, a base64-encoded run, a partial
substring, a differing published manifest, an unreadable file --- and reports
three facts:

* the unmutated detector catches it (otherwise the control is worthless);
* the mutated detector misses it (the escape the requirement names);
* the surface family and encoding class the escape occurred on.

``tests/detector-mutation-run.sh`` runs one isolated process per mutation and
additionally requires the emitted census to report ``V-3`` instrument channel
``INVALID_HARNESS``, which ``conftest.py`` sets whenever a detector mutation is
active. Probe and census together are the demonstration the requirement asks for.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .canaries import Canary, generate_canary, make_rng
from .detectors import DETECTOR_MUTATIONS, CanaryDetector, ScannerError
from .requirements import HarnessInvalid
from .scanners import read_file_surfaces, sqlite_surfaces, sweep

#: Deterministic probe seed. Frozen so the escape demonstration is reproducible.
PROBE_SEED = 20260907


def _canary(index: int, family: str) -> Canary:
    return generate_canary(make_rng(PROBE_SEED + index), index=index, family=family)


def _detector(canary: Canary, *, mutation: str | None,
              partial_min_chars: int = 12) -> CanaryDetector:
    return CanaryDetector(
        registry={canary.canary_id: canary.value},
        lineage={},
        partial_min_chars=partial_min_chars,
        hmac_of=lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest(),
        mutation=mutation,
    )


@dataclass(frozen=True)
class ProbeResult:
    """What one detector mutation did to its own positive control."""

    mutation: str
    surface_family: str
    encoding_class: str
    control_digest: str
    detected_unmutated: bool
    detected_mutated: bool

    @property
    def escaped(self) -> bool:
        return self.detected_unmutated and not self.detected_mutated

    def as_json(self) -> dict:
        return {
            "detector_mutation": self.mutation,
            "meaning": DETECTOR_MUTATIONS[self.mutation],
            "surface_family": self.surface_family,
            "encoding_class": self.encoding_class,
            "control_digest": self.control_digest,
            "detected_by_unmutated_detector": self.detected_unmutated,
            "detected_by_mutated_detector": self.detected_mutated,
            "positive_control_escaped": self.escaped,
        }


# --------------------------------------------------------------------------
# Probes. Each returns (surface_family, encoding_class, detect(detector) -> bool)
# --------------------------------------------------------------------------


def _probe_archive(root: Path, canary: Canary):
    member = root / "member.txt"
    member.write_text("build log\n" + canary.value + "\n", encoding="utf-8")
    archive = root / "packed.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(member, arcname="member.txt")
    member.unlink()

    def detect(detector: CanaryDetector) -> bool:
        result = sweep(detector, read_file_surfaces(root, "archive", detector))
        return not result.clean

    return "archive", "archive-member", detect


def _probe_sqlite_blob(root: Path, canary: Canary):
    """Scoped to the SQL column surfaces, which is what the mutation disables.

    ``sqlite_surfaces`` also yields the database file's raw bytes, so a canary in
    a BLOB is still visible to raw-page scanning even when column scanning is
    off. That redundancy is deliberate defence in depth and it must not be
    confused with the mutation being inert: the escape is demonstrated on the
    column surfaces the mutation actually governs, and the raw-page surface is
    excluded here so the demonstration is about the disabled detector and not
    about its backup.
    """
    db = root / "cache.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE entries (id INTEGER PRIMARY KEY, payload BLOB)")
        conn.execute("INSERT INTO entries (payload) VALUES (?)",
                     (canary.value.encode("utf-8"),))

    def detect(detector: CanaryDetector) -> bool:
        columns = (
            s for s in sqlite_surfaces(db, detector)
            if not s.label.startswith("sqlite-raw:")
            and not s.label.startswith("sqlite-sidecar:")
        )
        result = sweep(detector, columns)
        return not result.clean

    return "sqlite", "blob", detect


def _probe_normalisation(root: Path, canary: Canary):
    encoded = base64.b64encode(canary.value.encode("utf-8")).decode("ascii")
    target = root / "receipt.json"
    target.write_text(json.dumps({"note": encoded}), encoding="utf-8")

    def detect(detector: CanaryDetector) -> bool:
        result = sweep(detector, read_file_surfaces(root, "receipt", detector))
        return not result.clean

    return "receipt", "base64", detect


def _probe_partial(root: Path, canary: Canary):
    # The frozen partial rule takes the first or last ``partial_min_chars`` of
    # the canary body (the part after the first hyphen), so the planted control
    # must be exactly one of those runs to exercise the rule rather than an
    # exact match.
    body = canary.value.split("-", 1)[-1]
    fragment = body[:12]
    target = root / "log.txt"
    target.write_text("prefix " + fragment + " suffix\n", encoding="utf-8")

    def detect(detector: CanaryDetector) -> bool:
        result = sweep(detector, read_file_surfaces(root, "log", detector))
        return not result.clean

    return "log", "partial", detect


def _probe_manifest_comparison(root: Path, canary: Canary):
    published = {"heads": {"main": "a" * 40}, "count": 12, "canary": canary.value}
    local = {"heads": {"main": "b" * 40}, "count": 11}
    (root / "published.json").write_text(json.dumps(published), encoding="utf-8")
    (root / "local.json").write_text(json.dumps(local), encoding="utf-8")

    def detect(detector: CanaryDetector) -> bool:
        from .detectors import compare_manifests

        report = compare_manifests(detector, published=published, local=local)
        return bool(report["differences"]) or bool(report["canary_findings"])

    return "manifest", "structural", detect


def _probe_fail_closed(root: Path, canary: Canary):
    """An unreadable surface must fail closed, not be silently skipped."""
    unreadable = root / "sealed.bin"
    unreadable.write_bytes(canary.value.encode("utf-8"))
    os.chmod(unreadable, 0o000)

    def detect(detector: CanaryDetector) -> bool:
        try:
            result = sweep(detector, read_file_surfaces(root, "sealed", detector))
        except ScannerError:
            return True
        return not result.clean

    return "sealed", "unreadable", detect


PROBES: dict[str, Callable[[Path, Canary], tuple[str, str, Callable]]] = {
    "disable_archive_scan": _probe_archive,
    "disable_sqlite_blob_scan": _probe_sqlite_blob,
    "disable_normalization_decoding": _probe_normalisation,
    "disable_partial_match": _probe_partial,
    "disable_manifest_comparison": _probe_manifest_comparison,
    "disable_fail_closed": _probe_fail_closed,
}


def run_probe(mutation: str, workdir: Path) -> ProbeResult:
    """Plant this mutation's control and report whether it escapes."""
    if mutation not in DETECTOR_MUTATIONS:
        raise HarnessInvalid(f"unknown detector mutation {mutation!r}")
    if mutation not in PROBES:
        raise HarnessInvalid(
            f"detector mutation {mutation!r} has no positive-control probe; a "
            "mutation whose escape cannot be demonstrated proves nothing"
        )
    root = workdir / mutation
    root.mkdir(parents=True, exist_ok=True)
    canary = _canary(list(DETECTOR_MUTATIONS).index(mutation), "receipt")
    family, encoding, detect = PROBES[mutation](root, canary)

    clean = detect(_detector(canary, mutation=None))
    mutated = detect(_detector(canary, mutation=mutation))

    for path in sorted(root.rglob("*")):
        if path.is_file():
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    return ProbeResult(
        mutation=mutation,
        surface_family=family,
        encoding_class=encoding,
        control_digest=hashlib.sha256(canary.value.encode("utf-8")).hexdigest(),
        detected_unmutated=clean,
        detected_mutated=mutated,
    )


def run_all(workdir: Path) -> tuple[ProbeResult, ...]:
    return tuple(run_probe(m, workdir) for m in sorted(DETECTOR_MUTATIONS))


def unsound(results: tuple[ProbeResult, ...]) -> tuple[str, ...]:
    """Mutations whose control did not escape, or was never caught at all."""
    out: list[str] = []
    for result in results:
        if not result.detected_unmutated:
            out.append(
                f"{result.mutation}: the unmutated detector missed its own "
                f"positive control on {result.surface_family}"
            )
        elif result.detected_mutated:
            out.append(
                f"{result.mutation}: the control did not escape the mutated "
                f"detector, so the mutation disables nothing observable"
            )
    return tuple(out)


def as_json(results: tuple[ProbeResult, ...]) -> dict:
    return {
        "schema": "kinbase-detector-mutation-probes/1",
        "declared": sorted(DETECTOR_MUTATIONS),
        "probed": [r.as_json() for r in results],
        "unsound": list(unsound(results)),
    }
