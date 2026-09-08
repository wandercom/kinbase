"""The complete V-3 surface x encoding x attack-family matrix.

Detector Reviewer finding 13. V-3 coverage was not total in three ways:

* family coverage was checked by looking for a registered ``spec_ref`` anchor
  name, so a family "had a probe" when a docstring mentioned it;
* qualification labelled in-memory payloads with a surface name without ever
  writing bytes onto that surface, so a SQLite BLOB, a packed Git object and a
  cache entry were all the same ``bytes`` object with different labels;
* the lifecycle stage list was reported by the product rather than executed.

This module plants **native bytes on each actual surface**: a real BLOB in a
real SQLite file, a real object inside a real packfile, a real file under the
cache root, a real event at its content-addressed path, and so on. Each planted
cell returns the exact detector class, encoding class and location digest the
sweep must produce, so ``V-3.positive-control`` can require an exact receipt per
cell rather than a count.

The matrix is total by construction: every declared surface family is crossed
with every declared transformation family, and every one of the nineteen frozen
threat-model families names the surfaces it ranges over. Nothing is sampled and
nothing is inferred from a name.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from . import canaries, scanners
from .canaries import SURFACE_FAMILIES, TRANSFORMATION_FAMILIES
from .detectors import CanaryDetector, Finding

#: The nineteen frozen threat-model families and the surfaces each ranges over.
#: A family with no surface would be untestable, so the mapping is total.
FAMILY_SURFACES: dict[int, tuple[str, ...]] = {
    1: ("kin_events", "receipts", "logs", "caches"),
    2: ("company_sqlite", "codebase_git_worktree", "receipts", "logs"),
    3: ("shared_outbox", "receipts", "kin_events"),
    4: ("kin_events", "codebase_git_objects", "caches"),
    5: ("kin_events", "host_projection"),
    6: ("codebase_git_objects", "codebase_git_worktree", "kin_events"),
    7: ("kin_events", "shared_outbox", "receipts"),
    8: ("logs", "process_artifacts", "receipts", "evidence_packet", "caches"),
    9: ("process_artifacts", "host_projection"),
    10: ("company_sqlite", "caches", "evidence_packet"),
    11: ("company_sqlite", "service_response", "kin_events"),
    12: ("kin_events", "service_response"),
    13: ("service_response", "caches"),
    14: ("process_artifacts",),
    15: ("kin_events", "shared_outbox", "receipts"),
    16: ("process_artifacts", "host_projection"),
    17: ("host_projection", "logs"),
    18: ("host_projection", "kin_events"),
    19: ("process_artifacts", "host_projection"),
}

#: The fourteen ratified lifecycle stages V-3 runs seeded messages through.
LIFECYCLE_STAGES: tuple[str, ...] = (
    "classification", "approval", "rejection", "defer", "expiry", "fan-out",
    "host projection", "logs", "receipts", "caches", "service", "kin",
    "restart", "cleanup",
)


@dataclass
class SurfaceRoots:
    """Where each surface family physically lives for one run."""

    repo: Path
    company_cache: Path
    state: Path
    evidence: Path
    outbox: Path

    @classmethod
    def create(cls, roots) -> "SurfaceRoots":
        outbox = roots.repo_root / ".kin" / "outbox"
        outbox.mkdir(parents=True, exist_ok=True)
        state = roots.run_root / "state"
        state.mkdir(parents=True, exist_ok=True)
        return cls(
            repo=roots.repo_root,
            company_cache=roots.company_cache,
            state=state,
            evidence=roots.evidence_root,
            outbox=outbox,
        )


@dataclass(frozen=True)
class PlantedCell:
    """One (surface, encoding) control, written as native bytes."""

    surface_family: str
    encoding_class: str
    canary_id: str
    raw_value: str
    encoded_value: str
    location: Path
    location_digest: str
    detector_class: str = "exact"

    def as_json(self) -> dict:
        return {
            "surface_family": self.surface_family,
            "encoding_class": self.encoding_class,
            "canary_id": self.canary_id,
            "location_digest": self.location_digest,
            "detector_class": self.detector_class,
        }


# --------------------------------------------------------------------------
# Native writers, one per surface family
# --------------------------------------------------------------------------


def _write_sqlite(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.company_cache / "facts-cache.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cached_facts "
            "(id INTEGER PRIMARY KEY, key TEXT, body BLOB)"
        )
        conn.execute("INSERT INTO cached_facts (key, body) VALUES (?, ?)",
                     (name, payload.encode("utf-8")))
    return path


def _write_worktree(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.repo / "docs" / "notes" / (name + ".md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# note\n\n" + payload + "\n", encoding="utf-8")
    return path


def _write_git_object(roots: SurfaceRoots, name: str, payload: str) -> Path:
    """Commit and repack so the bytes live inside a packfile, not a loose file."""
    path = roots.repo / "docs" / "packed" / (name + ".md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# packed note\n\n" + payload + "\n", encoding="utf-8")
    from .gitfix import GitRepo

    if not (roots.repo / ".git").exists():
        GitRepo.init(roots.repo)
    repo = GitRepo(path=roots.repo)
    repo.run("add", "-A")
    repo.commit("record a note for packing")
    repo.repack()
    path.unlink()
    repo.run("add", "-A")
    repo.commit("remove the working copy, leaving the packed object")
    return roots.repo / ".git"


def _write_kin_event(roots: SurfaceRoots, name: str, payload: str) -> Path:
    digest = hashlib.sha256((name + payload).encode("utf-8")).hexdigest()
    path = roots.repo / ".kin" / "events" / digest[:2] / (digest + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"statement": payload, "logical_key": name}),
                    encoding="utf-8")
    return path


def _write_outbox(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.outbox / (name + ".json")
    path.write_text(json.dumps({"body": payload}), encoding="utf-8")
    return path


def _write_receipt(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.repo / ".kin" / "receipts" / (name + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"receipt_id": name, "detail": payload}),
                    encoding="utf-8")
    return path


def _write_log(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.state / "guildhall.log"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(name + " " + payload + "\n")
    return path


def _write_cache(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.company_cache / "entries" / (name + ".bin")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload.encode("utf-8"))
    return path


def _write_projection(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.state / "projections" / (name + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"context": [{"statement": payload}]}),
                    encoding="utf-8")
    return path


def _write_process_artifact(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.state / "process" / (name + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"label": name, "argv": ["guildhall", payload],
                    "environ": {"NOTE": payload}, "fds": []}),
        encoding="utf-8",
    )
    return path


def _write_evidence(roots: SurfaceRoots, name: str, payload: str) -> Path:
    path = roots.evidence / "packet" / (name + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"failure_rows": [{"detail": payload}]}),
                    encoding="utf-8")
    return path


def _write_service_response(roots: SurfaceRoots, name: str, payload: str) -> Path:
    """A captured service response body, stored as a real archive member."""
    member = roots.state / "responses" / (name + ".json")
    member.parent.mkdir(parents=True, exist_ok=True)
    member.write_text(json.dumps({"body": payload}), encoding="utf-8")
    archive = roots.state / "responses" / (name + ".tar.gz")
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(member, arcname=member.name)
    member.unlink()
    return archive


WRITERS: dict[str, Callable[[SurfaceRoots, str, str], Path]] = {
    "company_sqlite": _write_sqlite,
    "codebase_git_worktree": _write_worktree,
    "codebase_git_objects": _write_git_object,
    "kin_events": _write_kin_event,
    "shared_outbox": _write_outbox,
    "receipts": _write_receipt,
    "logs": _write_log,
    "caches": _write_cache,
    "host_projection": _write_projection,
    "process_artifacts": _write_process_artifact,
    "evidence_packet": _write_evidence,
    "service_response": _write_service_response,
}


def _scan_root(roots: SurfaceRoots, surface: str) -> Path:
    return {
        "company_sqlite": roots.company_cache,
        "codebase_git_worktree": roots.repo / "docs",
        "codebase_git_objects": roots.repo,
        "kin_events": roots.repo / ".kin" / "events",
        "shared_outbox": roots.outbox,
        "receipts": roots.repo / ".kin" / "receipts",
        "logs": roots.state,
        "caches": roots.company_cache,
        "host_projection": roots.state / "projections",
        "process_artifacts": roots.state / "process",
        "evidence_packet": roots.evidence,
        "service_response": roots.state / "responses",
    }[surface]


# --------------------------------------------------------------------------
# The matrix
# --------------------------------------------------------------------------


@dataclass
class Matrix:
    """A total surface x encoding plant, with per-cell receipts."""

    roots: SurfaceRoots
    seed: int
    cells: list[PlantedCell] = field(default_factory=list)
    registry: dict[str, str] = field(default_factory=dict)

    @classmethod
    def plant(cls, roots: SurfaceRoots, *, seed: int) -> "Matrix":
        matrix = cls(roots=roots, seed=seed)
        rng = canaries.make_rng(seed)
        index = 0
        for surface in SURFACE_FAMILIES:
            for encoding in TRANSFORMATION_FAMILIES:
                canary = canaries.generate_canary(rng, index=index, family=surface)
                encoded = canaries.transform(canary.value, encoding)
                name = "c" + format(index, "04d")
                location = WRITERS[surface](roots, name, encoded)
                matrix.registry[canary.canary_id] = canary.value
                matrix.cells.append(PlantedCell(
                    surface_family=surface,
                    encoding_class=encoding,
                    canary_id=canary.canary_id,
                    raw_value=canary.value,
                    encoded_value=encoded,
                    location=location,
                    location_digest=scanners.location_digest(str(location)),
                    detector_class="exact",
                ))
                index += 1
        return matrix

    @property
    def expected_cells(self) -> int:
        return len(SURFACE_FAMILIES) * len(TRANSFORMATION_FAMILIES)

    def detector(self, *, mutation: str | None = None,
                 hmac_of: Callable[[str], str] | None = None) -> CanaryDetector:
        return CanaryDetector(
            registry=dict(self.registry),
            lineage={},
            partial_min_chars=12,
            hmac_of=hmac_of or (
                lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
            ),
            mutation=mutation,
        )

    def surfaces_for(self, surface: str, detector: CanaryDetector):
        root = _scan_root(self.roots, surface)
        if surface == "company_sqlite":
            db = self.roots.company_cache / "facts-cache.sqlite3"
            return scanners.sqlite_surfaces(db, detector)
        if surface == "codebase_git_objects":
            return scanners.git_object_surfaces(self.roots.repo, detector)
        return scanners.read_file_surfaces(root, surface, detector)

    def sweep(self, detector: CanaryDetector) -> dict[str, list[Finding]]:
        """Sweep every surface family and return findings keyed by family."""
        out: dict[str, list[Finding]] = {}
        for surface in SURFACE_FAMILIES:
            result = scanners.sweep(detector, self.surfaces_for(surface, detector))
            out[surface] = list(result.findings)
        return out

    def receipts(self, detector: CanaryDetector) -> list[dict]:
        """One exact receipt per planted cell: detected, where, in what form."""
        findings = self.sweep(detector)
        by_canary: dict[str, list[Finding]] = {}
        for family, entries in findings.items():
            for entry in entries:
                by_canary.setdefault(entry.canary_id, []).append(entry)
        out = []
        for cell in self.cells:
            hits = by_canary.get(cell.canary_id, [])
            out.append({
                "surface_family": cell.surface_family,
                "encoding_class": cell.encoding_class,
                "location_digest": cell.location_digest,
                "detected": bool(hits),
                "observed_surface_families": sorted({h.surface_family for h in hits}),
                "observed_encoding_classes": sorted({h.encoding_class for h in hits}),
            })
        return out

    def remove(self) -> int:
        """Remove every planted control so the clean assertion can run."""
        removed = 0
        for cell in self.cells:
            if cell.location.is_file():
                cell.location.unlink()
                removed += 1
        db = self.roots.company_cache / "facts-cache.sqlite3"
        if db.is_file():
            db.unlink()
            removed += 1
        log = self.roots.state / "guildhall.log"
        if log.is_file():
            log.unlink()
            removed += 1
        self.registry.clear()
        return removed

    def as_json(self) -> dict:
        return {
            "schema": "guildhall-v3-surface-encoding-matrix/1",
            "seed": self.seed,
            "surface_families": list(SURFACE_FAMILIES),
            "encoding_families": list(TRANSFORMATION_FAMILIES),
            "expected_cells": self.expected_cells,
            "planted_cells": len(self.cells),
            "cells": [c.as_json() for c in self.cells],
        }


def family_coverage(executed: Mapping[int, Mapping[str, Any]]) -> list[dict]:
    """One row per frozen threat-model family, with its declared surfaces.

    ``executed`` maps a family number to the observations a probe made. A
    family absent from that mapping reports ``executed: False``, which the
    catalogue clause rejects --- a docstring mentioning the family is no longer
    evidence that anything ran.
    """
    out = []
    for number in sorted(FAMILY_SURFACES):
        observed = executed.get(number, {})
        out.append({
            "family": number,
            "surfaces": list(FAMILY_SURFACES[number]),
            "executed": bool(observed.get("executed")),
            "positive_control_detected": bool(observed.get("positive_control_detected")),
            "negative_control_clean": bool(observed.get("negative_control_clean")),
            "detector_mutation_blinds": bool(observed.get("detector_mutation_blinds")),
        })
    return out


def digest(matrix: Matrix) -> str:
    return hashlib.sha256(
        json.dumps(matrix.as_json(), sort_keys=True).encode("utf-8")
    ).hexdigest()
