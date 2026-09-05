"""Recursive surface enumeration for the V-3 byte scan.

``spec/verification.md`` V-3:

    Recursively scan every persistent/shared byte and SQLite text/blob value for
    exact, encoded, normalized, partial, and deterministic-correlation canaries.

and:

    Plant known canaries in every scanned surface and encoding during a
    positive-control run, including packed Git objects and SQLite blobs, and
    require each exact detector/location receipt before trusting a clean run.

``spec/verification.md`` V-8 additionally requires: "Scan Git objects, not only
the worktree, for copied Company/private canaries."

Every surface reader is fail-closed: an unreadable surface raises through
:meth:`CanaryDetector.on_scanner_error` rather than being silently skipped,
because a skipped surface would manufacture a clean result.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

from .detectors import CanaryDetector, Finding, ScannerError

MAX_FILE_BYTES = 64 * 1024 * 1024


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def location_digest(label: str) -> str:
    """Digest of a location string. Evidence rows never carry raw paths."""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@dataclass
class Surface:
    family: str
    label: str
    payloads: Sequence[bytes]


# --------------------------------------------------------------------------
# Filesystem
# --------------------------------------------------------------------------


def walk_files(root: Path, *, follow_symlinks: bool = False) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames.sort()
        for name in sorted(filenames):
            yield Path(dirpath) / name


def read_file_surfaces(root: Path, family: str, detector: CanaryDetector) -> Iterator[Surface]:
    if not root.exists():
        return
    for path in walk_files(root):
        try:
            if path.is_symlink():
                # A symlink target outside the root is itself a finding-worthy
                # surface (threat-model catalog entry 3: pathname/symlink swap).
                yield Surface(
                    family=family,
                    label=f"symlink:{path}",
                    payloads=[os.readlink(path).encode("utf-8", "surrogateescape")],
                )
                continue
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                raise ScannerError(f"{path} exceeds the {MAX_FILE_BYTES} scan bound")
            payload = path.read_bytes()
        except ScannerError:
            raise
        except OSError as exc:
            detector.on_scanner_error(str(path), exc)
            continue
        yield Surface(family=family, label=str(path), payloads=[payload])
        if detector.archive_enabled:
            yield from _archive_members(path, payload, family, detector)


def _archive_members(
    path: Path, payload: bytes, family: str, detector: CanaryDetector
) -> Iterator[Surface]:
    """Expand archive containers so a canary cannot hide inside one."""
    suffix = path.suffix.lower()
    try:
        if suffix in {".gz", ".tgz"}:
            yield Surface(family, f"gz:{path}", [zlib.decompress(payload, 16 + zlib.MAX_WBITS)])
        elif suffix == ".zip":
            import zipfile
            import io

            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                for name in sorted(archive.namelist()):
                    yield Surface(family, f"zip:{path}!{name}", [archive.read(name)])
        elif suffix in {".tar", ".xz", ".bz2"}:
            import tarfile
            import io

            with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    handle = archive.extractfile(member)
                    if handle is not None:
                        yield Surface(family, f"tar:{path}!{member.name}", [handle.read()])
    except Exception as exc:  # noqa: BLE001 - fail closed, do not skip silently
        detector.on_scanner_error(f"archive:{path}", exc)


# --------------------------------------------------------------------------
# Git objects, including packed objects
# --------------------------------------------------------------------------


def git_object_surfaces(repo: Path, detector: CanaryDetector) -> Iterator[Surface]:
    """Every reachable and unreachable Git object body, loose and packed.

    ``git cat-file --batch-all-objects --batch`` enumerates packed objects too,
    which a worktree-only scan would miss entirely.
    """
    if not (repo / ".git").exists() and not (repo / "HEAD").exists():
        return
    try:
        listing = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            ],
            capture_output=True,
            timeout=600,
        )
        if listing.returncode != 0:
            raise ScannerError(
                f"git cat-file failed in {repo}: {listing.stderr[:400]!r}"
            )
        names = [
            line.split()[0].decode("ascii")
            for line in listing.stdout.splitlines()
            if line.strip()
        ]
        for name in names:
            body = subprocess.run(
                ["git", "-C", str(repo), "cat-file", "-p", name],
                capture_output=True,
                timeout=120,
            )
            if body.returncode != 0:
                detector.on_scanner_error(f"git-object:{name}", RuntimeError(body.stderr[:200]))
                continue
            yield Surface("codebase_git_objects", f"git:{repo}:{name}", [body.stdout])
        # Packfile bytes themselves, so a canary in a delta base is still seen.
        pack_dir = repo / ".git" / "objects" / "pack"
        if pack_dir.is_dir():
            for pack in sorted(pack_dir.glob("*.pack")):
                yield Surface(
                    "codebase_git_objects", f"packfile:{pack}", [pack.read_bytes()]
                )
        # Reflogs and ORIG_HEAD retain rewritten history.
        for extra in ("logs", "ORIG_HEAD", "packed-refs"):
            candidate = repo / ".git" / extra
            if candidate.is_file():
                yield Surface(
                    "codebase_git_objects", f"git-meta:{candidate}", [candidate.read_bytes()]
                )
            elif candidate.is_dir():
                for path in walk_files(candidate):
                    yield Surface(
                        "codebase_git_objects", f"git-meta:{path}", [path.read_bytes()]
                    )
    except ScannerError:
        raise
    except Exception as exc:  # noqa: BLE001
        detector.on_scanner_error(f"git-objects:{repo}", exc)


# --------------------------------------------------------------------------
# SQLite text and blob values
# --------------------------------------------------------------------------


def sqlite_surfaces(db_path: Path, detector: CanaryDetector) -> Iterator[Surface]:
    """Every TEXT and BLOB cell, plus free pages via the raw file body."""
    if not db_path.is_file():
        return
    # Raw file bytes cover freelist pages and WAL remnants that SQL cannot read.
    yield Surface("company_sqlite", f"sqlite-raw:{db_path}", [db_path.read_bytes()])
    for sidecar in (f"{db_path}-wal", f"{db_path}-shm", f"{db_path}-journal"):
        p = Path(sidecar)
        if p.is_file():
            yield Surface("company_sqlite", f"sqlite-sidecar:{p}", [p.read_bytes()])
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    except sqlite3.Error as exc:
        detector.on_scanner_error(f"sqlite:{db_path}", exc)
        return
    try:
        conn.text_factory = bytes
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            )
        ]
        for table in tables:
            name = table.decode() if isinstance(table, bytes) else str(table)
            if name.startswith("sqlite_"):
                continue
            try:
                cursor = conn.execute(f'SELECT * FROM "{name}"')  # noqa: S608 - read-only fixture db
            except sqlite3.Error as exc:
                detector.on_scanner_error(f"sqlite-table:{name}", exc)
                continue
            for rowno, row in enumerate(cursor):
                payloads: list[bytes] = []
                for cell in row:
                    if isinstance(cell, bytes):
                        if detector.sqlite_blob_enabled or _looks_textual(cell):
                            payloads.append(cell)
                    elif isinstance(cell, str):
                        payloads.append(cell.encode("utf-8", "surrogateescape"))
                    elif cell is not None:
                        payloads.append(str(cell).encode())
                if payloads:
                    yield Surface(
                        "company_sqlite", f"sqlite:{db_path}:{name}:{rowno}", payloads
                    )
    finally:
        conn.close()


def _looks_textual(value: bytes) -> bool:
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# --------------------------------------------------------------------------
# Process artifacts
# --------------------------------------------------------------------------


def process_artifact_surfaces(records: Sequence[dict]) -> Iterator[Surface]:
    """argv, environment, descriptor metadata, config and error bodies.

    ``spec/threat-model.md`` frozen attack catalog entry 14: "process-capability
    inspection: dump argv, environment, file descriptors, serialized config,
    exception bodies, and child-process inputs from every shared
    writer/projector and search for the Personal root/path/capability canary."
    """
    for record in records:
        label = record.get("label", "process")
        payload_parts: list[bytes] = []
        for key in ("argv", "environ", "fds", "config", "stderr", "stdout", "child_input"):
            value = record.get(key)
            if value is None:
                continue
            if isinstance(value, bytes):
                payload_parts.append(value)
            elif isinstance(value, str):
                payload_parts.append(value.encode("utf-8", "surrogateescape"))
            else:
                payload_parts.append(repr(value).encode("utf-8", "surrogateescape"))
        yield Surface("process_artifacts", f"process:{label}", payload_parts)


# --------------------------------------------------------------------------
# Full sweep
# --------------------------------------------------------------------------


@dataclass
class SweepResult:
    findings: tuple[Finding, ...]
    surfaces_scanned: int
    bytes_scanned: int
    surface_families: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.findings


def sweep(detector: CanaryDetector, surfaces: Iterator[Surface]) -> SweepResult:
    findings: list[Finding] = []
    count = 0
    total_bytes = 0
    families: set[str] = set()
    now = _now()
    for surface in surfaces:
        count += 1
        families.add(surface.family)
        digest = location_digest(surface.label)
        for payload in surface.payloads:
            total_bytes += len(payload)
            findings.extend(
                detector.scan_bytes(
                    payload,
                    surface_family=surface.family,
                    location_digest=digest,
                    observed_at=now,
                )
            )
    return SweepResult(
        findings=tuple(findings),
        surfaces_scanned=count,
        bytes_scanned=total_bytes,
        surface_families=tuple(sorted(families)),
    )
