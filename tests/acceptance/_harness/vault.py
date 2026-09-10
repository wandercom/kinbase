"""Tester-custodied mode-0700 canary vault.

``spec/threat-model.md`` "Canary and auxiliary-corpus custody":

    The Tester generates randomized raw V-2/V-3 canary values into a dedicated
    mode-0700 test vault outside every repository, worktree, agent home, and
    evidence packet. Committed fixtures contain generators, structural labels,
    and placeholder IDs only. Raw instantiated messages, registry entries,
    salts, and keys never enter a Coder-visible or Git-reachable path.

and:

    Raw registry plaintext, raw fixture instantiations, and decryption keys are
    destroyed within 24 hours of terminal verdict unless an explicitly
    authorized incident hold applies.

Location resolution:

* ``KINBASE_TESTER_VAULT`` when set (the Validator supplies a run-scoped path);
* otherwise ``$TMPDIR/kinbase-acceptance-vault-<uid>``.

The vault refuses to sit inside any Git worktree, inside a configured agent
home, or inside the proof repository, and refuses to operate unless its root is
mode 0700. Both refusals are ``INVALID_HARNESS``: a leaky vault would make the
whole V-3 result untrustworthy in the *favourable* direction.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import crypto_box
from .requirements import HarnessInvalid, repo_root

VAULT_ENV = "KINBASE_TESTER_VAULT"
REGISTRY_NAME = "canary-registry.sealed"
KEY_NAME = "registry.key"
RETENTION_SECONDS = 24 * 60 * 60


def _in_git_worktree(path: Path) -> bool:
    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


@dataclass
class VaultEntry:
    """One registry row. Raw values never leave the vault."""

    canary_id: str
    raw_value: str
    transformation_family: str
    planted_surfaces: tuple[str, ...]
    expected_destination_denial: tuple[str, ...]
    gold_atom_label: str
    gold_destination_labels: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "raw_value": self.raw_value,
            "transformation_family": self.transformation_family,
            "planted_surfaces": list(self.planted_surfaces),
            "expected_destination_denial": list(self.expected_destination_denial),
            "gold_atom_label": self.gold_atom_label,
            "gold_destination_labels": list(self.gold_destination_labels),
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "VaultEntry":
        return cls(
            canary_id=payload["canary_id"],
            raw_value=payload["raw_value"],
            transformation_family=payload["transformation_family"],
            planted_surfaces=tuple(payload["planted_surfaces"]),
            expected_destination_denial=tuple(payload["expected_destination_denial"]),
            gold_atom_label=payload["gold_atom_label"],
            gold_destination_labels=tuple(payload["gold_destination_labels"]),
        )


class CanaryVault:
    """Encrypted registry plus raw fixture instantiations, mode 0700."""

    def __init__(self, root: Path | None = None, forbidden_roots: Iterable[Path] = ()) -> None:
        self.root = Path(root or self._default_root()).resolve()
        self.forbidden_roots = [Path(p).resolve() for p in forbidden_roots]
        self._entries: dict[str, VaultEntry] = {}
        self._key: bytes | None = None
        self._prepare()

    # -- location and mode -----------------------------------------------

    @staticmethod
    def _default_root() -> Path:
        override = os.environ.get(VAULT_ENV)
        if override:
            return Path(override)
        base = Path(tempfile.gettempdir())
        return base / f"kinbase-acceptance-vault-{os.getuid()}"

    def _prepare(self) -> None:
        spec_root = repo_root().resolve()
        if self.root == spec_root or spec_root in self.root.parents:
            raise HarnessInvalid(
                "the canary vault must live outside the proof repository; "
                f"{self.root} is inside {spec_root}"
            )
        for forbidden in self.forbidden_roots:
            if self.root == forbidden or forbidden in self.root.parents:
                raise HarnessInvalid(
                    f"the canary vault must not live under {forbidden}"
                )
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        if _in_git_worktree(self.root):
            raise HarnessInvalid(
                "the canary vault resolved inside a Git worktree; raw canary "
                "values must never be Git-reachable"
            )
        self.assert_mode()
        (self.root / "raw").mkdir(exist_ok=True)
        os.chmod(self.root / "raw", 0o700)

    def assert_mode(self) -> None:
        mode = stat.S_IMODE(self.root.stat().st_mode)
        if mode != 0o700:
            raise HarnessInvalid(
                f"canary vault {self.root} is mode {mode:04o}, must be 0700"
            )

    # -- key and registry -------------------------------------------------

    @property
    def key(self) -> bytes:
        if self._key is None:
            key_path = self.root / KEY_NAME
            if key_path.exists():
                self._key = key_path.read_bytes()
            else:
                self._key = os.urandom(32)
                key_path.write_bytes(self._key)
                os.chmod(key_path, 0o600)
        return self._key

    @property
    def registry_path(self) -> Path:
        return self.root / REGISTRY_NAME

    def add(self, entry: VaultEntry) -> VaultEntry:
        self._entries[entry.canary_id] = entry
        return entry

    def get(self, canary_id: str) -> VaultEntry:
        return self._entries[canary_id]

    def entries(self) -> tuple[VaultEntry, ...]:
        return tuple(self._entries.values())

    def raw_values(self) -> tuple[str, ...]:
        return tuple(e.raw_value for e in self._entries.values())

    def seal(self) -> dict[str, Any]:
        """Write the sealed registry and return the manifest-bindable metadata.

        Returns only ciphertext digest, schema and count -- never key or
        plaintext -- matching ``spec/threat-model.md``: "The manifest binds its
        ciphertext digest and schema/count metadata without its key or
        plaintext."
        """
        payload = {
            "schema": "kinbase-acceptance-canary-registry/1",
            "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "entries": [e.to_json() for e in self._entries.values()],
        }
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        blob = crypto_box.seal(self.key, plaintext, b"kinbase-acceptance-canary-registry/1")
        self.registry_path.write_bytes(blob)
        os.chmod(self.registry_path, 0o600)
        import hashlib

        return {
            "schema": "kinbase-acceptance-canary-registry/1",
            "ciphertext_sha256": hashlib.sha256(blob).hexdigest(),
            "entry_count": len(self._entries),
            "transformation_families": sorted(
                {e.transformation_family for e in self._entries.values()}
            ),
        }

    def load(self) -> None:
        blob = self.registry_path.read_bytes()
        payload = json.loads(
            crypto_box.unseal(
                self.key, blob, b"kinbase-acceptance-canary-registry/1"
            )
        )
        self._entries = {
            row["canary_id"]: VaultEntry.from_json(row) for row in payload["entries"]
        }

    # -- evidence-safe reporting -----------------------------------------

    def hmac_of(self, value: str) -> str:
        """Keyed HMAC for permanent evidence rows; never the raw value."""
        return crypto_box.keyed_hmac(self.key, value.encode("utf-8"))

    def raw_fixture_dir(self, name: str) -> Path:
        path = self.root / "raw" / name
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    # -- retention --------------------------------------------------------

    def destroy(self) -> None:
        """Destroy raw values, registry and key.

        ``spec/threat-model.md``: raw registry plaintext, raw fixture
        instantiations and decryption keys "are destroyed within 24 hours of
        terminal verdict unless an explicitly authorized incident hold applies".
        """
        self._entries.clear()
        self._key = None
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)

    def retention_deadline_seconds(self) -> int:
        return RETENTION_SECONDS
