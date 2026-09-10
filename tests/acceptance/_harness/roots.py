"""Isolated filesystem roots, config writers, and mode assertions.

``spec/verification.md`` V-9: "Use isolated temporary ``HOME``, config, and
repository roots." ``spec/architecture.md`` section 12: "All PoC services bind
loopback by default and run against dedicated temporary roots. Real Personal and
Company stores are opt-in and never used in acceptance."

Every root this module creates is under the pytest ``tmp_path`` tree, so no
acceptance run can touch a real Personal store, a real Company service or the
operator's own ``HOME``.
"""

from __future__ import annotations

import os
import shutil
import socket
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from . import planters
from .requirements import HarnessInvalid, ProductFailure


def assert_mode(path: Path, expected: int, *, why: str) -> None:
    observed = stat.S_IMODE(path.stat().st_mode)
    if observed != expected:
        raise ProductFailure(
            f"{path} is mode {observed:04o}; {why} requires {expected:04o}"
        )


def assert_mode_no_broader_than(path: Path, expected: int, *, why: str) -> None:
    observed = stat.S_IMODE(path.stat().st_mode)
    if observed & ~expected:
        raise ProductFailure(
            f"{path} is mode {observed:04o}, broader than {expected:04o}; {why}"
        )


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_toml(table: Mapping[str, object], *, section: str | None = None) -> str:
    lines: list[str] = []
    if section:
        lines.append(f"[{section}]")
    for key, value in table.items():
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        elif isinstance(value, (list, tuple)):
            rendered = ", ".join(f'"{toml_escape(str(v))}"' for v in value)
            lines.append(f"{key} = [{rendered}]")
        else:
            lines.append(f'{key} = "{toml_escape(str(value))}"')
    return "\n".join(lines) + "\n"


@dataclass
class ProofRoots:
    """One fully isolated acceptance environment.

    ``personal_root`` is deliberately created *outside* every repository and
    agent home. ``spec/architecture.md`` "Personal": "PersonalKindexAdapter owns
    a Kindex SQLite data directory outside all repositories, mode 0700."
    """

    base: Path
    home: Path
    xdg_config_home: Path
    personal_root: Path
    company_root: Path
    company_cache: Path
    #: Client-side (launcher) secrets and certificates: the facts-token copy the
    #: user config names and the out-of-worktree certificate file handed to
    #: ``repo init --certificate``. Outside every repository and outside the
    #: service root, so neither side reads the other's bytes.
    client_root: Path
    repo_root: Path
    run_root: Path
    evidence_root: Path
    company_port: int
    #: The keyword arguments of the last ``write_user_config`` call, retained so
    #: a probe can re-render the same config with one value changed (for
    #: example a blackholed Company URL, Validator ruling C28).
    user_config_kwargs: dict = field(default_factory=dict)

    @classmethod
    def create(cls, base: Path, *, company_port: int | None = None) -> "ProofRoots":
        base = Path(base)
        home = base / "home"
        xdg = base / "config"
        personal = base / "private" / "kindex-personal"
        company = base / "company"
        cache = base / "company-cache"
        client = base / "client"
        repo = base / "workspace" / "example-service"
        run = base / "run"
        evidence = base / "evidence"
        for path in (home, xdg, personal, company, cache, client, repo, run, evidence):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(personal, 0o700)
        os.chmod(cache, 0o700)
        os.chmod(client, 0o700)
        os.chmod(run, 0o700)
        os.chmod(evidence, 0o700)
        return cls(
            base=base,
            home=home,
            xdg_config_home=xdg,
            personal_root=personal,
            company_root=company,
            company_cache=cache,
            client_root=client,
            repo_root=repo,
            run_root=run,
            evidence_root=evidence,
            company_port=free_loopback_port() if company_port is None else company_port,
        )

    def uncertified_environment(self, name: str) -> tuple[Path, Path]:
        """A fresh ``HOME``/``XDG_CONFIG_HOME`` pair carrying no user config.

        Validator ruling C2: "uncertified" is constructed by withholding the
        cache and config, never by deleting a tracked file. A product invoked
        with these roots has no Company URL, no root key, no cache and no
        certificate, so ``spec/cli.md`` "no user config" applies: Codebase-only,
        zero trusted facts.
        """
        base = self.base / "uncertified" / name
        home = base / "home"
        xdg = base / "config"
        for path in (home, xdg):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(base, 0o700)
        return home, xdg

    # -- config files -----------------------------------------------------

    @property
    def user_config_path(self) -> Path:
        """``${XDG_CONFIG_HOME:-~/.config}/kinbase/config.toml`` (0600)."""
        return self.xdg_config_home / "kinbase" / "config.toml"

    @property
    def service_config_path(self) -> Path:
        return self.company_root / "kinbased.toml"

    @property
    def company_url(self) -> str:
        return f"http://127.0.0.1:{self.company_port}"

    def write_user_config(
        self,
        *,
        classifier_path: Path,
        classifier_sha256: str,
        facts_token_file: Path,
        root_public_key_file: Path,
        classifier_args: Iterable[str] = ("classifier", "--json"),
        classifier_model: str | None = None,
        classifier_timeout: int = 20,
        codex_version: str = ">=0.0.0",
        claude_version: str = ">=0.0.0",
        personal_data_root: Path | None = None,
        company_url: str | None = None,
        maintainer_key_file: Path | None = None,
    ) -> Path:
        """Write the launcher-only user config exactly as ``spec/cli.md`` frames it.

        Validator ruling C1: the config lives at
        ``${XDG_CONFIG_HOME:-$HOME/.config}/kinbase/config.toml`` (0600) with
        exactly the ``spec/cli.md`` keys, under an isolated ``HOME`` /
        ``XDG_CONFIG_HOME`` per world, and is written before any command that
        needs Company, cache, certificate or Personal.
        """
        self.user_config_kwargs = {
            "classifier_path": Path(classifier_path),
            "classifier_sha256": classifier_sha256,
            "facts_token_file": Path(facts_token_file),
            "root_public_key_file": Path(root_public_key_file),
            "classifier_args": tuple(classifier_args),
            "classifier_timeout": classifier_timeout,
            "classifier_model": classifier_model,
            "codex_version": codex_version,
            "claude_version": claude_version,
            "personal_data_root": personal_data_root,
            "company_url": company_url,
            "maintainer_key_file": maintainer_key_file,
        }
        path = self.user_config_path
        path.parent.mkdir(parents=True, exist_ok=True)
        # Detector Reviewer finding 7: the configuration a shared process loads
        # is raw pre-execution state. A config planter changes it here, before
        # the file is written and long before any product reads it.
        table = planters.mutate(
            "config.user",
            {
                "personal_data_root": str(personal_data_root or self.personal_root),
                "classifier_args": list(classifier_args),
            },
            personal_root=str(self.personal_root),
        )
        extra_lines = {
            k: v for k, v in table.items()
            if k not in ("personal_data_root", "classifier_args")
        }
        classifier_args = table["classifier_args"]
        body = 'schema_version = "1"\n\n'
        if maintainer_key_file is not None:
            body += render_toml(
                {"maintainer_key_file": str(maintainer_key_file.resolve())},
                section="identity",
            ) + "\n"
        if extra_lines:
            body += render_toml(extra_lines, section="policy")
            body += "\n"
        body += render_toml(
            {"data_root": str(table["personal_data_root"])},
            section="personal",
        )
        body += "\n"
        body += render_toml(
            {
                "url": company_url or self.company_url,
                "facts_token_file": str(facts_token_file),
                "root_public_key_file": str(root_public_key_file),
                "cache_root": str(self.company_cache),
            },
            section="company",
        )
        body += "\n"
        body += render_toml(
            {
                "executable": str(classifier_path),
                "executable_sha256": classifier_sha256,
                "args": list(classifier_args),
                "timeout_seconds": classifier_timeout,
                **({"model": classifier_model} if classifier_model is not None else {}),
            },
            section="classifier",
        )
        body += "\n"
        body += render_toml(
            {"codex_version": codex_version, "claude_version": claude_version},
            section="hosts",
        )
        path.write_text(body, encoding="utf-8")
        os.chmod(path, 0o600)
        planters.witness_path(path)
        return path

    def rewrite_user_config(self, **changes) -> Path:
        """Re-render the last user config with ``changes`` applied."""
        if not self.user_config_kwargs:
            raise HarnessInvalid(
                "rewrite_user_config called before any user config was written"
            )
        kwargs = dict(self.user_config_kwargs)
        kwargs.update(changes)
        return self.write_user_config(**kwargs)

    def write_service_config(
        self,
        *,
        company_id: str = "company-demo",
        root_key_file: Path | None = None,
        facts_token_file: Path | None = None,
        directory_token_file: Path | None = None,
        auth_failures_per_minute: int = 10,
        default_fact_freshness_seconds: int = 3600,
        candidate_lifetime_seconds: int = 900,
        clock_skew_seconds: int = 300,
        nonce_retention_seconds: int = 604800,
        bind: str | None = None,
    ) -> Path:
        path = self.service_config_path
        path.parent.mkdir(parents=True, exist_ok=True)
        table = {
            "schema_version": "1",
            "company_id": company_id,
            "sqlite_path": str(self.company_root / "company.sqlite3"),
            "bind": bind or f"127.0.0.1:{self.company_port}",
            "root_key_file": str(root_key_file or self.company_root / "company-root.key"),
            "facts_token_file": str(facts_token_file or self.company_root / "facts.token"),
            "directory_token_file": str(
                directory_token_file or self.company_root / "directory.token"
            ),
            "auth_failures_per_minute": auth_failures_per_minute,
            "default_fact_freshness_seconds": default_fact_freshness_seconds,
            "candidate_lifetime_seconds": candidate_lifetime_seconds,
            "clock_skew_seconds": clock_skew_seconds,
            "nonce_retention_seconds": nonce_retention_seconds,
        }
        table = planters.mutate("config.service", table, port=self.company_port)
        path.write_text(render_toml(table), encoding="utf-8")
        os.chmod(path, 0o600)
        planters.witness_path(path)
        return path

    # -- helpers ----------------------------------------------------------

    def write_secret(self, name: str, value: bytes, mode: int = 0o600) -> Path:
        path = self.company_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        os.chmod(path, mode)
        return path

    def plant_personal_canary_file(self, name: str, payload: str) -> Path:
        """Place a raw canary inside the Personal root only.

        Nothing in the shared boundary may ever reproduce these bytes.
        """
        path = self.personal_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def shared_surface_roots(self) -> tuple[Path, ...]:
        """Every root the V-3 scan treats as shared or durable."""
        return (
            self.company_root,
            self.company_cache,
            self.client_root,
            self.repo_root,
            self.evidence_root,
            self.home,
            self.xdg_config_home,
            self.run_root,
        )

    def assert_personal_is_not_a_shared_root(self) -> None:
        personal = self.personal_root.resolve()
        for root in self.shared_surface_roots():
            resolved = root.resolve()
            if resolved == personal or personal in resolved.parents:
                raise HarnessInvalid(
                    "the acceptance layout must keep the Personal root outside "
                    f"every shared root; {resolved} contains {personal}"
                )

    def destroy(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)
