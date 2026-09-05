"""Deterministic repository fixture builder for V-1, V-4 and V-8 lifecycle cells.

Covers every version-control-shaped lifecycle cell the ratified adapter matrix
names: branch, merge, reject, revert, delete ref, rebase/force-push, squash,
shallow fetch, sparse checkout, linked worktree, submodule, nested repository,
case alias, ``core.ignorecase``, ``core.autocrlf`` and macOS normalisation.

``spec/verification.md`` V-1 freezes the ``repo_code``, ``repo_tests``,
``git_history`` and ``docs_adr`` rows of the lifecycle matrix; V-4 requires
"Delete/modify an event, delete its local manifest, use a shallow clone, use a
sparse checkout, rebase, force-push, and squash".

Fixture commits use a fixed identity and timestamp so a rebuild is byte-stable,
which V-4 determinism assertions depend on.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .requirements import HarnessInvalid

VCS = "git"

FIXTURE_NAME = "Acceptance Fixture"
FIXTURE_EMAIL = "fixture@invalid.example"
FIXED_STAMP = "1767225600 +0000"  # 2026-01-01T00:00:00Z

_BASE_ENV = {
    "GIT_AUTHOR_NAME": FIXTURE_NAME,
    "GIT_AUTHOR_EMAIL": FIXTURE_EMAIL,
    "GIT_COMMITTER_NAME": FIXTURE_NAME,
    "GIT_COMMITTER_EMAIL": FIXTURE_EMAIL,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
    "TZ": "UTC",
}


@dataclass
class GitRepo:
    """A throwaway repository with deterministic commit identities.

    Nothing here touches the operator's own configuration: ``GIT_CONFIG_SYSTEM``
    is redirected to ``os.devnull`` and ``GIT_CONFIG_GLOBAL`` to a file inside
    the fixture, so an acceptance fixture can never read or mutate real user
    identity or hooks.
    """

    path: Path
    default_branch: str = "main"

    @classmethod
    def init(
        cls, path: Path, *, default_branch: str = "main", bare: bool = False
    ) -> "GitRepo":
        path.mkdir(parents=True, exist_ok=True)
        repo = cls(path=path, default_branch=default_branch)
        args = ["init", "-q", f"--initial-branch={default_branch}"]
        if bare:
            args.append("--bare")
        repo.run(*args)
        if not bare:
            repo.run("config", "user.name", FIXTURE_NAME)
            repo.run("config", "user.email", FIXTURE_EMAIL)
            repo.run("config", "commit.gpgsign", "false")
            repo.run("config", "core.ignorecase", "false")
            repo.run("config", "core.autocrlf", "false")
        return repo

    # -- primitives -------------------------------------------------------

    def env(self, overrides: Mapping[str, str] | None = None) -> dict[str, str]:
        env = {
            k: os.environ[k]
            for k in ("PATH", "LANG", "TMPDIR")
            if k in os.environ
        }
        env["HOME"] = str(self.path.parent)
        env.update(_BASE_ENV)
        env["GIT_CONFIG_GLOBAL"] = str(self.path / ".fixture-config")
        env["GIT_AUTHOR_DATE"] = FIXED_STAMP
        env["GIT_COMMITTER_DATE"] = FIXED_STAMP
        env.update(overrides or {})
        return env

    def run(
        self,
        *args: str,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> str:
        proc = subprocess.run(
            [VCS, "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            env=self.env(env),
            timeout=300,
        )
        if check and proc.returncode != 0:
            raise HarnessInvalid(
                f"{VCS} {' '.join(args)} failed in {self.path}: {proc.stderr.strip()}"
            )
        return proc.stdout

    # -- content ----------------------------------------------------------

    def write(self, rel: str, content: str, *, mode: int | None = None) -> Path:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        if mode is not None:
            os.chmod(target, mode)
        return target

    def write_bytes(self, rel: str, content: bytes) -> Path:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def commit(self, message: str, *, paths: Sequence[str] | None = None) -> str:
        if paths:
            self.run("add", "--", *paths)
        else:
            self.run("add", "-A")
        self.run("commit", "-q", "--allow-empty", "-m", message)
        return self.head()

    def head(self, ref: str = "HEAD") -> str:
        return self.run("rev-parse", ref).strip()

    # -- lifecycle cells ---------------------------------------------------

    def branch(self, name: str, *, start: str | None = None) -> "GitRepo":
        args = ["checkout", "-q", "-b", name]
        if start:
            args.append(start)
        self.run(*args)
        return self

    def checkout(self, ref: str) -> "GitRepo":
        self.run("checkout", "-q", ref)
        return self

    def merge(self, ref: str, *, message: str = "merge") -> str:
        self.run("merge", "-q", "--no-ff", "-m", message, ref)
        return self.head()

    def revert(self, ref: str) -> str:
        self.run("revert", "--no-edit", "-n", ref)
        self.run("commit", "-q", "-m", f"revert {ref[:8]}")
        return self.head()

    def delete_ref(self, ref: str) -> None:
        self.run("update-ref", "-d", ref)

    def rebase(self, onto: str) -> str:
        self.run("rebase", "-q", onto)
        return self.head()

    def squash_last(self, count: int, message: str) -> str:
        base = self.run("rev-parse", f"HEAD~{count}").strip()
        self.run("reset", "--soft", base)
        self.run("commit", "-q", "-m", message)
        return self.head()

    def push(self, remote_path: Path, refspec: str, *, force: bool = False) -> None:
        args = ["push", "-q"]
        if force:
            args.append("--force")
        args += [str(remote_path), refspec]
        self.run(*args)

    def clone(
        self,
        dest: Path,
        *,
        depth: int | None = None,
        sparse: Sequence[str] | None = None,
        no_checkout: bool = False,
    ) -> "GitRepo":
        args = ["clone", "-q"]
        if depth is not None:
            args += ["--depth", str(depth)]
        if sparse is not None:
            args += ["--filter=blob:none", "--no-checkout"]
        elif no_checkout:
            args.append("--no-checkout")
        args += [str(self.path), str(dest)]
        proc = subprocess.run(
            [VCS, *args],
            capture_output=True,
            text=True,
            env=self.env(),
            timeout=300,
        )
        if proc.returncode != 0:
            raise HarnessInvalid(f"clone failed: {proc.stderr.strip()}")
        cloned = GitRepo(path=dest, default_branch=self.default_branch)
        if sparse is not None:
            cloned.run("sparse-checkout", "init", "--cone")
            cloned.run("sparse-checkout", "set", *sparse)
            cloned.run("checkout", "-q", self.default_branch)
        return cloned

    def add_worktree(self, dest: Path, branch: str) -> "GitRepo":
        """Linked worktree sharing the common directory (V-4 lock, V-9 identity)."""
        self.run("worktree", "add", "-q", "-b", branch, str(dest))
        return GitRepo(path=dest, default_branch=self.default_branch)

    def add_submodule(self, child: "GitRepo", rel: str) -> None:
        self.run(
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(child.path),
            rel,
        )
        self.commit(f"add nested repository {rel}")

    def set_config(self, key: str, value: str) -> None:
        self.run("config", key, value)

    def repack(self) -> None:
        """Force objects into a packfile so packed-object scanning is exercised.

        ``spec/verification.md`` V-3 requires positive controls "including packed
        Git objects and SQLite blobs".
        """
        self.run("gc", "-q", "--prune=now")

    def object_count(self) -> int:
        out = self.run("cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
        return len([line for line in out.splitlines() if line.strip()])

    def reachable_from(self, ref: str, candidate: str) -> bool:
        proc = subprocess.run(
            [VCS, "-C", str(self.path), "merge-base", "--is-ancestor", candidate, ref],
            capture_output=True,
            text=True,
            env=self.env(),
            timeout=120,
        )
        return proc.returncode == 0

    def common_dir(self) -> Path:
        return Path(self.run("rev-parse", "--git-common-dir").strip())

    def install_attributes(self, lines: Sequence[str], *, append: bool = True) -> Path:
        """Attribute rules for ``.kin/events/**`` and ``.kin/manifests/**``.

        ``spec/architecture.md`` "Codebase": "Repository initialization installs
        and ``fsck`` verifies effective Git attributes ``.kin/events/** -text
        -diff -merge`` and ``.kin/manifests/** -text -diff -merge``."
        """
        path = self.path / ".gitattributes"
        body = "\n".join(lines) + "\n"
        if append and path.exists():
            path.write_text(path.read_text(encoding="utf-8") + body, encoding="utf-8")
        else:
            path.write_text(body, encoding="utf-8")
        return path

    def effective_attributes(self, rel: str) -> dict[str, str]:
        out = self.run("check-attr", "-a", "--", rel)
        attrs: dict[str, str] = {}
        for line in out.splitlines():
            if ": " not in line:
                continue
            parts = line.split(": ")
            if len(parts) >= 3:
                attrs[parts[-2]] = parts[-1]
        return attrs


#: The attribute lines ``spec/architecture.md`` requires ``repo init`` to install.
REQUIRED_ATTRIBUTE_LINES: tuple[str, ...] = (
    ".kin/events/** -text -diff -merge",
    ".kin/manifests/** -text -diff -merge",
)
