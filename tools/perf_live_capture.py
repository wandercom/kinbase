#!/usr/bin/env python3
"""Times live capture (`session observe`) and projection (`kinbase project`)
for two kinbase binaries on the same generated workload.

Each binary gets its own Company service, certified repository and
deterministic classifier (`kinbase classifier --json`, the binary under test),
set up as spec/cli.md's first working session describes. Every repetition uses
a fresh repository: one session observes all the messages in one event file
(timestamped now, as live capture requires), then the projection runs once per
question. The workload is generated from a fixed seed, and its SHA-256 is
reported with the platform, the core count and both binaries' digests, so a run
can be compared with another.

  cargo build --release --locked            # the new binary
  git worktree add ../kinbase-main main && (cd ../kinbase-main && cargo build --release --locked)
  python3 tools/perf_live_capture.py \\
      --old ../kinbase-main/target/release/kinbase --new target/release/kinbase \\
      --messages 80 --reps 5 --out perf.json

Binaries are copied into --bin-dir (default ~/.kinbase-perf-bin), whose whole
ancestry must not be group or other writable: the classifier rules refuse
otherwise.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import random
import shutil
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

SUBJECTS = ["the retry policy", "the ledger export", "the booking webhook", "the invoice job",
            "the cache warmer", "the payment reconciler", "the scheduler", "the search index",
            "the onboarding flow", "the nightly backup", "the rate limiter", "the audit log"]
VERBS = ["moved", "rewrote", "paused", "tested", "documented", "measured", "split", "retired",
         "reviewed", "profiled", "renamed", "migrated"]
DETAILS = ["because timeouts doubled under load", "after the incident on the third",
           "so the queue drains before midnight", "to keep the v1 wire format stable",
           "since two services wrote the same rows", "while the vendor fixes their API",
           "with a 30 second budget per call", "behind a feature flag for one week"]
QUESTIONS = ["Why did we change the retry policy?", "What happened to the ledger export?",
             "How should the payment reconciler handle duplicate rows?",
             "What is the budget for calls to the vendor API?", "Who owns the nightly backup?"]


def workload(messages: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    out = []
    for i in range(messages):
        role = "user" if i % 2 == 0 else "assistant"
        sentences = []
        for _ in range(rng.randint(2, 6)):
            sentences.append(f"We {rng.choice(VERBS)} {rng.choice(SUBJECTS)} {rng.choice(DETAILS)}.")
        out.append({"role": role, "text": f"[2026-09-{1 + i % 28:02d}] " + " ".join(sentences)})
    return out


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Install:
    """One binary with its own Company service and configuration."""

    def __init__(self, name: str, binary: Path, root: Path, bin_dir: Path) -> None:
        self.root = root / name
        self.root.mkdir(parents=True)
        bin_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(bin_dir, 0o755)
        self.bin = bin_dir / f"kinbase-{name}"
        shutil.copy2(binary, self.bin)
        os.chmod(self.bin, 0o755)
        self.digest = hashlib.sha256(self.bin.read_bytes()).hexdigest()
        self.port = free_port()
        self.secret = self.root / "secret"
        self.secret.mkdir(mode=0o700)
        conf = self.secret / "kinbased.toml"
        s = self.secret
        conf.write_text(
            f'schema_version = "1"\ncompany_id = "company-perf"\nsqlite_path = "{s}/company.sqlite3"\n'
            f'bind = "127.0.0.1:{self.port}"\nroot_key_file = "{s}/company-root.key"\n'
            f'facts_token_file = "{s}/facts.token"\ndirectory_token_file = "{s}/directory.token"\n'
            f'admin_token_file = "{s}/admin.token"\nauth_failures_per_minute = 10\n'
            "default_fact_freshness_seconds = 3600\ncandidate_lifetime_seconds = 900\n"
            "clock_skew_seconds = 300\nnonce_retention_seconds = 604800\n")
        os.chmod(conf, 0o600)
        self.run("company", "init", "--config", str(conf))
        self.log = open(self.root / "company.log", "a")
        self.service = subprocess.Popen([str(self.bin), "company", "serve", "--config", str(conf)],
                                        stdout=self.log, stderr=self.log, start_new_session=True)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=1)
                break
            except urllib.error.HTTPError:
                break
            except Exception:
                time.sleep(0.1)

    def close(self) -> None:
        self.service.terminate()
        self.service.wait(timeout=10)
        self.log.close()

    def run(self, *args: str, cwd: Path | None = None, cfg: Path | None = None) -> dict:
        env = dict(os.environ)
        if cfg:
            env["XDG_CONFIG_HOME"] = str(cfg)
        p = subprocess.run([str(self.bin), *args, "--json"], cwd=cwd, env=env, capture_output=True, text=True)
        first = (p.stdout or p.stderr).split("\n", 1)[0]
        out = json.loads(first)
        if "error" in out and p.returncode not in (0, 3):
            raise RuntimeError(f"kinbase {' '.join(args[:2])}: {out['error']}")
        return out

    def repository(self, tag: str) -> tuple[Path, Path]:
        repo, cfg, state = self.root / "repos" / tag, self.root / "cfg" / tag, self.root / "state" / tag
        repo.mkdir(parents=True)
        git = ["git", "-c", "user.name=perf", "-c", "user.email=perf@localhost"]
        subprocess.run(git + ["init", "-q"], cwd=repo, check=True)
        subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "init"], cwd=repo, check=True)
        for d in (cfg / "kinbase", state / "personal", state / "cache"):
            d.mkdir(parents=True)
        os.chmod(state / "cache", 0o700)
        s = self.secret
        conf = cfg / "kinbase" / "config.toml"
        conf.write_text(
            f'schema_version = "1"\n\n[personal]\ndata_root = "{state}/personal"\n\n[company]\n'
            f'url = "http://127.0.0.1:{self.port}"\nfacts_token_file = "{s}/facts.token"\n'
            f'root_public_key_file = "{s}/company-root.pub"\nadmin_token_file = "{s}/admin.token"\n'
            f'cache_root = "{state}/cache"\n\n[classifier]\nmodel = "deterministic"\n'
            f'executable = "{self.bin}"\nexecutable_sha256 = "{self.digest}"\n'
            'args = ["classifier", "--json"]\ntimeout_seconds = 60\n')
        os.chmod(conf, 0o600)
        issued = self.run("repo", "issue", "--repo", str(repo), "--company", f"http://127.0.0.1:{self.port}", cfg=cfg)
        cert = self.root / f"{tag}.cert.json"
        cert.write_text(json.dumps(issued["certificate"]))
        self.run("repo", "init", "--repo", str(repo), "--certificate", str(cert), cfg=cfg)
        return repo, cfg

    def repetition(self, tag: str, messages: list[dict]) -> dict:
        repo, cfg = self.repository(tag)
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        events = self.root / f"{tag}.events.jsonl"
        with events.open("w") as out:
            for i, m in enumerate(messages):
                out.write(json.dumps({"id": hashlib.sha256(f"{tag}|{i}".encode()).hexdigest()[:24],
                                      "role": m["role"], "text": m["text"], "observed_at": now,
                                      "source_kind": "codex_jsonl"}) + "\n")
        session = self.run("session", "start", "--host", "codex", "--repo", str(repo), cwd=repo, cfg=cfg)["session_id"]
        t0 = time.perf_counter()
        observed = self.run("session", "observe", session, "--event", str(events), cwd=repo, cfg=cfg)
        observe = time.perf_counter() - t0
        self.run("session", "end", session, cwd=repo, cfg=cfg)
        projections, outputs = [], []
        for question in QUESTIONS:
            t0 = time.perf_counter()
            projected = self.run("project", "--repo", str(repo), "--task", question, "--decision", question,
                                 cwd=repo, cfg=cfg)
            projections.append(time.perf_counter() - t0)
            outputs.append(sorted(row["fact_id"] for row in projected.get("selected") or []))
        return {"observe_s": observe, "admissions": len(observed.get("admissions") or []),
                "project_s": projections, "selected": outputs}


def summary(values: list[float]) -> dict:
    values = sorted(values)
    p90 = values[min(len(values) - 1, round(0.9 * (len(values) - 1)))]
    return {"n": len(values), "min": round(values[0], 3), "median": round(statistics.median(values), 3),
            "p90": round(p90, 3), "max": round(values[-1], 3)}


def machine() -> dict:
    cpu = platform.processor() or platform.machine()
    if Path("/proc/cpuinfo").exists():
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith(("model name", "cpu part")):
                cpu = line.split(":", 1)[1].strip()
                break
        lscpu = subprocess.run(["lscpu"], capture_output=True, text=True).stdout
        for line in lscpu.splitlines():
            if line.startswith("Model name:"):
                cpu = line.split(":", 1)[1].strip()
    elif platform.system() == "Darwin":
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
    return {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
            "cpu": cpu, "cores": os.cpu_count()}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", type=Path, required=True)
    ap.add_argument("--new", type=Path, required=True)
    ap.add_argument("--messages", type=int, default=80)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20261003)
    ap.add_argument("--bin-dir", type=Path, default=Path.home() / ".kinbase-perf-bin")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    messages = workload(a.messages, a.seed)
    workload_sha = hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()
    report = {"machine": machine(), "workload": {"messages": a.messages, "seed": a.seed, "sha256": workload_sha,
                                                 "questions": QUESTIONS}, "binaries": {}}
    with tempfile.TemporaryDirectory(prefix="kinbase-perf-") as tmp:
        installs = {name: Install(name, path, Path(tmp), a.bin_dir) for name, path in (("old", a.old), ("new", a.new))}
        try:
            runs: dict[str, list[dict]] = {name: [] for name in installs}
            # Alternate the binaries so drift in the machine hits both alike.
            for rep in range(a.reps):
                for name, install in installs.items():
                    runs[name].append(install.repetition(f"rep{rep}", messages))
                    print(f"rep {rep} {name}: observe {runs[name][-1]['observe_s']:.2f}s", flush=True)
        finally:
            for install in installs.values():
                install.close()
    for name, install in installs.items():
        report["binaries"][name] = {
            "sha256": install.digest,
            "observe_s": summary([r["observe_s"] for r in runs[name]]),
            "observe_ms_per_message": summary([1000 * r["observe_s"] / a.messages for r in runs[name]]),
            "project_s": summary([t for r in runs[name] for t in r["project_s"]]),
            "admissions": sorted({r["admissions"] for r in runs[name]}),
        }
        report["binaries"][name]["selected_per_question"] = sorted(
            {len(selected) for r in runs[name] for selected in r["selected"]})
    text = json.dumps(report, indent=2)
    print(text)
    if a.out:
        a.out.write_text(text + "\n")


if __name__ == "__main__":
    main()
