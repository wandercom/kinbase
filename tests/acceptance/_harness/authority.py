"""A real, separately registered authority process for V-6.

Detector Reviewer finding 16. The previous fixture never registered anything:
no key, no scope, no channel entered the ``AuthorityRegistry``, and the test
invoked the answering helper itself. The product therefore never delivered a
question through a registered channel, and "a targeted question is delivered to
that authority" was asserted about a call the harness made.

This module starts an **independent process** that

* listens on its own loopback port;
* appends every delivered request to a log the harness reads;
* returns an Ed25519-signed answer under the architect's registered key;
* refuses more than two calls for one task, per V-6's frozen ceiling;
* never returns code, only a fact and a rationale.

Its public key, scope and channel endpoint are published through the live
registry in :mod:`acceptance._harness.trust`, so the product resolves the
channel from Company rather than from anything the test passed it. The delivery
evidence is the helper's own log plus the digest of the exact request bytes it
received --- both produced by the process, not by the assertion.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import prereq, synth

#: V-6 freezes the per-task call ceiling of the frozen answer service.
CALL_CEILING = 2

HELPER_SOURCE = '''#!/usr/bin/env python3
"""Frozen authority answer service. Started by the acceptance instrument."""
import hashlib, http.server, json, os, sys, threading

SEED = bytes.fromhex(os.environ["AUTHORITY_SEED_HEX"])
LOG = os.environ["AUTHORITY_LOG"]
CEILING = int(os.environ["AUTHORITY_CALL_CEILING"])
HARNESS = os.environ["AUTHORITY_HARNESS_PATH"]
sys.path.insert(0, HARNESS)

from acceptance._harness import canonical, ed25519_pure  # noqa: E402

CALLS = {}
LOCK = threading.Lock()


def sign(payload):
    body = dict(payload)
    body["signer"] = ed25519_pure.public_key(SEED).hex()
    digest = canonical.signing_digest("answer", canonical.jcs(body))
    body["signature"] = ed25519_pure.sign(SEED, digest).hex()
    return body


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw.decode("utf-8"))
        except ValueError:
            request = {}
        task = str(request.get("task_id", ""))
        with LOCK:
            CALLS[task] = CALLS.get(task, 0) + 1
            count = CALLS[task]
            with open(LOG, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "task_id": task,
                    "question_id": request.get("question_id"),
                    "request_digest": hashlib.sha256(raw).hexdigest(),
                    "request_bytes": len(raw),
                    "call_index": count,
                    "peer": self.client_address[0],
                }) + "\\n")
        if count > CEILING:
            self.send_response(429)
            body = json.dumps({"error": {"code": "LIMIT_EXCEEDED",
                                         "retryable": False}}).encode()
        else:
            self.send_response(200)
            body = json.dumps(sign({
                "message_type": "answer",
                "question_id": request.get("question_id"),
                "answer": "the compatibility invariant is the wire format version",
                "rationale": "the pre-change architecture record fixes it",
                "contains_code": False,
            })).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1])
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''


@dataclass
class AuthorityProcess:
    """A live, separately registered answering authority."""

    signer: synth.Signer
    process: subprocess.Popen
    port: int
    log: Path
    script: Path

    @property
    def channel(self) -> str:
        return "http://127.0.0.1:" + str(self.port) + "/questions"

    def deliveries(self) -> list[dict]:
        if not self.log.is_file():
            return []
        out = []
        for line in self.log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def log_digest(self) -> str:
        raw = self.log.read_bytes() if self.log.is_file() else b""
        return hashlib.sha256(raw).hexdigest()

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def as_json(self) -> dict:
        return {
            "authority_id": self.signer.authority_id,
            "scope": self.signer.scope,
            "public_key": self.signer.public_hex,
            "channel_reference": self.channel,
            "pid": self.process.pid,
            "log_digest": self.log_digest(),
            "delivery_count": len(self.deliveries()),
        }


def _free_port() -> int:
    with socket.socket() as handle:
        handle.bind(("127.0.0.1", 0))
        return handle.getsockname()[1]


def start(signer: synth.Signer, workdir: Path, *, timeout: float = 20.0) -> AuthorityProcess:
    """Start the answering process. Failure is an instrument prerequisite."""
    workdir.mkdir(parents=True, exist_ok=True)
    script = workdir / "authority-helper.py"
    script.write_text(HELPER_SOURCE, encoding="utf-8")
    script.chmod(0o700)
    log = workdir / "deliveries.jsonl"
    log.write_text("", encoding="utf-8")
    port = _free_port()
    harness_path = str(Path(__file__).resolve().parents[2])
    process = subprocess.Popen(
        [sys.executable, str(script), str(port)],
        env={
            "AUTHORITY_SEED_HEX": signer.seed.hex(),
            "AUTHORITY_LOG": str(log),
            "AUTHORITY_CALL_CEILING": str(CALL_CEILING),
            "AUTHORITY_HARNESS_PATH": harness_path,
            "PATH": os.environ.get("PATH", ""),
            "PYTHONHASHSEED": "0",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise prereq.missing(
                "service", "authority answer process",
                "the helper exited before listening: "
                + (process.stderr.read().decode("utf-8", "replace")[:400]
                   if process.stderr else ""),
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return AuthorityProcess(signer=signer, process=process, port=port,
                                        log=log, script=script)
        except OSError:
            time.sleep(0.02)
    process.terminate()
    raise prereq.missing(
        "service", "authority answer process",
        "the helper did not accept a loopback connection within "
        + str(timeout) + "s",
    )
