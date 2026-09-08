"""Loopback client for ``guildhalld``, the Company HTTP service.

``spec/architecture.md`` "Company / Guildhall" freezes the access contract:

    Every endpoint, including reads, requires a per-instance bearer token loaded
    from a mode-0600 file, exact loopback Host validation, absent Origin header,
    and JSON content type for bodies. Tokens are capability-scoped
    (``facts:read``, ``questions:write``, ``directory:read``, or administrative
    issuance), compared in constant time, bound to a client-instance public key,
    rotated by the Company owner, and throttled by a serialized
    failed-authentication counter.

and:

    Every read, write, question, and answer also requires a scoped
    domain-separated request signature over method, path, body digest, monotonic
    nonce, and short expiry; answers must match the AuthorityRegistry signer.

The client uses only ``http.client`` from the standard library so the suite has
no network-stack dependency, and it can emit *deliberately malformed* requests
(missing signature, wrong Host, present Origin, non-JSON body, wildcard scope)
because those are the V-3 denial probes.
"""

from __future__ import annotations

import http.client
import json
import socket
import subprocess
import os
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import canonical, ed25519_pure
from .requirements import HarnessInvalid, ProductFailure

#: ``spec/architecture.md``: closed capability-scope set for service tokens.
TOKEN_CAPABILITIES: tuple[str, ...] = (
    "facts:read",
    "questions:write",
    "directory:read",
    "admin:issue",
)

#: ``spec/architecture.md`` HTTP API surface, section 7, completed by Validator
#: ruling C6: ``POST /v1/authority-registry``, ``POST /facts`` (aliases
#: ``/v1/facts``, ``/v1/company/facts``), ``GET|POST /questions``,
#: ``POST /answers``, ``GET /status``, ``GET /facts``.
QUESTION_PATH = "/questions"
ANSWER_PATH = "/answers"
FACTS_PATH = "/facts"
FACTS_PATH_ALIASES: tuple[str, ...] = ("/facts", "/v1/facts", "/v1/company/facts")
REGISTRY_PATH = "/v1/authority-registry"
STATUS_PATH = "/status"

#: Validator ruling C6: the closed token scope sets.
FACTS_TOKEN_SCOPES: tuple[str, ...] = ("facts:read", "questions:write")
DIRECTORY_TOKEN_SCOPES: tuple[str, ...] = ("directory:read", "admin:issue")

#: ``spec/verification.md`` "Nonfunctional proof gates": "Guildhall HTTP rejects
#: unauthenticated reads, non-loopback Host, Origin-bearing requests, and
#: non-JSON writes; all receive typed remediation-safe errors."
REJECTION_PROBES: tuple[str, ...] = (
    "unauthenticated_read",
    "non_loopback_host",
    "origin_header_present",
    "non_json_write",
)


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def json(self) -> Any:
        if not self.body:
            raise ProductFailure("empty HTTP body where JSON was required")
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProductFailure(
                f"non-JSON service body: {self.body[:400]!r}"
            ) from exc

    def assert_refused(self, *, allowed: tuple[int, ...] = (400, 401, 403, 404, 429)) -> "Response":
        if self.status not in allowed:
            raise ProductFailure(
                f"expected a typed refusal, observed HTTP {self.status}: "
                f"{self.body[:400]!r}"
            )
        return self

    def assert_bounded_body(self, limit: int = 4096) -> "Response":
        """Refusals must be bounded and indistinguishable.

        ``spec/architecture.md``: "Authentication/authorization failures return
        the same bounded body and typed refusal."
        """
        if len(self.body) > limit:
            raise ProductFailure(
                f"refusal body is {len(self.body)} bytes, above the {limit} bound"
            )
        return self


@dataclass
class ClientKey:
    """A client-instance signing key bound to a token."""

    seed: bytes

    @property
    def public(self) -> bytes:
        return ed25519_pure.public_key(self.seed)

    def sign(self, message: bytes) -> bytes:
        return ed25519_pure.sign(self.seed, message)


@dataclass
class ServiceClient:
    """Loopback HTTP client with explicit, individually defeatable controls."""

    host: str
    port: int
    token: str
    client_key: ClientKey
    authority_scopes: tuple[str, ...] = ()
    timeout: float = 30.0
    clock_offset_seconds: int = 0
    _nonce: int = field(default=0, init=False)

    # -- request signing --------------------------------------------------

    def next_nonce(self) -> str:
        self._nonce += 1
        return str(self._nonce)

    def request_signature(
        self,
        method: str,
        path: str,
        body: bytes,
        nonce: str,
        expires_at: str,
    ) -> str:
        """Domain-separated signature over method, path, body digest, nonce, expiry.

        Validator ruling C5 (R-4 stands): request signatures use message type
        ``receipt`` over ``{"method","path","body_sha256","nonce","expires_at"}``;
        the client key binds on first successful use per token.
        """
        payload = {
            "method": method,
            "path": path,
            "body_sha256": canonical.content_digest_hex(body),
            "nonce": nonce,
            "expires_at": expires_at,
        }
        digest = canonical.signing_digest("receipt", canonical.jcs(payload))
        return self.client_key.sign(digest).hex()

    # -- transport --------------------------------------------------------

    def call(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        raw_body: bytes | None = None,
        token: str | None = None,
        host_header: str | None = None,
        origin: str | None = None,
        content_type: str | None = "application/json",
        sign: bool = True,
        expires_in: int = 60,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Response:
        payload = raw_body if raw_body is not None else (
            canonical.jcs(body) if body is not None else b""
        )
        headers: dict[str, str] = {}
        effective_token = self.token if token is None else token
        if effective_token:
            headers["Authorization"] = f"Bearer {effective_token}"
        headers["Host"] = host_header or f"{self.host}:{self.port}"
        if content_type is not None:
            headers["Content-Type"] = content_type
        if origin is not None:
            headers["Origin"] = origin
        if sign:
            nonce = self.next_nonce()
            expires_at = time.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + expires_in + self.clock_offset_seconds +
                    int(os.environ.get("GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS", "0")))
            )
            headers["X-Guildhall-Nonce"] = nonce
            headers["X-Guildhall-Expires-At"] = expires_at
            headers["X-Guildhall-Client-Key"] = self.client_key.public.hex()
            headers["X-Guildhall-Signature"] = self.request_signature(
                method, path, payload, nonce, expires_at
            )
        headers.update(extra_headers or {})

        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=payload or None, headers=headers)
            raw = conn.getresponse()
            return Response(
                status=raw.status,
                headers={k.lower(): v for k, v in raw.getheaders()},
                body=raw.read(),
            )
        finally:
            conn.close()

    # -- convenience ------------------------------------------------------

    def get(self, path: str, **kwargs: Any) -> Response:
        return self.call("GET", path, **kwargs)

    def post(self, path: str, body: Any = None, **kwargs: Any) -> Response:
        return self.call("POST", path, body=body, **kwargs)


def wait_for_loopback(host: str, port: int, *, timeout: float = 30.0) -> bool:
    """Block until the service accepts a loopback connection."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def assert_loopback_only(port: int) -> None:
    """The default bind must be loopback.

    ``spec/verification.md`` "Nonfunctional proof gates": "All service/data roots
    are explicit; default bind is loopback". ``spec/cli.md`` service config:
    "bind address (loopback only in the PoC)".
    """
    reachable_externally = False
    try:
        hostname_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        hostname_ip = None
    if hostname_ip and not hostname_ip.startswith("127."):
        try:
            with socket.create_connection((hostname_ip, port), timeout=1.0):
                reachable_externally = True
        except OSError:
            reachable_externally = False
    if reachable_externally:
        raise ProductFailure(
            f"service port {port} accepted a non-loopback connection on "
            f"{hostname_ip}; spec/cli.md pins the PoC bind to loopback only"
        )


def blackhole_endpoint(port: int) -> "Blackhole":
    """A socket that accepts and never answers, for the connect-budget probe.

    ``spec/verification.md`` V-9: "Blackhole the Company endpoint; SessionStart
    remains under the two-second p95 budget while affected facts are withheld
    and loudly degraded."
    """
    return Blackhole(port)


class Blackhole:
    def __init__(self, port: int) -> None:
        self.port = port
        self._sock: socket.socket | None = None

    def __enter__(self) -> "Blackhole":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        self.port = sock.getsockname()[1]
        sock.listen(16)
        # Deliberately never accept(): a connect succeeds, a read never returns.
        self._sock = sock
        return self

    def __exit__(self, *exc: object) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


def process_capability_record(proc: subprocess.Popen, label: str) -> dict[str, Any]:
    """Collect argv, environment and descriptor metadata for one live process.

    ``spec/verification.md`` V-3: "Dump argv, environment, file-descriptor
    metadata, serialized config, errors, and child inputs for every shared
    process; the Personal-root canary must be absent."
    """
    pid = proc.pid
    record: dict[str, Any] = {"label": label, "pid": pid}
    try:
        argv = subprocess.run(
            ["ps", "-o", "command=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        record["argv"] = argv.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise HarnessInvalid(f"cannot read argv for {label}: {exc}") from exc
    try:
        env = subprocess.run(
            ["ps", "-o", "command=", "-ww", "-E", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        record["environ"] = env.stdout
    except (OSError, subprocess.SubprocessError):
        record["environ"] = ""
    try:
        fds = subprocess.run(
            ["lsof", "-p", str(pid), "-Fn"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        record["fds"] = fds.stdout
    except (OSError, subprocess.SubprocessError):
        record["fds"] = ""
    return record
