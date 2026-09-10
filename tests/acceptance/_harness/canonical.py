"""RFC 8785 canonical bytes and ``kinbase-sig/1`` domain separation.

``spec/architecture.md`` section 3 "Canonical data model" freezes:

    All durable messages use RFC 8785 JSON Canonicalization Scheme bytes after
    NFC normalization, with duplicate keys and non-finite numbers rejected and
    integers bounded to the interoperable +/-(2^53-1) range.

and:

    Every signer signs ``SHA-256("kinbase-sig/1" || 0x00 || message_type ||
    0x00 || jcs_bytes)`` where ``message_type`` is one closed enum.

The instrument implements both independently of the product so cross-domain
reuse, parser-differential and digest-substitution probes (``spec/threat-model.md``
attack family 12) are driven by bytes the product did not produce.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from typing import Any

#: Closed ``message_type`` enum, ``spec/architecture.md`` section 3.
MESSAGE_TYPES: tuple[str, ...] = (
    "fact-event",
    "unknown-event",
    "manifest",
    "approval-token",
    "repo-certificate",
    "authority-registry-entry",
    "rotation",
    "revocation",
    "tombstone",
    "question",
    "answer",
    "receipt",
)

SIG_DOMAIN = b"kinbase-sig/1"

#: ``spec/architecture.md`` section 3: integers bounded to +/-(2^53-1).
INT_MAX = 2**53 - 1
INT_MIN = -(2**53 - 1)

#: ``spec/architecture.md`` section 3 forbids these in human-readable text
#: fields "before signature verification".
FORBIDDEN_BIDI = (
    "؜",
    "‎",
    "‏",
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
)

_C0 = {chr(c) for c in range(0x00, 0x20)}
_C1 = {chr(c) for c in range(0x7F, 0xA0)}


def is_noncharacter(ch: str) -> bool:
    cp = ord(ch)
    if 0xFDD0 <= cp <= 0xFDEF:
        return True
    return (cp & 0xFFFE) == 0xFFFE


def rejects_control_text(value: str) -> list[str]:
    """Return the forbidden code points present in a human-readable field."""
    found: list[str] = []
    for ch in value:
        if ch in _C0 or ch in _C1 or ch in FORBIDDEN_BIDI or is_noncharacter(ch):
            found.append(f"U+{ord(ch):04X}")
    return found


class CanonicalisationError(ValueError):
    pass


def _check_scalars(node: Any) -> None:
    if isinstance(node, dict):
        seen: set[str] = set()
        for key in node:
            if not isinstance(key, str):
                raise CanonicalisationError("object keys must be strings")
            nk = unicodedata.normalize("NFC", key)
            if nk in seen:
                raise CanonicalisationError(f"duplicate key after NFC: {key!r}")
            seen.add(nk)
            _check_scalars(node[key])
    elif isinstance(node, (list, tuple)):
        for item in node:
            _check_scalars(item)
    elif isinstance(node, bool) or node is None or isinstance(node, str):
        return
    elif isinstance(node, int):
        if not (INT_MIN <= node <= INT_MAX):
            raise CanonicalisationError(
                f"integer {node} outside the interoperable +/-(2^53-1) range"
            )
    elif isinstance(node, float):
        if not math.isfinite(node):
            raise CanonicalisationError("non-finite numbers are rejected")
        raise CanonicalisationError(
            "spec/architecture.md section 3: 'No binary floats enter a signed event.'"
        )
    else:
        raise CanonicalisationError(f"unsupported node type {type(node)!r}")


def _nfc(node: Any) -> Any:
    if isinstance(node, str):
        return unicodedata.normalize("NFC", node)
    if isinstance(node, dict):
        return {unicodedata.normalize("NFC", k): _nfc(v) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [_nfc(v) for v in node]
    return node


def jcs(value: Any) -> bytes:
    """RFC 8785 canonical JSON bytes after NFC normalisation."""
    _check_scalars(value)
    normalised = _nfc(value)
    return json.dumps(
        normalised,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def signing_digest(message_type: str, jcs_bytes: bytes) -> bytes:
    """``SHA-256("kinbase-sig/1" || 0x00 || message_type || 0x00 || jcs_bytes)``."""
    if message_type not in MESSAGE_TYPES:
        raise CanonicalisationError(
            f"{message_type!r} is not in the closed message_type enum"
        )
    return hashlib.sha256(
        SIG_DOMAIN + b"\x00" + message_type.encode("ascii") + b"\x00" + jcs_bytes
    ).digest()


def content_digest_hex(jcs_bytes: bytes) -> str:
    return hashlib.sha256(jcs_bytes).hexdigest()


#: ``spec/architecture.md`` section 3: "Times are RFC 3339 UTC strings with
#: exactly millisecond precision and a ``Z`` suffix".
RFC3339_MS = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


def is_rfc3339_ms(value: str) -> bool:
    return bool(RFC3339_MS.match(value))


def event_shard_path(digest_hex: str) -> str:
    """``.kin/events/<hex-0:2>/<hex-2:4>/<remaining-60-hex>.json``.

    ``spec/architecture.md`` "Codebase": paths are "constructed only from a
    computed lowercase ASCII SHA-256 digest with fixed sharded length".
    """
    if len(digest_hex) != 64 or digest_hex != digest_hex.lower():
        raise CanonicalisationError("expected 64 lowercase hex characters")
    if any(c not in "0123456789abcdef" for c in digest_hex):
        raise CanonicalisationError("non-hex character in digest path")
    return f"{digest_hex[0:2]}/{digest_hex[2:4]}/{digest_hex[4:]}.json"
