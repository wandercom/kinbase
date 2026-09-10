"""Hermetic authenticated encryption for the Tester canary vault.

``spec/threat-model.md`` "Canary and auxiliary-corpus custody" requires:

    The canary registry is a Tester-custodied encrypted file in that vault. It
    maps an opaque canary ID to raw value, transformation family, planted
    surfaces, expected destination denial, and gold atom/destination labels. The
    manifest binds its ciphertext digest and schema/count metadata without its
    key or plaintext.

ChaCha20 (RFC 8439) followed by HMAC-SHA256 encrypt-then-MAC, implemented here
so the vault works with no third-party dependency and no network access.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

_SIGMA = b"expand 32-byte k"


def _quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    m = 0xFFFFFFFF
    state[a] = (state[a] + state[b]) & m
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & m
    state[c] = (state[c] + state[d]) & m
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & m
    state[a] = (state[a] + state[b]) & m
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & m
    state[c] = (state[c] + state[d]) & m
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & m


def _block(key: bytes, counter: int, nonce: bytes) -> bytes:
    init = list(struct.unpack("<4I", _SIGMA))
    init += list(struct.unpack("<8I", key))
    init += [counter]
    init += list(struct.unpack("<3I", nonce))
    working = list(init)
    for _ in range(10):
        _quarter(working, 0, 4, 8, 12)
        _quarter(working, 1, 5, 9, 13)
        _quarter(working, 2, 6, 10, 14)
        _quarter(working, 3, 7, 11, 15)
        _quarter(working, 0, 5, 10, 15)
        _quarter(working, 1, 6, 11, 12)
        _quarter(working, 2, 7, 8, 13)
        _quarter(working, 3, 4, 9, 14)
    out = [(working[i] + init[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20 needs a 32-byte key and 12-byte nonce")
    out = bytearray()
    for offset in range(0, len(data), 64):
        stream = _block(key, counter + offset // 64, nonce)
        chunk = data[offset : offset + 64]
        out.extend(bytes(a ^ b for a, b in zip(chunk, stream)))
    return bytes(out)


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    enc = hashlib.sha256(b"kinbase-acceptance-vault/enc\x00" + key).digest()
    mac = hashlib.sha256(b"kinbase-acceptance-vault/mac\x00" + key).digest()
    return enc, mac


def seal(key: bytes, plaintext: bytes, associated: bytes = b"") -> bytes:
    """nonce(12) || ciphertext || tag(32), encrypt-then-MAC."""
    enc_key, mac_key = _subkeys(key)
    nonce = os.urandom(12)
    ciphertext = chacha20(enc_key, nonce, plaintext)
    tag = hmac.new(
        mac_key,
        b"kinbase-acceptance-vault/1"
        + struct.pack("<Q", len(associated))
        + associated
        + nonce
        + ciphertext,
        hashlib.sha256,
    ).digest()
    return nonce + ciphertext + tag


def unseal(key: bytes, blob: bytes, associated: bytes = b"") -> bytes:
    if len(blob) < 44:
        raise ValueError("sealed blob is truncated")
    enc_key, mac_key = _subkeys(key)
    nonce, ciphertext, tag = blob[:12], blob[12:-32], blob[-32:]
    expected = hmac.new(
        mac_key,
        b"kinbase-acceptance-vault/1"
        + struct.pack("<Q", len(associated))
        + associated
        + nonce
        + ciphertext,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("vault authentication failed")
    return chacha20(enc_key, nonce, ciphertext)


def keyed_hmac(key: bytes, value: bytes) -> str:
    """Keyed HMAC used in permanent evidence rows.

    ``spec/verification.md`` "Evidence packet": "Permanent failure rows contain
    canary ID, keyed-HMAC match, detector/encoding class, destination/location
    digest, offset, and times---not the canary or leaked bytes."
    """
    return hmac.new(key, value, hashlib.sha256).hexdigest()
