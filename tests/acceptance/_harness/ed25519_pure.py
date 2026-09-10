"""Self-contained Ed25519 (RFC 8032) for acceptance test keys.

``spec/architecture.md`` "Trust and key lifecycle" states: "The PoC uses Ed25519
keys and one externally configured Company root" and "Test runs use fictional
principals and generated keys."

The suite carries its own implementation so that:

* it runs with no network access, which ``spec/verification.md`` "Nonfunctional
  proof gates" requires of the full test suite;
* the signature bytes the instrument produces are independent of whatever
  library the product links, which keeps the signature/parser-differential
  probes in ``spec/threat-model.md`` attack family 12 genuinely independent.

``test_harness_selftest.py`` cross-checks this implementation against RFC 8032
test vectors and, when ``cryptography`` is installed, against that library.
"""

from __future__ import annotations

import hashlib
import os

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _x_recover(_BY)
_B = (_BX % _P, _BY % _P, 1, _BX * _BY % _P)


def _edwards_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _edwards_double(p: tuple[int, int, int, int]):
    return _edwards_add(p, p)


def _scalarmult(p: tuple[int, int, int, int], e: int):
    if e == 0:
        return (0, 1, 1, 0)
    q = _scalarmult(p, e // 2)
    q = _edwards_double(q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


def _encode_point(p: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return ((y & ~(1 << 255)) | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(data: bytes):
    value = int.from_bytes(data, "little")
    y = value & ((1 << 255) - 1)
    sign = value >> 255
    x = _x_recover(y)
    if x & 1 != sign:
        x = _P - x
    point = (x, y, 1, x * y % _P)
    if not _is_on_curve(point):
        raise ValueError("point is not on the curve")
    return point


def _is_on_curve(p: tuple[int, int, int, int]) -> bool:
    x, y, z, t = p
    return (
        (-x * x + y * y - z * z - _D * t * t) % _P == 0
        and x * y % _P == z * t % _P
    )


def _clamp(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def generate_seed() -> bytes:
    """32 random bytes. Test keys only; never a product key."""
    return os.urandom(32)


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _sha512(seed)
    a = _clamp(h)
    return _encode_point(_scalarmult(_B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _sha512(seed)
    a = _clamp(h)
    prefix = h[32:]
    pub = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    big_r = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(big_r + pub + message), "little") % _L
    s = (r + k * a) % _L
    return big_r + s.to_bytes(32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(pub) != 32:
        return False
    try:
        big_r = _decode_point(signature[:32])
        point_a = _decode_point(pub)
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(signature[:32] + pub + message), "little") % _L
    left = _scalarmult(_B, s)
    right = _edwards_add(big_r, _scalarmult(point_a, k))
    lx, ly, lz, _ = left
    rx, ry, rz, _ = right
    return (lx * rz - rx * lz) % _P == 0 and (ly * rz - ry * lz) % _P == 0
