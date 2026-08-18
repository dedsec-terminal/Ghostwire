"""
ghostwire.hashing — hash functions and hash identification.

Algorithms: MD5, SHA-1, SHA-256, SHA-512, SHA3-256, CRC32, HMAC, NTLM.
Identification: guess algorithm(s) by hash length and character set.
"""

import binascii
import hashlib
import hmac as _hmac
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Hash identification — length + charset heuristics
# ---------------------------------------------------------------------------

# Map (length, charset) → list of candidate algorithm names.
# charset: 'hex' = [0-9a-f], 'hex_upper' = [0-9A-F], 'b64' = base64 chars
_HEX_LENGTHS: dict[int, list[str]] = {
    8:  ['CRC32'],
    32: ['MD5', 'NTLM', 'MD4', 'LM'],
    40: ['SHA-1', 'RIPEMD-160'],
    48: ['Tiger-192', 'MD6-192'],
    56: ['SHA-224', 'SHA3-224'],
    64: ['SHA-256', 'SHA3-256', 'BLAKE2s-256', 'Whirlpool-256'],
    96: ['SHA-384', 'SHA3-384'],
    128: ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool'],
}

_B64_LENGTHS: dict[int, list[str]] = {
    24: ['MD5 (Base64)'],
    28: ['SHA-1 (Base64)'],
    44: ['SHA-256 (Base64)'],
    88: ['SHA-512 (Base64)'],
}


def identify_hash(hash_str: str) -> list[str]:
    """
    Return a list of candidate algorithm names for hash_str.
    Checks hex (lower/upper), base64, and special patterns.
    """
    s = hash_str.strip()
    length = len(s)
    candidates = []

    is_hex = all(c in '0123456789abcdefABCDEF' for c in s)
    is_b64 = all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in s)

    if is_hex and length in _HEX_LENGTHS:
        candidates.extend(_HEX_LENGTHS[length])

    if is_b64 and not is_hex and length in _B64_LENGTHS:
        candidates.extend(_B64_LENGTHS[length])

    # NT hash pattern: 32 hex uppercase
    if is_hex and length == 32 and s == s.upper() and 'NTLM' not in candidates:
        candidates.append('NTLM (uppercase)')

    # bcrypt
    if s.startswith('$2') and len(s) == 60:
        candidates = ['bcrypt']

    # sha512crypt
    if s.startswith('$6$'):
        candidates = ['sha512crypt']

    if not candidates:
        candidates.append(f'Unknown — length {length}, charset {"hex" if is_hex else "base64" if is_b64 else "other"}')

    return candidates


# ---------------------------------------------------------------------------
# CRC32
# ---------------------------------------------------------------------------

def crc32(data: bytes) -> str:
    value = binascii.crc32(data) & 0xFFFFFFFF
    return f"{value:08x}"


# ---------------------------------------------------------------------------
# NTLM (NT hash) — MD4 of UTF-16LE
# ---------------------------------------------------------------------------

def _md4(data: bytes) -> bytes:
    """Pure-Python MD4 implementation (RFC 1320)."""
    import struct

    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z

    msg = bytearray(data)
    orig_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[i:i + 64]))
        a, b, c, d = a0, b0, c0, d0

        for j, (k, s) in enumerate([(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),
                                     (8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19)]):
            a = _left_rotate((a + _f(b, c, d) + X[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        for k, s in [(0,3),(4,7),(8,11),(12,15),(1,3),(5,7),(9,11),(13,15),
                     (2,3),(6,7),(10,11),(14,15),(3,3),(7,7),(11,11),(15,15)]:
            a = _left_rotate((a + _g(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        for k, s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
                     (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            a = _left_rotate((a + _h(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack('<4I', a0, b0, c0, d0)


def ntlm_hash(plaintext: str) -> str:
    """Compute NT hash (NTLM) = MD4(UTF-16LE(password))."""
    return _md4(plaintext.encode('utf-16-le')).hex()


# ---------------------------------------------------------------------------
# Core hash dispatcher
# ---------------------------------------------------------------------------

def hash_text(algorithm: str, data: bytes, hmac_key: Optional[str] = None) -> str:
    algorithm = algorithm.lower()
    if algorithm == 'crc32':
        return crc32(data)
    if algorithm == 'ntlm':
        # NTLM takes the text decoded as UTF-8 then re-encodes to UTF-16LE
        return ntlm_hash(data.decode('utf-8', errors='replace'))
    if hmac_key is not None:
        key = hmac_key.encode()
        algo_name = algorithm if algorithm != 'sha3-256' else 'sha3_256'
        h = _hmac.new(key, data, algo_name)
        return h.hexdigest()
    algo_map = {
        'md5': 'md5', 'sha1': 'sha1', 'sha256': 'sha256',
        'sha512': 'sha512', 'sha3-256': 'sha3_256',
    }
    if algorithm not in algo_map:
        sys.exit(f"error: unknown hash algorithm '{algorithm}'")
    return hashlib.new(algo_map[algorithm], data).hexdigest()
