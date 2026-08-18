"""
ghostwire.web_ctf — web and CTF-specific operations.

JWT decode (header/payload inspection, no signature verification).
Gzip/zlib decompression (magic-byte detection).
"""

import base64
import gzip
import json
import sys
import zlib
from typing import Optional


# ---------------------------------------------------------------------------
# JWT decode
# ---------------------------------------------------------------------------

def _b64url_decode_segment(segment: str) -> bytes:
    """Decode a base64url segment, adding padding as needed."""
    segment = segment.strip()
    # Normalise: replace URL-safe chars, add padding
    segment = segment.replace('-', '+').replace('_', '/')
    padding = (4 - len(segment) % 4) % 4
    segment += '=' * padding
    return base64.b64decode(segment)


def jwt_decode(token: str) -> dict:
    """
    Split a JWT into header, payload, signature.
    Decode header and payload as JSON; return a dict with all three.
    Does NOT verify the signature — inspection only.
    """
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError(f"Expected 3 dot-separated parts, got {len(parts)}")

    try:
        header_bytes = _b64url_decode_segment(parts[0])
        header = json.loads(header_bytes)
    except Exception as e:
        header = {'_raw': parts[0], '_error': str(e)}

    try:
        payload_bytes = _b64url_decode_segment(parts[1])
        payload = json.loads(payload_bytes)
    except Exception as e:
        payload = {'_raw': parts[1], '_error': str(e)}

    return {
        'header':    header,
        'payload':   payload,
        'signature': parts[2],  # raw base64url, not decoded
    }


def jwt_decode_pretty(token: str) -> str:
    """Human-readable JWT decode output."""
    result = jwt_decode(token)
    lines = []
    lines.append('--- HEADER ---')
    lines.append(json.dumps(result['header'], indent=2))
    lines.append('--- PAYLOAD ---')
    lines.append(json.dumps(result['payload'], indent=2))
    lines.append('--- SIGNATURE (raw, not verified) ---')
    lines.append(result['signature'])
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Gzip / Zlib decompression
# ---------------------------------------------------------------------------

_GZIP_MAGIC = b'\x1f\x8b'
_ZLIB_MAGIC_PREFIXES = {b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e'}


def decompress_auto(data: bytes) -> bytes:
    """
    Detect gzip or zlib magic bytes and decompress accordingly.
    Raises ValueError if neither magic is found.
    """
    if data[:2] == _GZIP_MAGIC:
        return gzip.decompress(data)
    if data[:2] in _ZLIB_MAGIC_PREFIXES:
        return zlib.decompress(data)
    # Try both anyway before giving up
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    try:
        return zlib.decompress(data)
    except Exception:
        pass
    raise ValueError("Data does not appear to be gzip or zlib compressed")


def decompress_hex(hex_input: str) -> str:
    """Decompress hex-encoded gzip/zlib data; return UTF-8 text."""
    raw = bytes.fromhex(hex_input.strip().replace(' ', ''))
    return decompress_auto(raw).decode('utf-8', errors='replace')


def decompress_b64(b64_input: str) -> str:
    """Decompress base64-encoded gzip/zlib data; return UTF-8 text."""
    b64 = b64_input.strip()
    padding = (4 - len(b64) % 4) % 4
    b64 += '=' * padding
    raw = base64.b64decode(b64)
    return decompress_auto(raw).decode('utf-8', errors='replace')


def compress_gzip(data: str) -> str:
    """Compress text with gzip; return hex-encoded bytes."""
    return gzip.compress(data.encode('utf-8')).hex()


def compress_zlib(data: str) -> str:
    """Compress text with zlib; return hex-encoded bytes."""
    return zlib.compress(data.encode('utf-8')).hex()
