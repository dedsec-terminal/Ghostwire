"""
ghostwire.cipher_lab — classical ciphers, brute-force recovery, frequency analysis.

Ciphers: Caesar, Vigenère, XOR, Atbash, Rail Fence, Playfair, Baconian, RC4.
Recovery: Caesar brute-force, single-byte XOR brute-force, character frequency analysis.
"""

import sys
from collections import Counter
from typing import Optional

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

ENGLISH_FREQ = 'etaoinsrhdlucmfywgpbvkxjqz'
PRINTABLE_ASCII = set(range(32, 127))


def score_english(text: str) -> float:
    """Score text by English letter frequency match."""
    text_lower = text.lower()
    total = sum(1 for c in text_lower if c.isalpha())
    if total == 0:
        return 0.0
    freq_weights = {ch: (26 - i) for i, ch in enumerate(ENGLISH_FREQ)}
    freq_score = sum(freq_weights.get(c, 0) for c in text_lower)
    printable_ratio = sum(1 for c in text if ord(c) in PRINTABLE_ASCII) / max(len(text), 1)
    return (freq_score / total) * printable_ratio


# ---------------------------------------------------------------------------
# Caesar
# ---------------------------------------------------------------------------

def _rot_alpha(data: str, n: int) -> str:
    n = n % 26
    result = []
    for ch in data:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + n) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def caesar_encode(data: str, shift: int) -> str:
    return _rot_alpha(data, shift)


def caesar_decode(data: str, shift: int) -> str:
    return _rot_alpha(data, -shift)


# ---------------------------------------------------------------------------
# Vigenère
# ---------------------------------------------------------------------------

def vigenere_encode(data: str, key: str) -> str:
    key = key.upper()
    if not key:
        raise ValueError("Key must not be empty")
    result = []
    ki = 0
    for ch in data:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            ki += 1
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_decode(data: str, key: str) -> str:
    key = key.upper()
    if not key:
        raise ValueError("Key must not be empty")
    result = []
    ki = 0
    for ch in data:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            ki += 1
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


# ---------------------------------------------------------------------------
# XOR
# ---------------------------------------------------------------------------

def xor_encode(data: str, key: str) -> str:
    """XOR plaintext with multi-byte key; returns hex-encoded ciphertext."""
    key_bytes = key.encode()
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data.encode()))
    return result.hex()


def xor_decode(data: str, key: str) -> str:
    """XOR hex ciphertext with multi-byte key; returns plaintext."""
    raw = bytes.fromhex(data.strip())
    key_bytes = key.encode()
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return result.decode(errors='replace')


# ---------------------------------------------------------------------------
# Atbash
# ---------------------------------------------------------------------------

def atbash_encode(data: str) -> str:
    result = []
    for ch in data:
        if 'a' <= ch <= 'z':
            result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        elif 'A' <= ch <= 'Z':
            result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        else:
            result.append(ch)
    return ''.join(result)


def atbash_decode(data: str) -> str:
    return atbash_encode(data)


# ---------------------------------------------------------------------------
# Rail Fence cipher
# ---------------------------------------------------------------------------

def rail_fence_encode(data: str, rails: int) -> str:
    """Rail fence (zig-zag) cipher encode."""
    if rails < 2:
        return data
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for ch in data:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return ''.join(''.join(r) for r in fence)


def rail_fence_decode(data: str, rails: int) -> str:
    """Rail fence (zig-zag) cipher decode."""
    if rails < 2:
        return data
    n = len(data)
    # Compute which position belongs to which rail
    pattern = []
    rail = 0
    direction = 1
    for i in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    indices = sorted(range(n), key=lambda i: pattern[i])
    result = [''] * n
    for pos, ch in zip(indices, data):
        result[pos] = ch
    return ''.join(result)


# ---------------------------------------------------------------------------
# Playfair cipher
# ---------------------------------------------------------------------------

def _playfair_keysquare(key: str) -> list[str]:
    """Build 5×5 Playfair key square (I/J merged)."""
    key = key.upper().replace('J', 'I')
    seen = set()
    square = []
    for ch in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            square.append(ch)
    return square


def _playfair_pos(square: list[str], ch: str) -> tuple[int, int]:
    idx = square.index(ch)
    return idx // 5, idx % 5


def _playfair_process(data: str, square: list[str], encode: bool) -> str:
    # Prepare bigrams
    data = data.upper().replace('J', 'I').replace(' ', '')
    data = ''.join(c for c in data if c.isalpha())
    pairs = []
    i = 0
    while i < len(data):
        a = data[i]
        if i + 1 < len(data):
            b = data[i + 1]
        else:
            b = 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2

    result = []
    shift = 1 if encode else -1
    for a, b in pairs:
        ra, ca = _playfair_pos(square, a)
        rb, cb = _playfair_pos(square, b)
        if ra == rb:
            result.append(square[ra * 5 + (ca + shift) % 5])
            result.append(square[rb * 5 + (cb + shift) % 5])
        elif ca == cb:
            result.append(square[((ra + shift) % 5) * 5 + ca])
            result.append(square[((rb + shift) % 5) * 5 + cb])
        else:
            result.append(square[ra * 5 + cb])
            result.append(square[rb * 5 + ca])
    return ''.join(result)


def playfair_encode(data: str, key: str) -> str:
    square = _playfair_keysquare(key)
    return _playfair_process(data, square, encode=True)


def playfair_decode(data: str, key: str) -> str:
    square = _playfair_keysquare(key)
    return _playfair_process(data, square, encode=False)


# ---------------------------------------------------------------------------
# Baconian cipher (Francis Bacon's biliteral cipher)
# A=AAAAA … Z=BBBBB, uses A and B (or 0/1)
# ---------------------------------------------------------------------------

_BACON_TABLE = {
    'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
    'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAA',
    'K': 'ABAAB', 'L': 'ABABA', 'M': 'ABABB', 'N': 'ABBAA', 'O': 'ABBAB',
    'P': 'ABBBA', 'Q': 'ABBBB', 'R': 'BAAAA', 'S': 'BAAAB', 'T': 'BAABA',
    'U': 'BAABB', 'V': 'BABAA', 'W': 'BABAB', 'X': 'BABBA', 'Y': 'BABBB',
    'Z': 'BAAAA',
}
_BACON_REVERSE = {v: k for k, v in _BACON_TABLE.items() if k not in ('J', 'Z')}


def baconian_encode(data: str) -> str:
    result = []
    for ch in data.upper():
        if ch in _BACON_TABLE:
            result.append(_BACON_TABLE[ch])
        elif ch == ' ':
            result.append(' ')
    return ' '.join(result).strip()


def baconian_decode(data: str) -> str:
    # Normalize: accept A/B or 0/1
    data = data.upper().replace('0', 'A').replace('1', 'B')
    result = []
    # Split on spaces but treat double-space as word separator
    tokens = data.strip().split()
    for tok in tokens:
        if tok in _BACON_REVERSE:
            result.append(_BACON_REVERSE[tok])
        elif tok in _BACON_TABLE:
            result.append(tok)  # shouldn't happen
        else:
            result.append('?')
    return ''.join(result)


# ---------------------------------------------------------------------------
# RC4
# ---------------------------------------------------------------------------

def _rc4_keystream(key: bytes, length: int) -> bytes:
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    keystream = []
    i = j = 0
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def rc4_encode(data: str, key: str) -> str:
    """RC4 encrypt plaintext; returns hex-encoded ciphertext."""
    plaintext = data.encode('utf-8')
    ks = _rc4_keystream(key.encode('utf-8'), len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, ks)).hex()


def rc4_decode(data: str, key: str) -> str:
    """RC4 decrypt hex ciphertext; returns plaintext."""
    raw = bytes.fromhex(data.strip())
    ks = _rc4_keystream(key.encode('utf-8'), len(raw))
    return bytes(a ^ b for a, b in zip(raw, ks)).decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
# Cipher recovery
# ---------------------------------------------------------------------------

def caesar_bruteforce(ciphertext: str) -> list:
    """Return [(shift, plaintext, score)] for all 25 shifts, sorted by score."""
    results = []
    for shift in range(1, 26):
        plaintext = caesar_decode(ciphertext, shift)
        results.append((shift, plaintext, score_english(plaintext)))
    results.sort(key=lambda x: x[2], reverse=True)
    return results


def xor_single_byte_bruteforce(hex_ciphertext: str) -> list:
    """
    Try all 256 single-byte XOR keys.
    Returns [(key_byte, key_char, plaintext, score)], sorted by score desc.
    """
    try:
        raw = bytes.fromhex(hex_ciphertext.strip())
    except ValueError:
        sys.exit("error: input must be hex-encoded ciphertext for xor-brute")
    results = []
    for key_byte in range(256):
        decrypted = bytes(b ^ key_byte for b in raw)
        plaintext = decrypted.decode('utf-8', errors='replace')
        score = score_english(plaintext)
        results.append((key_byte, chr(key_byte) if 32 <= key_byte < 127 else '.', plaintext, score))
    results.sort(key=lambda x: x[3], reverse=True)
    return results


def frequency_analysis(text: str) -> list:
    """Return [(char, count, pct)] for printable characters, sorted by count desc."""
    filtered = [c for c in text if c.isprintable()]
    total = len(filtered)
    if total == 0:
        return []
    counts = Counter(filtered)
    return [(ch, count, 100.0 * count / total)
            for ch, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)]
