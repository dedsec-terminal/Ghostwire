"""
ghostwire.encode_decode — encoding and decoding functions.

Schemes: Base64 (standard + URL-safe), Base32, Base58, Base85/ASCII85,
         Hex, URL, HTML entities, Binary, Morse, ROT-N, ROT47,
         Uuencode, Quoted-Printable, Punycode, Leetspeak, NATO phonetic.
"""

import base64
import binascii
import html
import quopri
import sys
import urllib.parse
from typing import Optional

# ---------------------------------------------------------------------------
# Morse
# ---------------------------------------------------------------------------

MORSE_TABLE = {
    'A': '.-',   'B': '-...', 'C': '-.-.', 'D': '-..',  'E': '.',
    'F': '..-.', 'G': '--.',  'H': '....', 'I': '..',   'J': '.---',
    'K': '-.-',  'L': '.-..', 'M': '--',   'N': '-.',   'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.',  'S': '...',  'T': '-',
    'U': '..-',  'V': '...-', 'W': '.--',  'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.',
    '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
    '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
    '$': '...-..-', '@': '.--.-.', ' ': '/',
}
MORSE_REVERSE = {v: k for k, v in MORSE_TABLE.items()}

# ---------------------------------------------------------------------------
# NATO phonetic alphabet
# ---------------------------------------------------------------------------

NATO_TABLE = {
    'A': 'Alpha',   'B': 'Bravo',   'C': 'Charlie', 'D': 'Delta',
    'E': 'Echo',    'F': 'Foxtrot', 'G': 'Golf',    'H': 'Hotel',
    'I': 'India',   'J': 'Juliet',  'K': 'Kilo',    'L': 'Lima',
    'M': 'Mike',    'N': 'November','O': 'Oscar',   'P': 'Papa',
    'Q': 'Quebec',  'R': 'Romeo',   'S': 'Sierra',  'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor',  'W': 'Whiskey', 'X': 'X-ray',
    'Y': 'Yankee',  'Z': 'Zulu',
    '0': 'Zero',    '1': 'One',     '2': 'Two',     '3': 'Three',
    '4': 'Four',    '5': 'Five',    '6': 'Six',     '7': 'Seven',
    '8': 'Eight',   '9': 'Nine',
}
NATO_REVERSE = {v.lower(): k for k, v in NATO_TABLE.items()}

# ---------------------------------------------------------------------------
# Leetspeak
# ---------------------------------------------------------------------------

LEET_ENCODE_MAP = {
    'a': '4', 'e': '3', 'g': '9', 'i': '1', 'l': '1',
    'o': '0', 's': '5', 't': '7', 'b': '8', 'z': '2',
}
LEET_DECODE_MAP = {v: k for k, v in LEET_ENCODE_MAP.items()}

# ---------------------------------------------------------------------------
# Base58 (Bitcoin alphabet)
# ---------------------------------------------------------------------------

BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def encode_base58(data: str) -> str:
    payload = data.encode('utf-8')
    n = int.from_bytes(payload, 'big')
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(BASE58_ALPHABET[remainder:remainder + 1].decode())
    # Leading zero bytes become '1'
    leading = len(payload) - len(payload.lstrip(b'\x00'))
    return '1' * leading + ''.join(reversed(result))


def decode_base58(data: str) -> str:
    data = data.strip()
    alphabet = BASE58_ALPHABET.decode()
    n = 0
    for ch in data:
        if ch not in alphabet:
            raise ValueError(f"Invalid Base58 character: {ch!r}")
        n = n * 58 + alphabet.index(ch)
    # Determine byte length
    byte_count = (n.bit_length() + 7) // 8
    result = n.to_bytes(byte_count, 'big') if n > 0 else b''
    leading = len(data) - len(data.lstrip('1'))
    return (b'\x00' * leading + result).decode('utf-8')


# ---------------------------------------------------------------------------
# Base85 / ASCII85
# ---------------------------------------------------------------------------

def encode_base85(data: str) -> str:
    return base64.b85encode(data.encode()).decode()


def decode_base85(data: str) -> str:
    return base64.b85decode(data.strip().encode()).decode()


def encode_ascii85(data: str) -> str:
    return base64.a85encode(data.encode(), adobe=False).decode()


def decode_ascii85(data: str) -> str:
    return base64.a85decode(data.strip().encode(), adobe=False).decode()


# ---------------------------------------------------------------------------
# Uuencode / Uudecode
# ---------------------------------------------------------------------------

def encode_uuencode(data: str, name: str = 'file') -> str:
    payload = data.encode('utf-8')
    # binascii.b2a_uu works line by line (max 45 bytes per chunk)
    lines = [b'begin 644 ' + name.encode() + b'\n']
    for i in range(0, len(payload), 45):
        lines.append(binascii.b2a_uu(payload[i:i + 45]))
    lines.append(b'`\n')
    lines.append(b'end\n')
    return b''.join(lines).decode('ascii')


def decode_uuencode(data: str) -> str:
    lines = data.strip().splitlines()
    payload_lines = []
    in_body = False
    for line in lines:
        if line.startswith('begin '):
            in_body = True
            continue
        if line in ('end', '`') or line.startswith('end'):
            break
        if in_body and line:
            payload_lines.append(line)
    result = b''
    for line in payload_lines:
        if line == '`':
            break
        result += binascii.a2b_uu(line)
    return result.decode('utf-8')


# ---------------------------------------------------------------------------
# Quoted-Printable
# ---------------------------------------------------------------------------

def encode_qp(data: str) -> str:
    return quopri.encodestring(data.encode(), quotetabs=True).decode('ascii')


def decode_qp(data: str) -> str:
    return quopri.decodestring(data.encode()).decode('utf-8')


# ---------------------------------------------------------------------------
# Punycode
# ---------------------------------------------------------------------------

def encode_punycode(data: str) -> str:
    """Encode a domain name (or label) to its Punycode / ACE form."""
    # encodings.idna works on full domain names
    try:
        return data.encode('idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError):
        # Fall back to raw punycode label encoding
        return data.encode('punycode').decode('ascii')


def decode_punycode(data: str) -> str:
    data = data.strip()
    try:
        return data.encode('ascii').decode('idna')
    except (UnicodeError, UnicodeDecodeError):
        return data.encode('ascii').decode('punycode')


# ---------------------------------------------------------------------------
# Existing schemes
# ---------------------------------------------------------------------------

def encode_base64(data: str, urlsafe: bool = False) -> str:
    b = data.encode()
    if urlsafe:
        return base64.urlsafe_b64encode(b).decode()
    return base64.b64encode(b).decode()


def decode_base64(data: str, urlsafe: bool = False) -> str:
    data = data.strip()
    padding = (4 - len(data) % 4) % 4
    data += '=' * padding
    if urlsafe:
        return base64.urlsafe_b64decode(data).decode()
    return base64.b64decode(data).decode()


def encode_base32(data: str) -> str:
    return base64.b32encode(data.encode()).decode()


def decode_base32(data: str) -> str:
    data = data.strip().upper()
    padding = (8 - len(data) % 8) % 8
    data += '=' * padding
    return base64.b32decode(data).decode()


def encode_hex(data: str) -> str:
    return data.encode().hex()


def decode_hex(data: str) -> str:
    data = data.strip().replace(' ', '').replace('0x', '')
    return bytes.fromhex(data).decode()


def encode_url(data: str) -> str:
    return urllib.parse.quote(data, safe='')


def decode_url(data: str) -> str:
    return urllib.parse.unquote(data)


def encode_html(data: str) -> str:
    return html.escape(data)


def decode_html(data: str) -> str:
    return html.unescape(data)


def encode_binary(data: str) -> str:
    return ' '.join(f'{byte:08b}' for byte in data.encode())


def decode_binary(data: str) -> str:
    groups = data.strip().split()
    return bytes(int(g, 2) for g in groups).decode()


def encode_morse(data: str) -> str:
    result = []
    for ch in data.upper():
        result.append(MORSE_TABLE.get(ch, '?'))
    return ' '.join(result)


def decode_morse(data: str) -> str:
    result = []
    for token in data.strip().split(' '):
        if token == '/':
            result.append(' ')
        elif token in MORSE_REVERSE:
            result.append(MORSE_REVERSE[token])
        else:
            result.append('?')
    return ''.join(result)


def encode_rot(data: str, n: int) -> str:
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


def decode_rot(data: str, n: int) -> str:
    return encode_rot(data, -n)


def encode_rot47(data: str) -> str:
    """ROT47: rotate printable ASCII characters 33–126 by 47."""
    result = []
    for ch in data:
        o = ord(ch)
        if 33 <= o <= 126:
            result.append(chr((o - 33 + 47) % 94 + 33))
        else:
            result.append(ch)
    return ''.join(result)


def decode_rot47(data: str) -> str:
    # ROT47 is its own inverse
    return encode_rot47(data)


# ---------------------------------------------------------------------------
# NATO phonetic
# ---------------------------------------------------------------------------

def encode_nato(data: str) -> str:
    result = []
    for ch in data.upper():
        if ch in NATO_TABLE:
            result.append(NATO_TABLE[ch])
        elif ch == ' ':
            result.append('[space]')
        else:
            result.append(f'[{ch}]')
    return ' '.join(result)


def decode_nato(data: str) -> str:
    tokens = data.strip().split()
    result = []
    for tok in tokens:
        lower = tok.lower().strip('[]')
        if lower == 'space':
            result.append(' ')
        elif lower in NATO_REVERSE:
            result.append(NATO_REVERSE[lower])
        elif tok.startswith('[') and tok.endswith(']'):
            result.append(tok[1:-1])
        else:
            result.append('?')
    return ''.join(result)


# ---------------------------------------------------------------------------
# Leetspeak
# ---------------------------------------------------------------------------

def encode_leet(data: str) -> str:
    result = []
    for ch in data.lower():
        result.append(LEET_ENCODE_MAP.get(ch, ch))
    return ''.join(result)


def decode_leet(data: str) -> str:
    result = []
    for ch in data:
        result.append(LEET_DECODE_MAP.get(ch, ch))
    return ''.join(result)
