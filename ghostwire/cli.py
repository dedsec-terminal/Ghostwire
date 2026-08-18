"""
ghostwire.cli — argparse entrypoint; dispatches to module functions.

All command syntax and behaviour is identical to the original ghostwire.py.
New operations added in this refactor are listed in README.md.
"""

import argparse
import hmac as _hmac
import json
import sys
from typing import Optional

from ghostwire import encode_decode as enc_mod
from ghostwire import hashing as hash_mod
from ghostwire import cipher_lab as cipher_mod
from ghostwire import text_utils as text_mod
from ghostwire import web_ctf as web_mod

# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def read_input(text_arg: Optional[str]) -> str:
    """Return text_arg if provided, else read from stdin."""
    if text_arg is not None:
        return text_arg
    if sys.stdin.isatty():
        sys.exit("error: no input — provide TEXT argument or pipe via stdin")
    return sys.stdin.read()


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

ENCODE_OPS = [
    'base64', 'base64url', 'base32', 'base58', 'base85', 'ascii85',
    'hex', 'url', 'html', 'binary', 'morse', 'rot', 'rot47',
    'uuencode', 'qp', 'punycode', 'leet', 'nato',
]

DECODE_OPS = [
    'base64', 'base64url', 'base32', 'base58', 'base85', 'ascii85',
    'hex', 'url', 'html', 'binary', 'morse', 'rot', 'rot47',
    'uuencode', 'qp', 'punycode', 'leet', 'nato',
]


def cmd_encode(args):
    text = read_input(args.text)
    op = args.operation
    try:
        if op == 'base64':
            print(enc_mod.encode_base64(text, urlsafe=getattr(args, 'urlsafe', False)))
        elif op == 'base64url':
            print(enc_mod.encode_base64(text, urlsafe=True))
        elif op == 'base32':
            print(enc_mod.encode_base32(text))
        elif op == 'base58':
            print(enc_mod.encode_base58(text))
        elif op == 'base85':
            print(enc_mod.encode_base85(text))
        elif op == 'ascii85':
            print(enc_mod.encode_ascii85(text))
        elif op == 'hex':
            print(enc_mod.encode_hex(text))
        elif op == 'url':
            print(enc_mod.encode_url(text))
        elif op == 'html':
            print(enc_mod.encode_html(text))
        elif op == 'binary':
            print(enc_mod.encode_binary(text))
        elif op == 'morse':
            print(enc_mod.encode_morse(text))
        elif op == 'rot':
            print(enc_mod.encode_rot(text, getattr(args, 'n', 13)))
        elif op == 'rot47':
            print(enc_mod.encode_rot47(text))
        elif op == 'uuencode':
            print(enc_mod.encode_uuencode(text))
        elif op == 'qp':
            print(enc_mod.encode_qp(text))
        elif op == 'punycode':
            print(enc_mod.encode_punycode(text))
        elif op == 'leet':
            print(enc_mod.encode_leet(text))
        elif op == 'nato':
            print(enc_mod.encode_nato(text))
        else:
            sys.exit(f"error: unknown encoding '{op}'")
    except Exception as e:
        sys.exit(f"error: {e}")


def cmd_decode(args):
    text = read_input(args.text)
    op = args.operation
    try:
        if op == 'base64':
            print(enc_mod.decode_base64(text, urlsafe=getattr(args, 'urlsafe', False)))
        elif op == 'base64url':
            print(enc_mod.decode_base64(text, urlsafe=True))
        elif op == 'base32':
            print(enc_mod.decode_base32(text))
        elif op == 'base58':
            print(enc_mod.decode_base58(text))
        elif op == 'base85':
            print(enc_mod.decode_base85(text))
        elif op == 'ascii85':
            print(enc_mod.decode_ascii85(text))
        elif op == 'hex':
            print(enc_mod.decode_hex(text))
        elif op == 'url':
            print(enc_mod.decode_url(text))
        elif op == 'html':
            print(enc_mod.decode_html(text))
        elif op == 'binary':
            print(enc_mod.decode_binary(text))
        elif op == 'morse':
            print(enc_mod.decode_morse(text))
        elif op == 'rot':
            print(enc_mod.decode_rot(text, getattr(args, 'n', 13)))
        elif op == 'rot47':
            print(enc_mod.decode_rot47(text))
        elif op == 'uuencode':
            print(enc_mod.decode_uuencode(text))
        elif op == 'qp':
            print(enc_mod.decode_qp(text))
        elif op == 'punycode':
            print(enc_mod.decode_punycode(text))
        elif op == 'leet':
            print(enc_mod.decode_leet(text))
        elif op == 'nato':
            print(enc_mod.decode_nato(text))
        else:
            sys.exit(f"error: unknown encoding '{op}'")
    except Exception as e:
        sys.exit(f"error: {e}")


def cmd_hash(args):
    text = read_input(args.text)
    data = text.encode('utf-8')
    algorithm = args.algorithm
    hmac_key = getattr(args, 'key', None)

    try:
        if algorithm == 'hmac':
            if not hmac_key:
                sys.exit("error: --key is required for hmac")
            digest_algo = getattr(args, 'digest', 'sha256') or 'sha256'
            h = _hmac.new(hmac_key.encode(), data, digest_algo)
            print(h.hexdigest())
        elif algorithm == 'identify':
            candidates = hash_mod.identify_hash(text.strip())
            print(f"Hash: {text.strip()}")
            print(f"Length: {len(text.strip())} characters")
            print("Likely algorithm(s):")
            for c in candidates:
                print(f"  - {c}")
        else:
            print(hash_mod.hash_text(algorithm, data, hmac_key))
    except Exception as e:
        sys.exit(f"error: {e}")


CIPHER_CHOICES = ['caesar', 'vigenere', 'xor', 'atbash',
                  'railfence', 'playfair', 'baconian', 'rc4']


def cmd_cipher(args):
    text = read_input(args.text)
    op = args.operation
    cipher = args.cipher
    key = getattr(args, 'key', None)
    shift = getattr(args, 'shift', 13) or 13
    rails = getattr(args, 'rails', 3) or 3

    try:
        if cipher == 'caesar':
            print(cipher_mod.caesar_encode(text, shift) if op == 'encode'
                  else cipher_mod.caesar_decode(text, shift))
        elif cipher == 'vigenere':
            if not key:
                sys.exit("error: --key is required for vigenere")
            print(cipher_mod.vigenere_encode(text, key) if op == 'encode'
                  else cipher_mod.vigenere_decode(text, key))
        elif cipher == 'xor':
            if not key:
                sys.exit("error: --key is required for xor")
            print(cipher_mod.xor_encode(text, key) if op == 'encode'
                  else cipher_mod.xor_decode(text, key))
        elif cipher == 'atbash':
            print(cipher_mod.atbash_encode(text) if op == 'encode'
                  else cipher_mod.atbash_decode(text))
        elif cipher == 'railfence':
            print(cipher_mod.rail_fence_encode(text, rails) if op == 'encode'
                  else cipher_mod.rail_fence_decode(text, rails))
        elif cipher == 'playfair':
            if not key:
                sys.exit("error: --key is required for playfair")
            print(cipher_mod.playfair_encode(text, key) if op == 'encode'
                  else cipher_mod.playfair_decode(text, key))
        elif cipher == 'baconian':
            print(cipher_mod.baconian_encode(text) if op == 'encode'
                  else cipher_mod.baconian_decode(text))
        elif cipher == 'rc4':
            if not key:
                sys.exit("error: --key is required for rc4")
            print(cipher_mod.rc4_encode(text, key) if op == 'encode'
                  else cipher_mod.rc4_decode(text, key))
        else:
            sys.exit(f"error: unknown cipher '{cipher}'")
    except Exception as e:
        sys.exit(f"error: {e}")


def cmd_recover(args):
    text = read_input(args.text)
    method = args.method
    top = getattr(args, 'top', 5) or 5

    if method == 'caesar-brute':
        results = cipher_mod.caesar_bruteforce(text)
        print(f"Caesar brute-force — top {top} results (of 25 shifts):")
        print(f"  {'SHIFT':>5}  {'SCORE':>8}  PLAINTEXT")
        print(f"  {'-'*5}  {'-'*8}  {'-'*40}")
        for shift, plaintext, score in results[:top]:
            preview = plaintext.replace('\n', ' ')[:60]
            print(f"  {shift:>5}  {score:>8.3f}  {preview}")

    elif method == 'xor-brute':
        results = cipher_mod.xor_single_byte_bruteforce(text)
        print(f"Single-byte XOR brute-force — top {top} results (of 256 keys):")
        print(f"  {'KEY':>5}  {'CHAR':>4}  {'SCORE':>8}  PLAINTEXT")
        print(f"  {'-'*5}  {'-'*4}  {'-'*8}  {'-'*40}")
        for key_byte, key_char, plaintext, score in results[:top]:
            preview = plaintext.replace('\n', ' ')[:55]
            print(f"  {key_byte:>5}  {key_char!r:>4}  {score:>8.3f}  {preview}")

    elif method == 'freq':
        results = cipher_mod.frequency_analysis(text)
        print(f"Character frequency analysis ({len(text)} chars):")
        print(f"  {'CHAR':^6}  {'COUNT':>6}  {'PCT':>7}")
        print(f"  {'-'*6}  {'-'*6}  {'-'*7}")
        for ch, count, pct in results[:50]:
            display = repr(ch) if ch in (' ', '\n', '\t', '\r') else ch
            print(f"  {display:^6}  {count:>6}  {pct:>6.2f}%")

    else:
        sys.exit(f"error: unknown recovery method '{method}'")


def cmd_text(args):
    text = read_input(args.text)
    op = args.operation

    if op == 'upper':
        print(text.upper())
    elif op == 'lower':
        print(text.lower())
    elif op == 'title':
        print(text.title())
    elif op == 'reverse':
        print(text_mod.text_reverse(text))
    elif op == 'freq':
        results = cipher_mod.frequency_analysis(text)
        print(f"Frequency count ({len(text)} chars):")
        print(f"  {'CHAR':^6}  {'COUNT':>6}  {'PCT':>7}")
        print(f"  {'-'*6}  {'-'*6}  {'-'*7}")
        for ch, count, pct in results[:50]:
            display = repr(ch) if ch in (' ', '\n', '\t', '\r') else ch
            print(f"  {display:^6}  {count:>6}  {pct:>6.2f}%")
    elif op == 'entropy':
        print(f"{text_mod.shannon_entropy(text):.6f} bits/char")
    else:
        sys.exit(f"error: unknown text operation '{op}'")


def cmd_web(args):
    text = read_input(args.text)
    op = args.operation
    try:
        if op == 'jwt-decode':
            print(web_mod.jwt_decode_pretty(text))
        elif op == 'gzip-decompress':
            # Accept hex or base64 input
            fmt = getattr(args, 'fmt', 'hex') or 'hex'
            if fmt == 'b64':
                print(web_mod.decompress_b64(text))
            else:
                print(web_mod.decompress_hex(text))
        elif op == 'gzip-compress':
            print(web_mod.compress_gzip(text))
        elif op == 'zlib-decompress':
            fmt = getattr(args, 'fmt', 'hex') or 'hex'
            if fmt == 'b64':
                print(web_mod.decompress_b64(text))
            else:
                print(web_mod.decompress_hex(text))
        elif op == 'zlib-compress':
            print(web_mod.compress_zlib(text))
        else:
            sys.exit(f"error: unknown web operation '{op}'")
    except Exception as e:
        sys.exit(f"error: {e}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='ghostwire',
        description='Encoding, decoding, hashing, and cipher toolkit.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ghostwire encode base64 "hello world"
  ghostwire encode base58 "hello"
  ghostwire encode rot47 "Hello World!"
  ghostwire encode nato "SOS"
  ghostwire encode leet "elite hacker"
  ghostwire decode base64 "aGVsbG8gd29ybGQ="
  ghostwire hash sha256 "abc"
  ghostwire hash ntlm "password"
  ghostwire hash identify "5d41402abc4b2a76b9719d911017c592"
  ghostwire cipher encode railfence --rails 3 "Hello World"
  ghostwire cipher encode playfair --key SECRET "Hello"
  ghostwire cipher encode baconian "Hello"
  ghostwire cipher encode rc4 --key mykey "secret"
  ghostwire recover caesar-brute "Khoor Zruog"
  ghostwire web jwt-decode "<token>"
  ghostwire web gzip-compress "hello"
  ghostwire web gzip-decompress "<hex>"
  cat file.txt | ghostwire hash sha256
  echo "hello" | ghostwire encode base64 | ghostwire decode base64
        """,
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # --- encode ---
    enc = sub.add_parser('encode', help='Encode text using various schemes')
    enc.add_argument('operation', choices=ENCODE_OPS, metavar='OPERATION',
                     help=f'Encoding scheme. Choices: {", ".join(ENCODE_OPS)}')
    enc.add_argument('text', nargs='?', default=None, help='Input text (default: stdin)')
    enc.add_argument('--urlsafe', action='store_true', help='URL-safe base64 alphabet')
    enc.add_argument('-n', type=int, default=13, dest='n', help='ROT shift (default: 13)')
    enc.set_defaults(func=cmd_encode)

    # --- decode ---
    dec = sub.add_parser('decode', help='Decode text using various schemes')
    dec.add_argument('operation', choices=DECODE_OPS, metavar='OPERATION',
                     help=f'Encoding scheme. Choices: {", ".join(DECODE_OPS)}')
    dec.add_argument('text', nargs='?', default=None, help='Input text (default: stdin)')
    dec.add_argument('--urlsafe', action='store_true', help='URL-safe base64 alphabet')
    dec.add_argument('-n', type=int, default=13, dest='n', help='ROT shift (default: 13)')
    dec.set_defaults(func=cmd_decode)

    # --- hash ---
    hsh = sub.add_parser('hash', help='Hash text or identify a hash string')
    hsh.add_argument('algorithm', choices=[
        'md5', 'sha1', 'sha256', 'sha512', 'sha3-256', 'crc32', 'hmac', 'ntlm', 'identify',
    ], help='Hash algorithm, or "identify" to guess algorithm from a hash string')
    hsh.add_argument('text', nargs='?', default=None, help='Input text (default: stdin)')
    hsh.add_argument('--key', '-k', default=None, help='HMAC key')
    hsh.add_argument('--digest', default='sha256', help='HMAC digest algorithm (default: sha256)')
    hsh.set_defaults(func=cmd_hash)

    # --- cipher ---
    cph = sub.add_parser('cipher', help='Encode/decode classical ciphers')
    cph.add_argument('operation', choices=['encode', 'decode'], help='Direction')
    cph.add_argument('cipher', choices=CIPHER_CHOICES)
    cph.add_argument('text', nargs='?', default=None, help='Input text (default: stdin)')
    cph.add_argument('--shift', type=int, default=13, help='Caesar shift (default: 13)')
    cph.add_argument('--key', '-k', default=None, help='Key for vigenere/xor/playfair/rc4')
    cph.add_argument('--rails', type=int, default=3, help='Rail count for railfence (default: 3)')
    cph.set_defaults(func=cmd_cipher)

    # --- recover ---
    rec = sub.add_parser('recover', help='Cipher recovery on ciphertext (local only)')
    rec.add_argument('method', choices=['caesar-brute', 'xor-brute', 'freq'],
                     help='Recovery method')
    rec.add_argument('text', nargs='?', default=None, help='Ciphertext (default: stdin)')
    rec.add_argument('--top', type=int, default=5, help='Number of top results to show')
    rec.set_defaults(func=cmd_recover)

    # --- text ---
    txt = sub.add_parser('text', help='Text transformation utilities')
    txt.add_argument('operation', choices=['upper', 'lower', 'title', 'reverse', 'freq', 'entropy'])
    txt.add_argument('text', nargs='?', default=None, help='Input text (default: stdin)')
    txt.set_defaults(func=cmd_text)

    # --- web ---
    web = sub.add_parser('web', help='Web and CTF-specific operations (local only)')
    web.add_argument('operation', choices=[
        'jwt-decode', 'gzip-compress', 'gzip-decompress', 'zlib-compress', 'zlib-decompress',
    ])
    web.add_argument('text', nargs='?', default=None, help='Input text/hex/token (default: stdin)')
    web.add_argument('--fmt', choices=['hex', 'b64'], default='hex',
                     help='Input format for decompress operations (default: hex)')
    web.set_defaults(func=cmd_web)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
