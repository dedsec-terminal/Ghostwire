# Ghostwire

A CLI and browser GUI toolkit for encoding, decoding, hashing, cryptographic operations, and cipher analysis. All operations are local — no network calls, no telemetry.

---

## Contents

- [CLI](#cli)
  - [Install](#install)
  - [Command reference](#command-reference)
  - [Stdin chaining](#stdin-chaining)
- [Browser GUI](#browser-gui)
- [Constraints and scope](#constraints-and-scope)
- [License](#license)

---

## CLI

### Install

No dependencies. Requires Python 3.8+.

```sh
# clone or download, then:
python ghostwire.py --help
```

No virtual environment or `pip install` needed. All modules used are part of the Python standard library.

---

### Command reference

#### `encode` — Encode text

```
python ghostwire.py encode <scheme> [TEXT] [options]
```

| Scheme | Description | Options |
|---|---|---|
| `base64` | Standard Base64 (RFC 4648) | |
| `base64url` | URL-safe Base64 (no padding) | |
| `base32` | Base32 | |
| `base58` | Base58 (Bitcoin alphabet) | |
| `base85` | Base85 (RFC 1924 / Python b85encode) | |
| `ascii85` | ASCII85 | |
| `hex` | Hexadecimal | |
| `url` | Percent-encoding (URL encoding) | |
| `html` | HTML entity encoding | |
| `binary` | UTF-8 bytes as space-separated 8-bit groups | |
| `uuencode` | Uuencode | |
| `qp` | Quoted-Printable | |
| `punycode` | Punycode (IDNA) | |
| `morse` | International Morse code | |
| `rot` | ROT-N substitution | `-n N` (default 13) |
| `rot47` | ROT47 substitution | |
| `leet` | Leetspeak substitution | |
| `nato` | NATO phonetic alphabet | |

**Examples:**

```sh
python ghostwire.py encode base64 "hello world"
# aGVsbG8gd29ybGQ=

python ghostwire.py encode base64url "hello world"
# aGVsbG8gd29ybGQ

python ghostwire.py encode hex "secret"
# 736563726574

python ghostwire.py encode binary "AB"
# 01000001 01000010

python ghostwire.py encode morse "SOS"
# ... --- ...

python ghostwire.py encode rot -n 13 "Hello"
# Uryyb

python ghostwire.py encode url "https://example.com/path?q=1&r=2"
# https%3A%2F%2Fexample.com%2Fpath%3Fq%3D1%26r%3D2
```

---

#### `decode` — Decode text

```
python ghostwire.py decode <scheme> [TEXT] [options]
```

Same scheme list as `encode`. Decode is the inverse of encode.

**Examples:**

```sh
python ghostwire.py decode base64 "aGVsbG8gd29ybGQ="
# hello world

python ghostwire.py decode hex "736563726574"
# secret

python ghostwire.py decode morse "... --- ..."
# SOS

python ghostwire.py decode rot -n 13 "Uryyb"
# Hello
```

---

#### `hash` — Compute a hash

```
python ghostwire.py hash <algorithm> [TEXT] [--key KEY] [--digest ALGO]
```

| Algorithm | Notes |
|---|---|
| `md5` | 128-bit digest |
| `sha1` | 160-bit digest |
| `sha256` | SHA-2, 256-bit |
| `sha512` | SHA-2, 512-bit |
| `sha3-256` | SHA-3, 256-bit (Keccak) |
| `crc32` | CRC-32 checksum (hex, 8 chars) |
| `ntlm` | Windows NTLM hash (MD4 of UTF-16LE) |
| `hmac` | HMAC — requires `--key`. Digest algorithm set via `--digest` (default: sha256) |
| `identify` | Guesses hash algorithm from a hash string |

**Examples:**

```sh
python ghostwire.py hash sha256 "abc"
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

python ghostwire.py hash md5 "hello"
# 5d41402abc4b2a76b9719d911017c592

python ghostwire.py hash crc32 "data"
# 2ab4e8e4

python ghostwire.py hash hmac --key mykey "message"
# (HMAC-SHA256 of "message" with key "mykey")

python ghostwire.py hash hmac --key mykey --digest sha512 "message"
```

---

#### `cipher` — Classical ciphers

```
python ghostwire.py cipher <encode|decode> <cipher> [TEXT] [options]
```

| Cipher | Options | Notes |
|---|---|---|
| `caesar` | `--shift N` (default 13) | Alphabetic rotation |
| `vigenere` | `--key KEY` (required) | Polyalphabetic substitution |
| `xor` | `--key KEY` (required) | XOR with multi-byte key; encode outputs hex |
| `atbash` | — | Symmetric; encode and decode are identical |
| `railfence`| `--rails N` (default 3) | Transposition cipher |
| `playfair` | `--key KEY` (required) | Digraph substitution |
| `baconian` | — | 5-bit binary substitution (A/B) |
| `rc4`      | `--key KEY` (required) | Stream cipher; encode outputs hex |

**Examples:**

```sh
python ghostwire.py cipher encode caesar --shift 3 "Hello"
# Khoor

python ghostwire.py cipher decode caesar --shift 3 "Khoor"
# Hello

python ghostwire.py cipher encode vigenere --key SECRET "Hello World"
# Zincs Pgvnu

python ghostwire.py cipher decode vigenere --key SECRET "Zincs Pgvnu"
# Hello World

python ghostwire.py cipher encode xor --key pass "hello"
# 1811141e0e

python ghostwire.py cipher decode xor --key pass "1811141e0e"
# hello

python ghostwire.py cipher encode atbash "Hello"
# Svool
```

---

#### `recover` — Cipher recovery (local ciphertext only)

These operations analyse ciphertext you supply. They do not connect to any remote service or system.

```
python ghostwire.py recover <method> [CIPHERTEXT] [--top N]
```

| Method | Description |
|---|---|
| `caesar-brute` | Try all 25 Caesar shifts, rank by English letter frequency |
| `xor-brute` | Try all 256 single-byte XOR keys on hex ciphertext, rank by frequency score |
| `freq` | Character frequency table |

**Examples:**

```sh
python ghostwire.py recover caesar-brute "Khoor Zruog"
# top result: shift 3 → "Hello World"

python ghostwire.py recover xor-brute "1811141e0e"
# top result: key 0x70 ('p') → "hello"

python ghostwire.py recover freq "Hello World"
# frequency table sorted by count

python ghostwire.py recover caesar-brute "Khoor" --top 3
```

---

#### `text` — Text utilities

```
python ghostwire.py text <operation> [TEXT]
```

| Operation | Description |
|---|---|
| `upper` | Convert to uppercase |
| `lower` | Convert to lowercase |
| `title` | Convert to title case |
| `reverse` | Reverse characters |
| `freq` | Character frequency table |
| `entropy` | Shannon entropy in bits per character |

**Examples:**

```sh
python ghostwire.py text entropy "the quick brown fox"
# 3.984085 bits/char

python ghostwire.py text reverse "Hello"
# olleH

python ghostwire.py text freq "aababc"
# a: 3 (50.00%)  b: 2 (33.33%)  c: 1 (16.67%)
```

---

#### `web` — Web and CTF tools

```
python ghostwire.py web <operation> [TEXT] [options]
```

| Operation | Options | Notes |
|---|---|---|
| `jwt-decode` | — | Parses and pretty-prints JWT header and payload |
| `gzip-compress` | — | Compresses text to gzip (outputs hex) |
| `gzip-decompress` | `--fmt hex\|b64` (default hex) | Decompresses gzip data |
| `zlib-compress` | — | Compresses text to zlib (outputs hex) |
| `zlib-decompress` | `--fmt hex\|b64` (default hex) | Decompresses zlib data |

---

### Stdin chaining

When no `TEXT` argument is given, ghostwire reads from stdin. This allows operations to be piped.

```sh
# hash a file
cat README.md | python ghostwire.py hash sha256

# encode then decode (round-trip)
echo "hello" | python ghostwire.py encode base64 | python ghostwire.py decode base64

# encode to hex, then compute hash
echo "secret" | python ghostwire.py encode hex | python ghostwire.py hash sha256

# caesar encrypt then brute-force recover
echo "Hello World" | python ghostwire.py cipher encode caesar --shift 7 | python ghostwire.py recover caesar-brute
```

---

## Browser GUI

Static HTML pages, GitHub Pages compatible. Located in `tools/`.

```
tools/
  index.html       Landing page
  encode-decode.html   All encoding / decoding operations, live textarea
  hashing.html         Hash text or file; MD5 + SHA family + CRC32 + HMAC
  cipher-lab.html      Ciphers, brute-force, frequency analysis
```

To serve locally:

```sh
# Python
python -m http.server 8000 --directory tools

# Node
npx serve tools
```

Then open `http://localhost:8000`.

All computation is client-side. The pages use:
- [Tailwind CSS via CDN](https://tailwindcss.com) for layout
- [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) via Google Fonts
- Web Crypto API for SHA-1, SHA-256, SHA-512
- Vanilla JS for MD5, CRC32, SHA3-256, all encoding schemes, and all cipher logic

No other JavaScript libraries are loaded.

---

## Constraints and scope

- All operations work on text or files supplied by the user.
- No operations connect to remote hosts, authenticate against live services, or brute-force remote endpoints.
- `recover` subcommands analyse ciphertext locally only — they are frequency-analysis and exhaustive-key-search tools for classical ciphers, not attack tools for modern protocols.
- If any future feature would require network access against a system not controlled by the user, it will not be implemented.

---

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
