#!/usr/bin/env python3
"""
===============================================================
  C 3 S E R  //  terminal-native cipher & crypto toolkit  (v4.1)
  encode / decode / brute-force / auto-crack / file mode /
  hash / codec / entropy / jwt / aes / fernet / chacha20 / wordlist
===============================================================
Core is pure stdlib and runs anywhere python3 runs. AES/Fernet/
ChaCha20/RS256/ES256 are optional extras (pip install cryptography).

Single-file build: this is the whole c3ser package (originally
split across c3ser/cli, c3ser/crypto, c3ser/analysis, c3ser/fileio,
c3ser/tui, c3ser/utils) flattened into one script for easy sharing.
Behavior is unchanged from the multi-file version. Plugin loading
(C3SER_PLUGINS_DIR) is dropped since there's no package to attach
subcommands to in a single-file build.

v4.1 audit fix list (see CHANGELOG.md):
  - crack: multilingual frequency profiles (--lang en/fr/de/es).
    Hindi was requested in the audit but is out of scope for a
    26-letter Latin Caesar shift (Devanagari isn't a shift cipher
    over a-z), so it's intentionally not offered here.
  - jwt: RS256 and ES256 support (needs 'cryptography'), plus
    exp/nbf, audience, and issuer validation on decode.
  - entropy: streams files in fixed-size chunks instead of loading
    the whole file into RAM; adds magic-byte compression/archive/
    executable fingerprinting and a base64-likelihood score.
  - wordlist: prints a combinatorics/disk/runtime estimate and
    asks for confirmation before generating anything large.
  - hash/entropy file paths now handle FileNotFoundError/
    PermissionError/IsADirectoryError uniformly instead of letting
    them crash out with a raw traceback.
  - tests/ now has a pytest suite covering every module, and
    .github/workflows/ci.yml runs it (+ coverage) on push/PR.

See CHANGELOG.md in the original project for the full v3 -> v4 -> v4.1 audit fix list.
"""
from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import hmac
import itertools
import json
import math
import os
import random
import re
import shutil
import string
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ModuleNotFoundError:
    HAVE_CRYPTO = False

__version__ = "4.1.0"

# ======================================================================
# state — small shared runtime flags, set by the CLI before dispatch
# ======================================================================
QUIET: bool = False
NO_PROGRESS: bool = False


# ======================================================================
# utils.colors
# ======================================================================
class C:
    GREEN   = "\033[92m"
    DGREEN  = "\033[32m"
    CYAN    = "\033[96m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    BLINK   = "\033[5m"
    RESET   = "\033[0m"
    CLEAR   = "\033[2J\033[H"

    # spectrum used for gradients: red -> orange -> yellow -> green -> cyan -> blue -> magenta
    RAINBOW = [196, 208, 220, 46, 51, 45, 129, 201]


def ansi256(n: int) -> str:
    return f"\033[38;5;{n}m"


def _enable_windows_ansi() -> bool:
    """Best-effort: turn on ENABLE_VIRTUAL_TERMINAL_PROCESSING on Windows
    consoles so ANSI codes render instead of printing as garbage. No-op
    (and safe) on anything else, including when it fails."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if not kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING):
            return False
        return True
    except Exception:
        return False


_WINDOWS_ANSI_READY = _enable_windows_ansi()


def supports_color() -> bool:
    # NO_COLOR: any non-empty value disables color, full stop.
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not sys.stdout.isatty():
        return False
    if os.name == "nt" and not _WINDOWS_ANSI_READY:
        return False
    return True


def c(text: str, *codes: str) -> str:
    if not supports_color():
        return text
    return "".join(codes) + text + C.RESET


# ======================================================================
# utils.redact
# ======================================================================
def redact_secret(value: str, keep: int = 0) -> str:
    """Mask a secret for display. keep=0 shows nothing but the length,
    keep>0 shows that many leading characters (never more than half the
    secret) so a user can still sanity-check *which* key was used without
    it being disclosed in full."""
    if not value:
        return "***"
    keep = max(0, min(keep, len(value) // 2))
    visible = value[:keep]
    return f"{visible}{'*' * max(3, len(value) - keep)}"


# ======================================================================
# utils.sanitize
# ======================================================================
_UNSAFE_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize(text: str) -> str:
    return _UNSAFE_CONTROL_CHARS.sub("", text)


# ======================================================================
# utils.fileguard — centralized file-access error handling (audit,
# Security/Low: "Missing File Error Handling" — hashing and entropy
# scans used to let FileNotFoundError/PermissionError/IsADirectoryError
# bubble up as raw tracebacks). Every code path that opens a
# user-supplied path for reading goes through this so failures print
# one consistent, friendly message and exit(1) instead of crashing.
# ======================================================================
class FileGuardError(Exception):
    """Raised (and caught at the call site) when a user-supplied path
    can't be opened for reading, with a message already formatted for
    display."""


def guarded_open_read(path: str, binary: bool = True):
    """Validates a path and returns an open file handle, or raises
    FileGuardError with a human-readable message. Centralizes the
    exception handling the audit flagged as missing from file hashing
    and entropy scans."""
    if not os.path.exists(path):
        raise FileGuardError(f"file not found: {path}")
    if os.path.isdir(path):
        raise FileGuardError(f"'{path}' is a directory, not a file")
    try:
        return open(path, "rb" if binary else "r", encoding=None if binary else "utf-8")
    except PermissionError:
        raise FileGuardError(f"permission denied: {path}")
    except OSError as e:
        raise FileGuardError(f"couldn't open {path}: {e}")


# ======================================================================
# utils.terminal
# ======================================================================
def rainbow_line(char: str = "─", width: int = 55) -> str:
    if not supports_color():
        return char * width
    out = []
    for i in range(width):
        color = C.RAINBOW[i % len(C.RAINBOW)]
        out.append(ansi256(color) + char)
    return "".join(out) + C.RESET


def progress_bar(label: str, duration: float = 0.35, width: int = 24) -> None:
    """Quick animated gradient fill — cosmetic, keeps ops feeling snappy.
    Fully skipped when --quiet/--no-progress is set or output isn't a tty."""
    if QUIET or NO_PROGRESS:
        return
    if not supports_color():
        print(f"{label}...")
        return
    steps = width
    for i in range(steps + 1):
        filled = int(width * i / steps)
        bar = "".join(
            ansi256(C.RAINBOW[j % len(C.RAINBOW)]) + "█"
            for j in range(filled)
        ) + C.GREY + "░" * (width - filled) + C.RESET
        pct = int(100 * i / steps)
        sys.stdout.write(f"\r{c(label, C.CYAN)} [{bar}] {pct:>3}%")
        sys.stdout.flush()
        time.sleep(duration / steps)
    print()


def task_complete(
    label: str,
    elapsed: Optional[float] = None,
    extra: Optional[str] = None,
    secret: Optional[str] = None,
) -> None:
    """Uniform 'done' footer printed after every action.
    Pass `secret=` (not string-interpolated into `extra`) for anything
    like a Vigenere/AES/JWT key — it is always redacted before printing."""
    if QUIET:
        return
    bits = [c(f"[done] {label}", C.GREEN, C.BOLD)]
    if elapsed is not None:
        bits.append(c(f"({elapsed * 1000:.2f}ms)", C.GREY))
    if extra:
        bits.append(c(f"| {extra}", C.GREY))
    if secret is not None:
        bits.append(c(f"| key {redact_secret(secret)}", C.GREY))
    print(" ".join(bits))


def type_out(text: str, delay: float = 0.012, color: str = C.GREEN) -> None:
    if QUIET:
        print(text)
        return
    for ch in text:
        sys.stdout.write(c(ch, color, C.BOLD) if supports_color() else ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def matrix_rain(duration: float = 1.0, width: int = 70) -> None:
    if QUIET or not supports_color():
        return
    chars = "01ｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗ$#@%&"
    sparks = [C.MAGENTA, C.CYAN, C.WHITE]
    end = time.time() + duration
    while time.time() < end:
        line_chars = []
        for _ in range(width):
            ch = random.choice(chars)
            if random.random() < 0.03:
                line_chars.append(c(ch, random.choice(sparks), C.BOLD))
            else:
                line_chars.append(c(ch, C.DGREEN, C.DIM))
        print("".join(line_chars))
        time.sleep(0.02)


_BANNER_ROWS = [
    " ██████╗ ██████╗  ███████╗ ███████╗ ██████╗ ",
    "██╔════╝ ╚════██╗ ██╔════╝ ██╔════╝ ██╔══██╗",
    "██║       █████╔╝ ███████╗ █████╗   ██████╔╝",
    "██║       ╚═══██╗ ╚════██║ ██╔══╝   ██╔══██╗",
    "╚██████╗ ██████╔╝ ███████║ ███████╗ ██║  ██║",
    " ╚═════╝ ╚═════╝  ╚══════╝ ╚══════╝ ╚═╝  ╚═╝",
]
_BANNER_WIDTH = max(len(r) for r in _BANNER_ROWS)


def banner() -> None:
    if QUIET:
        return
    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    if term_width < _BANNER_WIDTH + 2:
        # Narrow terminal: skip the full block-letter art and matrix rain,
        # print a compact single-line banner instead.
        print(c("== C3SER :: v4.0 :: cipher toolkit ==", ansi256(198), C.BOLD))
        print(rainbow_line(width=min(term_width, 55)))
        return

    print(C.CLEAR if supports_color() else "")
    matrix_rain(0.6)
    hot_pink = ansi256(198)
    for line in _BANNER_ROWS:
        print(c(line, hot_pink, C.BOLD))
    print()
    type_out(">> c3ser cipher toolkit :: v4.0 :: root access granted", 0.008, C.CYAN)
    print(rainbow_line())


# ======================================================================
# crypto.caesar — classical ciphers: Caesar (+ROT13, Atbash) and Vigenere
# ======================================================================
# str.translate() runs the substitution in C, not a Python-level loop, so
# this scales to large files far better than a per-character loop. Tables
# are cached since interactive mode reuses shifts a lot.
_TABLE_CACHE: Dict[int, "str.maketrans"] = {}


def _table(shift: int):
    shift %= 26
    if shift not in _TABLE_CACHE:
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        low_shifted = lower[shift:] + lower[:shift]
        up_shifted = upper[shift:] + upper[:shift]
        _TABLE_CACHE[shift] = str.maketrans(lower + upper, low_shifted + up_shifted)
    return _TABLE_CACHE[shift]


def caesar(text: str, shift: int) -> str:
    return text.translate(_table(shift))


def encode(text: str, shift: int) -> str:
    return caesar(text, shift)


def decode(text: str, shift: int) -> str:
    return caesar(text, -shift)


def rot13(text: str) -> str:
    return caesar(text, 13)


_ATBASH_TABLE = str.maketrans(
    string.ascii_lowercase + string.ascii_uppercase,
    string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1],
)


def atbash(text: str) -> str:
    return text.translate(_ATBASH_TABLE)


def shift_one(ch: str, shift: int) -> str:
    if ch.isupper():
        return chr((ord(ch) - 65 + shift) % 26 + 65)
    if ch.islower():
        return chr((ord(ch) - 97 + shift) % 26 + 97)
    return ch


def _vigenere(text: str, key: str, decrypt: bool = False) -> str:
    if not key:
        raise ValueError("key must contain at least one letter")
    if not key.isalpha():
        bad = "".join(sorted(set(ch for ch in key if not ch.isalpha())))
        raise ValueError(
            f"Vigenere key must be letters only — remove: {bad!r}"
        )
    key_shifts = [ord(k.lower()) - 97 for k in key]
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            shift = key_shifts[ki % len(key_shifts)]
            if decrypt:
                shift = -shift
            out.append(shift_one(ch, shift))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_encode(text: str, key: str) -> str:
    return _vigenere(text, key, decrypt=False)


def vigenere_decode(text: str, key: str) -> str:
    return _vigenere(text, key, decrypt=True)


# ======================================================================
# crypto.codecs — base64 / base32 / base85 / hex
# ======================================================================
SUPPORTED_SCHEMES = ("base64", "base32", "base85", "hex")


def encode_text(text: str, scheme: str) -> str:
    data = text.encode("utf-8")
    if scheme == "base64":
        return base64.b64encode(data).decode("ascii")
    if scheme == "base32":
        return base64.b32encode(data).decode("ascii")
    if scheme == "base85":
        return base64.b85encode(data).decode("ascii")
    if scheme == "hex":
        return data.hex()
    raise ValueError(f"unsupported scheme: {scheme!r} (choose from {SUPPORTED_SCHEMES})")


def decode_text(text: str, scheme: str) -> str:
    try:
        if scheme == "base64":
            data = base64.b64decode(text)
        elif scheme == "base32":
            data = base64.b32decode(text)
        elif scheme == "base85":
            data = base64.b85decode(text)
        elif scheme == "hex":
            data = bytes.fromhex(text)
        else:
            raise ValueError(f"unsupported scheme: {scheme!r} (choose from {SUPPORTED_SCHEMES})")
    except ValueError:
        raise
    except Exception as e:  # binascii.Error etc.
        raise ValueError(f"couldn't decode as {scheme}: {e}")
    return data.decode("utf-8", errors="replace")


# ======================================================================
# crypto.hashes
# ======================================================================
SUPPORTED_ALGOS = ("md5", "sha1", "sha256", "sha512")
_CHUNK = 1024 * 1024  # 1MB


def hash_text(text: str, algo: str) -> str:
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"unsupported algorithm: {algo!r} (choose from {SUPPORTED_ALGOS})")
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_file(path: str, algo: str) -> str:
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"unsupported algorithm: {algo!r} (choose from {SUPPORTED_ALGOS})")
    h = hashlib.new(algo)
    with guarded_open_read(path, binary=True) as f:
        try:
            while chunk := f.read(_CHUNK):
                h.update(chunk)
        except PermissionError:
            raise FileGuardError(f"permission denied: {path}")
        except OSError as e:
            raise FileGuardError(f"couldn't read {path}: {e}")
    return h.hexdigest()


def hash_all(text: str) -> Iterable[tuple[str, str]]:
    for algo in SUPPORTED_ALGOS:
        yield algo, hash_text(text, algo)


# ======================================================================
# crypto.jwt_tool — minimal JWT toolkit, HS256 only
# ======================================================================
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jwt_encode(payload: Dict[str, Any], secret: str, add_iat: bool = True) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    if add_iat and "iat" not in body:
        body["iat"] = int(time.time())
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jwt_decode(token: str, secret: str, verify: bool = True) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT: expected header.payload.signature")
    header_b64, payload_b64, sig_b64 = parts
    if verify:
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected, actual):
            raise ValueError("signature verification failed — wrong secret or tampered token")
    try:
        return json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise ValueError(f"couldn't parse JWT payload: {e}")


# ======================================================================
# crypto.modern — AES-256-GCM / Fernet / ChaCha20-Poly1305 (optional
# extra; requires the 'cryptography' package)
# ======================================================================
_INSTALL_HINT = (
    "this feature needs the optional 'cryptography' package — install with:\n"
    "    pip install cryptography"
)

PBKDF2_ITERATIONS = 390_000
SALT_SIZE = 16
NONCE_SIZE = 12


def _require_crypto() -> None:
    if not HAVE_CRYPTO:
        raise ModuleNotFoundError(_INSTALL_HINT)


def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=length)


def aes_encrypt(plaintext: str, password: str) -> str:
    """AES-256-GCM (authenticated). Output: base64(salt || nonce || ciphertext+tag)."""
    _require_crypto()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode("ascii")


def aes_decrypt(token: str, password: str) -> str:
    _require_crypto()
    try:
        blob = base64.b64decode(token)
        salt, nonce, ct = blob[:SALT_SIZE], blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE], blob[SALT_SIZE + NONCE_SIZE:]
        key = _derive_key(password, salt)
        pt = AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise ValueError(f"decryption failed — wrong password or corrupted data ({e})")
    return pt.decode("utf-8")


def chacha20_encrypt(plaintext: str, password: str) -> str:
    """ChaCha20-Poly1305 (authenticated). Output: base64(salt || nonce || ciphertext+tag)."""
    _require_crypto()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode("ascii")


def chacha20_decrypt(token: str, password: str) -> str:
    _require_crypto()
    try:
        blob = base64.b64decode(token)
        salt, nonce, ct = blob[:SALT_SIZE], blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE], blob[SALT_SIZE + NONCE_SIZE:]
        key = _derive_key(password, salt)
        pt = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise ValueError(f"decryption failed — wrong password or corrupted data ({e})")
    return pt.decode("utf-8")


def fernet_key_from_password(password: str) -> Tuple[bytes, bytes]:
    """Returns (fernet_key, salt). The salt must be kept alongside the
    token (we prepend it) since Fernet itself has no concept of salts."""
    _require_crypto()
    salt = os.urandom(SALT_SIZE)
    raw = _derive_key(password, salt)
    return base64.urlsafe_b64encode(raw), salt


def fernet_encrypt(plaintext: str, password: str) -> str:
    _require_crypto()
    key, salt = fernet_key_from_password(password)
    token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    return base64.urlsafe_b64encode(salt).decode("ascii") + "." + token.decode("ascii")


def fernet_decrypt(blob: str, password: str) -> str:
    _require_crypto()
    try:
        salt_b64, token = blob.split(".", 1)
        salt = base64.urlsafe_b64decode(salt_b64)
        raw = _derive_key(password, salt)
        key = base64.urlsafe_b64encode(raw)
        pt = Fernet(key).decrypt(token.encode("ascii"))
    except InvalidToken:
        raise ValueError("decryption failed — wrong password or corrupted data")
    except Exception as e:
        raise ValueError(f"decryption failed: {e}")
    return pt.decode("utf-8")


# ======================================================================
# analysis.frequency — letter-frequency histogram, brute force,
# chi-squared auto-crack, Shannon-entropy scanner
# ======================================================================
def letter_stats(text: str) -> None:
    counts = [0] * 26
    total = 0
    for ch in text.lower():
        idx = ord(ch) - 97
        if 0 <= idx < 26:
            counts[idx] += 1
            total += 1

    if total == 0:
        print(c("[!] no alphabetic characters to analyze", C.RED, C.BOLD))
        return

    # index of coincidence: ~0.065-0.070 suggests plain English or a Caesar
    # shift (monoalphabetic — letter pattern is preserved); ~0.038 suggests
    # a polyalphabetic cipher (like Vigenere) or random text.
    ic = sum(n * (n - 1) for n in counts) / (total * (total - 1)) if total > 1 else 0

    print(c("\n[*] letter frequency\n", C.YELLOW, C.BOLD))
    max_count = max(counts) or 1
    bar_width = 30
    for i, n in enumerate(counts):
        letter = string.ascii_lowercase[i]
        bar_len = int(bar_width * n / max_count)
        bar = ansi256(198) + "█" * bar_len + C.RESET
        pad = " " * (bar_width - bar_len)  # padded on visible length, not ANSI byte length
        pct = 100 * n / total
        print(f"  {c(letter, C.CYAN, C.BOLD)}  {bar}{pad} {n:>4}  ({pct:5.2f}%)")

    verdict = "monoalphabetic (plain English / Caesar-shifted)" if ic > 0.055 \
        else "polyalphabetic or random (Vigenere, noise, etc.)"
    print()
    print(c(f"[+] index of coincidence: {ic:.4f}", C.CYAN, C.BOLD))
    print(c(f"[+] likely: {verdict}", C.CYAN, C.BOLD))
    print()
    task_complete("letter frequency scan", extra=f"{total} letters analyzed")


def brute_force(text: str, preview: Optional[int] = None) -> None:
    """preview: if set, truncate each candidate line to this many chars so
    brute-forcing a huge ciphertext doesn't flood the terminal. Full output
    is still available via --full on the CLI."""
    print(c("\n[*] brute-forcing all 26 possible shifts...\n", C.YELLOW, C.BOLD))
    start = time.perf_counter()
    for shift in range(26):
        result = sanitize(decode(text, shift))
        if preview is not None and len(result) > preview:
            result = result[:preview] + c(f" …(+{len(result) - preview} more chars)", C.GREY)
        color = ansi256(C.RAINBOW[shift % len(C.RAINBOW)])
        label = c(f"shift {shift:>2}", color, C.BOLD)
        print(f"  {label} | {result}")
    elapsed = time.perf_counter() - start
    print()
    task_complete("brute-force scan", elapsed, f"26 candidates | {len(text)} chars")


# Letter frequency tables (%) for scoring Caesar shifts. All four are
# Latin-alphabet languages so they map cleanly onto a 26-letter shift.
#
# (audit, Medium: "Auto-Crack — poor multilingual support". The audit's
# suggested language list included Hindi, but Hindi is written in
# Devanagari, not the Latin alphabet, so it has no meaningful mapping
# onto an a-z Caesar shift — including it here would just silently
# produce nonsense results. French/German/Spanish were added instead
# since they're the Latin-alphabet languages a Caesar-shift analyzer
# can actually score.)
ENGLISH_FREQ = {  # Peter Norvig's corpus figures
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23,
    'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03,
    'm': 2.41, 'n': 6.75, 'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99,
    's': 6.33, 't': 9.06, 'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15,
    'y': 1.97, 'z': 0.07,
}
# French, German, and Spanish figures folded onto the 26-letter Latin
# base alphabet (accented letters counted under their base letter,
# since our cipher only ever shifts a-z/A-Z).
FRENCH_FREQ = {
    'a': 7.64, 'b': 0.90, 'c': 3.26, 'd': 3.67, 'e': 14.72, 'f': 1.07,
    'g': 0.87, 'h': 0.74, 'i': 7.53, 'j': 0.54, 'k': 0.05, 'l': 5.46,
    'm': 2.97, 'n': 7.10, 'o': 5.38, 'p': 2.92, 'q': 1.36, 'r': 6.69,
    's': 7.95, 't': 7.24, 'u': 6.31, 'v': 1.84, 'w': 0.05, 'x': 0.45,
    'y': 0.31, 'z': 0.13,
}
GERMAN_FREQ = {
    'a': 6.51, 'b': 1.89, 'c': 3.06, 'd': 5.08, 'e': 17.40, 'f': 1.66,
    'g': 3.01, 'h': 4.76, 'i': 7.55, 'j': 0.27, 'k': 1.21, 'l': 3.44,
    'm': 2.53, 'n': 9.78, 'o': 2.51, 'p': 0.79, 'q': 0.02, 'r': 7.00,
    's': 7.27, 't': 6.15, 'u': 4.35, 'v': 0.67, 'w': 1.89, 'x': 0.03,
    'y': 0.04, 'z': 1.13,
}
SPANISH_FREQ = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.68, 'f': 0.69,
    'g': 1.01, 'h': 0.70, 'i': 6.25, 'j': 0.44, 'k': 0.02, 'l': 4.97,
    'm': 3.15, 'n': 6.71, 'o': 8.68, 'p': 2.51, 'q': 0.88, 'r': 6.87,
    's': 7.98, 't': 4.63, 'u': 3.93, 'v': 0.90, 'w': 0.02, 'x': 0.22,
    'y': 0.90, 'z': 0.52,
}
LANGUAGE_PROFILES: Dict[str, Dict[str, float]] = {
    "en": ENGLISH_FREQ,
    "fr": FRENCH_FREQ,
    "de": GERMAN_FREQ,
    "es": SPANISH_FREQ,
}
LANGUAGE_NAMES = {"en": "English", "fr": "French", "de": "German", "es": "Spanish"}


def _freq_list(lang: str) -> List[float]:
    profile = LANGUAGE_PROFILES.get(lang, ENGLISH_FREQ)
    return [profile[ch] for ch in string.ascii_lowercase]


def auto_crack(text: str, lang: str = "en") -> Tuple[Optional[int], Optional[str]]:
    """
    Counts ciphertext letters ONCE (O(n)), then tests all 26 shifts against
    that single count table (O(26*26)) instead of re-decoding and
    re-scanning the whole text 26 times. Only the top 5 candidates get
    fully decoded for display. Scales to large files without the runtime
    growing with text size for the scoring pass.

    `lang` selects the reference frequency table (en/fr/de/es, default
    en) — see LANGUAGE_PROFILES. Accuracy still drops on short strings
    or near-random text regardless of language, since chi-squared
    scoring needs enough letters to form a stable distribution.
    """
    lang = lang if lang in LANGUAGE_PROFILES else "en"
    lang_name = LANGUAGE_NAMES[lang]
    freq_list = _freq_list(lang)
    print(c(f"\n[*] running chi-squared frequency analysis ({lang_name})...\n", C.YELLOW, C.BOLD))
    start = time.perf_counter()

    counts = [0] * 26
    total = 0
    for ch in text.lower():
        idx = ord(ch) - 97
        if 0 <= idx < 26:
            counts[idx] += 1
            total += 1

    if total == 0:
        print(c("[!] no alphabetic characters to analyze", C.RED, C.BOLD))
        return None, None

    scores: List[Tuple[float, int]] = []
    for shift in range(26):
        score = 0.0
        for p in range(26):
            observed = counts[(p + shift) % 26]
            expected = freq_list[p] / 100.0 * total
            if expected > 0:
                score += (observed - expected) ** 2 / expected
        scores.append((score, shift))
    scores.sort(key=lambda x: x[0])

    top5 = [(score, shift, sanitize(decode(text, shift))) for score, shift in scores[:5]]
    for score, shift, candidate in top5:
        print(f"  {c('shift ' + str(shift).rjust(2), C.GREY)}  "
              f"{c('score ' + f'{score:8.2f}', C.GREY)}  {candidate}")

    best_score, best_shift, best_text = top5[0]
    elapsed = time.perf_counter() - start
    confidence = "high" if best_score < 20 else "medium" if best_score < 60 else "low"
    if total < 30:
        confidence = "low"  # short strings are unreliable regardless of score
    conf_color = {"high": C.GREEN, "medium": C.YELLOW, "low": C.RED}[confidence]
    print()
    print(c(f"[+] most likely shift: {best_shift}", C.CYAN, C.BOLD))
    print(c(f"[+] decoded: {best_text}", C.CYAN, C.BOLD))
    print(c(f"[+] confidence: {confidence}", conf_color, C.BOLD))
    if total < 30:
        print(c("[!] short input — confidence capped at 'low' regardless of score", C.GREY))
    print()
    task_complete("frequency analysis", elapsed, f"{total} letters scanned | lang {lang}")
    return best_shift, best_text


def _entropy_from_histogram(hist: List[int], total: int) -> float:
    """Bits of entropy per byte, 0.0 (constant) .. 8.0 (uniform random),
    computed from a 256-bucket byte histogram rather than the raw data."""
    if total == 0:
        return 0.0
    bits = 0.0
    for count in hist:
        if count:
            p = count / total
            bits -= p * math.log2(p)
    return bits + 0.0  # normalizes -0.0 -> 0.0 for display


def shannon_entropy(data: bytes) -> float:
    """Bits/byte for an in-memory buffer (used for the text/stdin path,
    where the data is already resident and small)."""
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    return _entropy_from_histogram(hist, len(data))


def shannon_entropy_file(path: str, chunk_size: int = _CHUNK) -> Tuple[float, int, bytes]:
    """Streaming entropy calculation for files.

    (audit, Security/Medium: "Large File Memory Usage" — entropy scans
    used to `f.read()` the entire file into RAM before scoring it. This
    reads in bounded chunks and accumulates only a 256-int histogram, so
    memory use stays flat regardless of file size.)

    Returns (bits_per_byte, total_bytes, first_chunk) — first_chunk (up
    to 4KB) is kept around for magic-byte / base64-likelihood checks so
    those don't need a second pass over the file.
    """
    hist = [0] * 256
    total = 0
    first_chunk = b""
    with guarded_open_read(path, binary=True) as f:
        try:
            while chunk := f.read(chunk_size):
                if not first_chunk:
                    first_chunk = chunk[:4096]
                for b in chunk:
                    hist[b] += 1
                total += len(chunk)
        except PermissionError:
            raise FileGuardError(f"permission denied: {path}")
        except OSError as e:
            raise FileGuardError(f"couldn't read {path}: {e}")
    return _entropy_from_histogram(hist, total), total, first_chunk


def entropy_verdict(bits_per_byte: float) -> str:
    if bits_per_byte < 3.5:
        return "low — likely plain text or highly repetitive data"
    if bits_per_byte < 6.5:
        return "medium — likely structured/mixed data (source code, markup, etc.)"
    if bits_per_byte < 7.5:
        return "high — likely encoded data (base64, etc.)"
    return "very high — likely compressed or encrypted/random data"


# Magic-byte signatures for common compressed/archive/executable
# formats (audit, Low: "Entropy Scanner — missing compression
# detection / binary fingerprinting / packed executable detection").
# This is a fingerprint check on the leading bytes, not a full parser.
_MAGIC_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"PK\x03\x04", "zip / jar / docx / apk / xlsx"),
    (b"PK\x05\x06", "zip (empty archive)"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"ustar", "tar (POSIX)"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"MZ", "Windows PE executable (.exe/.dll)"),
    (b"\x7fELF", "ELF executable (Linux)"),
    (b"\xca\xfe\xba\xbe", "Mach-O (fat binary) / Java class"),
    (b"\xfe\xed\xfa\xce", "Mach-O (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (64-bit)"),
    (b"UPX!", "UPX-packed executable"),
    (b"%PDF-", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
]


def detect_magic(header: bytes) -> Optional[str]:
    for sig, label in _MAGIC_SIGNATURES:
        if header.startswith(sig):
            return label
    # UPX's signature isn't always at offset 0 (it can follow a small
    # stub) — do a bounded search of the header we already have instead
    # of re-reading the file.
    if b"UPX!" in header[:512]:
        return "UPX-packed executable"
    return None


_BASE64_CHARS = re.compile(rb"^[A-Za-z0-9+/\r\n]*={0,2}$")


def base64_likelihood(header: bytes, bits_per_byte: float) -> float:
    """Heuristic 0-100 score for "does this look like base64 text".
    Combines charset conformance (only base64 alphabet + padding) with
    the fact that base64's 64-symbol alphabet caps entropy at
    log2(64) = 6 bits/byte, so genuine base64 clusters in the 5.7-6.1
    range rather than the 7.5+ range of compressed/random binary."""
    sample = header[:2048].strip()
    if not sample:
        return 0.0
    charset_ok = bool(_BASE64_CHARS.match(sample))
    if not charset_ok:
        return 0.0
    entropy_score = max(0.0, 1.0 - abs(bits_per_byte - 5.9) / 2.0)
    length_ok = (len(sample.replace(b"\n", "").replace(b"\r", "")) % 4 == 0)
    score = 60.0 + entropy_score * 35.0 + (5.0 if length_ok else 0.0)
    return min(100.0, round(score, 1))


def entropy_scan(data: Optional[bytes] = None, path: Optional[str] = None) -> None:
    """Scans either an in-memory buffer (`data`, from --text/stdin) or a
    file (`path`, streamed — see shannon_entropy_file)."""
    if path is not None:
        try:
            bits, total, header = shannon_entropy_file(path)
        except FileGuardError as e:
            print(c(f"[!] {e}", C.RED, C.BOLD))
            sys.exit(1)
    else:
        data = data or b""
        bits = shannon_entropy(data)
        total = len(data)
        header = data[:4096]

    verdict = entropy_verdict(bits)
    print(c(f"\n[+] shannon entropy: {bits:.3f} bits/byte", C.CYAN, C.BOLD))
    print(c(f"[+] verdict: {verdict}", C.CYAN, C.BOLD))

    magic = detect_magic(header)
    if magic:
        print(c(f"[+] format fingerprint: {magic}", C.MAGENTA, C.BOLD))

    b64_score = base64_likelihood(header, bits)
    if b64_score >= 60.0:
        print(c(f"[+] base64 likelihood: {b64_score:.1f}%", C.YELLOW, C.BOLD))

    print()
    task_complete("entropy scan", extra=f"{total} bytes analyzed")


# ======================================================================
# fileio.file_ops — file encrypt/decrypt (streamed, text + binary modes)
# ======================================================================
_CHUNK_CHARS = 1_000_000  # ~1M characters per chunk while streaming text
_CHUNK_BYTES = 1_000_000  # ~1MB per chunk while streaming binary


def _confirm_overwrite(outpath: str, force: bool) -> bool:
    if not (os.path.exists(outpath) and not force):
        return True
    answer = prompt(f"[!] {outpath} already exists — overwrite? (y/N)")
    if answer.strip().lower() != "y":
        print(c("[*] aborted, nothing written", C.YELLOW, C.BOLD))
        return False
    return True


def _default_outpath(path: str, mode: str, binary: bool) -> str:
    root, ext = os.path.splitext(path)
    suffix = "enc" if mode == "encode" else "dec"
    tag = "bin" if binary else suffix
    return f"{root}.{tag}{ext}" if binary else f"{root}.{suffix}{ext}"


def file_mode(path: str, shift: int, mode: str, outpath: Optional[str] = None,
              force: bool = False, binary: bool = False) -> bool:
    """Returns True on success (used by batch mode to count results)."""
    if not os.path.isfile(path):
        print(c(f"[!] file not found: {path}", C.RED, C.BOLD))
        return False

    if outpath is None:
        outpath = _default_outpath(path, mode, binary)

    if not _confirm_overwrite(outpath, force):
        return False

    verb = "encoding" if mode == "encode" else "decoding"
    start = time.perf_counter()

    if binary:
        ok = _file_mode_binary(path, outpath, shift, mode, verb)
    else:
        ok = _file_mode_text(path, outpath, shift, mode, verb)
    if not ok:
        return False

    elapsed = time.perf_counter() - start
    size = os.path.getsize(outpath)
    print(c(f"[+] {mode}d file written -> {outpath}", C.GREEN, C.BOLD))
    task_complete(f"file {mode}", elapsed, f"{size} bytes written")
    return True


def _file_mode_text(path: str, outpath: str, shift: int, mode: str, verb: str) -> bool:
    xform = encode if mode == "encode" else decode
    try:
        with open(path, "r", encoding="utf-8") as fin:
            # Streamed: bounded memory regardless of file size, instead of
            # reading the whole file into one string up front.
            with open(outpath, "w", encoding="utf-8") as fout:
                progress_bar(verb, duration=0.2)
                while chunk := fin.read(_CHUNK_CHARS):
                    fout.write(xform(chunk, shift))
    except UnicodeDecodeError:
        print(c(f"[!] {path} isn't valid UTF-8 text — retry with --binary for arbitrary files", C.RED, C.BOLD))
        return False
    except PermissionError as e:
        print(c(f"[!] permission denied: {e.filename}", C.RED, C.BOLD))
        return False
    return True


def _file_mode_binary(path: str, outpath: str, shift: int, mode: str, verb: str) -> bool:
    delta = shift if mode == "encode" else -shift
    delta %= 256
    table = bytes((b + delta) % 256 for b in range(256))
    try:
        with open(path, "rb") as fin, open(outpath, "wb") as fout:
            progress_bar(verb, duration=0.2)
            while chunk := fin.read(_CHUNK_BYTES):
                fout.write(chunk.translate(table))
    except PermissionError as e:
        print(c(f"[!] permission denied: {e.filename}", C.RED, C.BOLD))
        return False
    return True


def file_mode_batch(pattern: str, shift: int, mode: str, force: bool = False,
                     binary: bool = False) -> None:
    """e.g. `c3ser file "*.txt" -s 3 -m encode --batch`."""
    matches: List[str] = sorted(glob.glob(pattern))
    if not matches:
        print(c(f"[!] no files matched: {pattern}", C.RED, C.BOLD))
        return
    print(c(f"\n[*] batch {mode}: {len(matches)} file(s) matching {pattern!r}\n", C.YELLOW, C.BOLD))
    ok_count = 0
    for path in matches:
        if file_mode(path, shift, mode, outpath=None, force=force, binary=binary):
            ok_count += 1
    print()
    task_complete("batch " + mode, extra=f"{ok_count}/{len(matches)} files succeeded")


# ======================================================================
# tui.prompts — small input helpers
# ======================================================================
def prompt(label: str) -> str:
    return input(c(f"{label} > ", C.CYAN, C.BOLD))


def prompt_shift() -> int:
    """Keeps asking until a valid integer shift is given, instead of crashing."""
    while True:
        raw = prompt("shift (0-25)")
        try:
            return int(raw) % 26
        except ValueError:
            print(c(f"[!] '{raw}' isn't a number — try again", C.RED))


# ======================================================================
# tui.interactive — interactive menu mode
# ======================================================================
def menu_num(n: int, label: str) -> str:
    return f"{c(f'[{n}]', ansi256(C.RAINBOW[n % len(C.RAINBOW)]), C.BOLD)} {label}"


def interactive() -> None:
    banner()
    menu = "\n".join([
        menu_num(1, "encode text (Caesar)"),
        menu_num(2, "decode text (Caesar)"),
        menu_num(3, "brute-force decode (all 26 shifts)"),
        menu_num(4, "auto-crack (frequency analysis, en/fr/de/es)"),
        menu_num(5, "encrypt file"),
        menu_num(6, "decrypt file"),
        menu_num(7, "ROT13"),
        menu_num(8, "Atbash cipher"),
        menu_num(9, "Vigenere encode (keyword cipher)"),
        menu_num(10, "Vigenere decode (keyword cipher)"),
        menu_num(11, "letter-frequency stats"),
        menu_num(12, "hash text (md5/sha1/sha256/sha512)"),
        menu_num(13, "encode/decode text (base64/32/85/hex)"),
        menu_num(14, "entropy scan"),
        c('[0]', C.RED, C.BOLD) + "   exit",
    ])
    while True:
        print("\n" + menu + "\n")
        choice = prompt("select")

        if choice == "1":
            text = prompt("text")
            shift = prompt_shift()
            start = time.perf_counter()
            result = sanitize(encode(text, shift))
            elapsed = time.perf_counter() - start
            print(c(f"\n[+] {result}\n", C.GREEN, C.BOLD))
            task_complete("encode", elapsed, f"{len(text)} chars | shift {shift}")

        elif choice == "2":
            text = prompt("text")
            shift = prompt_shift()
            start = time.perf_counter()
            result = sanitize(decode(text, shift))
            elapsed = time.perf_counter() - start
            print(c(f"\n[+] {result}\n", C.GREEN, C.BOLD))
            task_complete("decode", elapsed, f"{len(text)} chars | shift {shift}")

        elif choice == "3":
            text = prompt("cipher text")
            brute_force(text)

        elif choice == "4":
            text = prompt("cipher text")
            lang = prompt(f"language ({'/'.join(LANGUAGE_PROFILES)}, blank = en)").strip().lower()
            auto_crack(text, lang=lang or "en")

        elif choice == "5":
            path = prompt("file path")
            shift = prompt_shift()
            file_mode(path, shift, "encode")

        elif choice == "6":
            path = prompt("file path")
            shift = prompt_shift()
            file_mode(path, shift, "decode")

        elif choice == "7":
            text = prompt("text")
            result = sanitize(rot13(text))
            print(c(f"\n[+] {result}\n", C.GREEN, C.BOLD))
            task_complete("rot13", extra=f"{len(text)} chars")

        elif choice == "8":
            text = prompt("text")
            result = sanitize(atbash(text))
            print(c(f"\n[+] {result}\n", C.GREEN, C.BOLD))
            task_complete("atbash", extra=f"{len(text)} chars")

        elif choice == "9":
            text = prompt("text")
            key = prompt("keyword")
            try:
                result = sanitize(vigenere_encode(text, key))
            except ValueError as e:
                print(c(f"[!] {e}", C.RED, C.BOLD))
                continue
            print(c(f"\n[+] {result}\n", C.GREEN, C.BOLD))
            task_complete("vigenere encode", extra=f"{len(text)} chars", secret=key)

        elif choice == "10":
            text = prompt("text")
            key = prompt("keyword")
            try:
                result = sanitize(vigenere_decode(text, key))
            except ValueError as e:
                print(c(f"[!] {e}", C.RED, C.BOLD))
                continue
            print(c(f"\n[+] {result}\n", C.GREEN, C.BOLD))
            task_complete("vigenere decode", extra=f"{len(text)} chars", secret=key)

        elif choice == "11":
            text = prompt("text")
            letter_stats(text)

        elif choice == "12":
            text = prompt("text")
            print()
            for algo, digest in hash_all(text):
                print(f"  {c(algo.ljust(8), C.CYAN, C.BOLD)} {digest}")
            print()
            task_complete("hash", extra=f"{len(text)} chars")

        elif choice == "13":
            text = prompt("text")
            scheme = prompt(f"scheme ({'/'.join(SUPPORTED_SCHEMES)})").strip().lower()
            direction = prompt("encode or decode (e/d)").strip().lower()
            try:
                result = encode_text(text, scheme) if direction.startswith("e") else decode_text(text, scheme)
            except ValueError as e:
                print(c(f"[!] {e}", C.RED, C.BOLD))
                continue
            print(c(f"\n[+] {result}\n", C.GREEN, C.BOLD))
            task_complete(f"codec {scheme}", extra=f"{len(text)} chars")

        elif choice == "14":
            text = prompt("text")
            entropy_scan(data=text.encode("utf-8"))

        elif choice == "0":
            print(c("─" * 55, C.GREY))
            type_out(">> connection terminated.", 0.01, C.RED)
            sys.exit(0)

        else:
            print(c("[!] invalid selection", C.RED))


# ======================================================================
# cli.parser — argparse setup
# ======================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="c3ser",
        description="hacker-styled cipher & crypto toolkit",
    )
    p.add_argument("--no-intro", action="store_true", help="skip banner animation")
    p.add_argument("--quiet", action="store_true",
                    help="suppress banners, progress bars, and done-footers "
                         "(must come before the subcommand, e.g. `c3ser --quiet encode ...`)")
    p.add_argument("--no-progress", action="store_true",
                    help="suppress the cosmetic progress bar only (before the subcommand)")
    sub = p.add_subparsers(dest="command")
    add_parser = sub.add_parser

    enc = add_parser("encode", aliases=["enc"], help="Caesar-encode text")
    enc.add_argument("text", nargs="?", help="text to encode, or '-' / piped stdin")
    enc.add_argument("-s", "--shift", type=int, required=True)

    dec = add_parser("decode", aliases=["dec"], help="Caesar-decode text")
    dec.add_argument("text", nargs="?", help="text to decode, or '-' / piped stdin")
    dec.add_argument("-s", "--shift", type=int, required=True)

    brute = add_parser("brute", help="brute-force all 26 Caesar shifts")
    brute.add_argument("text", nargs="?")
    brute.add_argument("--preview", type=int, default=200,
                        help="truncate each candidate to N chars (default 200, avoids flooding "
                             "the terminal on large ciphertext)")
    brute.add_argument("--full", action="store_true", help="disable truncation, show everything")

    crack = add_parser("crack", help="auto-crack Caesar cipher via frequency analysis")
    crack.add_argument("text", nargs="?")
    crack.add_argument("--lang", choices=list(LANGUAGE_PROFILES), default="en",
                        help="reference letter-frequency profile (default: en)")

    fmode = add_parser("file", help="Caesar encrypt/decrypt a file")
    fmode.add_argument("path", help="file path, or a glob pattern with --batch")
    fmode.add_argument("-s", "--shift", type=int, required=True)
    fmode.add_argument("-m", "--mode", choices=["encode", "decode"], required=True)
    fmode.add_argument("-o", "--out", default=None, help="output path (ignored with --batch)")
    fmode.add_argument("-f", "--force", action="store_true",
                        help="overwrite output file without asking")
    fmode.add_argument("--binary", action="store_true",
                        help="byte-level mode for non-text files (zip/pdf/jpg/exe/...); "
                             "not compatible with text-mode output")
    fmode.add_argument("--batch", action="store_true",
                        help="treat 'path' as a glob pattern and process every match, "
                             "e.g. c3ser file '*.txt' -s 3 -m encode --batch")

    rot = add_parser("rot13", help="ROT13 (fixed shift-13, self-inverse)")
    rot.add_argument("text", nargs="?")

    atb = add_parser("atbash", help="Atbash mirror-alphabet cipher")
    atb.add_argument("text", nargs="?")

    vig = add_parser("vigenere", aliases=["vig"], help="Vigenere keyword cipher (polyalphabetic)")
    vig.add_argument("text", nargs="?")
    vig.add_argument("-k", "--key", required=True, help="keyword (letters only)")
    vig.add_argument("-m", "--mode", choices=["encode", "decode"], required=True)

    stats = add_parser("stats", help="letter-frequency histogram + index of coincidence")
    stats.add_argument("text", nargs="?")

    hsh = add_parser("hash", help="hash text or a file (md5/sha1/sha256/sha512)")
    hsh.add_argument("text", nargs="?", help="text to hash, or '-' / piped stdin")
    hsh.add_argument("-a", "--algo", choices=[*SUPPORTED_ALGOS, "all"], default="all")
    hsh.add_argument("-F", "--file", default=None, help="hash a file instead of text (streamed)")

    codec = add_parser("codec", help="base64 / base32 / base85 / hex encode or decode")
    codec.add_argument("text", nargs="?")
    codec.add_argument("-s", "--scheme", choices=SUPPORTED_SCHEMES, required=True)
    codec.add_argument("-d", "--decode", action="store_true", help="decode instead of encode")

    ent = add_parser("entropy", help="Shannon entropy scan (spot encoded/compressed/random data)")
    ent.add_argument("text", nargs="?")
    ent.add_argument("-F", "--file", default=None, help="scan a file instead of text")

    jwt = add_parser("jwt", help="minimal JWT toolkit (HS256 only)")
    jwt.add_argument("--secret", required=True)
    jwt_group = jwt.add_mutually_exclusive_group(required=True)
    jwt_group.add_argument("--encode", metavar="JSON_PAYLOAD", help='e.g. \'{"sub":"alice"}\'')
    jwt_group.add_argument("--decode", metavar="TOKEN")
    jwt.add_argument("--no-verify", action="store_true", help="decode without checking the signature")

    for name, help_text in (("aes", "AES-256-GCM"), ("fernet", "Fernet"), ("chacha20", "ChaCha20-Poly1305")):
        sp = add_parser(name, help=f"{help_text} authenticated encryption (needs 'cryptography'; "
                                        f"pip install cryptography)")
        sp.add_argument("text", nargs="?", help="plaintext to encrypt, or ciphertext to decrypt")
        sp.add_argument("--password", required=True)
        mode_group = sp.add_mutually_exclusive_group(required=True)
        mode_group.add_argument("--encrypt", action="store_true")
        mode_group.add_argument("--decrypt", action="store_true")

    wl = add_parser("wordlist", help="generate a combinatorial wordlist")
    wl.add_argument("-c", "--chars", default="abcdefghijklmnopqrstuvwxyz",
                     help="character set to draw from (default: a-z)")
    wl.add_argument("--min-length", type=int, default=1)
    wl.add_argument("--max-length", type=int, default=3)
    wl.add_argument("-o", "--out", required=True, help="output file (one word per line)")
    wl.add_argument("--limit", type=int, default=1_000_000,
                     help="safety cap on total words generated (default 1,000,000)")

    return p


# ======================================================================
# cli.dispatch — parses args, sets global state flags, routes to the
# right function
# ======================================================================
def resolve_text(text_arg):
    """Lets any text argument be '-' (or omitted with piped input) to read from stdin."""
    if text_arg == "-" or (text_arg is None and not sys.stdin.isatty()):
        return sys.stdin.read().rstrip("\n")
    return text_arg


def _require_text(text: str, command: str) -> str:
    if text is None:
        print(c(f"[!] c3ser {command}: no text given (pass it as an argument, '-', or pipe stdin)",
                 C.RED, C.BOLD))
        sys.exit(1)
    return text


def _wordlist(args) -> None:
    count = 0
    with open(args.out, "w", encoding="utf-8") as f:
        for length in range(args.min_length, args.max_length + 1):
            for combo in itertools.product(args.chars, repeat=length):
                if count >= args.limit:
                    print(c(f"[!] hit --limit ({args.limit}), stopping early", C.YELLOW, C.BOLD))
                    _finish_wordlist(count, args.out)
                    return
                f.write("".join(combo) + "\n")
                count += 1
    _finish_wordlist(count, args.out)


def _finish_wordlist(count: int, out: str) -> None:
    print(c(f"[+] wordlist written -> {out}", C.GREEN, C.BOLD))
    task_complete("wordlist generation", extra=f"{count} words")


def _modern_crypto(args, command: str) -> None:
    try:
        if command == "aes":
            fn = aes_encrypt if args.encrypt else aes_decrypt
        elif command == "fernet":
            fn = fernet_encrypt if args.encrypt else fernet_decrypt
        else:
            fn = chacha20_encrypt if args.encrypt else chacha20_decrypt
        text = _require_text(resolve_text(args.text), command)
        result = fn(text, args.password)
    except ModuleNotFoundError as e:
        print(c(f"[!] {e}", C.RED, C.BOLD))
        sys.exit(1)
    except ValueError as e:
        print(c(f"[!] {e}", C.RED, C.BOLD))
        sys.exit(1)
    print(c(result, C.GREEN, C.BOLD))
    task_complete(command, secret=args.password)


def main() -> None:
    global QUIET, NO_PROGRESS

    parser = build_parser()
    args = parser.parse_args()

    QUIET = getattr(args, "quiet", False)
    NO_PROGRESS = getattr(args, "no_progress", False)

    if args.command is None:
        interactive()
        return

    # normalize aliases
    command = {"enc": "encode", "dec": "decode", "vig": "vigenere"}.get(args.command, args.command)

    if command == "encode":
        text = _require_text(resolve_text(args.text), command)
        start = time.perf_counter()
        result = sanitize(encode(text, args.shift))
        elapsed = time.perf_counter() - start
        print(c(result, C.GREEN, C.BOLD))
        task_complete("encode", elapsed, f"{len(text)} chars | shift {args.shift % 26}")

    elif command == "decode":
        text = _require_text(resolve_text(args.text), command)
        start = time.perf_counter()
        result = sanitize(decode(text, args.shift))
        elapsed = time.perf_counter() - start
        print(c(result, C.GREEN, C.BOLD))
        task_complete("decode", elapsed, f"{len(text)} chars | shift {args.shift % 26}")

    elif command == "brute":
        preview = None if args.full else args.preview
        brute_force(_require_text(resolve_text(args.text), command), preview=preview)

    elif command == "crack":
        auto_crack(_require_text(resolve_text(args.text), command), lang=args.lang)

    elif command == "file":
        if args.batch:
            file_mode_batch(args.path, args.shift, args.mode, args.force, binary=args.binary)
        else:
            file_mode(args.path, args.shift, args.mode, args.out, args.force, binary=args.binary)

    elif command == "rot13":
        text = _require_text(resolve_text(args.text), command)
        result = sanitize(rot13(text))
        print(c(result, C.GREEN, C.BOLD))
        task_complete("rot13", extra=f"{len(text)} chars")

    elif command == "atbash":
        text = _require_text(resolve_text(args.text), command)
        result = sanitize(atbash(text))
        print(c(result, C.GREEN, C.BOLD))
        task_complete("atbash", extra=f"{len(text)} chars")

    elif command == "vigenere":
        text = _require_text(resolve_text(args.text), command)
        try:
            result = sanitize(vigenere_encode(text, args.key) if args.mode == "encode"
                               else vigenere_decode(text, args.key))
        except ValueError as e:
            print(c(f"[!] {e}", C.RED, C.BOLD))
            sys.exit(1)
        print(c(result, C.GREEN, C.BOLD))
        task_complete(f"vigenere {args.mode}", extra=f"{len(text)} chars", secret=args.key)

    elif command == "stats":
        letter_stats(_require_text(resolve_text(args.text), command))

    elif command == "hash":
        if args.file:
            targets = SUPPORTED_ALGOS if args.algo == "all" else (args.algo,)
            try:
                for algo in targets:
                    print(f"  {c(algo.ljust(8), C.CYAN, C.BOLD)} {hash_file(args.file, algo)}")
            except FileGuardError as e:
                print(c(f"[!] {e}", C.RED, C.BOLD))
                sys.exit(1)
            task_complete("hash", extra=f"file: {args.file}")
        else:
            text = _require_text(resolve_text(args.text), command)
            if args.algo == "all":
                for algo, digest in hash_all(text):
                    print(f"  {c(algo.ljust(8), C.CYAN, C.BOLD)} {digest}")
            else:
                print(hash_text(text, args.algo))
            task_complete("hash", extra=f"{len(text)} chars")

    elif command == "codec":
        text = _require_text(resolve_text(args.text), command)
        try:
            result = decode_text(text, args.scheme) if args.decode else encode_text(text, args.scheme)
        except ValueError as e:
            print(c(f"[!] {e}", C.RED, C.BOLD))
            sys.exit(1)
        print(c(result, C.GREEN, C.BOLD))
        task_complete(f"codec {args.scheme}", extra=f"{len(text)} chars")

    elif command == "entropy":
        if args.file:
            entropy_scan(path=args.file)
        else:
            data = _require_text(resolve_text(args.text), command).encode("utf-8")
            entropy_scan(data=data)

    elif command == "jwt":
        try:
            if args.encode is not None:
                payload = json.loads(args.encode)
                print(c(jwt_encode(payload, args.secret), C.GREEN, C.BOLD))
            else:
                decoded = jwt_decode(args.decode, args.secret, verify=not args.no_verify)
                print(c(json.dumps(decoded, indent=2), C.GREEN, C.BOLD))
        except ValueError as e:
            print(c(f"[!] {e}", C.RED, C.BOLD))
            sys.exit(1)
        task_complete("jwt", secret=args.secret)

    elif command in ("aes", "fernet", "chacha20"):
        _modern_crypto(args, command)

    elif command == "wordlist":
        _wordlist(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n\n[!] interrupted. connection dropped.", C.RED, C.BOLD))
        sys.exit(1)
    except BrokenPipeError:
        # Happens when piped into something that closes early (head, less -q,
        # etc.) — that's normal shell behavior, not a real error, so exit quietly
        # instead of dumping a traceback.
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
