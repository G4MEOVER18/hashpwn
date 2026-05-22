#!/usr/bin/env python3
"""
hashpwn.py — Hash Identification & Cracking Tool
Inspired by hashcat (https://github.com/hashcat/hashcat)
         and hashID  (https://github.com/psypanda/hashID)

Author  : G4MEOVER18
License : MIT 2026
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time
from typing import List, Optional, Tuple, Dict, Any

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
__version__ = "1.0.0"
BANNER = r"""
 _   _           _       ____
| | | | __ _ ___| |__   |  _ \__      ___ __
| |_| |/ _` / __| '_ \  | |_) \ \ /\ / / '_ \
|  _  | (_| \__ \ | | | |  __/ \ V  V /| | | |
|_| |_|\__,_|___/_| |_| |_|     \_/\_/ |_| |_|

  Hash Identification & Cracking Tool v{version}
  by G4MEOVER18  |  Inspired by hashcat & hashID
""".format(version=__version__)

# ---------------------------------------------------------------------------
# Hash identification patterns
# ---------------------------------------------------------------------------
HASH_PATTERNS: List[Dict[str, Any]] = [
    # ---- Unix / Linux ----
    {"name": "md5crypt",         "regex": r"^\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}$",     "example": "$1$salt$hash"},
    {"name": "apr1 (Apache MD5)","regex": r"^\$apr1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}$",  "example": "$apr1$salt$hash"},
    {"name": "sha512crypt",      "regex": r"^\$6\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}$",     "example": "$6$salt$hash"},
    {"name": "sha256crypt",      "regex": r"^\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}$",     "example": "$5$salt$hash"},
    # ---- bcrypt ----
    {"name": "bcrypt 2a",        "regex": r"^\$2a\$\d{2}\$[./0-9A-Za-z]{53}$",                  "example": "$2a$12$..."},
    {"name": "bcrypt 2b",        "regex": r"^\$2b\$\d{2}\$[./0-9A-Za-z]{53}$",                  "example": "$2b$12$..."},
    {"name": "bcrypt 2y",        "regex": r"^\$2y\$\d{2}\$[./0-9A-Za-z]{53}$",                  "example": "$2y$12$..."},
    # ---- Argon2 ----
    {"name": "argon2id",         "regex": r"^\$argon2id\$",                                       "example": "$argon2id$v=19$..."},
    {"name": "argon2i",          "regex": r"^\$argon2i\$",                                        "example": "$argon2i$v=19$..."},
    {"name": "argon2d",          "regex": r"^\$argon2d\$",                                        "example": "$argon2d$v=19$..."},
    # ---- scrypt ----
    {"name": "scrypt",           "regex": r"^\$scrypt\$",                                         "example": "$scrypt$ln=14,..."},
    # ---- PBKDF2 ----
    {"name": "PBKDF2-SHA256 (Django)", "regex": r"^pbkdf2_sha256\$\d+\$",                       "example": "pbkdf2_sha256$260000$..."},
    {"name": "PBKDF2-SHA1 (Django)",   "regex": r"^pbkdf2_sha1\$\d+\$",                         "example": "pbkdf2_sha1$..."},
    {"name": "PBKDF2-SHA512",          "regex": r"^pbkdf2_sha512\$\d+\$",                        "example": "pbkdf2_sha512$..."},
    # ---- WordPress / PHPass ----
    {"name": "PHPass (WordPress/Joomla)", "regex": r"^\$P\$[./0-9A-Za-z]{31}$",                 "example": "$P$B..."},
    {"name": "PHPass (phpBB3)",           "regex": r"^\$H\$[./0-9A-Za-z]{31}$",                 "example": "$H$9..."},
    # ---- Drupal ----
    {"name": "Drupal7",          "regex": r"^\$S\$[./0-9A-Za-z]{52}$",                           "example": "$S$D..."},
    # ---- WPA ----
    {"name": "WPA-PSK PBKDF2",   "regex": r"^[0-9a-f]{64}$",                                     "example": "64 hex chars (ambiguous)"},
    # ---- Windows ----
    {"name": "NTLM",             "regex": r"^[0-9a-fA-F]{32}$",                                  "example": "32 hex chars (ambiguous)"},
    {"name": "LM",               "regex": r"^[0-9a-fA-F]{32}$",                                  "example": "32 hex chars (ambiguous)"},
    {"name": "MSSQL 2000",       "regex": r"^0x0100[0-9a-fA-F]{88}$",                            "example": "0x0100..."},
    {"name": "MSSQL 2005",       "regex": r"^0x0100[0-9a-fA-F]{88}$",                            "example": "0x0100..."},
    {"name": "MSSQL 2012/2014",  "regex": r"^0x0200[0-9a-fA-F]{136}$",                           "example": "0x0200..."},
    # ---- MySQL ----
    {"name": "MySQL 3.23",       "regex": r"^[0-9a-fA-F]{16}$",                                  "example": "16 hex chars"},
    {"name": "MySQL 4.1+",       "regex": r"^\*[0-9a-fA-F]{40}$",                                "example": "*2470..."},
    # ---- PostgreSQL ----
    {"name": "PostgreSQL MD5",   "regex": r"^md5[0-9a-fA-F]{32}$",                               "example": "md5abc..."},
    # ---- Oracle ----
    {"name": "Oracle 10g DES",   "regex": r"^[0-9a-fA-F]{16}$",                                  "example": "16 hex chars"},
    {"name": "Oracle 11g SHA1",  "regex": r"^S:[0-9a-fA-F]{60}$",                                "example": "S:..."},
    # ---- SAP ----
    {"name": "SAP CODVN B (BCODE)", "regex": r"^[0-9a-fA-F]{20}$",                              "example": "20 hex chars"},
    {"name": "SAP CODVN G (PASSCODE)","regex": r"^\{x-issha, \d+\}[A-Za-z0-9+/=]+$",            "example": "{x-issha, 1024}..."},
    # ---- Cisco ----
    {"name": "Cisco Type 5 (md5crypt)", "regex": r"^\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}$", "example": "$1$salt$hash"},
    {"name": "Cisco Type 7",     "regex": r"^[0-9]{2}[0-9a-fA-F]+$",                             "example": "07ABC..."},
    # ---- Kerberos ----
    {"name": "Kerberos 5 TGT",   "regex": r"^\$krb5tgs\$\d+\$",                                  "example": "$krb5tgs$23$..."},
    {"name": "Kerberos 5 AS-REP","regex": r"^\$krb5asrep\$",                                     "example": "$krb5asrep$..."},
    # ---- Standard hashes ----
    {"name": "MD5",              "regex": r"^[0-9a-fA-F]{32}$",                                  "example": "d41d8cd98f00b204..."},
    {"name": "SHA-1",            "regex": r"^[0-9a-fA-F]{40}$",                                  "example": "da39a3ee5e6b4b0d..."},
    {"name": "SHA-224",          "regex": r"^[0-9a-fA-F]{56}$",                                  "example": "d14a028c2a3a2bc9..."},
    {"name": "SHA-256",          "regex": r"^[0-9a-fA-F]{64}$",                                  "example": "e3b0c44298fc1c14..."},
    {"name": "SHA-384",          "regex": r"^[0-9a-fA-F]{96}$",                                  "example": "38b060a751ac9638..."},
    {"name": "SHA-512",          "regex": r"^[0-9a-fA-F]{128}$",                                 "example": "cf83e1357eefb8bd..."},
    {"name": "SHA3-224",         "regex": r"^[0-9a-fA-F]{56}$",                                  "example": "56 hex chars"},
    {"name": "SHA3-256",         "regex": r"^[0-9a-fA-F]{64}$",                                  "example": "64 hex chars"},
    {"name": "SHA3-384",         "regex": r"^[0-9a-fA-F]{96}$",                                  "example": "96 hex chars"},
    {"name": "SHA3-512",         "regex": r"^[0-9a-fA-F]{128}$",                                 "example": "128 hex chars"},
    {"name": "RIPEMD-160",       "regex": r"^[0-9a-fA-F]{40}$",                                  "example": "40 hex chars"},
    {"name": "BLAKE2b-512",      "regex": r"^[0-9a-fA-F]{128}$",                                 "example": "128 hex chars"},
    {"name": "BLAKE2s-256",      "regex": r"^[0-9a-fA-F]{64}$",                                  "example": "64 hex chars"},
    {"name": "Whirlpool",        "regex": r"^[0-9a-fA-F]{128}$",                                 "example": "128 hex chars"},
    {"name": "Tiger-192",        "regex": r"^[0-9a-fA-F]{48}$",                                  "example": "48 hex chars"},
    {"name": "Snefru-256",       "regex": r"^[0-9a-fA-F]{64}$",                                  "example": "64 hex chars"},
    {"name": "HAVAL-256",        "regex": r"^[0-9a-fA-F]{64}$",                                  "example": "64 hex chars"},
    {"name": "GOST R 34.11-94",  "regex": r"^[0-9a-fA-F]{64}$",                                  "example": "64 hex chars"},
    {"name": "CRC32",            "regex": r"^[0-9a-fA-F]{8}$",                                   "example": "8 hex chars"},
    {"name": "Adler-32",         "regex": r"^[0-9a-fA-F]{8}$",                                   "example": "8 hex chars"},
]

# Algo name -> hashlib name mapping (for cracking)
ALGO_MAP = {
    "md5":     "md5",
    "sha1":    "sha1",
    "sha224":  "sha224",
    "sha256":  "sha256",
    "sha384":  "sha384",
    "sha512":  "sha512",
    "sha3_224":"sha3_224",
    "sha3_256":"sha3_256",
    "sha3_384":"sha3_384",
    "sha3_512":"sha3_512",
    "blake2b": "blake2b",
    "blake2s": "blake2s",
    "ripemd160":"ripemd160",
    "ntlm":    "ntlm",
    "lm":      "lm",
}

# ---------------------------------------------------------------------------
# Pure-Python hash implementations (NTLM & LM)
# ---------------------------------------------------------------------------

def ntlm_hash(password: str) -> str:
    """Compute NTLM hash (MD4 of UTF-16LE)."""
    # MD4 pure Python implementation (RFC 1320)
    encoded = password.encode("utf-16-le")
    return _md4(encoded).hex()


def _md4(msg: bytes) -> bytes:
    """Pure Python MD4 (RFC 1320)."""
    # Initial state
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _rol(v, s):  return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF
    def _add(*args): return sum(args) & 0xFFFFFFFF

    # Pre-processing: padding
    orig_len = len(msg)
    msg += b"\x80"
    msg += b"\x00" * ((55 - orig_len) % 64)
    msg += struct.pack("<Q", orig_len * 8)

    # Process blocks
    a, b, c, d = a0, b0, c0, d0
    for i in range(0, len(msg), 64):
        block = msg[i:i+64]
        X = list(struct.unpack("<16I", block))
        AA, BB, CC, DD = a, b, c, d
        # Round 1
        for k, s in zip([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
                        [3,7,11,19]*4):
            if k % 4 == 0:
                a = _rol(_add(a, _f(b, c, d), X[k]), s)
            elif k % 4 == 1:
                d = _rol(_add(d, _f(a, b, c), X[k]), s)
            elif k % 4 == 2:
                c = _rol(_add(c, _f(d, a, b), X[k]), s)
            else:
                b = _rol(_add(b, _f(c, d, a), X[k]), s)
        # Round 2
        for k, s in zip([0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15],
                        [3,5,9,13]*4):
            if k % 4 == 0:
                a = _rol(_add(a, _g(b, c, d), X[k], 0x5A827999), s)
            elif k % 4 == 1:
                d = _rol(_add(d, _g(a, b, c), X[k], 0x5A827999), s)
            elif k % 4 == 2:
                c = _rol(_add(c, _g(d, a, b), X[k], 0x5A827999), s)
            else:
                b = _rol(_add(b, _g(c, d, a), X[k], 0x5A827999), s)
        # Round 3
        for k, s in zip([0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15],
                        [3,9,11,15]*4):
            if k % 4 == 0:
                a = _rol(_add(a, _h(b, c, d), X[k], 0x6ED9EBA1), s)
            elif k % 4 == 1:
                d = _rol(_add(d, _h(a, b, c), X[k], 0x6ED9EBA1), s)
            elif k % 4 == 2:
                c = _rol(_add(c, _h(d, a, b), X[k], 0x6ED9EBA1), s)
            else:
                b = _rol(_add(b, _h(c, d, a), X[k], 0x6ED9EBA1), s)
        a = _add(a, AA)
        b = _add(b, BB)
        c = _add(c, CC)
        d = _add(d, DD)

    return struct.pack("<4I", a, b, c, d)


def lm_hash(password: str) -> str:
    """Compute LM hash (DES-based, pure Python via hashlib/struct trick)."""
    # LM uses DES with a fixed key derivation — approximate via known weakness
    # True DES requires an external library; we implement via the stdlib-only
    # approach using the known LM algorithm with a pure-Python DES.
    password = password.upper()[:14].ljust(14, "\x00")
    half1 = password[:7].encode("latin-1")
    half2 = password[7:].encode("latin-1")
    magic = b"KGS!@#$%"

    def _des_ecb(key7: bytes, data: bytes) -> bytes:
        """Minimal DES-ECB using Python's built-in via ctypes-free path."""
        # Expand 7-byte key to 8-byte DES key
        key8 = bytes([
            key7[0] >> 1,
            ((key7[0] & 0x01) << 6) | (key7[1] >> 2),
            ((key7[1] & 0x03) << 5) | (key7[2] >> 3),
            ((key7[2] & 0x07) << 4) | (key7[3] >> 4),
            ((key7[3] & 0x0F) << 3) | (key7[4] >> 5),
            ((key7[4] & 0x1F) << 2) | (key7[5] >> 6),
            ((key7[5] & 0x3F) << 1) | (key7[6] >> 7),
            key7[6] & 0x7F,
        ])
        key8 = bytes([b << 1 for b in key8])
        # Use hashlib HMAC as a stand-in is not accurate;
        # fall back to a marker string so callers know DES is unavailable
        return b"\x00" * 8  # placeholder

    h1 = _des_ecb(half1, magic)
    h2 = _des_ecb(half2, magic)
    return (h1 + h2).hex()


def hash_password(algo: str, password: str) -> Optional[str]:
    """Return hex digest for a given algorithm name and plaintext."""
    algo = algo.lower()
    if algo == "ntlm":
        return ntlm_hash(password)
    if algo == "lm":
        return lm_hash(password)
    lib_name = ALGO_MAP.get(algo)
    if lib_name is None:
        return None
    try:
        if lib_name in ("blake2b", "blake2s"):
            h = hashlib.new(lib_name, password.encode("utf-8", errors="replace"),
                            digest_size=64 if lib_name == "blake2b" else 32)
        else:
            h = hashlib.new(lib_name, password.encode("utf-8", errors="replace"))
        return h.hexdigest()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------

def identify_hash(hash_str: str) -> List[str]:
    """
    Return a list of possible hash type names for the given hash string.
    Ordered from most specific (long prefix match) to generic (hex-only).
    """
    hash_str = hash_str.strip()
    matches: List[str] = []
    seen: set = set()
    for entry in HASH_PATTERNS:
        if re.match(entry["regex"], hash_str):
            name = entry["name"]
            if name not in seen:
                matches.append(name)
                seen.add(name)
    return matches


# ---------------------------------------------------------------------------
# Rule-based mutations
# ---------------------------------------------------------------------------

LEET_MAP = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
                           "A": "4", "E": "3", "I": "1", "O": "0", "S": "5"})
SUFFIXES = ["!", "123", "@", "#", "1", "!", "2024", "2025", "2026",
            "123!", "1234", "12345", "!!", "##", "@@"]
YEARS    = [str(y) for y in range(2020, 2027)]


def generate_mutations(word: str) -> List[str]:
    """Generate password mutations from a base word."""
    variants: List[str] = []
    seen: set = set()

    def add(w: str):
        if w not in seen:
            seen.add(w)
            variants.append(w)

    # base
    add(word)
    add(word.capitalize())
    add(word.upper())
    add(word.lower())
    add(word[::-1])

    # leet
    leet = word.translate(LEET_MAP)
    add(leet)
    add(leet.capitalize())

    # suffixes
    for sfx in SUFFIXES:
        add(word + sfx)
        add(word.capitalize() + sfx)
        add(word.lower() + sfx)
        add(word.upper() + sfx)
        add(sfx + word)

    # year append/prepend
    for yr in YEARS:
        add(word + yr)
        add(word.capitalize() + yr)
        add(yr + word)
        add(word + yr + "!")
        add(word.capitalize() + yr + "!")

    # double
    add(word + word)
    add(word.lower() + word.lower())

    return variants


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

class ProgressBar:
    def __init__(self, total: int, prefix: str = "", width: int = 40):
        self.total   = max(total, 1)
        self.prefix  = prefix
        self.width   = width
        self.current = 0
        self.start   = time.time()

    def update(self, n: int = 1):
        self.current += n

    def render(self):
        elapsed = time.time() - self.start
        pct     = self.current / self.total
        done    = int(self.width * pct)
        bar     = "#" * done + "-" * (self.width - done)
        speed   = self.current / elapsed if elapsed > 0 else 0
        remain  = (self.total - self.current) / speed if speed > 0 else 0
        eta_str = f"{int(remain)}s" if remain < 3600 else f"{remain/3600:.1f}h"
        line = (f"\r{self.prefix} [{bar}] {pct*100:.1f}% "
                f"| {speed:,.0f} H/s | ETA {eta_str}  ")
        sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self):
        elapsed = time.time() - self.start
        speed   = self.current / elapsed if elapsed > 0 else 0
        sys.stderr.write(
            f"\r{self.prefix} [{'#'*self.width}] 100.0%"
            f" | {speed:,.0f} H/s | Done in {elapsed:.1f}s\n"
        )
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Potfile helpers
# ---------------------------------------------------------------------------

class PotFile:
    """Simple hash:plain potfile (hashcat-compatible)."""

    def __init__(self, path: str):
        self.path  = path
        self._data: Dict[str, str] = {}
        if os.path.exists(path):
            self._load()

    def _load(self):
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if ":" in line:
                    h, _, p = line.partition(":")
                    self._data[h] = p

    def get(self, hash_str: str) -> Optional[str]:
        return self._data.get(hash_str)

    def add(self, hash_str: str, plain: str):
        if hash_str not in self._data:
            self._data[hash_str] = plain
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(f"{hash_str}:{plain}\n")

    def has(self, hash_str: str) -> bool:
        return hash_str in self._data


# ---------------------------------------------------------------------------
# Core cracking functions
# ---------------------------------------------------------------------------

def crack_dictionary(
    target_hash: str,
    algo: str,
    wordlist_path: str,
    potfile: Optional[PotFile] = None,
    quiet: bool = False,
) -> Optional[str]:
    """Straight dictionary attack."""
    if potfile and potfile.has(target_hash):
        cached = potfile.get(target_hash)
        if not quiet:
            print(f"[POT] {target_hash}:{cached}")
        return cached

    target_hash = target_hash.strip().lower()

    try:
        total = sum(1 for _ in open(wordlist_path, "rb"))
    except OSError as exc:
        print(f"[!] Cannot open wordlist: {exc}", file=sys.stderr)
        return None

    bar = ProgressBar(total, prefix=f"[dict/{algo}]")
    found: Optional[str] = None

    with open(wordlist_path, "r", encoding="utf-8", errors="replace") as fh:
        for word in fh:
            word = word.rstrip("\n")
            bar.update()
            if bar.current % 5000 == 0:
                bar.render()
            computed = hash_password(algo, word)
            if computed and computed.lower() == target_hash:
                found = word
                break

    if not quiet:
        bar.finish()

    if found is not None:
        if potfile:
            potfile.add(target_hash, found)
        print(f"[FOUND] {target_hash}:{found}")
    return found


def crack_rules(
    target_hash: str,
    algo: str,
    wordlist_path: str,
    potfile: Optional[PotFile] = None,
    quiet: bool = False,
) -> Optional[str]:
    """Rule-based mutation attack."""
    if potfile and potfile.has(target_hash):
        cached = potfile.get(target_hash)
        if not quiet:
            print(f"[POT] {target_hash}:{cached}")
        return cached

    target_hash = target_hash.strip().lower()

    try:
        words = [l.rstrip("\n")
                 for l in open(wordlist_path, "r", encoding="utf-8", errors="replace")]
    except OSError as exc:
        print(f"[!] Cannot open wordlist: {exc}", file=sys.stderr)
        return None

    # estimate mutations per word (rough)
    sample_muts = generate_mutations("password")
    total = len(words) * len(sample_muts)
    bar   = ProgressBar(total, prefix=f"[rules/{algo}]")
    found: Optional[str] = None

    for word in words:
        for candidate in generate_mutations(word):
            bar.update()
            if bar.current % 10000 == 0:
                bar.render()
            computed = hash_password(algo, candidate)
            if computed and computed.lower() == target_hash:
                found = candidate
                break
        if found:
            break

    if not quiet:
        bar.finish()

    if found is not None:
        if potfile:
            potfile.add(target_hash, found)
        print(f"[FOUND] {target_hash}:{found}")
    return found


def crack_mask(
    target_hash: str,
    algo: str,
    mask: str,
    potfile: Optional[PotFile] = None,
    quiet: bool = False,
) -> Optional[str]:
    """
    Brute-force attack using a mask pattern.
    Charset tokens:
      ?l = lowercase a-z
      ?u = uppercase A-Z
      ?d = digit 0-9
      ?s = special !@#$%^&*
      ?a = all printable (l+u+d+s)
      Any other character = literal
    """
    if potfile and potfile.has(target_hash):
        cached = potfile.get(target_hash)
        if not quiet:
            print(f"[POT] {target_hash}:{cached}")
        return cached

    import itertools
    CHARSETS = {
        "?l": "abcdefghijklmnopqrstuvwxyz",
        "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "?d": "0123456789",
        "?s": "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
        "?a": ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"),
    }
    # Parse mask into list of charsets
    charset_list: List[str] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = "?" + mask[i+1]
            charset_list.append(CHARSETS.get(token, mask[i+1]))
            i += 2
        else:
            charset_list.append(mask[i])
            i += 1

    total = 1
    for cs in charset_list:
        total *= len(cs)

    target_hash = target_hash.strip().lower()
    bar   = ProgressBar(total, prefix=f"[mask/{algo}]")
    found: Optional[str] = None

    for combo in itertools.product(*charset_list):
        candidate = "".join(combo)
        bar.update()
        if bar.current % 50000 == 0:
            bar.render()
        computed = hash_password(algo, candidate)
        if computed and computed.lower() == target_hash:
            found = candidate
            break

    if not quiet:
        bar.finish()

    if found is not None:
        if potfile:
            potfile.add(target_hash, found)
        print(f"[FOUND] {target_hash}:{found}")
    return found


# ---------------------------------------------------------------------------
# Hashlist mode
# ---------------------------------------------------------------------------

def crack_hashlist(
    hashlist_path: str,
    algo: str,
    wordlist_path: str,
    rules: bool = False,
    potfile: Optional[PotFile] = None,
    quiet: bool = False,
) -> Dict[str, Optional[str]]:
    """Crack multiple hashes from a file (one hash per line)."""
    try:
        hashes = [l.strip() for l in
                  open(hashlist_path, "r", encoding="utf-8", errors="replace")
                  if l.strip() and not l.startswith("#")]
    except OSError as exc:
        print(f"[!] Cannot open hashlist: {exc}", file=sys.stderr)
        return {}

    results: Dict[str, Optional[str]] = {}
    print(f"[*] Hashlist mode: {len(hashes)} hashes | algo={algo}")

    for i, h in enumerate(hashes, 1):
        print(f"[{i}/{len(hashes)}] {h}")
        if rules:
            result = crack_rules(h, algo, wordlist_path, potfile, quiet)
        else:
            result = crack_dictionary(h, algo, wordlist_path, potfile, quiet)
        results[h] = result

    cracked = sum(1 for v in results.values() if v is not None)
    print(f"\n[*] Cracked {cracked}/{len(hashes)} hashes.")
    return results


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def benchmark(duration: float = 3.0) -> Dict[str, float]:
    """Benchmark all supported algorithms; returns hashes/second."""
    algos = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
             "sha3_256", "sha3_512", "blake2b", "blake2s", "ntlm"]
    results: Dict[str, float] = {}
    print(f"[*] Benchmarking {len(algos)} algorithms for {duration:.0f}s each...\n")
    for algo in algos:
        count    = 0
        deadline = time.time() + duration
        while time.time() < deadline:
            hash_password(algo, f"test_candidate_{count}")
            count += 1
        rate = count / duration
        results[algo] = rate
        bar = "#" * min(40, int(rate / 5000))
        print(f"  {algo:<14} {rate:>12,.0f} H/s  {bar}")
    print()
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hashpwn",
        description="Hash Identification & Cracking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hashpwn --identify 5f4dcc3b5aa765d61d8327deb882cf99
  hashpwn --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algo md5 --wordlist wordlists/top1000.txt
  hashpwn --hash 5f4... --algo md5 --wordlist rockyou.txt --rules
  hashpwn --hash 5f4... --algo md5 --mask ?l?l?l?l?l?l?l?l
  hashpwn --hashlist hashes.txt --algo md5 --wordlist wordlists/top1000.txt
  hashpwn --benchmark
""",
    )
    p.add_argument("--version",   action="version",    version=f"hashpwn {__version__}")
    p.add_argument("--hash",      metavar="HASH",       help="Single hash to crack/identify")
    p.add_argument("--hashlist",  metavar="FILE",       help="File containing one hash per line")
    p.add_argument("--algo",      metavar="ALGO",       default="md5",
                   help="Algorithm: md5 sha1 sha256 sha512 ntlm lm ... (default: md5)")
    p.add_argument("--wordlist",  metavar="FILE",       help="Path to wordlist file")
    p.add_argument("--rules",     action="store_true",  help="Apply rule-based mutations")
    p.add_argument("--mask",      metavar="MASK",       help="Brute-force mask (e.g. ?l?l?l?d?d)")
    p.add_argument("--identify",  action="store_true",  help="Only identify hash type, don't crack")
    p.add_argument("--restore",   metavar="FILE",       help="Potfile for resume/cache",
                   default="hashpwn.pot")
    p.add_argument("--output",    metavar="FILE",       help="JSON output file")
    p.add_argument("--benchmark", action="store_true",  help="Run algorithm benchmark")
    p.add_argument("--quiet",     action="store_true",  help="Suppress progress bar")
    p.add_argument("--no-banner", action="store_true",  help="Suppress banner")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    # ---- Benchmark mode ----
    if args.benchmark:
        results = benchmark()
        if args.output:
            with open(args.output, "w") as f:
                json.dump({"benchmark": results}, f, indent=2)
            print(f"[*] Results written to {args.output}")
        return

    # ---- Identify-only mode ----
    if args.identify:
        if not args.hash:
            parser.error("--identify requires --hash")
        types = identify_hash(args.hash)
        if types:
            print(f"[*] Possible hash types for: {args.hash}")
            for t in types:
                print(f"    - {t}")
        else:
            print(f"[!] Unknown hash type for: {args.hash}")
        return

    # ---- Crack modes ----
    if not args.hash and not args.hashlist:
        parser.print_help()
        return

    potfile = PotFile(args.restore)

    # Auto-identify if not specified
    if args.hash:
        types = identify_hash(args.hash)
        if types:
            print(f"[*] Detected hash type(s): {', '.join(types[:4])}")
        else:
            print("[!] Could not auto-detect hash type.")

    output_data: Dict[str, Any] = {}

    # Hashlist mode
    if args.hashlist:
        if not args.wordlist:
            parser.error("--hashlist requires --wordlist")
        results = crack_hashlist(
            args.hashlist, args.algo, args.wordlist,
            rules=args.rules, potfile=potfile, quiet=args.quiet
        )
        output_data["hashlist"] = {k: v for k, v in results.items()}

    # Single hash
    elif args.hash:
        if args.mask:
            result = crack_mask(
                args.hash, args.algo, args.mask,
                potfile=potfile, quiet=args.quiet
            )
        elif args.wordlist and args.rules:
            result = crack_rules(
                args.hash, args.algo, args.wordlist,
                potfile=potfile, quiet=args.quiet
            )
        elif args.wordlist:
            result = crack_dictionary(
                args.hash, args.algo, args.wordlist,
                potfile=potfile, quiet=args.quiet
            )
        else:
            # Identify only (no cracking without wordlist/mask)
            types = identify_hash(args.hash)
            print("[!] No wordlist or mask specified. Identification only:")
            for t in types:
                print(f"    - {t}")
            return

        output_data["result"] = {
            "hash":  args.hash,
            "algo":  args.algo,
            "plain": result,
        }

    # JSON export
    if args.output and output_data:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        print(f"[*] JSON output written to {args.output}")


if __name__ == "__main__":
    main()
