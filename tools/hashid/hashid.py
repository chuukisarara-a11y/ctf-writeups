#!/usr/bin/env python3
"""hashid — 哈希类型识别工具（仅依赖标准库）。

根据前缀、长度、字符集等特征给出"可能的哈希类型"候选列表，
并附带 hashcat 模式号与 John the Ripper 格式名，方便直接进入爆破环节。

对无盐的原始摘要（MD5/SHA*/NTLM 等），还可以用 --try 给出候选明文
或 --wordlist 跑一个小字典做快速验证——CTF 中经常一步出 flag。

注意：纯十六进制摘要只能按长度推断，同长度的多种算法无法区分，
因此结果按"常见程度"排序，而不是给出唯一答案。
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, asdict


@dataclass
class Candidate:
    name: str
    hashcat: int | None = None
    john: str | None = None
    note: str = ""
    verifiable: bool = False  # 是否支持 --try 本地验证


@dataclass
class Rule:
    pattern: re.Pattern
    candidates: list[Candidate]


def R(regex: str, *cands: Candidate, flags: int = 0) -> Rule:
    return Rule(re.compile(regex, flags), list(cands))


C = Candidate
HEX = "[a-fA-F0-9]"

# 先匹配带结构/前缀的格式（唯一性高），再匹配纯十六进制（只能按长度猜）
RULES: list[Rule] = [
    R(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$",
      C("bcrypt", 3200, "bcrypt", "Blowfish，cost 因子在第二段")),
    R(r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$",
      C("Argon2", 34000, "argon2", "现代 KDF，GPU 爆破极慢")),
    R(r"^\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$",
      C("yescrypt", None, "crypt", "新版 Debian/Ubuntu /etc/shadow 默认")),
    R(r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$",
      C("sha512crypt (Unix $6$)", 1800, "sha512crypt", "Linux /etc/shadow")),
    R(r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$",
      C("sha256crypt (Unix $5$)", 7400, "sha256crypt")),
    R(r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$",
      C("md5crypt (Unix $1$)", 500, "md5crypt", "老 Linux / Cisco IOS type 5")),
    R(r"^\$apr1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$",
      C("Apache apr1 MD5", 1600, "md5crypt", ".htpasswd")),
    R(r"^\$[PH]\$[./A-Za-z0-9]{31}$",
      C("phpass (WordPress/phpBB3)", 400, "phpass")),
    R(r"^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$",
      C("Django PBKDF2-SHA256", 10000, "django")),
    R(r"^sha1\$[^$]+\$" + HEX + r"{40}$",
      C("Django SHA1 (旧版)", 124, None)),
    R(r"^\$krb5tgs\$23\$.+",
      C("Kerberos 5 TGS-REP etype 23 (Kerberoasting)", 13100, "krb5tgs")),
    R(r"^\$krb5asrep\$23\$.+",
      C("Kerberos 5 AS-REP etype 23 (AS-REP Roasting)", 18200, "krb5asrep")),
    R(r"^[^:]+::[^:]*:" + HEX + r"{16}:" + HEX + r"{32}:" + HEX + r"+$",
      C("NetNTLMv2", 5600, "netntlmv2", "Responder 抓到的格式")),
    R(r"^\*" + HEX + r"{40}$",
      C("MySQL 4.1+ (SHA1(SHA1(p)))", 300, "mysql-sha1")),
    R(r"^0x0100" + HEX + r"{48}$",
      C("MSSQL 2005", 132, "mssql05")),
    R(r"^0x0200" + HEX + r"{136}$",
      C("MSSQL 2012/2014", 1731, "mssql12")),
    R(r"^\{SSHA\}[A-Za-z0-9+/=]+$",
      C("LDAP SSHA (salted SHA1)", 111, "salted-sha1")),
    R(r"^\{SHA\}[A-Za-z0-9+/=]{28}$",
      C("LDAP SHA1 (base64)", 101, "nsldap")),
    R(r"^" + HEX + r"{32}:" + HEX + r"{32}$",
      C("LM:NTLM (pwdump/secretsdump)", 1000, "nt", "冒号后半段是 NTLM，可直接爆破")),
    R(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$",
      C("JWT (HS256 等)", 16500, None, "不是哈希；HS* 签名可用 hashcat 16500 爆破密钥")),
    # ---- 纯十六进制，只能按长度猜 ----
    R(r"^" + HEX + r"{8}$",
      C("CRC32", 11500, "crc32", "校验和，非密码学哈希"),
      C("Adler-32", None, None)),
    R(r"^" + HEX + r"{16}$",
      C("MySQL 3.2.3 (OLD_PASSWORD)", 200, "mysql"),
      C("Half MD5", 5100, None),
      C("CRC64", None, None)),
    R(r"^" + HEX + r"{32}$",
      C("MD5", 0, "raw-md5", verifiable=True),
      C("NTLM", 1000, "nt", "Windows 本地账户；= MD4(UTF-16LE(p))", verifiable=True),
      C("MD4", 900, "raw-md4", verifiable=True),
      C("LM", 3000, "lm", "若后半段为 aad3b435b51404ee 说明密码 ≤7 位"),
      C("md5(md5(p))", 2600, None, verifiable=True)),
    R(r"^" + HEX + r"{40}$",
      C("SHA-1", 100, "raw-sha1", verifiable=True),
      C("RIPEMD-160", 6000, "ripemd-160", verifiable=True),
      C("sha1(sha1(p))", 4500, None, verifiable=True)),
    R(r"^" + HEX + r"{56}$",
      C("SHA-224", 1300, "raw-sha224", verifiable=True),
      C("SHA3-224", 17300, None, verifiable=True)),
    R(r"^" + HEX + r"{64}$",
      C("SHA-256", 1400, "raw-sha256", verifiable=True),
      C("SHA3-256", 17400, "raw-sha3", verifiable=True),
      C("BLAKE2s-256", None, None, verifiable=True),
      C("SM3", None, None, "国密", verifiable=True)),
    R(r"^" + HEX + r"{96}$",
      C("SHA-384", 10800, "raw-sha384", verifiable=True),
      C("SHA3-384", 17500, None, verifiable=True)),
    R(r"^" + HEX + r"{128}$",
      C("SHA-512", 1700, "raw-sha512", verifiable=True),
      C("SHA3-512", 17600, None, verifiable=True),
      C("BLAKE2b-512", 600, None, verifiable=True),
      C("Whirlpool", 6100, "whirlpool")),
]


# ---------------------------------------------------------------------------
# MD4：OpenSSL 3 默认禁用了 MD4，hashlib 可能不可用，这里提供纯 Python 实现
# 以支持 NTLM 的本地验证。仅用于 CTF/审计，不追求性能。
# ---------------------------------------------------------------------------
def _md4(data: bytes) -> bytes:
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, TypeError):
        pass

    def lrot(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    bitlen = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    F = lambda x, y, z: (x & y) | (~x & z)
    G = lambda x, y, z: (x & y) | (x & z) | (y & z)
    H = lambda x, y, z: x ^ y ^ z

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = lrot(a + F(b, c, d) + X[i], 3)
            d = lrot(d + F(a, b, c) + X[i + 1], 7)
            c = lrot(c + F(d, a, b) + X[i + 2], 11)
            b = lrot(b + F(c, d, a) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = lrot(a + G(b, c, d) + X[i] + 0x5A827999, 3)
            d = lrot(d + G(a, b, c) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + G(d, a, b) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + G(c, d, a) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = lrot(a + H(b, c, d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + H(a, b, c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + H(d, a, b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + H(c, d, a) + X[i + 12] + 0x6ED9EBA1, 15)
        a, b, c, d = [(v + w) & 0xFFFFFFFF for v, w in ((a, aa), (b, bb), (c, cc), (d, dd))]

    return struct.pack("<4I", a, b, c, d)


def _hl(name: str):
    return lambda p: hashlib.new(name, p).hexdigest()


VERIFIERS = {
    "MD5": _hl("md5"),
    "NTLM": lambda p: _md4(p.decode("utf-8", "ignore").encode("utf-16le")).hex(),
    "MD4": lambda p: _md4(p).hex(),
    "md5(md5(p))": lambda p: hashlib.md5(hashlib.md5(p).hexdigest().encode()).hexdigest(),
    "SHA-1": _hl("sha1"),
    "RIPEMD-160": _hl("ripemd160"),
    "sha1(sha1(p))": lambda p: hashlib.sha1(hashlib.sha1(p).hexdigest().encode()).hexdigest(),
    "SHA-224": _hl("sha224"),
    "SHA3-224": _hl("sha3_224"),
    "SHA-256": _hl("sha256"),
    "SHA3-256": _hl("sha3_256"),
    "BLAKE2s-256": _hl("blake2s"),
    "SM3": _hl("sm3"),
    "SHA-384": _hl("sha384"),
    "SHA3-384": _hl("sha3_384"),
    "SHA-512": _hl("sha512"),
    "SHA3-512": _hl("sha3_512"),
    "BLAKE2b-512": _hl("blake2b"),
}


def identify(h: str) -> list[Candidate]:
    h = h.strip()
    out: list[Candidate] = []
    for rule in RULES:
        if rule.pattern.match(h):
            out.extend(rule.candidates)
    if not out:
        out.extend(_guess_encoded(h))
    return out


def _guess_encoded(s: str) -> list[Candidate]:
    """不像已知哈希时，检查是否是 Base64 包装后的原始摘要。"""
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) or len(s) % 4:
        return []
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return []
    sizes = {16: "MD5/NTLM", 20: "SHA-1", 28: "SHA-224", 32: "SHA-256",
             48: "SHA-384", 64: "SHA-512"}
    if len(raw) in sizes:
        return [C(f"Base64({sizes[len(raw)]})", None, None,
                  f"解码后的十六进制: {raw.hex()}，可再次识别")]
    return []


def try_plaintexts(h: str, cands: list[Candidate], words) -> list[tuple[str, str]]:
    """对可验证的候选算法逐一尝试明文，返回 (算法, 明文) 命中列表。"""
    target = h.strip().lower()
    algos = [(c.name, VERIFIERS[c.name]) for c in cands
             if c.verifiable and c.name in VERIFIERS]
    working = []
    for name, fn in algos:
        try:
            fn(b"")
            working.append((name, fn))
        except (ValueError, TypeError):
            continue  # 当前环境不支持该算法（如缺少 sm3）
    hits = []
    for w in words:
        wb = w.encode("utf-8") if isinstance(w, str) else w
        for name, fn in working:
            if fn(wb) == target:
                hits.append((name, wb.decode("utf-8", "replace")))
    return hits


def _iter_wordlist(path: str):
    with open(path, "rb") as f:
        for line in f:
            yield line.rstrip(b"\r\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="哈希类型识别（附 hashcat / john 格式）")
    ap.add_argument("hash", nargs="*", help="待识别的哈希；省略则从 -f 或标准输入读取")
    ap.add_argument("-f", "--file", help="每行一个哈希的文件（支持 user:hash 形式）")
    ap.add_argument("--try", dest="trial", action="append", default=[],
                    help="候选明文，可多次指定，用于验证无盐摘要")
    ap.add_argument("-w", "--wordlist", help="小字典文件，逐行尝试（适合 CTF，大字典请用 hashcat）")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    args = ap.parse_args(argv)

    items: list[str] = list(args.hash)
    if args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as f:
            items += [l.strip() for l in f if l.strip()]
    if not items and not sys.stdin.isatty():
        items += [l.strip() for l in sys.stdin if l.strip()]
    if not items:
        ap.error("请提供至少一个哈希")

    results = []
    for raw in items:
        h = raw
        # 兼容 "user:hash" 形式（/etc/shadow、dump 输出），但保留 LM:NTLM / NetNTLMv2 原样
        if not identify(h) and ":" in h:
            parts = h.split(":")
            for p in parts[1:]:
                if p and identify(p):
                    h = p
                    break
        cands = identify(h)
        hits = []
        if args.trial or args.wordlist:
            words = list(args.trial)
            if args.wordlist:
                words = list(words) + list(_iter_wordlist(args.wordlist))
            hits = try_plaintexts(h, cands, words)
        results.append({"input": raw, "hash": h,
                        "candidates": [asdict(c) for c in cands],
                        "cracked": [{"algorithm": a, "plaintext": p} for a, p in hits]})

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0

    for r in results:
        print(f"\n[*] {r['hash']}")
        if not r["candidates"]:
            print("    未识别：可能是自定义编码、加盐拼接或截断的哈希")
            continue
        for i, c in enumerate(r["candidates"]):
            tag = "最可能" if i == 0 else "可能  "
            meta = []
            if c["hashcat"] is not None:
                meta.append(f"hashcat -m {c['hashcat']}")
            if c["john"]:
                meta.append(f"john --format={c['john']}")
            line = f"    [{tag}] {c['name']}"
            if meta:
                line += f"  ({', '.join(meta)})"
            print(line)
            if c["note"]:
                print(f"             {c['note']}")
        for hit in r["cracked"]:
            print(f"    [+] 命中! {hit['algorithm']}: {hit['plaintext']!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
