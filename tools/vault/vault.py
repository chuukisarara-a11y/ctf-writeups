#!/usr/bin/env python3
"""vault — 本地加密密码保险库。

加密方案：
    主密码 --scrypt(N=2^17, r=8, p=1, 16B 随机盐)--> 256 位密钥
    整个条目库 JSON --AES-256-GCM(96 位随机 nonce, 文件头作为 AAD)--> 密文

- 唯一的第三方依赖是 cryptography（AES-GCM）。标准库没有 AES，
  而自己实现分组密码是密码学大忌，所以这里不追求"零依赖"。
- 每次保存都重新生成 nonce；修改主密码时同时更换盐。
- GCM 认证标签保证完整性：主密码错误和文件被篡改都会解密失败。
- 写入采用"临时文件 + fsync + os.replace"的原子替换，文件权限 0600，
  并保留上一版本 .bak，避免写到一半断电导致整个库损坏。
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import shutil
import secrets
import string
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.exit("需要 cryptography 库：pip install cryptography")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pwcheck"))
import pwcheck  # noqa: E402

FORMAT = "ctfvault"
VERSION = 1
DEFAULT_KDF = {"name": "scrypt", "n": 2 ** 17, "r": 8, "p": 1}
DEFAULT_PATH = os.environ.get("VAULT_FILE", os.path.expanduser("~/.ctfvault.json"))
FIELDS = ("username", "password", "url", "notes")
MIN_MASTER_SCORE = 3


class VaultError(Exception):
    pass


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def derive_key(master: str, kdf: dict, salt: bytes) -> bytes:
    if kdf.get("name") != "scrypt":
        raise VaultError(f"不支持的 KDF: {kdf.get('name')}")
    n, r, p = kdf["n"], kdf["r"], kdf["p"]
    if n < 2 ** 14 or n & (n - 1):
        raise VaultError("KDF 参数异常（N 过小或不是 2 的幂），拒绝打开")
    return hashlib.scrypt(master.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=128 * r * n * 2 + 1024 * 1024, dklen=32)


def _aad(header: dict) -> bytes:
    """把文件头（格式、版本、KDF 参数、盐）绑定进认证标签，防止被单独篡改。"""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


class Vault:
    def __init__(self, path: str, key: bytes, header: dict, entries: dict):
        self.path = path
        self._key = key
        self.header = header
        self.entries: dict[str, dict] = entries

    # ---------------------------- 生命周期 ----------------------------
    @classmethod
    def create(cls, path: str, master: str, kdf: dict | None = None) -> "Vault":
        if os.path.exists(path):
            raise VaultError(f"{path} 已存在，不会覆盖")
        kdf = dict(kdf or DEFAULT_KDF)
        salt = secrets.token_bytes(16)
        header = {"format": FORMAT, "version": VERSION, "kdf": kdf, "salt": b64e(salt)}
        v = cls(path, derive_key(master, kdf, salt), header, {})
        v.save()
        return v

    @classmethod
    def open(cls, path: str, master: str) -> "Vault":
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except FileNotFoundError:
            raise VaultError(f"保险库不存在：{path}（先运行 init）") from None
        except json.JSONDecodeError:
            raise VaultError("保险库文件格式损坏") from None
        if doc.get("format") != FORMAT or doc.get("version") != VERSION:
            raise VaultError("不是受支持的保险库文件")
        header = {k: doc[k] for k in ("format", "version", "kdf", "salt")}
        key = derive_key(master, header["kdf"], b64d(header["salt"]))
        try:
            plain = AESGCM(key).decrypt(b64d(doc["nonce"]), b64d(doc["ciphertext"]), _aad(header))
        except InvalidTag:
            raise VaultError("主密码错误，或文件已被篡改") from None
        return cls(path, key, header, json.loads(plain))

    def save(self) -> None:
        nonce = secrets.token_bytes(12)
        plain = json.dumps(self.entries, ensure_ascii=False).encode()
        ct = AESGCM(self._key).encrypt(nonce, plain, _aad(self.header))
        doc = dict(self.header, nonce=b64e(nonce), ciphertext=b64e(ct))

        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".vault-", dir=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(self.path):
                shutil.copy2(self.path, self.path + ".bak")
                os.chmod(self.path + ".bak", 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def change_master(self, new_master: str) -> None:
        salt = secrets.token_bytes(16)
        self.header = dict(self.header, salt=b64e(salt))
        self._key = derive_key(new_master, self.header["kdf"], salt)
        self.save()

    # ---------------------------- 条目操作 ----------------------------
    def resolve(self, name: str) -> str:
        if name in self.entries:
            return name
        matches = [k for k in self.entries if k.lower() == name.lower()]
        if len(matches) == 1:
            return matches[0]
        raise VaultError(f"找不到条目：{name}")

    def add(self, name: str, **fields) -> None:
        if name in self.entries:
            raise VaultError(f"条目已存在：{name}（用 edit 修改）")
        ts = now()
        self.entries[name] = {**{f: fields.get(f) or "" for f in FIELDS},
                              "created": ts, "updated": ts}

    def edit(self, name: str, **fields) -> None:
        e = self.entries[self.resolve(name)]
        changed = {k: v for k, v in fields.items() if k in FIELDS and v is not None}
        if "password" in changed and changed["password"] != e["password"]:
            e.setdefault("history", []).append({"password": e["password"], "until": now()})
            e["history"] = e["history"][-5:]
        e.update(changed)
        e["updated"] = now()

    def remove(self, name: str) -> None:
        del self.entries[self.resolve(name)]

    def search(self, term: str | None = None) -> list[str]:
        names = sorted(self.entries, key=str.lower)
        if not term:
            return names
        t = term.lower()
        return [n for n in names
                if t in n.lower() or t in self.entries[n]["username"].lower()
                or t in self.entries[n]["url"].lower()]

    def audit(self, max_age_days: int = 365) -> list[tuple[str, str]]:
        problems: list[tuple[str, str]] = []
        by_pw: dict[str, list[str]] = {}
        for name, e in self.entries.items():
            pw = e["password"]
            if not pw:
                problems.append((name, "密码为空"))
                continue
            by_pw.setdefault(pw, []).append(name)
            r = pwcheck.analyze(pw)
            if r.score < 3:
                problems.append((name, f"弱密码：{r.score}/4 {r.label}"))
            if any(h["password"] == pw for h in e.get("history", [])):
                problems.append((name, "与历史密码重复"))
            age = datetime.now(timezone.utc) - datetime.fromisoformat(e["updated"])
            if age.days > max_age_days:
                problems.append((name, f"已 {age.days} 天未更换"))
        for names in by_pw.values():
            if len(names) > 1:
                for n in names:
                    others = ", ".join(x for x in names if x != n)
                    problems.append((n, f"与其他条目共用密码：{others}"))
        return sorted(problems, key=lambda p: p[0].lower())


# ---------------------------- 密码生成 ----------------------------
AMBIGUOUS = set("Il1O0o`'\"")


def generate_password(length: int = 20, symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    """用 secrets（CSPRNG）生成随机密码，保证每类字符至少出现一次。"""
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("!@#$%^&*()-_=+[]{};:,.?/")
    if avoid_ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
    if length < len(classes):
        raise VaultError(f"长度至少为 {len(classes)}")
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in cls for ch in pw) for cls in classes):
            return pw


# ---------------------------- 剪贴板 ----------------------------
def _clipboard_cmds() -> tuple[list[str], list[str]] | None:
    """返回 (复制命令, 读取命令)；没有可用剪贴板时返回 None。"""
    candidates = [
        (["pbcopy"], ["pbpaste"]),
        (["wl-copy"], ["wl-paste", "-n"]),
        (["xclip", "-selection", "clipboard"], ["xclip", "-selection", "clipboard", "-o"]),
        (["xsel", "-b", "-i"], ["xsel", "-b", "-o"]),
        (["clip.exe"], ["powershell.exe", "-NoProfile", "-Command", "Get-Clipboard"]),
    ]
    for copy, paste in candidates:
        if shutil.which(copy[0]):
            return copy, paste
    return None


# 子进程脚本：从 stdin 读取密码的哈希（密码本身不经过命令行参数，ps 看不到），
# 等待若干秒，如果剪贴板内容仍是这个密码就清空——不会误删用户之后复制的其他内容。
_CLEAR_SNIPPET = r"""
import hashlib, subprocess, sys, time, json
digest = sys.stdin.readline().strip()
copy, paste, delay = json.loads(sys.argv[1])
time.sleep(delay)
try:
    cur = subprocess.run(paste, capture_output=True, timeout=5).stdout
    if hashlib.sha256(cur.rstrip(b"\r\n")).hexdigest() == digest:
        subprocess.run(copy, input=b"", timeout=5)
except Exception:
    pass
"""


def copy_to_clipboard(value: str, clear_after: int) -> bool:
    cmds = _clipboard_cmds()
    if not cmds:
        return False
    copy, paste = cmds
    try:
        subprocess.run(copy, input=value.encode(), check=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    if clear_after > 0:
        p = subprocess.Popen([sys.executable, "-c", _CLEAR_SNIPPET,
                              json.dumps([copy, paste, clear_after])],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        p.stdin.write((hashlib.sha256(value.encode()).hexdigest() + "\n").encode())
        p.stdin.close()
    return True


# ---------------------------- CLI ----------------------------
def ask_master(confirm: bool = False, prompt: str = "主密码: ") -> str:
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("再次输入: ") != pw:
        raise VaultError("两次输入不一致")
    return pw


def check_master_strength(pw: str, allow_weak: bool) -> None:
    r = pwcheck.analyze(pw)
    if r.score >= MIN_MASTER_SCORE:
        return
    msg = f"主密码强度 {r.score}/4（{r.label}）：" + "；".join(r.issues or r.suggestions)
    if not allow_weak:
        raise VaultError(msg + f"\n主密码至少需要 {MIN_MASTER_SCORE}/4，"
                         "建议使用 4~5 个随机单词组成的口令短语（或加 --allow-weak 强制使用）")
    print("[!] " + msg, file=sys.stderr)


def read_entry_password(args) -> str | None:
    if getattr(args, "generate", None):
        return generate_password(args.generate, not args.no_symbols)
    if getattr(args, "prompt_password", False):
        pw = getpass.getpass("条目密码: ")
        if getpass.getpass("再次输入: ") != pw:
            raise VaultError("两次输入不一致")
        r = pwcheck.analyze(pw)
        if r.score < 3:
            print(f"[!] 该密码强度 {r.score}/4（{r.label}），建议用 --generate", file=sys.stderr)
        return pw
    return None


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="本地加密密码保险库（AES-256-GCM + scrypt）")
    ap.add_argument("-f", "--vault", default=DEFAULT_PATH,
                    help=f"保险库文件路径（默认 $VAULT_FILE 或 {DEFAULT_PATH}）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="创建新保险库")
    p.add_argument("--allow-weak", action="store_true", help="允许弱主密码（不推荐）")

    for name, helptext in (("add", "新增条目"), ("edit", "修改条目")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("name")
        p.add_argument("-u", "--username")
        p.add_argument("--url")
        p.add_argument("-n", "--notes")
        g = p.add_mutually_exclusive_group()
        g.add_argument("-g", "--generate", type=int, nargs="?", const=20, metavar="LEN",
                       help="自动生成随机密码（默认 20 位）")
        g.add_argument("-p", "--prompt-password", action="store_true",
                       help="交互输入密码（不回显）")
        p.add_argument("--no-symbols", action="store_true", help="生成时不含符号")

    p = sub.add_parser("get", help="取出密码（默认复制到剪贴板）")
    p.add_argument("name")
    p.add_argument("--show", action="store_true", help="打印到终端而不是复制")
    p.add_argument("--field", choices=FIELDS, default="password")
    p.add_argument("--clear", type=int, default=20, help="剪贴板自动清空秒数（0 不清空）")

    p = sub.add_parser("info", help="查看条目详情（密码打码）")
    p.add_argument("name")

    p = sub.add_parser("list", help="列出/搜索条目")
    p.add_argument("term", nargs="?")

    p = sub.add_parser("rm", help="删除条目")
    p.add_argument("name")
    p.add_argument("-y", "--yes", action="store_true", help="不确认直接删除")

    p = sub.add_parser("audit", help="检查弱密码、重复密码、过期密码")
    p.add_argument("--max-age", type=int, default=365)

    p = sub.add_parser("passwd", help="修改主密码")
    p.add_argument("--allow-weak", action="store_true")

    p = sub.add_parser("gen", help="只生成随机密码，不需要保险库")
    p.add_argument("length", type=int, nargs="?", default=20)
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--no-ambiguous", action="store_true", help="排除 I l 1 O 0 等易混淆字符")
    return ap


def run(args) -> int:
    if args.cmd == "gen":
        print(generate_password(args.length, not args.no_symbols, args.no_ambiguous))
        return 0

    if args.cmd == "init":
        master = ask_master(confirm=True, prompt="设置主密码: ")
        check_master_strength(master, args.allow_weak)
        Vault.create(args.vault, master)
        print(f"[+] 已创建保险库：{args.vault}")
        print("    主密码无法找回，请务必牢记，并定期备份该文件。")
        return 0

    vault = Vault.open(args.vault, ask_master())

    if args.cmd == "add":
        pw = read_entry_password(args)
        if pw is None:
            raise VaultError("请用 -g 生成密码或 -p 输入密码")
        vault.add(args.name, username=args.username, password=pw, url=args.url, notes=args.notes)
        vault.save()
        print(f"[+] 已添加：{args.name}" + ("（已生成随机密码，可用 get 取出）" if args.generate else ""))

    elif args.cmd == "edit":
        vault.edit(args.name, username=args.username, password=read_entry_password(args),
                   url=args.url, notes=args.notes)
        vault.save()
        print(f"[+] 已更新：{vault.resolve(args.name)}")

    elif args.cmd == "get":
        value = vault.entries[vault.resolve(args.name)][args.field]
        if args.show or args.field != "password":
            print(value)
        elif copy_to_clipboard(value, args.clear):
            tail = f"，{args.clear} 秒后自动清空" if args.clear else ""
            print(f"[+] 已复制到剪贴板{tail}", file=sys.stderr)
        else:
            print("[!] 未找到可用剪贴板（xclip / wl-copy / pbcopy 等），改为直接输出：",
                  file=sys.stderr)
            print(value)

    elif args.cmd == "info":
        name = vault.resolve(args.name)
        e = vault.entries[name]
        print(f"名称:   {name}")
        for label, key in (("用户名", "username"), ("网址", "url"), ("备注", "notes")):
            if e[key]:
                print(f"{label}:   {e[key]}")
        print(f"密码:   {'•' * 8}（{len(e['password'])} 位，强度 {pwcheck.analyze(e['password']).score}/4）")
        print(f"创建:   {e['created']}\n更新:   {e['updated']}")
        if e.get("history"):
            print(f"历史:   保留了 {len(e['history'])} 个旧密码")

    elif args.cmd == "list":
        names = vault.search(args.term)
        for n in names:
            e = vault.entries[n]
            print(f"{n:<28} {e['username']:<24} {e['url']}")
        print(f"\n共 {len(names)} 条", file=sys.stderr)

    elif args.cmd == "rm":
        name = vault.resolve(args.name)
        if not args.yes and input(f"确认删除 {name}? [y/N] ").strip().lower() != "y":
            print("已取消")
            return 0
        vault.remove(name)
        vault.save()
        print(f"[+] 已删除：{name}")

    elif args.cmd == "audit":
        problems = vault.audit(args.max_age)
        for name, msg in problems:
            print(f"[!] {name}: {msg}")
        print(f"\n检查了 {len(vault.entries)} 个条目，发现 {len(problems)} 个问题", file=sys.stderr)
        return 1 if problems else 0

    elif args.cmd == "passwd":
        new = ask_master(confirm=True, prompt="新主密码: ")
        check_master_strength(new, args.allow_weak)
        vault.change_master(new)
        print("[+] 主密码已修改（同时更换了盐，旧 .bak 备份仍可用旧主密码打开，请按需删除）")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except VaultError as e:
        print(f"[x] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
