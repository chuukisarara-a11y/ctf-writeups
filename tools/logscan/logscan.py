#!/usr/bin/env python3
"""logscan — 日志敏感信息扫描器（仅依赖标准库）。

在日志/配置/导出数据中查找不应出现的敏感信息：云厂商密钥、平台 Token、
私钥、JWT、明文密码、身份证号、手机号、银行卡号等。

设计要点：
- 正则 + 校验算法双重判断（身份证 ISO 7064 校验位、银行卡 Luhn）以降低误报；
- 默认对命中内容打码输出，扫描报告本身不会成为新的泄露源；
- 支持目录递归、.gz 压缩日志、标准输入；
- 有命中时返回码为 1，可直接接入 CI / pre-commit。
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Callable, Iterable, Iterator

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern
    group: int = 0                                   # 取哪个分组作为"敏感值"
    validator: Callable[[str], bool] | None = None   # 二次校验，返回 False 则丢弃


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    name: str
    severity: str
    match: str      # 已打码
    context: str    # 已打码的整行（截断）


# ------------------------------- 校验函数 -------------------------------
def luhn_ok(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def cn_id_ok(idn: str) -> bool:
    """中国居民身份证 18 位校验（GB 11643，ISO 7064 MOD 11-2）。"""
    if not re.fullmatch(r"\d{17}[\dXx]", idn):
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    codes = "10X98765432"
    s = sum(int(idn[i]) * weights[i] for i in range(17))
    return codes[s % 11] == idn[-1].upper()


def not_placeholder(v: str) -> bool:
    """过滤 password=*** / password=${PASS} / password=changeme 之类的占位值。"""
    v = v.strip("'\"")
    if len(v) < 4:
        return False
    if re.fullmatch(r"[*xX#.\-]+|<[^>]*>|\$\{?[A-Za-z_][\w]*\}?|%\(?\w+\)?s?", v):
        return False
    return v.lower() not in {"null", "none", "true", "false", "redacted",
                             "masked", "hidden", "password", "changeme", "example"}


# ------------------------------- 规则表 -------------------------------
def R(id_, name, sev, regex, group=0, validator=None, flags=0) -> Rule:
    return Rule(id_, name, sev, re.compile(regex, flags), group, validator)


RULES: list[Rule] = [
    R("private-key", "私钥", "critical",
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    R("aws-access-key", "AWS Access Key ID", "critical",
      r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b", 1),
    R("aws-secret-key", "AWS Secret Access Key", "critical",
      r"(?i)aws.{0,20}?secret.{0,20}?[=:]\s*['\"]?([A-Za-z0-9/+=]{40})\b", 1),
    R("aliyun-access-key", "阿里云 AccessKey ID", "critical",
      r"\b(LTAI[A-Za-z0-9]{12,20})\b", 1),
    R("github-token", "GitHub Token", "critical",
      r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,90})\b", 1),
    R("gitlab-token", "GitLab Token", "critical",
      r"\b(glpat-[A-Za-z0-9_\-]{20})\b", 1),
    R("slack-token", "Slack Token", "high",
      r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b", 1),
    R("slack-webhook", "Slack Webhook", "high",
      r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)", 1),
    R("google-api-key", "Google API Key", "high",
      r"\b(AIza[0-9A-Za-z_\-]{35})\b", 1),
    R("stripe-key", "Stripe Secret Key", "critical",
      r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b", 1),
    R("jwt", "JWT", "high",
      r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,})\b", 1),
    R("bearer-token", "Authorization Bearer", "high",
      r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+([A-Za-z0-9._~+/=-]{16,})", 1),
    R("basic-auth", "Authorization Basic", "high",
      r"(?i)authorization['\"]?\s*[:=]\s*['\"]?basic\s+([A-Za-z0-9+/=]{8,})", 1),
    R("url-credential", "URL 内嵌账号密码", "high",
      r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s:@]{3,})@[^\s/]+", 1,
      validator=not_placeholder),
    R("password-field", "明文密码字段", "high",
      r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|passphrase)['\"]?\s*[:=]\s*(['\"]?[^\s'\",;&}]{1,128}['\"]?)",
      1, validator=not_placeholder),
    R("api-key-field", "通用 API Key/Token 字段", "medium",
      r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{16,})",
      1, validator=not_placeholder),
    R("cn-id-card", "中国居民身份证号", "high",
      r"(?<!\d)(\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)",
      1, validator=cn_id_ok),
    R("credit-card", "银行卡号", "high",
      r"(?<!\d)((?:\d[ -]?){12,18}\d)(?!\d)", 1, validator=luhn_ok),
    R("cn-mobile", "中国大陆手机号", "medium",
      r"(?<!\d)(?:\+?86[- ]?)?(1[3-9]\d{9})(?!\d)", 1),
    R("email", "邮箱地址", "low",
      r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", 1),
    R("internal-ip", "内网 IP", "low",
      r"\b((?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
      1),
]


# ------------------------------- 打码 -------------------------------
def mask(value: str) -> str:
    v = value
    if len(v) <= 6:
        return "*" * len(v)
    keep = 2 if len(v) < 12 else 4
    return v[:keep] + "*" * min(len(v) - 2 * keep, 16) + v[-keep:]


# ------------------------------- 扫描核心 -------------------------------
def scan_line(line: str, rules: list[Rule]) -> list[tuple[Rule, re.Match]]:
    hits: list[tuple[Rule, re.Match]] = []
    taken: list[tuple[int, int]] = []  # 同一段文本只报告最严重的那条规则
    for rule in sorted(rules, key=lambda r: -SEVERITY[r.severity]):
        for m in rule.pattern.finditer(line):
            value = m.group(rule.group)
            if rule.validator and not rule.validator(value):
                continue
            span = m.span(rule.group)
            if any(span[0] < e and s < span[1] for s, e in taken):
                continue
            taken.append(span)
            hits.append((rule, m))
    return hits


def scan_lines(lines: Iterable[str], filename: str, rules: list[Rule],
               show_raw: bool = False, ignore: list[re.Pattern] | None = None
               ) -> Iterator[Finding]:
    for lineno, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if ignore and any(p.search(line) for p in ignore):
            continue
        hits = scan_line(line, rules)
        if not hits:
            continue
        masked_line = line
        # 从后往前替换，避免偏移变化
        for rule, m in sorted(hits, key=lambda h: -h[1].start(h[0].group)):
            s, e = m.span(rule.group)
            if not show_raw:
                masked_line = masked_line[:s] + mask(line[s:e]) + masked_line[e:]
        if len(masked_line) > 200:
            masked_line = masked_line[:197] + "..."
        for rule, m in hits:
            value = m.group(rule.group)
            yield Finding(filename, lineno, rule.id, rule.name, rule.severity,
                          value if show_raw else mask(value), masked_line)


def open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def is_binary(path: str) -> bool:
    if path.endswith(".gz"):
        return False
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(4096)
    except OSError:
        return True


def iter_files(paths: list[str], exts: set[str] | None) -> Iterator[str]:
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv"}
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for fn in sorted(files):
                    full = os.path.join(root, fn)
                    if exts and not any(fn.endswith(x) for x in exts):
                        continue
                    yield full
        else:
            yield p


# ------------------------------- 输出 -------------------------------
SEV_COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m"}


def print_text(findings: list[Finding], color: bool) -> None:
    for f in findings:
        c, r = (SEV_COLOR[f.severity], "\033[0m") if color else ("", "")
        print(f"{f.file}:{f.line}: {c}[{f.severity.upper()}]{r} {f.name} ({f.rule}): {f.match}")
        print(f"    {f.context}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{k}={counts[k]}" for k in SEVERITY if k in counts) or "无"
    print(f"\n共发现 {len(findings)} 处敏感信息（{summary}）", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="日志敏感信息扫描器")
    ap.add_argument("paths", nargs="*", help="文件或目录；省略或 '-' 表示标准输入")
    ap.add_argument("--min-severity", choices=list(SEVERITY), default="low",
                    help="只报告不低于此级别的命中（默认 low）")
    ap.add_argument("--rules", help="只启用这些规则 id，逗号分隔")
    ap.add_argument("--exclude-rules", help="禁用这些规则 id，逗号分隔")
    ap.add_argument("--ignore", action="append", default=[],
                    help="匹配此正则的行将被忽略（白名单，可多次指定）")
    ap.add_argument("--ext", help="目录扫描时只看这些后缀，逗号分隔，如 .log,.txt,.gz")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--show-raw", action="store_true",
                    help="输出原文不打码（仅限本地排查，切勿用于共享报告）")
    ap.add_argument("--list-rules", action="store_true", help="列出所有规则后退出")
    args = ap.parse_args(argv)

    if args.list_rules:
        for r in RULES:
            print(f"{r.id:<18} {r.severity:<9} {r.name}")
        return 0

    rules = [r for r in RULES if SEVERITY[r.severity] >= SEVERITY[args.min_severity]]
    if args.rules:
        wanted = set(args.rules.split(","))
        rules = [r for r in rules if r.id in wanted]
    if args.exclude_rules:
        excluded = set(args.exclude_rules.split(","))
        rules = [r for r in rules if r.id not in excluded]
    ignore = [re.compile(p) for p in args.ignore]
    exts = {e if e.startswith(".") else "." + e for e in args.ext.split(",")} if args.ext else None

    findings: list[Finding] = []
    paths = args.paths or ["-"]
    for path in iter_files(paths, exts):
        if path == "-":
            findings += scan_lines(sys.stdin, "<stdin>", rules, args.show_raw, ignore)
            continue
        if is_binary(path):
            continue
        try:
            with open_text(path) as fh:
                findings += scan_lines(fh, path, rules, args.show_raw, ignore)
        except (OSError, EOFError) as e:
            print(f"[!] 无法读取 {path}: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2))
    else:
        print_text(findings, sys.stdout.isatty())
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
