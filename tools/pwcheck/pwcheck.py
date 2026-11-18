#!/usr/bin/env python3
"""pwcheck — 离线密码强度检测器（仅依赖标准库）。

思路：先按字符集估算"理论熵"，再识别人类常见的弱模式（常用口令、
键盘序列、重复字符、年份/日期、leet 替换后的字典词），对熵做扣减，
最后映射为 0~4 分并给出可执行的改进建议。

密码默认通过 getpass 读取，不回显、不进入 shell 历史；
整个检测过程完全离线，不会把密码发往任何地方。
"""
from __future__ import annotations

import argparse
import getpass
import json
import math
import re
import sys
from dataclasses import dataclass, field, asdict

# 精简的高频弱口令表（来自公开泄露统计的头部），可用 --wordlist 扩充
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "password", "password1", "qwerty", "qwerty123", "abc123", "111111",
    "000000", "123123", "1q2w3e4r", "1qaz2wsx", "iloveyou", "admin",
    "admin123", "root", "toor", "welcome", "letmein", "monkey", "dragon",
    "football", "baseball", "master", "sunshine", "princess", "shadow",
    "superman", "trustno1", "passw0rd", "p@ssw0rd", "qwertyuiop",
    "woaini", "woaini1314", "5201314", "a123456", "aa123456", "zxcvbnm",
    "asdfghjkl", "666666", "888888", "test", "test123", "guest", "changeme",
}

# 字典词（检测"包含"关系，长度 >= 4 才有意义）
DICTIONARY_WORDS = {
    "password", "admin", "login", "welcome", "qwerty", "dragon", "monkey",
    "master", "secret", "summer", "winter", "spring", "autumn", "love",
    "hello", "china", "beijing", "shanghai", "flag", "ctf", "hacker",
    "root", "user", "test", "pass", "woaini", "iloveyou",
}

KEYBOARD_ROWS = [
    "`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",  # 竖向斜列
]
ALPHA_SEQ = "abcdefghijklmnopqrstuvwxyz"
DIGIT_SEQ = "01234567890"

LEET_MAP = str.maketrans({
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o",
    "$": "s", "5": "s", "7": "t", "+": "t", "9": "g", "8": "b",
})

YEAR_RE = re.compile(r"(19[5-9]\d|20[0-4]\d)")
DATE_RE = re.compile(r"(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])")

LABELS = ["极弱", "弱", "一般", "强", "很强"]


@dataclass
class Report:
    length: int
    charset_size: int
    raw_entropy: float
    effective_entropy: float
    score: int
    label: str
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    crack_time_offline: str = ""


def charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^a-zA-Z0-9\s]", pw):
        size += 33
    if re.search(r"\s", pw):
        size += 1
    if any(ord(c) > 127 for c in pw):
        size += 100  # 粗略：非 ASCII 字符显著扩大搜索空间
    return size


def _sequence_runs(pw: str, min_len: int = 4) -> list[str]:
    """找出长度 >= min_len 的键盘/字母/数字连续片段（正向或反向）。"""
    low = pw.lower()
    sources = KEYBOARD_ROWS + [ALPHA_SEQ, DIGIT_SEQ]
    found: list[str] = []
    i = 0
    while i < len(low):
        best = 0
        for src in sources:
            for s in (src, src[::-1]):
                j = i
                while j < len(low):
                    if low[i:j + 1] in s:
                        j += 1
                    else:
                        break
                best = max(best, j - i)
        if best >= min_len:
            found.append(pw[i:i + best])
            i += best
        else:
            i += 1
    return found


def _repeats(pw: str) -> list[str]:
    hits = [m.group(0) for m in re.finditer(r"(.)\1{2,}", pw)]          # aaa
    hits += [m.group(0) for m in re.finditer(r"(.{2,4})\1{1,}", pw)]    # abcabc
    return hits


def _human_time(seconds: float) -> str:
    if seconds < 1:
        return "瞬间"
    units = [("年", 365 * 86400), ("天", 86400), ("小时", 3600), ("分钟", 60), ("秒", 1)]
    if seconds > 1e3 * 365 * 86400:
        return "超过一千年"
    for name, size in units:
        if seconds >= size:
            return f"约 {seconds / size:.0f} {name}"
    return "瞬间"


def analyze(pw: str, extra_words: set[str] | None = None) -> Report:
    words = DICTIONARY_WORDS | (extra_words or set())
    common = COMMON_PASSWORDS | (extra_words or set())
    issues: list[str] = []
    tips: list[str] = []

    n = len(pw)
    pool = charset_size(pw)
    raw = n * math.log2(pool) if pool else 0.0
    eff = raw

    low = pw.lower()
    deleet = low.translate(LEET_MAP)

    if low in common or deleet in common:
        issues.append("属于常见弱口令（字典攻击第一轮就会命中）")
        eff = min(eff, 5.0)

    hit_words = {w for w in words if len(w) >= 4 and (w in low or w in deleet)}
    # 去掉被更长命中词包含的子词（password 命中时不再重复计 pass）
    hit_words = sorted(w for w in hit_words if not any(w != o and w in o for o in hit_words))
    if hit_words:
        issues.append(f"包含字典词：{', '.join(hit_words)}（leet 替换如 @→a、0→o 无法掩盖）")
        for w in hit_words:
            eff -= len(w) * math.log2(pool or 1) - math.log2(len(words) * 50)

    seqs = _sequence_runs(pw)
    if seqs:
        issues.append(f"包含连续/键盘序列：{', '.join(seqs)}")
        for s in seqs:
            eff -= (len(s) - 1) * math.log2(pool or 1)

    reps = _repeats(pw)
    if reps:
        issues.append(f"包含重复片段：{', '.join(sorted(set(reps)))}")
        for r in set(reps):
            eff -= (len(r) // 2) * math.log2(pool or 1)

    if DATE_RE.search(pw):
        issues.append("包含日期（如生日 19900101），属于社工高危信息")
        eff -= 20
    elif YEAR_RE.search(pw):
        issues.append("包含年份，常与生日/入学年份相关")
        eff -= 8

    if n < 8:
        issues.append(f"长度仅 {n} 位")
    if pw.isdigit():
        issues.append("纯数字")
    elif pw.isalpha():
        issues.append("纯字母")
    if re.fullmatch(r"[A-Z][a-z]+\d{1,4}[!@#.]?", pw):
        issues.append("符合'首字母大写+单词+数字+符号'的典型套路")
        eff -= 10

    eff = max(0.0, min(eff, raw))

    if eff < 28:
        score = 0
    elif eff < 36:
        score = 1
    elif eff < 60:
        score = 2
    elif eff < 80:
        score = 3
    else:
        score = 4
    if n < 8:
        score = min(score, 1)

    if n < 12:
        tips.append("把长度提高到 12 位以上；长度比复杂度更有效")
    if pool < 60:
        tips.append("混合大小写、数字和符号")
    if hit_words or low in common:
        tips.append("避免真实单词与常见口令，考虑 4~5 个随机单词组成的口令短语")
    if seqs or reps:
        tips.append("去掉键盘序列和重复字符")
    if not tips and score < 4:
        tips.append("使用密码管理器生成随机密码")

    # 假设离线快速哈希（如 MD5）+ 单卡 GPU 约 1e10 次/秒，平均需要遍历一半空间
    seconds = (2 ** eff) / 2 / 1e10

    return Report(
        length=n, charset_size=pool, raw_entropy=round(raw, 1),
        effective_entropy=round(eff, 1), score=score, label=LABELS[score],
        issues=issues, suggestions=tips, crack_time_offline=_human_time(seconds),
    )


def render(r: Report, color: bool) -> str:
    colors = ["\033[91m", "\033[91m", "\033[93m", "\033[92m", "\033[92m"]
    c, reset = (colors[r.score], "\033[0m") if color else ("", "")
    bar = "█" * (r.score + 1) + "░" * (4 - r.score)
    lines = [
        f"强度: {c}{bar} {r.score}/4 {r.label}{reset}",
        f"长度: {r.length}    字符集: {r.charset_size}",
        f"熵: 理论 {r.raw_entropy} bit / 有效 {r.effective_entropy} bit",
        f"离线暴破估计(1e10 次/秒): {r.crack_time_offline}",
    ]
    if r.issues:
        lines.append("问题:")
        lines += [f"  - {i}" for i in r.issues]
    if r.suggestions:
        lines.append("建议:")
        lines += [f"  + {s}" for s in r.suggestions]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="离线密码强度检测器")
    ap.add_argument("--stdin", action="store_true",
                    help="从标准输入逐行读取密码（批量审计用，输出不含明文）")
    ap.add_argument("--wordlist", help="额外的弱口令/字典词文件，每行一个（如公司名、项目名）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    ap.add_argument("--min-score", type=int, default=None,
                    help="若任一密码低于此分数则返回码为 1（适合脚本/CI 校验）")
    args = ap.parse_args(argv)

    extra: set[str] = set()
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            extra = {line.strip().lower() for line in f if line.strip()}

    if args.stdin:
        passwords = [line.rstrip("\r\n") for line in sys.stdin if line.rstrip("\r\n")]
    else:
        passwords = [getpass.getpass("输入要检测的密码(不回显): ")]

    reports = [analyze(p, extra) for p in passwords]
    if args.json:
        data = [asdict(r) for r in reports]
        print(json.dumps(data if len(data) > 1 else data[0], ensure_ascii=False, indent=2))
    else:
        color = sys.stdout.isatty()
        for idx, r in enumerate(reports):
            if len(reports) > 1:
                print(f"\n#{idx + 1}")
            print(render(r, color))

    if args.min_score is not None and any(r.score < args.min_score for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
