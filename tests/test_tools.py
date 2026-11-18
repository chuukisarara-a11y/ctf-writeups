"""三个工具的单元测试：python3 -m unittest discover -s tests -v"""
import gzip
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("pwcheck", "hashid", "logscan"):
    sys.path.insert(0, os.path.join(ROOT, "tools", sub))

import pwcheck  # noqa: E402
import hashid   # noqa: E402
import logscan  # noqa: E402


class TestPwcheck(unittest.TestCase):
    def test_common_password_is_weakest(self):
        for pw in ("123456", "password", "P@ssw0rd", "qwerty123"):
            self.assertEqual(pwcheck.analyze(pw).score, 0, pw)

    def test_dictionary_word_dedup(self):
        r = pwcheck.analyze("password")
        self.assertTrue(any("password" in i and "pass," not in i for i in r.issues))

    def test_keyboard_sequence_detected(self):
        r = pwcheck.analyze("Xy!asdfgh72")
        self.assertTrue(any("序列" in i for i in r.issues))

    def test_date_detected(self):
        r = pwcheck.analyze("Zhang19900101")
        self.assertTrue(any("日期" in i for i in r.issues))

    def test_short_capped(self):
        self.assertLessEqual(pwcheck.analyze("aB3$xZ").score, 1)

    def test_random_strong(self):
        self.assertEqual(pwcheck.analyze("xK9#mQ2$vL7!pR4&").score, 4)
        self.assertGreaterEqual(pwcheck.analyze("correct horse battery staple").score, 3)

    def test_custom_wordlist(self):
        base = pwcheck.analyze("acmecorp2026xyz!")
        custom = pwcheck.analyze("acmecorp2026xyz!", {"acmecorp"})
        self.assertLess(custom.effective_entropy, base.effective_entropy)

    def test_cli_min_score_exit_code(self):
        sys.stdin = io.StringIO("123456\n")
        try:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(pwcheck.main(["--stdin", "--min-score", "3"]), 1)
        finally:
            sys.stdin = sys.__stdin__


class TestHashid(unittest.TestCase):
    def names(self, h):
        return [c.name for c in hashid.identify(h)]

    def test_md5_family(self):
        self.assertEqual(self.names("5f4dcc3b5aa765d61d8327deb882cf99")[0], "MD5")

    def test_lengths(self):
        self.assertEqual(self.names("a" * 40)[0], "SHA-1")
        self.assertEqual(self.names("a" * 64)[0], "SHA-256")
        self.assertEqual(self.names("a" * 128)[0], "SHA-512")

    def test_prefixed_formats(self):
        self.assertEqual(self.names("$1$abc$" + "a" * 22), ["md5crypt (Unix $1$)"])
        self.assertEqual(self.names("$P$B" + "a" * 30), ["phpass (WordPress/phpBB3)"])
        self.assertEqual(self.names("*" + "A" * 40), ["MySQL 4.1+ (SHA1(SHA1(p)))"])
        self.assertEqual(self.names("$2b$10$" + "a" * 53), ["bcrypt"])

    def test_md4_vectors(self):
        # RFC 1320 测试向量
        self.assertEqual(hashid._md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(hashid._md4(b"message digest").hex(),
                         "d9130a8164549fe818874806e1c7014b")

    def test_crack_md5_and_ntlm(self):
        md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
        ntlm = "8846f7eaee8fb117ad06bdd830b7586c"
        self.assertIn(("MD5", "password"),
                      hashid.try_plaintexts(md5, hashid.identify(md5), ["x", "password"]))
        self.assertIn(("NTLM", "password"),
                      hashid.try_plaintexts(ntlm, hashid.identify(ntlm), ["password"]))

    def test_base64_wrapped(self):
        import base64, hashlib
        b = base64.b64encode(hashlib.sha256(b"x").digest()).decode()
        self.assertTrue(self.names(b)[0].startswith("Base64(SHA-256"))

    def test_user_hash_line(self):
        line = "admin:5f4dcc3b5aa765d61d8327deb882cf99"
        buf = io.StringIO()
        with redirect_stdout(buf):
            hashid.main([line, "--json"])
        self.assertEqual(json.loads(buf.getvalue())[0]["candidates"][0]["name"], "MD5")


class TestLogscan(unittest.TestCase):
    def rules_hit(self, text, **kw):
        return [f.rule for f in logscan.scan_lines(text.splitlines(), "t", logscan.RULES, **kw)]

    def test_validators(self):
        self.assertTrue(logscan.luhn_ok("4111 1111 1111 1111"))
        self.assertFalse(logscan.luhn_ok("1234567890123456"))
        self.assertTrue(logscan.cn_id_ok("11010519491231002X"))
        self.assertFalse(logscan.cn_id_ok("110105194912310021"))

    def test_tokens(self):
        # 运行时拼接，避免仓库里出现"像真的"的 token 触发平台密钥扫描
        gh = "ghp_" + "A1b2C3d4" * 4 + "abcd"
        slack = "xox" + "b-" + "1234567890-abcdefghijkl"
        hits = self.rules_hit(f"token={gh}\nslack {slack}\nkey AKIAIOSFODNN7EXAMPLE")
        self.assertIn("github-token", hits)
        self.assertIn("slack-token", hits)
        self.assertIn("aws-access-key", hits)

    def test_password_placeholder_ignored(self):
        self.assertEqual(self.rules_hit("password=****** pwd=${DB_PASS} pass=<redacted>"), [])
        self.assertEqual(self.rules_hit("password=Hunter2024"), ["password-field"])
        self.assertEqual(self.rules_hit("f(password=read_pw(args), pwd=cfg.db.pass)"), [])
        self.assertEqual(self.rules_hit('password="Open(Sesame)"'), ["password-field"])

    def test_masking(self):
        f = next(logscan.scan_lines(["password=SuperSecret123"], "t", logscan.RULES))
        self.assertNotIn("SuperSecret123", f.match)
        self.assertNotIn("SuperSecret123", f.context)
        raw = next(logscan.scan_lines(["password=SuperSecret123"], "t", logscan.RULES,
                                      show_raw=True))
        self.assertEqual(raw.match, "SuperSecret123")

    def test_private_key(self):
        self.assertEqual(self.rules_hit("-----BEGIN OPENSSH PRIVATE KEY-----"), ["private-key"])

    def test_ignore_pattern(self):
        import re
        hits = list(logscan.scan_lines(["mail admin@example.com"], "t", logscan.RULES,
                                       ignore=[re.compile("example\\.com")]))
        self.assertEqual(hits, [])

    def test_sample_log_and_gzip(self):
        sample = os.path.join(ROOT, "tools", "logscan", "sample.log")
        with tempfile.TemporaryDirectory() as d:
            gz = os.path.join(d, "old.log.gz")
            with open(sample, "rb") as src, gzip.open(gz, "wb") as dst:
                dst.write(src.read())
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = logscan.main([gz, "--json", "--min-severity", "high"])
            data = json.loads(buf.getvalue())
        self.assertEqual(rc, 1)
        rules = {f["rule"] for f in data}
        self.assertTrue({"aws-secret-key", "aws-access-key", "password-field",
                         "cn-id-card", "credit-card", "jwt", "url-credential"} <= rules)
        self.assertNotIn("email", rules)  # 被 --min-severity 过滤
        self.assertNotIn("S3cr3tPw!", buf.getvalue())

    def test_clean_exit_zero(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("2026-11-01 INFO healthy\n")
        try:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(logscan.main([f.name]), 0)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
