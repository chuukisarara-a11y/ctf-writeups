"""密码保险库测试（需要 cryptography）。"""
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools", "vault"))

try:
    import vault
except SystemExit:  # cryptography 未安装
    vault = None

FAST_KDF = {"name": "scrypt", "n": 2 ** 14, "r": 8, "p": 1}  # 测试用低参数，节省时间
MASTER = "tundra-violin-copper-mango-47"


def load(path):
    with open(path) as f:
        return json.load(f)


def dump(doc, path):
    with open(path, "w") as f:
        json.dump(doc, f)


@unittest.skipIf(vault is None, "cryptography 未安装")
class TestVault(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "v.json")

    def tearDown(self):
        self.tmp.cleanup()

    def new(self):
        return vault.Vault.create(self.path, MASTER, FAST_KDF)

    def test_roundtrip(self):
        v = self.new()
        v.add("github", username="alice", password="s3cret-Pass!", url="https://github.com")
        v.save()
        v2 = vault.Vault.open(self.path, MASTER)
        self.assertEqual(v2.entries["github"]["password"], "s3cret-Pass!")

    def test_file_has_no_plaintext_and_is_0600(self):
        v = self.new()
        v.add("mail", username="bob@example.com", password="PlainTextShouldNotLeak")
        v.save()
        with open(self.path) as f:
            raw = f.read()
        self.assertNotIn("PlainTextShouldNotLeak", raw)
        self.assertNotIn("bob@example.com", raw)
        self.assertNotIn("mail", json.loads(raw))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_wrong_password(self):
        self.new()
        with self.assertRaisesRegex(vault.VaultError, "主密码错误"):
            vault.Vault.open(self.path, "wrong")

    def test_tamper_ciphertext_detected(self):
        v = self.new()
        v.add("x", password="y")
        v.save()
        doc = load(self.path)
        ct = bytearray(vault.b64d(doc["ciphertext"]))
        ct[0] ^= 1
        doc["ciphertext"] = vault.b64e(bytes(ct))
        dump(doc, self.path)
        with self.assertRaises(vault.VaultError):
            vault.Vault.open(self.path, MASTER)

    def test_tamper_header_detected(self):
        self.new()
        doc = load(self.path)
        doc["kdf"]["p"] = 2  # 改了参数，密钥会变；即使不变 AAD 也会校验失败
        dump(doc, self.path)
        with self.assertRaises(vault.VaultError):
            vault.Vault.open(self.path, MASTER)

    def test_kdf_downgrade_rejected(self):
        self.new()
        doc = load(self.path)
        doc["kdf"]["n"] = 2 ** 4
        dump(doc, self.path)
        with self.assertRaisesRegex(vault.VaultError, "KDF"):
            vault.Vault.open(self.path, MASTER)

    def test_nonce_changes_every_save(self):
        v = self.new()
        n1 = load(self.path)["nonce"]
        v.save()
        n2 = load(self.path)["nonce"]
        self.assertNotEqual(n1, n2)
        self.assertTrue(os.path.exists(self.path + ".bak"))

    def test_create_refuses_overwrite(self):
        self.new()
        with self.assertRaises(vault.VaultError):
            self.new()

    def test_change_master(self):
        v = self.new()
        v.add("a", password="b")
        old_salt = v.header["salt"]
        v.change_master("new-master-phrase-orbit-92")
        self.assertNotEqual(old_salt, v.header["salt"])
        with self.assertRaises(vault.VaultError):
            vault.Vault.open(self.path, MASTER)
        self.assertEqual(vault.Vault.open(self.path, "new-master-phrase-orbit-92")
                         .entries["a"]["password"], "b")

    def test_edit_keeps_history_and_resolve_case(self):
        v = self.new()
        v.add("GitHub", password="old")
        v.edit("github", password="new")
        e = v.entries["GitHub"]
        self.assertEqual(e["password"], "new")
        self.assertEqual(e["history"][0]["password"], "old")

    def test_audit(self):
        v = self.new()
        strong = vault.generate_password(24)
        v.add("a", password="123456")
        v.add("b", password=strong)
        v.add("c", password=strong)
        v.add("d", password=vault.generate_password(24))
        msgs = v.audit()
        self.assertTrue(any(n == "a" and "弱密码" in m for n, m in msgs))
        self.assertTrue(any(n == "b" and "共用" in m for n, m in msgs))
        self.assertFalse(any(n == "d" for n, _ in msgs))

    def test_generate_password(self):
        for _ in range(50):
            pw = vault.generate_password(12, avoid_ambiguous=True)
            self.assertEqual(len(pw), 12)
            self.assertTrue(any(c.islower() for c in pw) and any(c.isupper() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw))
            self.assertFalse(set(pw) & vault.AMBIGUOUS)
        self.assertTrue(vault.generate_password(16, symbols=False).isalnum())

    def test_cli_flow(self):
        env = {"VAULT_FILE": self.path}
        def cli(*argv, pw=MASTER):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch("getpass.getpass", return_value=pw), \
                 mock.patch.object(vault, "DEFAULT_KDF", FAST_KDF), \
                 mock.patch.object(vault, "_clipboard_cmds", return_value=None), \
                 redirect_stdout(out), redirect_stderr(err):
                rc = vault.main(["-f", self.path, *argv])
            return rc, out.getvalue(), err.getvalue()

        self.assertEqual(cli("init", pw="weakpw")[0], 2)          # 弱主密码被拒绝
        self.assertEqual(cli("init")[0], 0)
        self.assertEqual(cli("add", "site", "-u", "me", "-g", "16")[0], 0)
        rc, out, _ = cli("get", "site")                          # 无剪贴板时回退输出
        self.assertEqual(len(out.strip()), 16)
        rc, out, _ = cli("info", "site")
        self.assertNotIn(cli("get", "site", "--show")[1].strip(), out)
        self.assertIn("site", cli("list")[1])
        self.assertEqual(cli("list", "--", "zzz")[1].strip(), "")
        self.assertEqual(cli("rm", "site", "-y")[0], 0)
        self.assertEqual(cli("get", "site")[0], 2)
        self.assertEqual(cli("list", pw="bad")[0], 2)


if __name__ == "__main__":
    unittest.main()
