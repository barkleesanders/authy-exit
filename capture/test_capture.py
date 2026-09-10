import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("capture", Path(__file__).with_name("mitm_authy.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CaptureTests(unittest.TestCase):
    def test_allowlist_and_partial_merge(self):
        with tempfile.TemporaryDirectory() as directory:
            c = module.Capture(directory, "192.168.50.20")
            c.save({"tokens": [{"unique_id": "demo", "salt": "synthetic", "encrypted_seed": "test",
                                  "logo": "demo", "password": "DO_NOT_SAVE", "authorization": "DO_NOT_SAVE"}]})
            c.save({"unique_id": "demo", "salt": "synthetic", "encrypted_seed": "test", "name": "new"})
            result = json.loads(c.path.read_text())["authenticator_tokens"]
            self.assertEqual(result[0]["logo"], "demo")
            self.assertEqual(result[0]["name"], "new")
            self.assertNotIn("DO_NOT_SAVE", c.path.read_text())
            self.assertEqual(c.path.stat().st_mode & 0o777, 0o600)

    def test_device_and_host_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            c = module.Capture(directory, "192.168.50.20")
            f = SimpleNamespace(client_conn=SimpleNamespace(peername=("192.168.50.20", 123)),
                                request=SimpleNamespace(host="api.authy.com", path="/json/authenticator_tokens"))
            self.assertTrue(c.eligible(f))
            f.request.host = "api.authy.com.attacker.example"
            self.assertFalse(c.eligible(f))
            f.request.host = "api.authy.com"
            f.client_conn.peername = ("192.168.50.21", 123)
            self.assertFalse(c.eligible(f))
            c.client_connected(f.client_conn)
            self.assertTrue(f.client_conn.error)

    def test_new_envelope_drops_old_iv(self):
        with tempfile.TemporaryDirectory() as directory:
            c = module.Capture(directory, "192.168.50.20")
            c.save({"unique_id": "demo", "salt": "s", "encrypted_seed": "old", "unique_iv": "old", "logo": "x"})
            c.save({"unique_id": "demo", "salt": "s2", "encrypted_seed": "new"})
            self.assertNotIn("unique_iv", c.records["demo"])
            self.assertEqual(c.records["demo"]["logo"], "x")

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "captured-encrypted-tokens.json").symlink_to(Path(directory, "other"))
            with self.assertRaises(ValueError):
                module.Capture(directory, "192.168.50.20")


if __name__ == "__main__":
    unittest.main()
