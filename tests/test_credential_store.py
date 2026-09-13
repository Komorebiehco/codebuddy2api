import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.credential_store import CredentialStore


class MemoryCredentialStore(CredentialStore):
    def __init__(self, key):
        from cryptography.fernet import Fernet

        self._cipher = Fernet(key)
        self._records = {}
        self._closed = False

    def rows(self):
        result = []
        for row in self._records.values():
            item = dict(row)
            if not item["deleted"]:
                try:
                    item["content"] = self._decrypt(item["payload"])
                except Exception:
                    continue
            else:
                item["content"] = None
            result.append(item)
        return result

    def put(self, name, identity, content):
        self._records[name] = {
            "name": name,
            "identity": identity,
            "payload": self._encrypt(content),
            "revision": 1,
            "deleted": False,
        }

    def delete(self, name, identity=None):
        row = self._records.get(name) or {
            "name": name,
            "identity": identity or "deleted:" + name,
            "revision": 0,
        }
        row.update(payload=None, revision=row["revision"] + 1, deleted=True)
        self._records[name] = row


class CredentialStoreTests(unittest.TestCase):
    def test_payload_is_encrypted_at_rest(self):
        from cryptography.fernet import Fernet

        store = CredentialStore.__new__(CredentialStore)
        store._cipher = Fernet(Fernet.generate_key())
        content = b'{"auth":{"accessToken":"secret-token"}}'
        encrypted = store._encrypt(content)
        self.assertNotIn(b"secret-token", encrypted)
        self.assertEqual(store._decrypt(encrypted), content)

    def test_sync_adopts_restores_and_honors_tombstones(self):
        from cryptography.fernet import Fernet

        store = MemoryCredentialStore(Fernet.generate_key())
        validate = lambda value: json.loads(value.decode("utf-8"))
        identity = lambda data: "cn-cli:" + data["account"]["uid"] + ":"
        content = b'{"account":{"uid":"one"},"auth":{"accessToken":"token"}}'

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "one.info").write_bytes(content)
            result = store.sync_directory(directory, validate, identity)
            self.assertEqual(result["adopted"], 1)

            (directory / "one.info").write_bytes(b"stale")
            result = store.sync_directory(directory, validate, identity)
            self.assertEqual(result["restored"], 1)
            self.assertEqual((directory / "one.info").read_bytes(), content)

            store.delete("one.info", "cn-cli:one:")
            result = store.sync_directory(directory, validate, identity)
            self.assertEqual(result["removed"], 1)
            self.assertFalse((directory / "one.info").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
