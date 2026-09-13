"""Encrypted credential persistence for the managed Supabase project."""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from .postgres_store import _connect


class CredentialStore:
    """Keep encrypted credential payloads in a separate PostgreSQL database."""

    def __init__(self, database_url, encryption_key):
        if not database_url:
            raise ValueError("credential database URL is required")
        if not encryption_key:
            raise RuntimeError("CODEBUDDY_CREDENTIALS_ENCRYPTION_KEY is required")
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise RuntimeError("凭据持久化已配置，但 cryptography 未安装") from exc
        try:
            self._cipher = Fernet(encryption_key.encode("ascii"))
        except Exception as exc:
            raise RuntimeError("CODEBUDDY_CREDENTIALS_ENCRYPTION_KEY 格式无效") from exc
        self._lock = threading.RLock()
        self._db = _connect(database_url)
        self._closed = False
        try:
            with self._db.transaction():
                self._db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS codebuddy_credentials (
                        id TEXT PRIMARY KEY,
                        filename TEXT NOT NULL,
                        account_key TEXT NOT NULL,
                        ciphertext BYTEA NOT NULL,
                        nonce BYTEA NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        revision BIGINT NOT NULL DEFAULT 1,
                        deleted BOOLEAN NOT NULL DEFAULT FALSE
                    )
                    """
                )
                self._db.execute(
                    """
                    ALTER TABLE codebuddy_credentials
                    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1
                    """
                )
                self._db.execute(
                    """
                    ALTER TABLE codebuddy_credentials
                    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE
                    """
                )
                self._db.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS codebuddy_credentials_filename
                    ON codebuddy_credentials (filename)
                    """
                )
                self._db.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS codebuddy_credentials_identity
                    ON codebuddy_credentials (account_key)
                    WHERE deleted = FALSE
                    """
                )
        except Exception:
            self._db.close()
            raise

    @staticmethod
    def _tombstone_identity(name):
        return "deleted:" + hashlib.sha256(name.encode("utf-8")).hexdigest()

    def _ensure_open(self):
        if self._closed:
            raise RuntimeError("credential store is closed")

    def _encrypt(self, content):
        return self._cipher.encrypt(bytes(content))

    def _decrypt(self, payload):
        return self._cipher.decrypt(bytes(payload))

    def rows(self):
        """Return metadata and decrypted payloads; corrupted rows are skipped."""
        with self._lock:
            self._ensure_open()
            rows = self._db.execute(
                """
                SELECT filename, account_key, ciphertext, revision, deleted
                FROM codebuddy_credentials
                ORDER BY filename
                """
            ).fetchall()
            result = []
            for row in rows:
                item = {
                    "name": row["filename"],
                    "identity": row["account_key"],
                    "revision": int(row["revision"]),
                    "deleted": bool(row["deleted"]),
                    "content": None,
                }
                if not item["deleted"]:
                    try:
                        item["content"] = self._decrypt(row["ciphertext"])
                    except Exception:
                        continue
                result.append(item)
            return result

    def put(self, name, identity, content):
        """Upsert one active record while preserving identity uniqueness."""
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".info"):
            raise ValueError("invalid credential name")
        if not identity:
            raise ValueError("credential identity is required")
        encrypted = self._encrypt(content)
        record_id = hashlib.sha256(name.encode("utf-8")).hexdigest()
        with self._lock:
            self._ensure_open()
            with self._db.transaction():
                conflict = self._db.execute(
                    """
                    SELECT filename FROM codebuddy_credentials
                    WHERE account_key=%s AND deleted=FALSE AND filename<>%s
                    FOR UPDATE
                    """,
                    (identity, name),
                ).fetchone()
                if conflict:
                    raise ValueError("credential identity already belongs to another file")
                self._db.execute(
                    """
                    INSERT INTO codebuddy_credentials
                        (id, filename, account_key, ciphertext, nonce, revision, deleted, updated_at)
                    VALUES (%s, %s, %s, %s, %s, 1, FALSE, now())
                    ON CONFLICT (filename) DO UPDATE SET
                        id=EXCLUDED.id,
                        filename=EXCLUDED.filename,
                        account_key=EXCLUDED.account_key,
                        ciphertext=EXCLUDED.ciphertext,
                        nonce=EXCLUDED.nonce,
                        revision=codebuddy_credentials.revision+1,
                        deleted=FALSE,
                        updated_at=now()
                    """,
                    (record_id, name, identity, encrypted, b""),
                )

    def delete(self, name, identity=None):
        """Write a tombstone so a stale local cache cannot resurrect a delete."""
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".info"):
            raise ValueError("invalid credential name")
        identity = identity or self._tombstone_identity(name)
        record_id = hashlib.sha256(name.encode("utf-8")).hexdigest()
        encrypted = self._encrypt(b"")
        with self._lock:
            self._ensure_open()
            with self._db.transaction():
                self._db.execute(
                    """
                    INSERT INTO codebuddy_credentials
                        (id, filename, account_key, ciphertext, nonce, revision, deleted, updated_at)
                    VALUES (%s, %s, %s, %s, %s, 1, TRUE, now())
                    ON CONFLICT (filename) DO UPDATE SET
                        id=EXCLUDED.id,
                        filename=EXCLUDED.filename,
                        account_key=EXCLUDED.account_key,
                        ciphertext=EXCLUDED.ciphertext,
                        nonce=EXCLUDED.nonce,
                        revision=codebuddy_credentials.revision+1,
                        deleted=TRUE,
                        updated_at=now()
                    """,
                    (record_id, name, identity, encrypted, b""),
                )

    def sync_directory(self, directory, validate, identity_for):
        """Adopt first-run local files and restore the database into the cache."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        local = {path.name: path for path in directory.glob("*.info") if path.is_file()}
        records = {row["name"]: row for row in self.rows()}
        active_identities = {
            row["identity"] for row in records.values()
            if not row["deleted"] and row["content"] is not None
        }
        adopted = restored = removed = 0

        for name, path in local.items():
            row = records.get(name)
            if row is not None and row["deleted"]:
                try:
                    path.unlink()
                    removed += 1
                except FileNotFoundError:
                    pass
                continue
            try:
                content = path.read_bytes()
                data = validate(content)
                identity = identity_for(data)
            except Exception:
                continue
            if row is None:
                if identity in active_identities:
                    continue
                self.put(name, identity, content)
                records[name] = {
                    "name": name, "identity": identity, "content": content,
                    "deleted": False, "revision": 1,
                }
                active_identities.add(identity)
                adopted += 1
            elif row["content"] is not None and row["content"] != content:
                _write_cache(directory, name, row["content"])
                restored += 1

        for name, row in records.items():
            if row["deleted"] or row["content"] is None:
                continue
            path = directory / name
            needs_restore = not path.exists()
            if not needs_restore:
                try:
                    needs_restore = path.read_bytes() != row["content"]
                except OSError:
                    needs_restore = True
            if needs_restore:
                _write_cache(directory, name, row["content"])
                restored += 1
        return {"adopted": adopted, "restored": restored, "removed": removed}

    def close(self):
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True


def _write_cache(directory, name, content):
    """Write a restored cache file atomically without exposing plaintext in logs."""
    target = Path(directory) / Path(name).name
    temporary = target.with_name("." + target.name + ".restore")
    try:
        temporary.write_bytes(content)
        temporary.replace(target)
        try:
            target.chmod(0o600)
        except OSError:
            pass
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
