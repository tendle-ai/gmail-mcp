"""Encrypted, expiring OAuth state. Raw bearer tokens are never stored."""

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, path: Path, key: str):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self.cipher = Fernet(key.encode())
        with self.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS state (kind TEXT, id TEXT, expires REAL, data BLOB, PRIMARY KEY(kind,id))"
            )
            db.execute("CREATE INDEX IF NOT EXISTS state_expiry ON state(expires)")
        os.chmod(path, 0o600)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def put(self, kind, key, data, ttl, db=None):
        if db is None:
            with self.transaction() as db:
                return self.put(kind, key, data, ttl, db)
        db.execute(
            "INSERT OR REPLACE INTO state VALUES (?,?,?,?)",
            (
                kind,
                key,
                time.time() + ttl,
                self.cipher.encrypt(json.dumps(data).encode()),
            ),
        )

    def get(self, kind, key, db=None):
        if db is None:
            with self.transaction() as db:
                return self.get(kind, key, db)
        row = db.execute(
            "SELECT data FROM state WHERE kind=? AND id=? AND expires>?",
            (kind, key, time.time()),
        ).fetchone()
        return json.loads(self.cipher.decrypt(row[0])) if row else None

    def delete(self, kind, key, db):
        db.execute("DELETE FROM state WHERE kind=? AND id=?", (kind, key))

    def cleanup(self):
        with self.transaction() as db:
            db.execute("DELETE FROM state WHERE expires<=?", (time.time(),))
