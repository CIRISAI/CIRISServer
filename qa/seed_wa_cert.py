#!/usr/bin/env python3
"""Seed a wa_cert row into a ciris-server SQLite DB so the QA runner can log in.

ciris-server is a *headless fabric node* — there is NO setup wizard (the agent's
first-run user-create flow lives in the brain, which a fabric node does not have).
The QA runner's auth/sdk modules expect a known admin user (`jeff`) to log in via
POST /v1/auth/login. We provide that user the way a staged environment would: by
writing a `wa_cert` row directly, with a password hash produced by the AGENT'S OWN
KDF (cryptography.PBKDF2HMAC) — which is exactly the byte format ciris-server's
`session.rs::verify_password` reads. This is the conformance hinge: an
agent-produced hash MUST authenticate against the Rust verifier.

Table is `cirislens_wa_cert` (persist feature-prefixed). Login handler uses the
`username` field of the request AS the `wa_id`, so wa_id == "jeff".
"""
import base64
import sqlite3
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets


def agent_hash_password(password: str) -> str:
    """Byte-for-byte the agent's services/auth_service.py::_hash_password:
    PBKDF2HMAC(SHA256, length=32, salt=token_bytes(32), iterations=100000),
    stored as standard-base64(salt(32) || key(32))."""
    salt = secrets.token_bytes(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    key = kdf.derive(password.encode())
    return base64.b64encode(salt + key).decode()


def seed(db_path: str, wa_id: str, password: str, role: str = "root") -> None:
    pw_hash = agent_hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    # Minimal valid row: NOT NULL cols are wa_id, name, role, pubkey, jwt_kid,
    # scopes, token_type, created, active. pubkey/scopes are opaque to the login
    # path (it only checks password_hash + active + role).
    pubkey = base64.b64encode(b"\x00" * 32).decode()
    scopes = '{"scopes": ["*"]}'
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """INSERT OR REPLACE INTO cirislens_wa_cert
               (wa_id, name, role, pubkey, jwt_kid, password_hash, scopes,
                token_type, created, active, auto_minted)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'standard', ?, 1, 0)""",
            (wa_id, wa_id, role, pubkey, f"kid-{wa_id}", pw_hash, scopes, now),
        )
        conn.commit()
    finally:
        conn.close()
    print(f"seeded wa_cert wa_id={wa_id} role={role} (agent-KDF password_hash)")


if __name__ == "__main__":
    db = sys.argv[1]
    wa_id = sys.argv[2] if len(sys.argv) > 2 else "jeff"
    password = sys.argv[3] if len(sys.argv) > 3 else "qa_test_password_12345"
    role = sys.argv[4] if len(sys.argv) > 4 else "root"
    seed(db, wa_id, password, role)
