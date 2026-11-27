"""urGuard Track 4 adapter application logic.

Persists state durably in TRACK4_STATE_DIR (or the OS temp directory when
running in a read-only judging container), enforces identity/ownership policy
and revocation, maintains a SHA-256 hash-chained audit log, and performs
ML-KEM-768 + HMAC-SHA-256 protected reads via pqcrypto==0.4.0.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

MLKEM768_PUBLIC_KEY_BYTES = 1184
MLKEM768_CIPHERTEXT_BYTES = 1088
MLKEM768_SHARED_SECRET_BYTES = 32
GENESIS_HASH_HEX = "0" * 64


def _state_db_path() -> Path:
    base = os.environ.get("TRACK4_STATE_DIR") or tempfile.gettempdir()
    state_dir = Path(base)
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / "urguard-track4-state.sqlite"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_state_db_path()), timeout=10.0, isolation_level=None)
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            body TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS revoked_actors (
            actor_id TEXT PRIMARY KEY
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE,
            actor_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            rule TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        )
        """
    )
    return conn


def _derive_audit_hmac_key(key_material: str) -> bytes:
    return hashlib.sha256(b"urguard-track4-audit-v1|" + key_material.encode("utf-8")).digest()


def _append_audit(
    conn: sqlite3.Connection,
    request_id: str | None,
    actor_id: str,
    asset_id: str,
    decision: str,
    rule: str,
) -> None:
    row = conn.execute(
        "SELECT entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev_hash = row[0] if row is not None else GENESIS_HASH_HEX

    hmac_row = conn.execute(
        "SELECT value FROM meta WHERE key = 'audit_hmac_hex'"
    ).fetchone()
    hmac_key = bytes.fromhex(hmac_row[0]) if hmac_row is not None else b""

    canonical = json.dumps(
        {
            "request_id": request_id or "",
            "actor_id": actor_id,
            "asset_id": asset_id,
            "decision": decision,
            "rule": rule,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    if hmac_key:
        entry_hash = hmac.new(hmac_key, canonical, hashlib.sha256).hexdigest()
    else:
        entry_hash = hashlib.sha256(canonical).hexdigest()

    conn.execute(
        """
        INSERT INTO audit_events (request_id, actor_id, asset_id, decision, rule, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (request_id, actor_id, asset_id, decision, rule, prev_hash, entry_hash),
    )


def _require_str(request: dict[str, Any], key: str) -> str:
    value = request.get(key)
    if not isinstance(value, str) or value == "":
        raise ValueError(f"missing or invalid string field: {key}")
    return value


def _handle_setup(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    owners = request.get("owners")
    contents = request.get("contents")
    disabled = request.get("disabled", [])
    key_material = request.get("key_material", "")

    if not isinstance(owners, dict) or not isinstance(contents, dict):
        raise ValueError("owners and contents must be objects")
    if not isinstance(disabled, list) or not all(isinstance(x, str) for x in disabled):
        raise ValueError("disabled must be a list of strings")
    if not isinstance(key_material, str):
        raise ValueError("key_material must be a string")

    for asset_id, owner_id in owners.items():
        if not isinstance(asset_id, str) or not isinstance(owner_id, str):
            raise ValueError("owners keys and values must be strings")
    for asset_id, body in contents.items():
        if not isinstance(asset_id, str) or not isinstance(body, str):
            raise ValueError("contents keys and values must be strings")

    audit_hmac_hex = _derive_audit_hmac_key(key_material).hex()

    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM meta")
        conn.execute("DELETE FROM assets")
        conn.execute("DELETE FROM revoked_actors")
        conn.execute("DELETE FROM audit_events")

        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('initialized', '1'), ('audit_hmac_hex', ?)",
            (audit_hmac_hex,),
        )
        for asset_id, owner_id in owners.items():
            body = contents.get(asset_id, "")
            conn.execute(
                "INSERT INTO assets (asset_id, owner_id, body) VALUES (?, ?, ?)",
                (asset_id, owner_id, body),
            )
        for actor_id in disabled:
            conn.execute(
                "INSERT OR IGNORE INTO revoked_actors (actor_id) VALUES (?)",
                (actor_id,),
            )
        _append_audit(conn, None, "system", "*", "allow", "setup_initialized")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    return {"ready": True}


def _authorize(conn: sqlite3.Connection, actor: str, asset: str) -> tuple[bool, str, str | None]:
    init_row = conn.execute(
        "SELECT value FROM meta WHERE key = 'initialized'"
    ).fetchone()
    if init_row is None or init_row[0] != "1":
        return False, "not_initialized", None

    revoked = conn.execute(
        "SELECT 1 FROM revoked_actors WHERE actor_id = ?",
        (actor,),
    ).fetchone()
    if revoked is not None:
        return False, "identity_disabled", None

    asset_row = conn.execute(
        "SELECT owner_id, body FROM assets WHERE asset_id = ?",
        (asset,),
    ).fetchone()
    if asset_row is None or asset_row[0] != actor:
        return False, "owner_required", None

    return True, "owner_allowed", asset_row[1]


def _handle_read(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    actor = _require_str(request, "actor")
    asset = _require_str(request, "asset")
    request_id = _require_str(request, "request_id")

    conn.execute("BEGIN IMMEDIATE")
    try:
        allowed, rule, body = _authorize(conn, actor, asset)
        decision = "allow" if allowed else "deny"
        _append_audit(conn, request_id, actor, asset, decision, rule)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    if allowed:
        return {"decision": "allow", "rule": rule, "body": body}
    return {"decision": "deny", "rule": rule}


def _handle_revoke(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    actor = _require_str(request, "actor")

    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_actors (actor_id) VALUES (?)",
            (actor,),
        )
        _append_audit(conn, None, actor, "*", "deny", "identity_revoked")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    return {}


def _handle_audit(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    request_id = _require_str(request, "request_id")
    row = conn.execute(
        "SELECT request_id, decision, rule FROM audit_events WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        return {"error": "unknown_request"}
    return {"request_id": row[0], "decision": row[1], "rule": row[2]}


def _mlkem768_encapsulate(raw_public_key: bytes) -> tuple[bytes, bytes]:
    if len(raw_public_key) != MLKEM768_PUBLIC_KEY_BYTES:
        raise ValueError("invalid ML-KEM-768 public key length")

    from pqcrypto.kem import ml_kem_768  # type: ignore[import-not-found]

    encap_fn = getattr(ml_kem_768, "encrypt", None) or getattr(ml_kem_768, "encaps", None)
    if encap_fn is None:
        raise RuntimeError("pqcrypto.kem.ml_kem_768 encapsulation function unavailable")

    out_a, out_b = encap_fn(raw_public_key)
    if len(out_a) == MLKEM768_CIPHERTEXT_BYTES and len(out_b) == MLKEM768_SHARED_SECRET_BYTES:
        return out_a, out_b
    if len(out_b) == MLKEM768_CIPHERTEXT_BYTES and len(out_a) == MLKEM768_SHARED_SECRET_BYTES:
        return out_b, out_a
    raise ValueError("unexpected ML-KEM-768 encapsulation output dimensions")


def _handle_protected_read(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    actor = _require_str(request, "actor")
    asset = _require_str(request, "asset")
    challenge = request.get("challenge")
    if not isinstance(challenge, str):
        raise ValueError("challenge must be a string")
    public_key_b64 = _require_str(request, "public_key")
    request_id = request.get("request_id")
    if request_id is not None and not isinstance(request_id, str):
        raise ValueError("request_id must be a string")

    conn.execute("BEGIN IMMEDIATE")
    try:
        allowed, rule, body = _authorize(conn, actor, asset)
        decision = "allow" if allowed else "deny"
        if request_id:
            _append_audit(conn, request_id, actor, asset, decision, rule)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    if not allowed or body is None:
        return {"decision": "deny", "rule": rule}

    raw_pk = base64.b64decode(public_key_b64, validate=True)
    ciphertext, shared_secret = _mlkem768_encapsulate(raw_pk)
    try:
        message = (challenge + body).encode("utf-8")
        proof = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()
    finally:
        del shared_secret

    return {
        "decision": "allow",
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "proof": proof,
    }


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    if not isinstance(op, str):
        raise ValueError("missing operation")

    conn = _connect()
    try:
        if op == "setup":
            return _handle_setup(conn, request)
        if op == "read":
            return _handle_read(conn, request)
        if op == "revoke":
            return _handle_revoke(conn, request)
        if op == "audit":
            return _handle_audit(conn, request)
        if op == "protected_read":
            return _handle_protected_read(conn, request)
        return {"error": "unsupported_operation"}
    finally:
        conn.close()
