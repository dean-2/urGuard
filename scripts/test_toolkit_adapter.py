"""Verification suite for the Track 4 judging adapter (including protected_read)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "track4_service.py"
VALIDATOR = ROOT / "trust-but-verify-toolkit-1.0.0" / "trust-but-verify-toolkit-1.0.0" / "validate.py"


def invoke(state_dir: Path, payload: dict) -> tuple[dict, bytes]:
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    proc = subprocess.run(
        [sys.executable, "-B", str(ENTRY)],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        env=env,
        cwd=str(ROOT),
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"adapter failed (rc={proc.returncode}): {proc.stderr.decode('utf-8', 'replace')}")
    return json.loads(proc.stdout.decode("utf-8")), proc.stderr


def test_official_validator() -> None:
    if not VALIDATOR.is_file():
        raise FileNotFoundError(f"validator not found at {VALIDATOR}")
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR), "--entry", str(ENTRY)],
        cwd=str(VALIDATOR.parent),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    print(proc.stdout.strip())
    if proc.returncode != 0:
        raise AssertionError(f"validate.py failed (rc={proc.returncode}):\n{proc.stderr}")


def test_protected_read_flow() -> None:
    try:
        from pqcrypto.kem import ml_kem_768  # type: ignore[import-not-found]
    except ImportError:
        print("SKIP [crypto] pqcrypto not installed in host Python; run container check for protected_read.")
        return

    keygen_fn = getattr(ml_kem_768, "generate_keypair", None) or getattr(ml_kem_768, "keygen")
    decap_fn = getattr(ml_kem_768, "decrypt", None) or getattr(ml_kem_768, "decaps")
    pk_bytes, sk_bytes = keygen_fn()
    pk_b64 = base64.b64encode(pk_bytes).decode("ascii")

    secret_body = "confidential post-quantum asset body"
    fake_key_material = "synthetic-secret-marker-999"
    challenge = "chal-nonce-abc123"

    with tempfile.TemporaryDirectory(prefix="urguard-prot-") as tmp:
        state_dir = Path(tmp)
        res, err = invoke(
            state_dir,
            {
                "op": "setup",
                "owners": {"brief": "maya", "other": "liam"},
                "contents": {"brief": secret_body, "other": "liam-secret"},
                "disabled": [],
                "key_material": fake_key_material,
            },
        )
        assert res == {"ready": True}, res
        assert fake_key_material.encode() not in err

        # Authorized protected_read must return ML-KEM-768 ciphertext + HMAC-SHA256 proof.
        allowed, err = invoke(
            state_dir,
            {
                "op": "protected_read",
                "actor": "maya",
                "asset": "brief",
                "challenge": challenge,
                "public_key": pk_b64,
            },
        )
        assert allowed.get("decision") == "allow", allowed
        ct_bytes = base64.b64decode(allowed["ciphertext"], validate=True)
        assert len(ct_bytes) == 1088
        shared_secret = decap_fn(sk_bytes, ct_bytes)
        expected_proof = hmac.new(
            shared_secret,
            (challenge + secret_body).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert allowed["proof"] == expected_proof, (allowed["proof"], expected_proof)
        assert allowed["proof"] == allowed["proof"].lower()
        assert secret_body not in json.dumps(allowed)

        # Wrong owner must be denied without ciphertext, proof, or body.
        wrong_owner, _ = invoke(
            state_dir,
            {
                "op": "protected_read",
                "actor": "maya",
                "asset": "other",
                "challenge": challenge,
                "public_key": pk_b64,
            },
        )
        assert wrong_owner.get("decision") == "deny"
        assert "ciphertext" not in wrong_owner and "proof" not in wrong_owner and "body" not in wrong_owner

        # Revoke maya -> subsequent protected_read denied, liam still allowed.
        invoke(state_dir, {"op": "revoke", "actor": "maya"})
        revoked_read, _ = invoke(
            state_dir,
            {
                "op": "protected_read",
                "actor": "maya",
                "asset": "brief",
                "challenge": challenge,
                "public_key": pk_b64,
            },
        )
        assert revoked_read.get("decision") == "deny"
        assert "ciphertext" not in revoked_read and "proof" not in revoked_read

        peer_ok, _ = invoke(
            state_dir,
            {
                "op": "protected_read",
                "actor": "liam",
                "asset": "other",
                "challenge": challenge,
                "public_key": pk_b64,
            },
        )
        assert peer_ok.get("decision") == "allow"
        print("PASS [crypto] protected_read ML-KEM-768 + HMAC-SHA256 + revocation checks passed.")


if __name__ == "__main__":
    test_official_validator()
    test_protected_read_flow()
