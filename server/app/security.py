from __future__ import annotations

import hashlib
import hmac
import secrets
import base64
import binascii
from datetime import datetime, timezone

import pyotp
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


DEVICE_KEY_TYPE_ED25519 = "ed25519"
DEVICE_KEY_TYPE_ECDSA_P256 = "ecdsa_p256"
DEVICE_KEY_TYPES = {DEVICE_KEY_TYPE_ED25519, DEVICE_KEY_TYPE_ECDSA_P256}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def random_secret(bytes_len: int = 32) -> str:
    return secrets.token_urlsafe(bytes_len)


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_eq(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def integration_signature(secret: str, method: str, path: str, body: bytes, timestamp: str, nonce: str) -> str:
    canonical = b"\n".join(
        [
            method.upper().encode(),
            path.encode(),
            timestamp.encode(),
            nonce.encode(),
            body,
        ]
    )
    return hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()


def decision_signature(secret: str, request_id: str, decision: str) -> str:
    return hmac.new(secret.encode(), f"{request_id}.{decision}".encode(), hashlib.sha256).hexdigest()


def normalize_device_key_type(key_type: str | None) -> str:
    if not key_type:
        return DEVICE_KEY_TYPE_ED25519
    if key_type not in DEVICE_KEY_TYPES:
        raise ValueError("unsupported device key_type")
    return key_type


def verify_device_message_signature(public_key: str, signature: str, message: str, key_type: str | None = DEVICE_KEY_TYPE_ED25519) -> bool:
    try:
        decoded_signature = base64.b64decode(signature, validate=True)
        message_bytes = message.encode("utf-8")
        normalized_key_type = normalize_device_key_type(key_type)
        if normalized_key_type == DEVICE_KEY_TYPE_ECDSA_P256:
            key = decode_ecdsa_p256_public_key(public_key)
            key.verify(decoded_signature, message_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            key = Ed25519PublicKey.from_public_bytes(decode_raw_ed25519_public_key(public_key))
            key.verify(decoded_signature, message_bytes)
        return True
    except (ValueError, TypeError, binascii.Error, InvalidSignature, UnsupportedAlgorithm):
        return False


def verify_device_signature(public_key: str, signature: str, request_id: str, decision: str, biometric_verified: bool = False, key_type: str | None = DEVICE_KEY_TYPE_ED25519) -> bool:
    return verify_device_message_signature(public_key, signature, f"{request_id}.{decision}.{str(biometric_verified).lower()}", key_type)


def decode_raw_ed25519_public_key(public_key: str) -> bytes:
    raw = base64.b64decode(public_key, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must decode to 32 raw bytes")
    Ed25519PublicKey.from_public_bytes(raw)
    return raw


def is_raw_ed25519_public_key(public_key: str) -> bool:
    try:
        decode_raw_ed25519_public_key(public_key)
        return True
    except (ValueError, binascii.Error):
        return False


def decode_ecdsa_p256_public_key(public_key: str) -> ec.EllipticCurvePublicKey:
    raw = base64.b64decode(public_key, validate=True)
    key = serialization.load_der_public_key(raw)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("ECDSA P-256 public key must be an EC public key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("ECDSA public key must use the P-256 curve")
    return key


def is_ecdsa_p256_spki_public_key(public_key: str) -> bool:
    try:
        decode_ecdsa_p256_public_key(public_key)
        return True
    except (ValueError, TypeError, binascii.Error, UnsupportedAlgorithm):
        return False


def is_valid_device_public_key(public_key: str, key_type: str | None = DEVICE_KEY_TYPE_ED25519) -> bool:
    normalized_key_type = normalize_device_key_type(key_type)
    if normalized_key_type == DEVICE_KEY_TYPE_ECDSA_P256:
        return is_ecdsa_p256_spki_public_key(public_key)
    return is_raw_ed25519_public_key(public_key)


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    return matching_totp_counter(secret, code, valid_window) is not None


def matching_totp_counter(secret: str, code: str, valid_window: int = 1) -> int | None:
    totp = pyotp.TOTP(secret)
    current = totp.timecode(utcnow())
    for counter in range(current - valid_window, current + valid_window + 1):
        if pyotp.utils.strings_equal(totp.generate_otp(counter), str(code)):
            return counter
    return None


def totp_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def generate_backup_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(16).upper() for _ in range(count)]
