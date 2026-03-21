# AEAD encryption (AES-GCM), key derivation (HKDF)

# Provides two things:
# 1. Key derivation: turn a PSK + nonces into per-session encryption keys using HKDF-SHA256
# 2. AEAD encryption/decryption: AES-GCM to encrypt payloads and authenticate metadata (AAD)

# Python's cryptography library handles the heavy lifting. We just wrap it
# into simple functions that the rest of the project can call.

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Key Derivation

def derive_session_keys(psk: bytes, client_nonce: bytes, server_nonce: bytes) -> dict:
    """
    Derive per-session encryption keys from the PSK and both nonces.

    Uses HKDF-SHA256:
      - salt   = client_nonce + server_nonce  (unique per session)
      - ikm    = PSK                          (input key material)
      - info   = context string               (separates enc_key from ack_key)
      - length = 32 bytes each                (AES-256)

    Returns:
        dict with 'enc_key' (32 bytes) and 'ack_key' (32 bytes)
    """
    salt = client_nonce + server_nonce

    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"srft-enc-key",
    ).derive(psk)

    ack_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"srft-ack-key",
    ).derive(psk)

    return {"enc_key": enc_key, "ack_key": ack_key}



# HMAC (used by handshake to authenticate HelloMessages)

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over data using key.

    Args:
        key:  the PSK (or any key)
        data: the message bytes to authenticate

    Returns:
        32-byte HMAC digest
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """
    Verify an HMAC-SHA256 tag.  Uses constant-time comparison to prevent
    timing attacks.

    Returns:
        True if valid, False otherwise
    """
    computed = compute_hmac(key, data)
    return hmac.compare_digest(computed, expected_mac)

# AES-GCM Encryption / Decryption

# AES-GCM nonce size: 12 bytes (standard for GCM)
NONCE_SIZE = 12

# AES-GCM appends a 16-byte authentication tag to the ciphertext
TAG_SIZE = 16


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM with authenticated associated data.

    Args:
        key:       32-byte encryption key (from derive_session_keys)
        plaintext: the data to encrypt (file chunk, ACK payload, etc.)
        aad:       additional authenticated data — not encrypted, but any
                   tampering with it will cause decryption to fail.
                   For SRFT this includes: session_id + seq_num + ack_num + flags

    Returns:
        (nonce, ciphertext_with_tag)
        - nonce: 12 bytes, must be sent alongside the ciphertext
        - ciphertext_with_tag: encrypted data + 16-byte GCM auth tag
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext_with_tag


def decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    """
    Decrypt and verify an AES-256-GCM ciphertext.

    Args:
        key:                32-byte encryption key
        nonce:              12-byte nonce that was used during encryption
        ciphertext_with_tag: encrypted data + 16-byte auth tag
        aad:                same AAD that was used during encryption

    Returns:
        The decrypted plaintext bytes

    Raises:
        InvalidTag: if the ciphertext or AAD was tampered with, or wrong key
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)


# AAD Builder (helper for consistent AAD across sender/receiver)

def build_aad(session_id: bytes, seq_num: int, ack_num: int, flags: int) -> bytes:
    """
    Build the Additional Authenticated Data bytes from packet metadata.

    The project spec requires these fields to be authenticated:
      - session_id
      - sequence_number
      - ack_number
      - flags/type

    We concatenate them in a fixed format so both sides produce identical AAD.

    Args:
        session_id: 8-byte session identifier from handshake
        seq_num:    packet sequence number
        ack_num:    packet acknowledgment number
        flags:      packet flags (DATA, ACK, FIN, etc.)

    Returns:
        bytes to pass as the aad argument to encrypt() / decrypt()
    """
    import struct
    return session_id + struct.pack("!IIH", seq_num, ack_num, flags)
