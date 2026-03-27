import os
import struct
import pytest
from security.crypto import (
    derive_session_keys,
    compute_hmac,
    verify_hmac,
    encrypt,
    decrypt,
    build_aad,
    NONCE_SIZE,
    TAG_SIZE,
)
from cryptography.exceptions import InvalidTag


class TestDeriveSessionKeys:
    """Tests for HKDF-SHA256 key derivation."""

    def test_returns_both_keys(self):
        psk = os.urandom(32)
        cn, sn = os.urandom(16), os.urandom(16)
        keys = derive_session_keys(psk, cn, sn)
        assert "enc_key" in keys and "ack_key" in keys

    def test_key_lengths_are_32_bytes(self):
        psk = os.urandom(32)
        cn, sn = os.urandom(16), os.urandom(16)
        keys = derive_session_keys(psk, cn, sn)
        assert len(keys["enc_key"]) == 32
        assert len(keys["ack_key"]) == 32

    def test_enc_key_differs_from_ack_key(self):
        psk = os.urandom(32)
        cn, sn = os.urandom(16), os.urandom(16)
        keys = derive_session_keys(psk, cn, sn)
        assert keys["enc_key"] != keys["ack_key"]

    def test_deterministic_same_inputs(self):
        psk = b"A" * 32
        cn, sn = b"B" * 16, b"C" * 16
        keys1 = derive_session_keys(psk, cn, sn)
        keys2 = derive_session_keys(psk, cn, sn)
        assert keys1 == keys2

    def test_different_nonces_produce_different_keys(self):
        psk = b"A" * 32
        cn1, sn1 = os.urandom(16), os.urandom(16)
        cn2, sn2 = os.urandom(16), os.urandom(16)
        keys1 = derive_session_keys(psk, cn1, sn1)
        keys2 = derive_session_keys(psk, cn2, sn2)
        assert keys1["enc_key"] != keys2["enc_key"]

    def test_different_psk_produces_different_keys(self):
        cn, sn = b"B" * 16, b"C" * 16
        keys1 = derive_session_keys(b"A" * 32, cn, sn)
        keys2 = derive_session_keys(b"Z" * 32, cn, sn)
        assert keys1["enc_key"] != keys2["enc_key"]


class TestHMAC:
    """Tests for HMAC-SHA256 compute and verify."""

    def test_hmac_length_is_32(self):
        mac = compute_hmac(b"key", b"data")
        assert len(mac) == 32

    def test_hmac_deterministic(self):
        mac1 = compute_hmac(b"key", b"data")
        mac2 = compute_hmac(b"key", b"data")
        assert mac1 == mac2

    def test_verify_valid_hmac(self):
        key, data = b"secret", b"hello"
        mac = compute_hmac(key, data)
        assert verify_hmac(key, data, mac) is True

    def test_verify_rejects_wrong_mac(self):
        key, data = b"secret", b"hello"
        bad_mac = b"\x00" * 32
        assert verify_hmac(key, data, bad_mac) is False

    def test_verify_rejects_tampered_data(self):
        key = b"secret"
        mac = compute_hmac(key, b"hello")
        assert verify_hmac(key, b"HELLO", mac) is False

    def test_verify_rejects_wrong_key(self):
        mac = compute_hmac(b"key1", b"data")
        assert verify_hmac(b"key2", b"data", mac) is False

    def test_hmac_different_keys_differ(self):
        mac1 = compute_hmac(b"key1", b"data")
        mac2 = compute_hmac(b"key2", b"data")
        assert mac1 != mac2

    def test_hmac_different_data_differ(self):
        mac1 = compute_hmac(b"key", b"data1")
        mac2 = compute_hmac(b"key", b"data2")
        assert mac1 != mac2


class TestAESGCM:
    """Tests for AES-256-GCM encrypt and decrypt."""

    def setup_method(self):
        self.key = os.urandom(32)
        self.aad = b"authenticated-metadata"
        self.plaintext = b"Hello, SRFT!"

    def test_encrypt_returns_nonce_and_ciphertext(self):
        nonce, ct = encrypt(self.key, self.plaintext, self.aad)
        assert len(nonce) == NONCE_SIZE  # 12 bytes
        assert len(ct) == len(self.plaintext) + TAG_SIZE  # 16-byte tag appended

    def test_roundtrip_decrypt(self):
        nonce, ct = encrypt(self.key, self.plaintext, self.aad)
        result = decrypt(self.key, nonce, ct, self.aad)
        assert result == self.plaintext

    def test_decrypt_fails_with_wrong_key(self):
        nonce, ct = encrypt(self.key, self.plaintext, self.aad)
        wrong_key = os.urandom(32)
        with pytest.raises(InvalidTag):
            decrypt(wrong_key, nonce, ct, self.aad)

    def test_decrypt_fails_with_tampered_ciphertext(self):
        nonce, ct = encrypt(self.key, self.plaintext, self.aad)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt(self.key, nonce, bytes(tampered), self.aad)

    def test_decrypt_fails_with_tampered_aad(self):
        nonce, ct = encrypt(self.key, self.plaintext, self.aad)
        with pytest.raises(InvalidTag):
            decrypt(self.key, nonce, ct, b"wrong-aad")

    def test_decrypt_fails_with_wrong_nonce(self):
        nonce, ct = encrypt(self.key, self.plaintext, self.aad)
        wrong_nonce = os.urandom(NONCE_SIZE)
        with pytest.raises(InvalidTag):
            decrypt(self.key, wrong_nonce, ct, self.aad)

    def test_empty_plaintext(self):
        nonce, ct = encrypt(self.key, b"", self.aad)
        assert decrypt(self.key, nonce, ct, self.aad) == b""

    def test_large_plaintext(self):
        big = os.urandom(4096)
        nonce, ct = encrypt(self.key, big, self.aad)
        assert decrypt(self.key, nonce, ct, self.aad) == big


class TestBuildAAD:
    """Tests for AAD builder helper."""

    def test_aad_length(self):
        # session_id(8) + seq(4) + ack(4) + flags(2) = 18 bytes
        aad = build_aad(b"\x00" * 8, 0, 0, 0)
        assert len(aad) == 18

    def test_aad_deterministic(self):
        sid = os.urandom(8)
        aad1 = build_aad(sid, 1, 2, 0x01)
        aad2 = build_aad(sid, 1, 2, 0x01)
        assert aad1 == aad2

    def test_aad_changes_with_seq(self):
        sid = os.urandom(8)
        assert build_aad(sid, 1, 0, 0) != build_aad(sid, 2, 0, 0)

    def test_aad_changes_with_flags(self):
        sid = os.urandom(8)
        assert build_aad(sid, 0, 0, 0x01) != build_aad(sid, 0, 0, 0x02)

    def test_aad_encodes_correctly(self):
        sid = b"\x01" * 8
        aad = build_aad(sid, 10, 20, 0x01)
        # Verify the packed portion
        assert aad[:8] == sid
        assert struct.unpack("!IIH", aad[8:]) == (10, 20, 0x01)
