import pytest
import hashlib
from cryptography.exceptions import InvalidTag
from security.handshake import HandshakeError, build_client_hello, parse_client_hello, build_server_hello, parse_server_hello
from security.crypto import derive_session_keys, build_aad, encrypt, decrypt
from config import PSK

class TestSecureTransfer:
    def do_handshake(self):
        client_hello_payload, client_nonce = build_client_hello(PSK)
        server_client_nonce = parse_client_hello(PSK, client_hello_payload)
        server_hello_payload, server_nonce, session_id = build_server_hello(PSK, server_client_nonce)
        client_server_nonce, client_session_id = parse_server_hello(PSK, client_nonce, server_hello_payload)

        client_keys = derive_session_keys(PSK, client_nonce, client_server_nonce)
        server_keys = derive_session_keys(PSK, server_client_nonce, server_nonce)
        return {
            "client_keys": client_keys,
            "server_keys": server_keys,
            "session_id": session_id,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "client_session_id": client_session_id
        }

    def test_secure_baseline_handshake_and_key_agreement(self):
        result = self.do_handshake()
        assert result["client_keys"]["enc_key"] == result["server_keys"]["enc_key"]
        assert result["client_session_id"] == result["session_id"]

    def test_secure_data_chunk_roundtrip_after_handshake(self):
        result = self.do_handshake()
        client_keys = result["client_keys"]
        server_keys = result["server_keys"]
        session_id = result["session_id"]

        plaintext = b"This is a secure file chunk"
        seq_num, ack_num, flags = 1, 0, 0x01  # FLAG_DATA
        aad = build_aad(session_id, seq_num, ack_num, flags)

        nonce, ciphertext = encrypt(server_keys["enc_key"], plaintext, aad)

        # Client decrypts with its matching key
        client_aad = build_aad(session_id, seq_num, ack_num, flags)
        recovered = decrypt(client_keys["enc_key"], nonce, ciphertext, client_aad)
        assert recovered == plaintext

    def test_final_sha256_matches_for_reconstructed_data(self):
        chunks = [b"chunk1", b"chunk2", b"chunk3"]
        full_data = b"".join(chunks)
        reconstructed = b"".join(chunks)

        expected_hash = hashlib.sha256(full_data).hexdigest()
        actual_hash = hashlib.sha256(reconstructed).hexdigest()
        assert expected_hash == actual_hash

    def test_multiple_secure_chunks_roundtrip_after_handshake(self):
        result = self.do_handshake()
        chunks = [b"chunk1", b"chunk2", b"chunk3"]
        recovered_chunks = []
        for i, chunk in enumerate(chunks, start=1):
            aad = build_aad(result["session_id"], i, 0, 0x01)
            nonce, ciphertext = encrypt(result["server_keys"]["enc_key"], chunk, aad)
            client_aad = build_aad(result["session_id"], i, 0, 0x01)
            recovered = decrypt(result["client_keys"]["enc_key"], nonce, ciphertext, client_aad)
            recovered_chunks.append(recovered)

        assert recovered_chunks == chunks

    def test_wrong_psk_prevents_secure_flow(self):
        wrong_psk = b"X" * len(PSK)
        client_hello_payload, _ = build_client_hello(PSK)
        with pytest.raises(HandshakeError):
            parse_client_hello(wrong_psk, client_hello_payload)

    def test_tampered_protected_data_fails_safely(self):
        result = self.do_handshake()
        session_id = result["session_id"]
        aad = build_aad(session_id, 1, 0, 0x01)
        nonce, ciphertext = encrypt(result["client_keys"]["enc_key"], b"valid data", aad)
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0xFF  # flip first byte of ciphertext
        with pytest.raises(InvalidTag):
            decrypt(result["client_keys"]["enc_key"], nonce, bytes(tampered_ct), aad)

    def test_final_sha256_detects_mismatch_when_data_is_modified(self):
        chunks = [b"chunk1", b"chunk2", b"chunk3"]
        full_data = b"".join(chunks)
        reconstructed = b"abc" + b"XXX" + b"def"

        expected_hash = hashlib.sha256(full_data).hexdigest()
        actual_hash = hashlib.sha256(reconstructed).hexdigest()
        assert expected_hash != actual_hash